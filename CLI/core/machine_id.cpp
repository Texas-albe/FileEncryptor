// 机器指纹采集：MAC 地址与主板序列号是两类独立来源，任一采集失败只丢弃该项，
// 最终指纹只取 SHA-256 前 16 字节，不含任何可复原的明文主机标识。
#include "machine_id.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
// NOMINMAX：Windows.h 的 min/max 宏会打断 std::min
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <winsock2.h>
#include <rpc.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <wbemidl.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/if_packet.h>   // sockaddr_ll（首个网卡 MAC，ifaddrs.h 只前向声明）
#endif
#endif

// 区块 trim：去除首尾空白与不可打印字符（BIOS 序列号常带尾随空格）
static std::string trim_ctrl(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (unsigned char)s[b] <= 0x20) ++b;
    while (e > b && (unsigned char)s[e - 1] <= 0x20) --e;
    return s.substr(b, e - b);
}

static void append_hex(std::string& out, const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out.push_back(d[p[i] >> 4]);
        out.push_back(d[p[i] & 15]);
    }
}

#ifdef _WIN32

// 区块 WMI：Win32_BaseBoard.SerialNumber（主板序列号的标准来源，缺权限时回退注册表）
static std::string wmi_board_serial() {
    std::string out;
    const HRESULT hr0 = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool coinit = SUCCEEDED(hr0) || hr0 == RPC_E_CHANGED_MODE;
    if (!coinit) return out;
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;
    IEnumWbemClassObject* en = nullptr;
    const _bstr_t ns(L"ROOT\\CIMV2");
    const _bstr_t q_text(L"SELECT SerialNumber FROM Win32_BaseBoard");
    const _bstr_t q_lang(L"WQL");
    do {
        if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_IWbemLocator, (void**)&loc)) || !loc) break;
        if (FAILED(loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr,
                                      nullptr, &svc)) || !svc) break;
        if (FAILED(CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                     RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                     nullptr, EOAC_NONE))) break;
        if (FAILED(svc->ExecQuery(q_lang, q_text, WBEM_FLAG_RETURN_IMMEDIATELY,
                                  nullptr, &en)) || !en) break;
        ULONG cnt = 0;
        IWbemClassObject* obj = nullptr;
        if (FAILED(en->Next(WBEM_INFINITE, 1, &obj, &cnt)) || !obj || cnt == 0) break;
        VARIANT v;
        VariantInit(&v);
        if (SUCCEEDED(obj->Get(L"SerialNumber", 0, &v, nullptr, nullptr)) &&
            v.vt == VT_BSTR && v.bstrVal) {
            const wchar_t* w = static_cast<const wchar_t*>(v.bstrVal);
            if (w) {
                int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::vector<char> buf((size_t)len, 0);
                    WideCharToMultiByte(CP_UTF8, 0, w, -1, buf.data(), len, nullptr, nullptr);
                    out.assign(buf.data());
                }
            }
        }
        VariantClear(&v);
    } while (0);
    if (en) en->Release();
    if (svc) svc->Release();
    if (loc) loc->Release();
    if (coinit) CoUninitialize();
    return trim_ctrl(out);
}

// 区块 注册表：WMI 不可用（精简镜像/服务未注册）时读 SMBIOS 遗留键
static std::string reg_board_serial() {
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS",
                      0, KEY_READ, &hk) != ERROR_SUCCESS) return std::string();
    const char* names[] = {"SerialNumber", "BaseBoardSerialNumber", "BdVersion", "Product"};
    std::string out;
    char buf[128];
    for (const char* n : names) {
        DWORD len = sizeof(buf);
        if (RegQueryValueExA(hk, n, nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &len)
                == ERROR_SUCCESS) {
            if (len >= sizeof(buf)) len = sizeof(buf) - 1;
            buf[len] = 0;
            const std::string s = trim_ctrl(std::string(buf, len));
            if (!s.empty()) { out = s; break; }
        }
    }
    RegCloseKey(hk);
    return out;
}

// 区块 win MAC：第一块已启用网卡的物理地址（跳过回环与全零地址）
static bool win_first_mac(std::string& mac_hex) {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
                             nullptr, &size) != NO_ERROR || size == 0) {
        return false;
    }
    std::vector<unsigned char> buf((size_t)size + sizeof(IP_ADAPTER_ADDRESSES) + 16, 0);
    IP_ADAPTER_ADDRESSES* first = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    DWORD rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
                                    first, &size);
    if (rc != NO_ERROR) return false;
    for (IP_ADAPTER_ADDRESSES* a = first; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->PhysicalAddressLength != 6) continue;
        unsigned char acc = 0;
        for (DWORD i = 0; i < a->PhysicalAddressLength; ++i) acc |= a->PhysicalAddress[i];
        if (acc == 0) continue;
        mac_hex.assign(a->PhysicalAddress, a->PhysicalAddress + 6);
        return true;
    }
    return false;
}
#endif

#ifndef _WIN32

// 区块 dmi：Linux 主板序列号（/sys/class/dmi 优先，容器里退到 dbus machine-id）
static std::string read_text_file(const char* path) {
    std::FILE* fp = std::fopen(path, "rb");
    if (!fp) return std::string();
    std::string out;
    char buf[256];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) out.append(buf, n);
    std::fclose(fp);
    return out;
}

static std::string linux_board_serial() {
#ifdef __ANDROID__
    return std::string();   // Android 无 dmi，/var/lib/dbus/machine-id 也不可读
#endif
    static const char* paths[] = {
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_serial",
        "/sys/class/dmi/id/chassis_serial",
        "/var/lib/dbus/machine-id",
    };
    for (const char* p : paths) {
        const std::string s = trim_ctrl(read_text_file(p));
        if (!s.empty()) return s;
    }
    return std::string();
}

// 区块 linux MAC：第一块已启用且非回环的链路层地址
static bool linux_first_mac(std::string& mac_hex) {
#ifdef __ANDROID__
    (void)mac_hex;
    return false;   // Android 10+ 限制 MAC 访问，getifaddrs 只返回全零地址
#endif
    struct ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) != 0 || !ifa) return false;
    bool found = false;
    for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
        if (!(p->ifa_flags & IFF_UP)) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        if (p->ifa_addr && p->ifa_addr->sa_family == AF_PACKET) {
            const struct sockaddr_ll* s = reinterpret_cast<const struct sockaddr_ll*>(p->ifa_addr);
            if (s->sll_halen == 6) {
                unsigned char acc = 0;
                for (int i = 0; i < 6; ++i) acc |= s->sll_addr[i];
                if (acc != 0) { mac_hex.assign(s->sll_addr, s->sll_addr + 6); found = true; break; }
            }
        }
    }
    freeifaddrs(ifa);
    return found;
}
#endif

MachineId collect_machine_id() {
    MachineId m;
    std::string mac_raw, board;
#ifdef _WIN32
    if (win_first_mac(mac_raw)) m.flags |= 0x01;
    board = wmi_board_serial();
    if (board.empty()) board = reg_board_serial();
#else
    if (linux_first_mac(mac_raw)) m.flags |= 0x01;
    board = linux_board_serial();
#endif
    if (!trim_ctrl(board).empty()) m.flags |= 0x02;
    if (m.flags == 0) return m;

    unsigned char buf[64];
    size_t n = 0;
    if (m.has_mac() && n < sizeof(buf)) {
        const size_t k = std::min(mac_raw.size(), sizeof(buf) - n);
        memcpy(buf + n, mac_raw.data(), k);
        n += k;
    }
    if (m.has_board() && n < sizeof(buf)) {
        const std::string b = trim_ctrl(board);
        memcpy(buf + n, b.data(), std::min(b.size(), sizeof(buf) - n));
        n += std::min(b.size(), sizeof(buf) - n);
    }
    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest), buf, (unsigned long long)n, nullptr, 0);
    memcpy(m.id, digest, WM_ID_LEN);
    sodium_memzero(digest, sizeof(digest));
    m.available = true;
    return m;
}

std::string machine_id_hex(const MachineId& m) {
    char hex[WM_ID_HEX_LEN + 1];
    for (size_t i = 0; i < WM_ID_LEN; ++i) {
        std::snprintf(hex + i * 2, 3, "%02x", m.id[i]);
    }
    hex[WM_ID_HEX_LEN] = 0;
    return std::string(hex);
}

std::string machine_id_prefix_hex(const MachineId& m, size_t bytes) {
    if (bytes == 0) bytes = 4;
    if (bytes > WM_ID_LEN) bytes = WM_ID_LEN;
    std::string s;
    s.reserve(bytes * 2);
    append_hex(s, m.id, bytes);
    return s;
}
