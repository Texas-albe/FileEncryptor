// fe_ipc：§5.1 受限 IPC 控制面（命名管道）。只传命令与一次性密码，
// KEK/索引密钥/明文一律不出 holder 进程（§5.1#1）。密码 hex 编码走管道、用后清零。
#include "fe_common.h"
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#  include <windows.h>
#  include <sddl.h>
#  include <vector>
#  pragma comment(lib, "advapi32.lib")
#endif

std::string   g_ipc_vault;
VDiskApi*     g_ipc_v = nullptr;
VDiskHandle** g_ipc_h = nullptr;
std::atomic<bool> g_ipc_unlocked{false};
std::atomic<bool> g_ipc_stop{false};

std::string ipc_pipe_name(const std::string& vault) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : vault) { h ^= (unsigned char)c; h *= 0x100000001b3ULL; }
    char buf[32]; snprintf(buf, sizeof buf, "%016llx", (unsigned long long)h);
#ifdef _WIN32
    return std::string("\\\\.\\pipe\\fe-") + buf;
#else
    // Linux：XDG_RUNTIME_DIR 优先（/run/user/<uid>，仅本人可访问），退化到 /tmp。
    const char* xdg = getenv("XDG_RUNTIME_DIR");
    std::string base = (xdg && *xdg) ? std::string(xdg) : std::string("/tmp");
    return base + "/fe-" + buf + ".sock";
#endif
}

std::string hex_encode(const std::string& s) {
    static const char* t = "0123456789abcdef";
    std::string o; o.reserve(s.size() * 2);
    for (unsigned char c : s) { o += t[c >> 4]; o += t[c & 0xF]; }
    return o;
}

std::string hex_decode(const std::string& s) {
    auto hv = [](char c) -> int { if (c>='0'&&c<='9')return c-'0'; if (c>='a'&&c<='f')return c-'a'+10; if (c>='A'&&c<='F')return c-'A'+10; return -1; };
    std::string o;
    for (size_t i = 0; i + 1 < s.size(); i += 2) { int a=hv(s[i]), b=hv(s[i+1]); if (a<0||b<0) break; o += (char)((a<<4)|b); }
    return o;
}

static std::string ipc_dispatch(const std::string& req) {
    size_t sp = req.find(' ');
    std::string cmd = (sp == std::string::npos) ? req : req.substr(0, sp);
    std::string arg = (sp == std::string::npos) ? "" : req.substr(sp + 1);
    if (!g_ipc_v || !g_ipc_h) return "ERR nostate";
    VDiskApi& v = *g_ipc_v;
    if (cmd == "status") {
        std::string s = std::string("OK unlocked=") + (g_ipc_unlocked.load() ? "1" : "0");
        if (g_ipc_unlocked.load() && v.idle_remaining && g_ipc_h && *g_ipc_h)
            s += " idle=" + std::to_string(v.idle_remaining(*g_ipc_h));
        return s;
    }
    if (cmd == "lock") {
        if (g_ipc_h && *g_ipc_h) v.lock(*g_ipc_h);
        g_ipc_unlocked = false;
        return "OK";
    }
    if (cmd == "unlock") {
        std::string pass = hex_decode(arg);
        if (pass.empty()) return "ERR badpass";
        VDiskStatus st = v.unlock(*g_ipc_h, pass.c_str(), 0);
        secure_zero(pass.data(), pass.size());   // 用后即清
        if (st == VDISK_OK) { g_ipc_unlocked = true; return "OK"; }
        if (st == VDISK_E_AUTH) return "ERR auth";
        return "ERR io";
    }
    if (cmd == "reindex") {
        VDiskStatus st = v.reindex(*g_ipc_h, nullptr);
        return (st == VDISK_OK) ? "OK" : "ERR io";
    }
    // M4：用恢复密钥解锁（等价解锁凭证，§4.4）
    if (cmd == "unlockr") {
        std::string code = hex_decode(arg);
        if (code.empty()) return "ERR badcode";
        VDiskStatus st = v.unlock(*g_ipc_h, code.c_str(), 1);
        secure_zero(code.data(), code.size());
        if (st == VDISK_OK) { g_ipc_unlocked = true; return "OK"; }
        if (st == VDISK_E_AUTH) return "ERR auth";
        return "ERR io";
    }
    // M5：空闲超时自动锁（秒，0=关闭）
    if (cmd == "idle") {
        if (!v.set_idle_timeout) return "ERR unsupported";
        uint32_t sec = (uint32_t)strtoul(arg.c_str(), nullptr, 10);
        return (v.set_idle_timeout(*g_ipc_h, sec) == VDISK_OK) ? "OK" : "ERR io";
    }
    // M5：预读缓存 cap_bytes ahead_segments
    if (cmd == "cache") {
        if (!v.set_read_cache) return "ERR unsupported";
        size_t sp2 = arg.find(' ');
        uint64_t cap = strtoull(arg.c_str(), nullptr, 10);
        uint32_t ahead = (sp2 == std::string::npos) ? 4
                       : (uint32_t)strtoul(arg.c_str() + sp2 + 1, nullptr, 10);
        return (v.set_read_cache(*g_ipc_h, cap, ahead) == VDISK_OK) ? "OK" : "ERR io";
    }
    return "ERR unknown";
}

#if defined(_WIN32)
// 管道 ACL 限「当前用户 + SYSTEM + Administrators」。不设则默认 DACL 来自进程 token，
// 服务以 LocalSystem 跑时普通用户 GUI 连不上（ERR nopipe）——安全与功能问题一体。
// 口径对齐 Linux 侧 0700 + SO_PEERCRED。
static PSECURITY_DESCRIPTOR ipc_pipe_sd() {
    static PSECURITY_DESCRIPTOR cached = nullptr;
    if (!cached) {
        HANDLE tok = nullptr;
        std::wstring sddl;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            DWORD sz = 0;
            GetTokenInformation(tok, TokenUser, nullptr, 0, &sz);
            if (sz >= sizeof(void*) * 2 && sz <= 1024) {
                std::vector<BYTE> buf(sz);
                if (GetTokenInformation(tok, TokenUser, buf.data(), sz, &sz) && sz >= sizeof(void*) * 2) {
                    void* sid = *reinterpret_cast<void**>(buf.data());   // TOKEN_USER 首字段即 PSID
                    wchar_t* sidstr = nullptr;
                    if (sid && ConvertSidToStringSidW(sid, &sidstr)) {
                        sddl = std::wstring(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;") + sidstr + L")";
                        LocalFree(sidstr);
                    }
                }
            }
            CloseHandle(tok);
        }
        if (sddl.empty()) sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";   // 兜底：仅特权身份
        PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.c_str(), SDDL_REVISION_1, &sd, &need)) return nullptr;
        cached = sd;   // LocalAlloc，生命周期=进程
    }
    return cached;
}

// 客户端身份校验：管道名可被同机任何人猜到，必须确认对端身份。
// 规则：同进程用户 或 SYSTEM/Administrators 才放行（LocalSystem 服务的客户端常是管理员 GUI）。
// 拿不到客户端 token 时保守拒绝——宁可不服务，也不给未验证方开解锁口。
static bool ipc_client_allowed(HANDLE pipe) {
    DWORD pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid) || pid == 0) return false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return false;
    HANDLE tok = nullptr;
    bool ok = false;
    if (OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
        DWORD sz = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &sz);
        if (sz >= sizeof(void*) * 2 && sz <= 1024) {
            std::vector<BYTE> buf(sz);
            if (GetTokenInformation(tok, TokenUser, buf.data(), sz, &sz) && sz >= sizeof(void*) * 2) {
                void* sid = *reinterpret_cast<void**>(buf.data());
                // 本进程用户
                HANDLE mytok = nullptr;
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mytok)) {
                    DWORD msz = 0;
                    GetTokenInformation(mytok, TokenUser, nullptr, 0, &msz);
                    if (msz >= sizeof(void*) * 2 && msz <= 1024) {
                        std::vector<BYTE> mbuf(msz);
                        if (GetTokenInformation(mytok, TokenUser, mbuf.data(), msz, &msz)) {
                            void* mysid = *reinterpret_cast<void**>(mbuf.data());
                            ok = (sid && mysid && EqualSid(sid, mysid));
                        }
                    }
                    CloseHandle(mytok);
                }
                // SYSTEM(S-1-5-18) / Administrators(S-1-5-32-544)
                if (!ok && sid) {
                    wchar_t* s = nullptr;
                    if (ConvertSidToStringSidW(sid, &s)) {
                        ok = (wcscmp(s, L"S-1-5-18") == 0 || wcscmp(s, L"S-1-5-32-544") == 0);
                        LocalFree(s);
                    }
                }
            }
        }
        CloseHandle(tok);
    }
    CloseHandle(proc);
    return ok;
}

void ipc_server_thread() {
    std::string name = ipc_pipe_name(g_ipc_vault);
    PSECURITY_DESCRIPTOR sd = ipc_pipe_sd();
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    while (!g_ipc_stop.load()) {
        HANDLE pipe = CreateNamedPipeW(utf8_to_wide(name).c_str(),
            PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, sd ? &sa : nullptr);
        if (pipe == INVALID_HANDLE_VALUE) break;
        if (ConnectNamedPipe(pipe, nullptr)) {
            if (ipc_client_allowed(pipe)) {
                // 读超时：客户端连上不发数据会永久占住服务线程 → 解锁/锁定全失效（M4/坏连接 DoS）
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
                char buf[8192]; DWORD n = 0;
                DWORD deadline = GetTickCount() + 5000;   // 5s 未发完即断开
                bool got = false;
                for (;;) {
                    if (!ReadFile(pipe, buf + n, (DWORD)(sizeof(buf) - 1 - n), &n, nullptr)) break;
                    if (n > 0) { got = true; break; }
                    if (GetTickCount() > deadline) break;
                }
                if (got && n > 0) {
                    buf[n] = 0; std::string req(buf);
                    while (!req.empty() && (req.back() == '\n' || req.back() == '\r')) req.pop_back();
                    std::string resp = ipc_dispatch(req);
                    DWORD w = 0; WriteFile(pipe, resp.c_str(), (DWORD)resp.size(), &w, nullptr);
                }
            }
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe); CloseHandle(pipe);
    }
}
std::string ipc_call(const std::string& vault, const std::string& req) {
    std::wstring wname = utf8_to_wide(ipc_pipe_name(vault));
    WaitNamedPipeW(wname.c_str(), 3000);   // 等服务起来（最多 3s）；失败也直接试连一次
    HANDLE pipe = CreateFileW(wname.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return "ERR nopipe";
    DWORD w = 0; WriteFile(pipe, req.c_str(), (DWORD)req.size(), &w, nullptr);
    // 读超时：服务端无响应时不让 GUI 永久卡住
    char buf[4096]; DWORD n = 0; std::string resp;
    DWORD deadline = GetTickCount() + 5000;
    for (;;) {
        if (ReadFile(pipe, buf, sizeof(buf) - 1, &n, nullptr) && n > 0) { buf[n] = 0; resp = buf; break; }
        if (GetTickCount() > deadline) break;
    }
    CloseHandle(pipe);
    return resp.empty() ? "ERR io" : resp;
}
#else
// Linux 控制面：Unix domain socket（SOCK_STREAM）。
// 安全口径对齐 §5.1：socket 文件 0700（仅 owner），并用 SO_PEERCRED 拒非同 uid 进程，
// 防止别的用户猜到路径后发 unlock 试探密码。协议与 Windows 命名管道完全一致。
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>

static bool ipc_fill_sun(sockaddr_un& sa, const std::string& path) {
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (path.size() >= sizeof(sa.sun_path)) return false;   // 路径过长无法表达
    memcpy(sa.sun_path, path.c_str(), path.size());
    return true;
}

void ipc_server_thread() {
    std::string path = ipc_pipe_name(g_ipc_vault);
    sockaddr_un sa;
    if (!ipc_fill_sun(sa, path)) return;
    unlink(path.c_str());                       // 清上次异常退出的残 socket
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) return;
    if (bind(srv, (sockaddr*)&sa, sizeof sa) != 0) { close(srv); return; }
    chmod(path.c_str(), 0700);                  // 仅 owner 可连接
    if (listen(srv, 8) != 0) { close(srv); unlink(path.c_str()); return; }
    while (!g_ipc_stop.load()) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) { if (errno == EINTR) continue; break; }
        // 同 uid 校验：拒绝其它用户进程
        ucred cr; socklen_t crl = sizeof cr;
        bool same_user = (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crl) == 0) &&
                         (cr.uid == getuid());
        if (same_user) {
            std::string req;
            char buf[4096];
            ssize_t n;
            while ((n = recv(fd, buf, sizeof buf - 1, 0)) > 0) {
                req.append(buf, (size_t)n);
                if (req.size() >= 8191) break;
            }
            while (!req.empty() && (req.back() == '\n' || req.back() == '\r')) req.pop_back();
            if (!req.empty()) {
                std::string resp = ipc_dispatch(req);
                size_t off = 0;
                while (off < resp.size()) {
                    ssize_t w = send(fd, resp.data() + off, resp.size() - off, 0);
                    if (w <= 0) break;
                    off += (size_t)w;
                }
            }
        }
        close(fd);
    }
    close(srv);
    unlink(path.c_str());                       // 退出不留残 socket 文件
}

std::string ipc_call(const std::string& vault, const std::string& req) {
    std::string path = ipc_pipe_name(vault);
    sockaddr_un sa;
    if (!ipc_fill_sun(sa, path)) return "ERR unsupported";
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return "ERR io";
    if (connect(fd, (sockaddr*)&sa, sizeof sa) != 0) { close(fd); return "ERR noserver"; }
    if (send(fd, req.data(), req.size(), 0) < 0) { close(fd); return "ERR io"; }
    shutdown(fd, SHUT_WR);                      // 告知服务端请求已完
    std::string resp;
    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof buf, 0)) > 0) resp.append(buf, (size_t)n);
    close(fd);
    return resp.empty() ? "ERR io" : resp;
}
#endif
