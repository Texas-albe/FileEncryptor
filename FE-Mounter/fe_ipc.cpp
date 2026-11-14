// fe_ipc
// KEK/索引密钥/明文一
#include "fe_common.h"
#include <cstdio>
#include <cstring>
#include <thread>
#include <mutex>
#include <chrono>
#include <sodium.h>
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
std::atomic<uint64_t> g_last_fg_activity_ms{0};   // M5 前台活动自动锁
std::atomic<int64_t> g_suspend_until_ms{0};   // M8
void        (*g_ipc_eject_hook)() = nullptr;

// M6
static std::mutex g_vdisk_call_mtx;
std::mutex& fe_vdisk_call_mutex() { return g_vdisk_call_mtx; }
// M7
static std::mutex g_idle_decision_mtx;
std::mutex& fe_idle_decision_mutex() { return g_idle_decision_mtx; }

// 管道名派生
// vault 路径构造哈希碰
std::string ipc_pipe_name(const std::string& vault) {
    unsigned char h[crypto_generichash_BYTES_MIN];   // 16 字节
    crypto_generichash(h, sizeof h, (const unsigned char*)vault.data(), vault.size(), nullptr, 0);
    char buf[64]; static const char* t = "0123456789abcdef";
    size_t hi = 0;
    for (unsigned char c : h) { buf[hi++] = t[c >> 4]; buf[hi++] = t[c & 0xF]; }
    buf[hi] = 0;
#ifdef _WIN32
    return std::string("\\\\.\\pipe\\fe-") + buf;
#else
    // Linux
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

// 解锁防暴破
// 单 mounter 进程只服务一
static constexpr int    kUnlockMaxFails = 5;
static constexpr uint64_t kUnlockLockMs = 30000;   // 锁定 30s
static std::atomic<int>      g_unlock_fails{0};
static std::atomic<uint64_t> g_unlock_lock_until{0};

static uint64_t now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// 是否处于暴破锁
static bool unlock_blocked() {
    uint64_t until = g_unlock_lock_until.load();
    if (!until) return false;
    if (now_ms() < until) return true;
    g_unlock_lock_until.store(0);
    g_unlock_fails.store(0);
    return false;
}

static std::string do_unlock(const std::string& arg, int flags) {
    if (unlock_blocked()) return "ERR locked";   // 暴破锁定
    if (!g_ipc_v || !g_ipc_h || !*g_ipc_h) return "ERR nostate";
    std::string pass = hex_decode(arg);
    if (pass.empty()) return "ERR badpass";
    VDiskStatus st = g_ipc_v->unlock(*g_ipc_h, pass.c_str(), flags);
    sodium_memzero(pass.data(), pass.size());   // 用后即清
    if (st == VDISK_OK) {
        // M7
        std::lock_guard<std::mutex> lk(fe_idle_decision_mutex());
        g_ipc_unlocked = true;
        g_suspend_until_ms.store(0, std::memory_order_relaxed);   // M8
        g_last_fg_activity_ms.store(now_ms(), std::memory_order_relaxed);   // 解锁即起算一
        g_unlock_fails.store(0);
        g_unlock_lock_until.store(0);
        // M8
        if (g_ipc_v->set_idle_timeout) g_ipc_v->set_idle_timeout(*g_ipc_h, g_svc_idle);
        return "OK";
    }
    if (++g_unlock_fails >= kUnlockMaxFails)
        g_unlock_lock_until.store(now_ms() + kUnlockLockMs);   // 触发锁定窗口
    if (st == VDISK_E_AUTH) return "ERR auth";
    return "ERR io";
}

static std::string ipc_dispatch(const std::string& req) {
    // M6
    std::lock_guard<std::mutex> lk(fe_vdisk_call_mutex());
    size_t sp = req.find(' ');
    std::string cmd = (sp == std::string::npos) ? req : req.substr(0, sp);
    std::string arg = (sp == std::string::npos) ? "" : req.substr(sp + 1);
    // 低危 C 组
    if (!g_ipc_v || !g_ipc_h || !*g_ipc_h) return "ERR nostate";
    VDiskApi& v = *g_ipc_v;
    if (cmd == "status") {
        std::string s = std::string("OK unlocked=") + (g_ipc_unlocked.load() ? "1" : "0");
        if (g_ipc_unlocked.load() && v.idle_remaining && g_ipc_h && *g_ipc_h)
            s += " idle=" + std::to_string(v.idle_remaining(*g_ipc_h));
        int64_t sus = g_suspend_until_ms.load(std::memory_order_relaxed);
        if (sus > 0) {
            uint64_t rem = (uint64_t)sus > now_ms() ? (uint64_t)sus - now_ms() : 0;
            s += " suspend=" + std::to_string(rem / 1000 + (rem % 1000 ? 1 : 0));
        }
        return s;
    }
    if (cmd == "lock") {
        if (g_ipc_h && *g_ipc_h) v.lock(*g_ipc_h);
        g_ipc_unlocked = false;
        g_suspend_until_ms.store(0, std::memory_order_relaxed);   // M8
        g_last_fg_activity_ms.store(0, std::memory_order_relaxed);   // 锁态不计
        // M8
        if (v.set_idle_timeout) v.set_idle_timeout(*g_ipc_h, g_svc_idle);
        return "OK";
    }
    if (cmd == "unlock") {
        return do_unlock(arg, 0);
    }
    if (cmd == "reindex") {
        VDiskStatus st = v.reindex(*g_ipc_h, nullptr);
        return (st == VDISK_OK) ? "OK" : "ERR io";
    }
    // M4
    if (cmd == "unlockr") {
        return do_unlock(arg, 1);
    }
    // M5
    if (cmd == "idle") {
        if (!v.set_idle_timeout) return "ERR unsupported";
        uint32_t sec = (uint32_t)strtoul(arg.c_str(), nullptr, 10);
        g_svc_idle = sec;   // 与 watchdog 同步
        g_last_fg_activity_ms.store(now_ms(), std::memory_order_relaxed);   // 改超时即重新起
        // M8
        int64_t sus = g_suspend_until_ms.load(std::memory_order_relaxed);
        if (sus > (int64_t)now_ms()) return "OK";
        if (v.set_idle_timeout(*g_ipc_h, sec) != VDISK_OK) return "ERR io";
        return "OK";
    }
    // M5
    if (cmd == "cache") {
        if (!v.set_read_cache) return "ERR unsupported";
        size_t sp2 = arg.find(' ');
        uint64_t cap = strtoull(arg.c_str(), nullptr, 10);
        uint32_t ahead = (sp2 == std::string::npos) ? 4
                       : (uint32_t)strtoul(arg.c_str() + sp2 + 1, nullptr, 10);
        return (v.set_read_cache(*g_ipc_h, cap, ahead) == VDISK_OK) ? "OK" : "ERR io";
    }
    // 卸载磁盘
    if (cmd == "eject") {
        g_ipc_stop = true;
        if (g_ipc_eject_hook) {
            std::thread([] {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));  // 等响应写回
                if (g_ipc_eject_hook) g_ipc_eject_hook();
            }).detach();
        }
        return "OK";
    }
    // M8
    if (cmd == "suspend") {
        if (!g_ipc_unlocked.load()) return "ERR locked";   // 锁态无可暂停
        long minutes = strtol(arg.c_str(), nullptr, 10);
        if (minutes <= 0) {
            g_suspend_until_ms.store(0, std::memory_order_relaxed);
            // 取消暂停
            if (v.set_idle_timeout) v.set_idle_timeout(*g_ipc_h, g_svc_idle);
            g_last_fg_activity_ms.store(now_ms(), std::memory_order_relaxed);   // 恢复即重新起算
            return "OK suspend=0";
        }
        if (minutes > 24 * 60) minutes = 24 * 60;
        g_suspend_until_ms.store((int64_t)now_ms() + (int64_t)minutes * 60000,
                                 std::memory_order_relaxed);
        g_last_fg_activity_ms.store(now_ms(), std::memory_order_relaxed);   // 暂停期间持续刷
        // 关键
        // 自行超时锁定
        // 「设了暂时不锁定
        if (v.set_idle_timeout) v.set_idle_timeout(*g_ipc_h, 0);
        return "OK suspend=" + std::to_string(minutes);
    }
    return "ERR unknown";
}

#if defined(_WIN32)
// 管道 ACL 限「当前用户 + SYSTEM +
// 服务
// 口径对齐 Linux 侧 0700 +
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
        if (sddl.empty()) sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";   // 兜底
        PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.c_str(), SDDL_REVISION_1, &sd, &need)) return nullptr;
        cached = sd;   // LocalAlloc
    }
    return cached;
}

// 客户端身份校验
// 规则
// 拿不到客户端 token
// 校验 token 是否隶属于
static bool token_in_group(HANDLE tok, const wchar_t* groupSidStr) {
    if (!tok) return false;
    PSID gsid = nullptr;
    if (!ConvertStringSidToSidW(groupSidStr, &gsid)) return false;
    BOOL member = FALSE;
    CheckTokenMembership(tok, gsid, &member);
    LocalFree(gsid);
    return member != FALSE;
}

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
                // SYSTEM
                if (!ok && sid) {
                    wchar_t* s = nullptr;
                    if (ConvertSidToStringSidW(sid, &s)) {
                        if (wcscmp(s, L"S-1-5-18") == 0) ok = true;
                        else if (tok && token_in_group(tok, L"S-1-5-32-544")) ok = true;   // 组隶属
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
    // P0-4 失败关闭
    // 旧行
    if (!sd) {
        fprintf(stderr, "[fe] ipc: restricted security descriptor unavailable, refusing to serve\n");
        return;
    }
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    while (!g_ipc_stop.load()) {
        HANDLE pipe = CreateNamedPipeW(utf8_to_wide(name).c_str(),
            PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa);
        if (pipe == INVALID_HANDLE_VALUE) break;
        if (ConnectNamedPipe(pipe, nullptr)) {
            if (ipc_client_allowed(pipe)) {
                // M4 读超
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
                OVERLAPPED ov; memset(&ov, 0, sizeof ov);
                ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (ov.hEvent) {
                    char buf[8192]; DWORD n = 0;
                    BOOL ok = ReadFile(pipe, buf, (DWORD)(sizeof(buf) - 1), &n, &ov);
                    if (!ok && GetLastError() == ERROR_IO_PENDING) {
                        if (WaitForSingleObject(ov.hEvent, 5000) != WAIT_OBJECT_0) {
                            CancelIo(pipe);                            // 5s 超
                            GetOverlappedResult(pipe, &ov, &n, TRUE);  // 等取消完成
                            n = 0;
                        } else if (!GetOverlappedResult(pipe, &ov, &n, FALSE)) {
                            n = 0;                                     // 读失败
                        }
                    } else if (!ok) {
                        n = 0;
                    }
                    CloseHandle(ov.hEvent);
                    if (n > 0) {
                        buf[n] = 0; std::string req(buf);
                        while (!req.empty() && (req.back() == '\n' || req.back() == '\r')) req.pop_back();
                        std::string resp = ipc_dispatch(req);
                        DWORD w = 0; WriteFile(pipe, resp.c_str(), (DWORD)resp.size(), &w, nullptr);
                    }
                }
            }
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe); CloseHandle(pipe);
    }
}
std::string ipc_call(const std::string& vault, const std::string& req) {
    std::wstring wname = utf8_to_wide(ipc_pipe_name(vault));
    WaitNamedPipeW(wname.c_str(), 3000);   // 等服务起来
    HANDLE pipe = CreateFileW(wname.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return "ERR nopipe";
    DWORD w = 0; WriteFile(pipe, req.c_str(), (DWORD)req.size(), &w, nullptr);
    // 读超
    char buf[4096]; DWORD n = 0; std::string resp;
    DWORD deadline = GetTickCount() + 5000;
    for (;;) {
        // 低危 C 组
        if (!ReadFile(pipe, buf, sizeof(buf) - 1, &n, nullptr)) break;
        if (n > 0) { buf[n] = 0; resp = buf; break; }
        if (GetTickCount() > deadline) break;
    }
    CloseHandle(pipe);
    return resp.empty() ? "ERR io" : resp;
}
#else
// Linux 控制面
// 安全口径对齐 §5.1
// 别的用户猜到路
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>

static bool ipc_fill_sun(sockaddr_un& sa, const std::string& path) {
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (path.size() >= sizeof(sa.sun_path)) return false;   // 路径过长无法表
    memcpy(sa.sun_path, path.c_str(), path.size());
    return true;
}

void ipc_server_thread() {
    std::string path = ipc_pipe_name(g_ipc_vault);
    sockaddr_un sa;
    if (!ipc_fill_sun(sa, path)) return;
    unlink(path.c_str());                       // 清上次异常退出
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) return;
    if (bind(srv, (sockaddr*)&sa, sizeof sa) != 0) { close(srv); return; }
    chmod(path.c_str(), 0700);                  // 仅 owner 可连接
    if (listen(srv, 8) != 0) { close(srv); unlink(path.c_str()); return; }
    while (!g_ipc_stop.load()) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) { if (errno == EINTR) continue; break; }
        // 同 uid 校验
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
    shutdown(fd, SHUT_WR);                      // 告知服务端请求
    std::string resp;
    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof buf, 0)) > 0) resp.append(buf, (size_t)n);
    close(fd);
    return resp.empty() ? "ERR io" : resp;
}
#endif
