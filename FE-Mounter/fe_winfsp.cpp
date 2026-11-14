// fe_winfsp
// 「进程本身即服务」
// 解锁 vault、起 IPC、挂载，不依
#include "fe_common.h"
#if FE_HAVE_WINFSP
// TOKEN_USER 等需 _WIN32_WINNT >=
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#  define WINVER 0x0601
#endif
#include <winfsp.h>
#include <sddl.h>
#include <windows.h>
#include <winnt.h>      // TOKEN_USER / LPTOKEN_USER
#include <shlobj.h>     // SHGetKnownFolderPath：允许根
#pragma comment(lib, "shell32.lib")
#include <tlhelp32.h>   // CreateToolhelp32Snapshot
#include <Wtsapi32.h>   // WTSGetActiveConsoleSessi
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>
#include <chrono>
#include <atomic>
#include <new>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")     
#pragma comment(lib, "wtsapi32.lib")   // WTSGetActiveConsoleSessionId

// 调试输出
#define WFDBG(...) do { if (getenv("FE_MOUNT_DEBUG")) fprintf(stderr, __VA_ARGS__); } while (0)

std::string g_svc_vault, g_svc_pass, g_svc_mp, g_svc_lib;
bool g_svc_rw = false;            // M6 可写挂载开关
uint32_t g_svc_idle = 0;          // M5 前台活动自动锁

// 单调时钟毫秒
static uint64_t wf_now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
// 权威锁定态
static bool fe_is_locked() { return !g_ipc_unlocked.load(std::memory_order_relaxed); }

// M5 前台活动判定
// 「前台程序」= 交互
// 后台服务
// 它们对盘内文件
// EnumWindows 能看到用户窗口
// 窗口
// M7
static std::mutex& g_idle_mtx = fe_idle_decision_mutex();   // 保护「刷新活动 ↔
static std::mutex g_fg_snap_mtx;               // 单独保护前台快
static DWORD     g_my_session = 0;             // mounter 自身
static bool      g_fg_can_enum = false;        // 能否枚举本
static std::atomic<bool> g_fg_stop{false};     // 前台快照线程退
static std::thread g_fg_thread;                // 后台周期刷新
static std::thread g_watchdog_thread;          // M5 空闲看门狗

// 可见顶层窗口进
// I/O 热路径只读取
struct FgSnapshot {
    DWORD                     foreground_pid = 0;
    std::unordered_set<DWORD> visible_pids;
};
static FgSnapshot g_fg_snap;

// 挂载上下文
struct FeCtx { bool is_dir; std::string vpath; PVOID dir_buffer; DWORD owner_pid; };

// M5+
// 目录句柄，计入
// 无从续期）
static std::mutex                        g_open_mtx;
static std::unordered_set<const FeCtx*>  g_open_files;

static BOOL CALLBACK fg_enum_cb(HWND h, LPARAM param) {
    FgSnapshot* s = reinterpret_cast<FgSnapshot*>(param);
    if (!IsWindowVisible(h)) return TRUE;                              // 隐藏窗
    wchar_t cls[64] = { 0 };
    GetClassNameW(h, cls, 64);
    // PseudoConsoleWindow 是控制台程序自
    // 任务栏不显示它
    // 操作加密盘
    bool pseudo_console = (wcscmp(cls, L"PseudoConsoleWindow") == 0);
    if (!pseudo_console && (GetWindowLongPtrW(h, GWL_EXSTYLE) & WS_EX_TOOLWINDOW)) return TRUE;   // 工具/浮动窗不计
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid) s->visible_pids.insert(pid);
    // 旧式控制台窗口
    // 此为兼容分支）
    if (!pseudo_console && wcscmp(cls, L"ConsoleWindowClass") == 0 && pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == pid && pe.th32ParentProcessID) {
                        s->visible_pids.insert(pe.th32ParentProcessID);
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
    return TRUE;
}

// 在「局部」快照上枚
// 关键
// 一旦
// 因此先
static FgSnapshot fg_build_snapshot() {
    FgSnapshot s;
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowThreadProcessId(fg, &s.foreground_pid);
    EnumWindows(fg_enum_cb, reinterpret_cast<LPARAM>(&s));
    return s;
}

// 后台线程
static void fg_snapshot_thread() {
    while (!g_fg_stop.load(std::memory_order_relaxed)) {
        FgSnapshot s = fg_build_snapshot();   // 无锁枚举
        { std::lock_guard<std::mutex> lk(g_fg_snap_mtx); g_fg_snap = std::move(s); }
        for (int i = 0; i < 10 && !g_fg_stop.load(std::memory_order_relaxed); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// 会话探测
static void fg_init_session() {
    DWORD my = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &my)) my = 0;
    g_my_session = my;
    g_fg_can_enum = (my == WTSGetActiveConsoleSessionId());
    {
        FgSnapshot s0 = fg_build_snapshot();
        std::lock_guard<std::mutex> lk(g_fg_snap_mtx); g_fg_snap = std::move(s0);
    }
    g_fg_stop = false;
    g_fg_thread = std::thread(fg_snapshot_thread);
}

// 判定进程是否
// PID=0
// 快照
static bool pid_is_fg_locked(DWORD pid) {
    if (pid == 0) return true;
    if (pid == GetCurrentProcessId()) return false;   // mounter 自身 I/O 不算活动
    DWORD sess = 0;
    if (!ProcessIdToSessionId(pid, &sess)) return true;
    if (!g_fg_can_enum) return sess == g_my_session;  // 服务态
    if (sess != g_my_session) return false;           // 别会话进程
    // 锁内直接判定
    std::lock_guard<std::mutex> lk(g_fg_snap_mtx);
    if (pid == g_fg_snap.foreground_pid) return true;
    return g_fg_snap.visible_pids.count(pid) > 0;
}

// 前台访问
// 本次锁定）
// 杜绝「判定
static void fe_note_if_fg(DWORD pid) {
    std::lock_guard<std::mutex> lk(g_idle_mtx);
    if (pid_is_fg_locked(pid))
        g_last_fg_activity_ms.store(wf_now_ms(), std::memory_order_relaxed);
}
// M5+
// 内部走 pid_is_fg_locked）。锁内
static bool fg_holds_open_file_locked() {
    std::lock_guard<std::mutex> lk(g_open_mtx);
    for (const FeCtx* c : g_open_files) {
        if (c && pid_is_fg_locked(c->owner_pid)) return true;
    }
    return false;
}
static VDiskApi    g_wapi;          // 静态存储
static VDiskApi*    g_wv = nullptr;
static VDiskHandle* g_wh = nullptr;
static FSP_FILE_SYSTEM* g_wfs = nullptr;
static FSP_FILE_SYSTEM_INTERFACE g_wf_iface = {};
static FSP_SERVICE*     g_wsvc = nullptr;   // 卸载用

// WinFSP 路径
static std::string wfspath_to_vpath(const WCHAR* FileName) {
    std::string raw = wide_to_utf8(FileName);
    std::string out;
    for (char c : raw) {
        if (c == '\\' || c == '/') { if (out.empty() || out.back() != '/') out += '/'; }
        else out += c;
    }
    if (out.empty()) out = "/";
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    // 纵深防御
    for (size_t i = 0; i < out.size(); ) {
        size_t j = out.find('/', i);
        if (j == std::string::npos) j = out.size();
        std::string comp = out.substr(i, j - i);
        if (comp == "." || comp == "..") return std::string();
        i = (j == out.size()) ? j : j + 1;
    }
    return out;
}

static void wf_fill_fileinfo(FSP_FSCTL_FILE_INFO* fi, bool isdir, uint64_t size, uint64_t mtime) {
    memset(fi, 0, sizeof(*fi));
    fi->FileAttributes  = isdir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    fi->ReparseTag      = 0;
    fi->AllocationSize  = isdir ? 0 : size;
    fi->FileSize        = size;
    UINT64 ft = ((UINT64)mtime + 11644473600ULL) * 10000000ULL;   // unix 秒转 FILETIME
    fi->CreationTime = ft; fi->LastAccessTime = ft; fi->LastWriteTime = ft; fi->ChangeTime = ft;
    fi->IndexNumber = 0; fi->HardLinks = 0; fi->EaSize = 0;
}

void fe_notify_locked_access(DWORD owner_pid);   // 前向声明
static void launch_gui_if_needed();   // 前向声明
static NTSTATUS wf_st(VDiskStatus st) {
    if (st == VDISK_OK) return STATUS_SUCCESS;
    // 锁定态一律拒绝
    // 「设备未
    if (st == VDISK_E_LOCKED) {
        // 注意
        // 被资源管理器刷
        // 解锁提示只
        return STATUS_ACCESS_DENIED;
    }
    if (st == VDISK_E_NOTFOUND) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (st == VDISK_E_NOTIMPL) return STATUS_NOT_SUPPORTED;
    if (st == VDISK_E_RO) return STATUS_MEDIA_WRITE_PROTECTED;   // 只读挂载拒绝写
    return FspNtStatusFromWin32(ERROR_READ_FAULT);
}

// 解锁通知
// Explorer 后台刷
// 但后台刷发生
// 窗口收紧到 3s
// 后台枚举
static const uint32_t kNotifyIdleWindowMs = 3000;
static bool user_recently_active(uint32_t max_idle_ms) {
    LASTINPUTINFO li;
    li.cbSize = sizeof(li);
    if (!GetLastInputInfo(&li)) return true;   // 取失败保守放行
    // dwTime 与 GetTickCount
    return (GetTickCount() - li.dwTime) < max_idle_ms;
}

// 访问进程是否
// 后台枚举、搜索索
// 借此彻底区分「用
static bool is_foreground_process(DWORD pid) {
    if (pid == 0) return true;   // 拿不到 PID 保守放行
    HWND fg = GetForegroundWindow();
    if (!fg) return true;
    DWORD fgPid = 0;
    GetWindowThreadProcessId(fg, &fgPid);
    return fgPid == pid;
}

// 锁定态
// 8 秒节流
static std::mutex                g_locked_notify_mtx;
static std::unordered_map<std::string, uint64_t> g_last_locked_notify;  // vault -> 上次写毫秒
void fe_notify_locked_access(DWORD owner_pid) {
    const std::string vault = g_svc_vault;
    if (vault.empty()) return;
    // 仅前台进程
    if (!is_foreground_process(owner_pid)) return;
    // 用户近期无输入 =
    if (!user_recently_active(kNotifyIdleWindowMs)) return;
    uint64_t now = wf_now_ms();
    {
        std::lock_guard<std::mutex> lk(g_locked_notify_mtx);
        auto it = g_last_locked_notify.find(vault);
        if (it != g_last_locked_notify.end() && now - it->second < 8000) return;
        g_last_locked_notify[vault] = now;
    }
    const char* la = getenv("LOCALAPPDATA");
    if (!la) return;
    std::string dir = std::string(la) + "\\FileEncryptor\\GUI";
    CreateDirectoryW(utf8_to_wide(dir).c_str(), nullptr);  // 已存
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : vault) { h ^= (unsigned char)c; h *= 0x100000001b3ULL; }
    char nm[64]; snprintf(nm, sizeof nm, "fe_locked_%016llx.event", (unsigned long long)h);
    std::string path = dir + "\\" + nm;
    // 防符号链接劫持
    FILE* f = fe_open_write_nofollow(path, false);
    if (f) { fprintf(f, "vault=%s\nmount=%s\n", vault.c_str(), g_svc_mp.c_str()); fclose(f); }
    // 事件已落盘
    launch_gui_if_needed();
}

// 检测 GUI 进程是否存
static bool gui_process_running() {
    bool found = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe; memset(&pe, 0, sizeof pe); pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"FileEncryptorGUI.WinUI3.exe") != 0) continue;
            // 反伪造
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                wchar_t img[MAX_PATH] = {0}; DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, img, &sz) && sz > 0) {
                    std::wstring s(img, sz);
                    auto p = s.find_last_of(L"\\/");
                    std::wstring base = (p == std::wstring::npos) ? s : s.substr(p + 1);
                    if (_wcsicmp(base.c_str(), L"FileEncryptorGUI.WinUI3.exe") == 0) found = true;
                }
                // 查询失败改判「未
                CloseHandle(h);
            }
            if (found) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// 校验待拉起
// 同用户预设 FE_GUI_PATH 指
static bool gui_path_allowed(const std::wstring& wp) {
    auto lower = [](std::wstring s) { for (auto& c : s) c = (wchar_t)towlower(c); return s; };
    std::wstring p = lower(wp);
    std::vector<std::wstring> allowed;
    // 允许根取自 Known Folder
    PWSTR kf = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &kf)) && kf) {
        allowed.push_back(lower(kf));
        CoTaskMemFree(kf);
    }
    kf = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFilesX86, 0, nullptr, &kf)) && kf) {
        allowed.push_back(lower(kf));
        CoTaskMemFree(kf);
    }
    wchar_t mod[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, mod, MAX_PATH)) {
        std::wstring m(mod); auto pos = m.find_last_of(L"\\/");
        if (pos != std::wstring::npos) allowed.push_back(lower(m.substr(0, pos)));
    }
    for (auto& a : allowed) {
        if (p.size() >= a.size() && _wcsnicmp(p.c_str(), a.c_str(), a.size()) == 0) {
            if (p.size() == a.size() || p[a.size()] == L'\\' || p[a.size()] == L'/')
                return true;
        }
    }
    return false;
}

// 锁定访问时确保 GUI
// 同一用户
static void launch_gui_if_needed() {
    if (gui_process_running()) return;
    std::string path = getenv("FE_GUI_PATH") ? getenv("FE_GUI_PATH") : "";
    if (path.empty()) path = "C:\\Program Files\\FileEncryptor (WinUI)\\FileEncryptorGUI.WinUI3.exe";
    std::wstring wp = utf8_to_wide(path);
    if (!gui_path_allowed(wp))
        wp = L"C:\\Program Files\\FileEncryptor (WinUI)\\FileEncryptorGUI.WinUI3.exe";   // 不可信路径回退
    STARTUPINFOW si; memset(&si, 0, sizeof si); si.cb = sizeof si;
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof pi);
    if (CreateProcessW(wp.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
    }
}

// 自相对 SD
// 去掉 WD
// O:BAG:BA 不能省
static PSECURITY_DESCRIPTOR wf_build_sd() {
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        DWORD sz = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &sz);   // 首次必失败
        // TOKEN_USER 的首字段即 PSID；手动
        if (sz >= sizeof(void*) * 2 && sz <= 1024) {
            std::vector<BYTE> buf(sz);
            if (GetTokenInformation(tok, TokenUser, buf.data(), sz, &sz) && sz >= sizeof(void*) * 2) {
                void* sid = *reinterpret_cast<void**>(buf.data());
                wchar_t* sidbuf = nullptr;
                if (sid && ConvertSidToStringSidW(sid, &sidbuf)) {
                    // 当前用户+Administrators+SYST
                    std::wstring sddl = std::wstring(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;")
                                      + sidbuf + L")";
                    LocalFree(sidbuf);
                    PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;
                    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            sddl.c_str(), SDDL_REVISION_1, &sd, &need)) {
                        CloseHandle(tok);
                        return sd;   // 调用方接管
                    }
                }
            }
        }
        CloseHandle(tok);
    }
    PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;   // 取不到用户 SID
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, &need)) return nullptr;
    return sd;
}

static NTSTATUS wf_fill_sd(PSECURITY_DESCRIPTOR buf, SIZE_T* PSize) {
    static PSECURITY_DESCRIPTOR cached = nullptr;   // LocalAlloc 生命周期 = 进程
    static SIZE_T cached_size = 0;
    if (!cached) {
        cached = wf_build_sd();
        if (!cached) {
            NTSTATUS es = FspNtStatusFromWin32(ERROR_INVALID_SID);
            WFDBG("[fe] build SD failed 0x%08lX\n", (unsigned long)es);
            return es;
        }
        cached_size = GetSecurityDescriptorLength(cached);
        WFDBG("[fe] SD ready size=%llu\n", (unsigned long long)cached_size);
    }
    if (!PSize) return STATUS_SUCCESS;
    if (!buf) { *PSize = cached_size; return STATUS_SUCCESS; }
    if (*PSize < cached_size) { *PSize = cached_size; return STATUS_BUFFER_OVERFLOW; }
    memcpy(buf, cached, cached_size);
    *PSize = cached_size;
    return STATUS_SUCCESS;
}

// 资源管理器显示
static const wchar_t* const kVolumeLabel = L"加密磁盘";

// 库内元数据文件
// 计算「盘容量 = 盘内
static uint64_t wf_file_size(const std::string& utf8_path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(utf8_to_wide(utf8_path).c_str(), GetFileExInfoStandard, &fad)) return 0;
    return ((uint64_t)fad.nFileSizeHigh << 32) | (uint64_t)fad.nFileSizeLow;
}

// 递归汇总目录内
static uint64_t wf_dir_size_w(const std::wstring& dir, int depth = 0) {
    uint64_t total = 0;
    std::wstring base = dir;
    if (base.empty()) return 0;
    if (base.back() != L'\\') base += L'\\';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((base + L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 低危 A 组
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (depth >= 32) continue;
            total += wf_dir_size_w(base + name, depth + 1);
        } else {
            total += ((uint64_t)fd.nFileSizeHigh << 32) | (uint64_t)fd.nFileSizeLow;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return total;
}
static uint64_t wf_dir_size(const std::string& utf8_dir) {
    return wf_dir_size_w(utf8_to_wide(utf8_dir));
}

static NTSTATUS wf_GetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo) {
    WFDBG("[fe] GetVolumeInfo\n");
    // 容量口径
    // 必须给非零 FreeSize
    // 枚举/访问行
    uint64_t used = 0, total = 0;
    if (!g_wv->stat_space || g_wv->stat_space(g_wh, &used, &total) != VDISK_OK || total == 0) {
        total = 64ull << 20;
        used = 0;
    }
    // 元数据
    if (!g_svc_vault.empty())
        used += wf_dir_size(g_svc_vault + "/.feindex.d")
              + wf_file_size(g_svc_vault + "/.feindex")     // 旧单索引
              + wf_file_size(g_svc_vault + "/vault.meta");
    if (total < used) total = used + (64ull << 20);   // 防元数据
    VolumeInfo->TotalSize = total;
    VolumeInfo->FreeSize  = (total > used) ? (total - used) : 0;
    // VolumeLabelLength 单位是「字节」
    // 误按字符数填
    VolumeInfo->VolumeLabelLength = (UINT16)(wcslen(kVolumeLabel) * sizeof(WCHAR));
    wcscpy_s(VolumeInfo->VolumeLabel, sizeof VolumeInfo->VolumeLabel / sizeof(WCHAR), kVolumeLabel);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetSecurityByName(FSP_FILE_SYSTEM*, PWSTR FileName, PUINT32 PFileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize) {
    std::string vp = wfspath_to_vpath(FileName);
    if (vp.empty()) return STATUS_OBJECT_NAME_INVALID;
    WFDBG("[fe] GetSecurityByName '%s'\n", vp.c_str());
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (st != VDISK_OK) return wf_st(st);
    if (PFileAttributes) *PFileAttributes = isdir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    return wf_fill_sd(SecurityDescriptor, PSecurityDescriptorSize);
}
static NTSTATUS wf_open_common(PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    if (vp.empty()) return STATUS_OBJECT_NAME_INVALID;
    // 锁定态
    if (fe_is_locked()) { fe_notify_locked_access((DWORD)FspFileSystemOperationProcessId()); return STATUS_ACCESS_DENIED; }
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (getenv("FE_MOUNT_DEBUG"))
        fprintf(stderr, "[fe] open '%s' opts=0x%lX acc=0x%lX getattr=%d\n",
                vp.c_str(), (unsigned long)CreateOptions, (unsigned long)GrantedAccess, (int)st);
    if (st != VDISK_OK) return wf_st(st);
    FeCtx* c = new (std::nothrow) FeCtx{ isdir != 0, vp, nullptr, 0 };
    if (!c) return STATUS_INSUFFICIENT_RESOURCES;
    // Create/Open 请求
    // 记到上下文
    c->owner_pid = (DWORD)FspFileSystemOperationProcessId();
    // 前台程序打开盘
    fe_note_if_fg(c->owner_pid);
    if (getenv("FE_MOUNT_DEBUG"))
        fprintf(stderr, "[fe] open '%s' pid=%lu isdir=%d fg=%d\n",
                vp.c_str(), (unsigned long)c->owner_pid, (int)isdir,
                (int)pid_is_fg_locked(c->owner_pid));
    // M5+
    if (!isdir) { std::lock_guard<std::mutex> lk(g_open_mtx); g_open_files.insert(c); }
    *PFileContext = c;
    if (FileInfo) wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Open(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    return wf_open_common(FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
}
// Create 与 Open 签名不同
// 可写挂载
// 只读挂载
static NTSTATUS wf_Create(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    UINT32 FileAttributes, PSECURITY_DESCRIPTOR, UINT64 AllocationSize,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    if (vp.empty()) return STATUS_OBJECT_NAME_INVALID;
    // H8
    if (fe_is_locked()) return STATUS_ACCESS_DENIED;
    WFDBG("[fe] Create '%s' rw=%d dir=%d\n", vp.c_str(), g_svc_rw ? 1 : 0,
          (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0);
    bool is_dir = (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    bool exists = (g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr) == VDISK_OK);
    if (!exists) {
        if (!g_svc_rw) return STATUS_OBJECT_NAME_NOT_FOUND;   // 只读
        // 目录
        if (g_wv->create_file_ex(g_wh, vp.c_str(), is_dir ? 1 : 0) != VDISK_OK) {
            if (!g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr))
                return STATUS_OBJECT_NAME_COLLISION;
            return STATUS_ACCESS_DENIED;
        }
    } else if (CreateOptions & FILE_CREATE) {
        return STATUS_OBJECT_NAME_COLLISION;   // FILE_CREATE 要求新建
    }
    return wf_open_common(FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
}
// 重命名 / 移动
static NTSTATUS wf_Rename(FSP_FILE_SYSTEM*, PVOID FileContext, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists) {
    std::string old_vp = wfspath_to_vpath(FileName);
    std::string new_vp = wfspath_to_vpath(NewFileName);
    if (old_vp.empty() || new_vp.empty()) return STATUS_OBJECT_NAME_INVALID;
    WFDBG("[fe] Rename '%s' -> '%s' replace=%d\n", old_vp.c_str(), new_vp.c_str(), ReplaceIfExists ? 1 : 0);
    if (!g_svc_rw) return STATUS_ACCESS_DENIED;   // 只读拒绝
    // H8
    if (fe_is_locked()) return STATUS_ACCESS_DENIED;
    FeCtx* rc = (FeCtx*)FileContext;
    if (rc)     fe_note_if_fg(rc->owner_pid);
    VDiskStatus st = g_wv->rename(g_wh, old_vp.c_str(), new_vp.c_str());
    switch (st) {
        case VDISK_OK:         return STATUS_SUCCESS;
        case VDISK_E_NOTFOUND: return STATUS_OBJECT_NAME_NOT_FOUND;
        case VDISK_E_EXIST:    return STATUS_OBJECT_NAME_COLLISION;
        case VDISK_E_RO:       return STATUS_ACCESS_DENIED;
        case VDISK_E_BADARG:   return STATUS_OBJECT_NAME_INVALID;
        default:               return STATUS_ACCESS_DENIED;
    }
}

static VOID wf_Cleanup(FSP_FILE_SYSTEM*, PVOID FileContext, PWSTR FileName, ULONG Flags) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c) return;
    // 删除
    WFDBG("[fe] Cleanup '%s' flags=0x%lX\n", c->vpath.c_str(), (unsigned long)Flags);
    // H8
    if ((Flags & FspCleanupDelete) && g_svc_rw && !fe_is_locked()) {
        // 前台程序发起删
        fe_note_if_fg(c->owner_pid);
        // 目录
        // 用 !c->is_dir 拦掉目录 →
        VDiskStatus st = g_wv->delete_file(g_wh, c->vpath.c_str());
        WFDBG("[fe] Cleanup delete '%s' (dir=%d) -> %s\n", c->vpath.c_str(), c->is_dir ? 1 : 0,
              st == VDISK_OK ? "ok" : g_wv->strerror(st));
    }
    if (c->dir_buffer) FspFileSystemDeleteDirectoryBuffer(&c->dir_buffer);
    // M5+
    { std::lock_guard<std::mutex> lk(g_open_mtx); g_open_files.erase(c); }
    delete c;
}
static VOID wf_Close(FSP_FILE_SYSTEM*, PVOID FileContext) {
    (void)FileContext;  // 上下文生命周期
}
static NTSTATUS wf_Read(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, PULONG PBytesTransferred) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    fe_note_if_fg(c->owner_pid);
    uint64_t len = Length;
    VDiskStatus st = g_wv->read_file(g_wh, c->vpath.c_str(), Offset, (uint8_t*)Buffer, &len);
    if (st != VDISK_OK) { if (fe_is_locked()) fe_notify_locked_access(c->owner_pid); return wf_st(st); }
    *PBytesTransferred = (ULONG)len;
    return STATUS_SUCCESS;
}
// M6 写支持
static NTSTATUS wf_Write(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, BOOLEAN, BOOLEAN, PULONG PBytesTransferred,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    fe_note_if_fg(c->owner_pid);
    VDiskStatus st = g_wv->write_file(g_wh, c->vpath.c_str(), Offset, (const uint8_t*)Buffer, (uint64_t)Length);
    if (st != VDISK_OK) { if (fe_is_locked()) fe_notify_locked_access(c->owner_pid); return wf_st(st); }
    *PBytesTransferred = Length;
    if (FileInfo) {  // 回填 FileInfo 让系统看到
        uint64_t mtime = 0, sz = 0; uint8_t isdir = 0;
        g_wv->getattr(g_wh, c->vpath.c_str(), &sz, &mtime, &isdir);
        wf_fill_fileinfo(FileInfo, false, sz, mtime);
    }
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SetFileSize(FSP_FILE_SYSTEM*, PVOID FileContext, UINT64 NewSize,
    BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    fe_note_if_fg(c->owner_pid);
    if (!SetAllocationSize) {  // 仅 EOF 调整改文件大
        VDiskStatus st = g_wv->truncate_file(g_wh, c->vpath.c_str(), NewSize);
        if (st != VDISK_OK) { if (fe_is_locked()) fe_notify_locked_access(c->owner_pid); return wf_st(st); }
    }
    if (FileInfo) {
        uint64_t mtime = 0, sz = NewSize; uint8_t isdir = 0;
        g_wv->getattr(g_wh, c->vpath.c_str(), &sz, &mtime, &isdir);
        wf_fill_fileinfo(FileInfo, false, sz, mtime);
    }
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    WFDBG("[fe] GetFileInfo '%s'\n", c ? c->vpath.c_str() : "?");
    if (!c) return STATUS_INVALID_PARAMETER;
    // 锁定态拒访
    // 注意
    // 会误触发弹窗
    if (fe_is_locked()) { return STATUS_ACCESS_DENIED; }
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    g_wv->getattr(g_wh, c->vpath.c_str(), &size, &mtime, &isdir);
    wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetDirInfoByName(FSP_FILE_SYSTEM*, PVOID, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    if (vp.empty()) return STATUS_OBJECT_NAME_INVALID;
    // H8
    if (fe_is_locked()) return STATUS_ACCESS_DENIED;
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (st != VDISK_OK) return wf_st(st);
    std::string base = vp.substr(vp.find_last_of('/') + 1);
    std::wstring wb = utf8_to_wide(base);
    DirInfo->Size = (UINT16)(FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + wb.size() * sizeof(WCHAR));
    wf_fill_fileinfo(&DirInfo->FileInfo, isdir != 0, size, mtime);
    memcpy(DirInfo->FileNameBuf, wb.c_str(), wb.size() * sizeof(WCHAR));
    return STATUS_SUCCESS;
}
// 目录枚举缓存已
// 缓存过期窗口内
// 卡顿

static NTSTATUS wf_ReadDirectory(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext0, PWSTR, PWSTR Marker,
    PVOID Buffer, ULONG BufferLength, PULONG PBytesTransferred) {
    FeCtx* c = (FeCtx*)FileContext0;
    WFDBG("[fe] ReadDirectory '%s'\n", c ? c->vpath.c_str() : "?");
    if (!c || !c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    // 锁定态
    // 「== VDISK_OK」判空后照常返回
    // 解锁提示永不触
    if (fe_is_locked()) { fe_notify_locked_access(c->owner_pid); return STATUS_ACCESS_DENIED; }
    // 浏览目录同样算
    // M5 空闲守护
    fe_note_if_fg(c->owner_pid);
    // 首页
    bool first_page = (Marker == NULL);
    std::vector<VDiskEntry> ents;
    if (first_page) {
        uint64_t n = 0;
        if (g_wv->readdir(g_wh, c->vpath.c_str(), nullptr, &n) == VDISK_OK && n > 0) {
            // M5
            if (n > kFeMaxDirEntries) {
                WFDBG("[fe] readdir '%s' n=%llu exceeds cap %llu\n", c->vpath.c_str(),
                      (unsigned long long)n, (unsigned long long)kFeMaxDirEntries);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            try { ents.resize((size_t)n); }
            catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
            VDiskEntry* parr = ents.data();
            if (g_wv->readdir(g_wh, c->vpath.c_str(), &parr, &n) == VDISK_OK && n <= kFeMaxDirEntries)
                ents.resize((size_t)n);
            else ents.clear();
        }
    }
    NTSTATUS r = STATUS_SUCCESS;
    if (FspFileSystemAcquireDirectoryBuffer(&c->dir_buffer, first_page, &r)) {
        if (first_page) {
            for (uint64_t i = 0; i < ents.size(); i++) {
                union { UINT8 B[FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + 512 * sizeof(WCHAR)];
                        FSP_FSCTL_DIR_INFO D; } buf;
                FSP_FSCTL_DIR_INFO* di = &buf.D;
                std::wstring wb = utf8_to_wide(ents[i].name);
                // 防御
                // 若按实际长度填 di->Size
                if (wb.size() > 512) continue;
                memset(di, 0, sizeof(buf));
                di->Size = (UINT16)(FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + wb.size() * sizeof(WCHAR));
                wf_fill_fileinfo(&di->FileInfo, ents[i].is_dir != 0, ents[i].size, ents[i].mtime);
                memcpy(di->FileNameBuf, wb.c_str(), wb.size() * sizeof(WCHAR));
                if (!FspFileSystemFillDirectoryBuffer(&c->dir_buffer, di, &r)) break;
            }
        }
        FspFileSystemReleaseDirectoryBuffer(&c->dir_buffer);
    }
    if (!NT_SUCCESS(r)) return r;
    FspFileSystemReadDirectoryBuffer(&c->dir_buffer, Marker, Buffer, BufferLength, PBytesTransferred);
    return STATUS_SUCCESS;
}
// 删除
// 真正删除
// ，与官方 memfs 样例一致
static NTSTATUS wf_CanDelete(FSP_FILE_SYSTEM*, PVOID, PWSTR FileName) {
    if (!g_svc_rw) { WFDBG("[fe] CanDelete denied (read-only)\n"); return STATUS_MEDIA_WRITE_PROTECTED; }
    std::string vp = wfspath_to_vpath(FileName);
    if (vp.empty()) return STATUS_OBJECT_NAME_INVALID;
    // H8
    if (fe_is_locked()) return STATUS_ACCESS_DENIED;
    return (g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr) == VDISK_OK)
        ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

// 已打开句柄
// 不实现时落 NULL 槽位 →
static NTSTATUS wf_GetSecurity(FSP_FILE_SYSTEM*, PVOID,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize) {
    WFDBG("[fe] GetSecurity\n");
    return wf_fill_sd(SecurityDescriptor, PSecurityDescriptorSize);
}
static NTSTATUS wf_SetSecurity(FSP_FILE_SYSTEM*, PVOID, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) {
    WFDBG("[fe] SetSecurity (ignored, read-only)\n");
    return STATUS_SUCCESS;   // 只读库
}
static NTSTATUS wf_SetBasicInfo(FSP_FILE_SYSTEM*, PVOID, UINT32, UINT64, UINT64, UINT64, UINT64,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    WFDBG("[fe] SetBasicInfo (ignored)\n");
    (void)FileInfo;
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Flush(FSP_FILE_SYSTEM*, PVOID, FSP_FSCTL_FILE_INFO*) {
    WFDBG("[fe] Flush\n");
    // 卷刷新
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Overwrite(FSP_FILE_SYSTEM*, PVOID FileContext, UINT32, BOOLEAN, UINT64,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    WFDBG("[fe] Overwrite\n");
    FeCtx* c = (FeCtx*)FileContext;
    if (!c) return STATUS_INVALID_PARAMETER;
    fe_note_if_fg(c->owner_pid);
    if (FileInfo) {
        uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
        g_wv->getattr(g_wh, c->vpath.c_str(), &size, &mtime, &isdir);
        wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    }
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SetVolumeLabel(FSP_FILE_SYSTEM*, PWSTR, FSP_FSCTL_VOLUME_INFO* VolumeInfo) {
    WFDBG("[fe] SetVolumeLabel (unsupported)\n");
    (void)VolumeInfo;
    return STATUS_INVALID_DEVICE_REQUEST;   // 不支持改卷标
}

// M5 前台活动守护
// 才刷新
// 达 g_svc_idle 秒即上锁滑动
// 取消/推迟本次锁
// 前台访问同样能
// 轮询间隔 1s
void idle_watchdog_thread() {
    while (!g_ipc_stop.load()) {
        bool done = false;
        for (int i = 0; i < 10 && !done; ++i) {   // 每秒醒一次
            if (g_ipc_stop.load()) { done = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (done) break;
        // P2-2 休眠/待机/快速启
        // 电源通知线程
        if (g_power_suspend_pending.exchange(false, std::memory_order_relaxed) ||
            g_power_resumed.exchange(false, std::memory_order_relaxed)) {
            {   // M6
                std::lock_guard<std::mutex> lk(fe_vdisk_call_mutex());
                if (g_wapi.lock && g_wh && g_ipc_unlocked.load()) {
                    // 同源清密钥
                    if (g_wapi.purge_on_suspend) g_wapi.purge_on_suspend(g_wh);
                    else g_wapi.lock(g_wh);
                    g_ipc_unlocked = false;
                    fprintf(stderr, "[fe] power: locked before/after suspend\n");
                }
            }
            std::lock_guard<std::mutex> lk2(g_idle_mtx);
            g_last_fg_activity_ms.store(0, std::memory_order_relaxed);  // 恢复后重新起算
            continue;
        }
        if (!g_ipc_unlocked.load() || !g_wv || !g_wapi.lock) continue;
        if (g_svc_idle == 0) continue;   // IPC `idle 0` 可运行时关闭自
        // 库可能
        // 用 is_unlocked 查真实锁态
        // 判「超
        {   // M6
            std::lock_guard<std::mutex> lk(fe_vdisk_call_mutex());
            if (g_wh && g_wapi.is_unlocked && !g_wapi.is_unlocked(g_wh)) {
                g_ipc_unlocked = false;
                std::lock_guard<std::mutex> lk2(g_idle_mtx);
                g_last_fg_activity_ms.store(0, std::memory_order_relaxed);
                continue;
            }
        }
        // M5+
        // 不算空闲，否
        uint64_t stamp = 0;
        {
            std::lock_guard<std::mutex> lks(fe_vdisk_call_mutex());
            if (g_wh && g_wapi.index_stamp) stamp = g_wapi.index_stamp(g_wh);
        }
        static uint64_t s_last_index_stamp = 0;   // watchdog 单线程
        const bool index_busy = (stamp != 0 && stamp != s_last_index_stamp);
        s_last_index_stamp = stamp;
        // M6+M7
        std::lock_guard<std::mutex> lkf(fe_vdisk_call_mutex());
        std::lock_guard<std::mutex> lk(g_idle_mtx);   // 与 fe_note_if_fg 互斥
        if (!g_ipc_unlocked.load()) continue;
        const uint64_t now = wf_now_ms();
        // M5+
        // ① 索引版本戳
        // ② 前台进程
        // 两层
        if (getenv("FE_MOUNT_DEBUG")) {
            size_t nopen = 0;
            { std::lock_guard<std::mutex> lk(g_open_mtx); nopen = g_open_files.size(); }
            fprintf(stderr, "[fe] wd: stamp=%llu busy=%d open=%zu holds=%d last=%llu now=%llu "
                    "note=%d idx=%d unl=%d\n",
                    (unsigned long long)stamp, (int)index_busy, nopen,
                    (int)fg_holds_open_file_locked(),
                    (unsigned long long)g_last_fg_activity_ms.load(std::memory_order_relaxed),
                    (unsigned long long)now,
                    g_wapi.note_activity ? 1 : 0, g_wapi.index_stamp ? 1 : 0,
                    g_wapi.is_unlocked ? 1 : 0);
        }
        if (index_busy || fg_holds_open_file_locked()) {
            g_last_fg_activity_ms.store(now, std::memory_order_relaxed);
            if (g_wapi.note_activity) g_wapi.note_activity(g_wh);
            continue;
        }
        uint64_t last = g_last_fg_activity_ms.load(std::memory_order_relaxed);
        if (last == 0) {   // 解锁后尚未记录
            g_last_fg_activity_ms.store(now, std::memory_order_relaxed);
            continue;
        }
        if (now - last < (uint64_t)g_svc_idle * 1000ull) continue;   // 窗口期内不到点
        // M8
        int64_t sus = g_suspend_until_ms.load(std::memory_order_relaxed);
        if (sus > (int64_t)now) {
            g_last_fg_activity_ms.store(now, std::memory_order_relaxed);
            continue;
        }
        if (sus > 0) {
            // 暂停到期
            // 窗口
            g_suspend_until_ms.store(0, std::memory_order_relaxed);
            if (g_wapi.set_idle_timeout) g_wapi.set_idle_timeout(g_wh, g_svc_idle);
            g_last_fg_activity_ms.store(now, std::memory_order_relaxed);
            continue;
        }
        if (g_wh) g_wapi.lock(g_wh);
        g_ipc_unlocked = false;
        g_last_fg_activity_ms.store(0, std::memory_order_relaxed);
        fprintf(stderr, "[fe] idle timeout: auto-locked (no foreground access for %u s)\n",
                (unsigned)g_svc_idle);
    }
}

static NTSTATUS wf_SvcStart(FSP_SERVICE* Service, ULONG, PWSTR*) {
    // 自给自足
    std::string err;
    if (!vdisk_load(g_wapi, g_svc_lib, err)) { fprintf(stderr, "[fe] load libvdisk: %s\n", err.c_str()); return STATUS_UNSUCCESSFUL; }
    g_wv = &g_wapi;
    g_wh = g_wapi.open(g_svc_vault.c_str());
    if (!g_wh) { fprintf(stderr, "[fe] open vault failed: %s\n", g_svc_vault.c_str()); return STATUS_UNSUCCESSFUL; }
    if (!g_svc_pass.empty()) {
        if (g_wapi.unlock(g_wh, g_svc_pass.c_str(), 0) != VDISK_OK) { fprintf(stderr, "[fe] unlock failed\n"); g_wapi.close(g_wh); g_wh = nullptr; return STATUS_UNSUCCESSFUL; }
        g_ipc_unlocked = true;
        g_last_fg_activity_ms.store(wf_now_ms(), std::memory_order_relaxed);   // 解锁即起算一
        secure_zero(g_svc_pass.data(), g_svc_pass.size());   // 解锁后即清
        g_svc_pass.clear();
    } else {
        g_ipc_unlocked = false;   // 无密码
    }
    // M2 读缓存
    // Windows 挂载此前漏开
    // 64MB 上限
    // 卡顿真因是窗口
    if (g_wapi.set_read_cache) g_wapi.set_read_cache(g_wh, 64ull << 20, 8);   // 64MB 上限 / 预读 8 段
    g_ipc_v = g_wv; g_ipc_h = &g_wh; g_ipc_stop = false;
    // M5 前台活动自动锁
    // 立刻
    if (g_svc_idle > 0 && g_wapi.set_idle_timeout) g_wapi.set_idle_timeout(g_wh, g_svc_idle);
    fg_init_session();   // 前台判定依赖
    power_register();    // P2-2 休眠/待机/恢复通
    std::thread(ipc_server_thread).detach();
    // 前台活动守护
    // （含后台程序），不满
    // 到点直接锁
    // 无条件启动
    // idle==0 时自动锁判定
    if (g_wapi.lock)
        g_watchdog_thread = std::thread(idle_watchdog_thread);   // 可 join

    FSP_FSCTL_VOLUME_PARAMS vol; memset(&vol, 0, sizeof vol);
    FILETIME nowft; GetSystemTimeAsFileTime(&nowft);
    vol.Version = sizeof(FSP_FSCTL_VOLUME_PARAMS);
    vol.SectorSize = 512; vol.SectorsPerAllocationUnit = 1; vol.MaxComponentLength = 255;
    vol.VolumeCreationTime = ((PLARGE_INTEGER)&nowft)->QuadPart;
    vol.VolumeSerialNumber = 0x20261005;
    vol.FileInfoTimeout = 1000; vol.CaseSensitiveSearch = 0; vol.CasePreservedNames = 1;
    // PostCleanupWhenModifiedOnly 必须
    // 纯读取
    vol.UnicodeOnDisk = 1; vol.PersistentAcls = 1; vol.PostCleanupWhenModifiedOnly = 0;
    vol.PassQueryDirectoryPattern = 1; vol.FlushAndPurgeOnCleanup = 1; vol.UmFileContextIsUserContext2 = 1;
    // 删除链路必需
    // FspCleanupDelete 并执行删除。缺
    vol.PostDispositionWhenNecessaryOnly = 1;
    if (!g_svc_rw) vol.ReadOnlyVolume = 1;
    // FileSystemName 是属性页「文件系
    wcscpy_s(vol.FileSystemName, sizeof vol.FileSystemName / sizeof(WCHAR), L"FE-Vault");
    FSP_FILE_SYSTEM* fs = nullptr;
    // 显式转 PWSTR
    NTSTATUS st = FspFileSystemCreate(const_cast<PWSTR>(L"" FSP_FSCTL_DISK_DEVICE_NAME),
                                      &vol, &g_wf_iface, &fs);
    if (!NT_SUCCESS(st)) { fprintf(stderr, "[fe] FspFileSystemCreate failed 0x%08lX\n", (unsigned long)st); return st; }
    std::wstring mount_w = utf8_to_wide(g_svc_mp);
    st = FspFileSystemSetMountPoint(fs, (PWSTR)mount_w.c_str());
    if (!NT_SUCCESS(st)) {
        // P0-2 盘符冲突
        // GUI 又关闭了 stderr 重定
        fprintf(stderr, "[fe] SetMountPoint(%s) failed 0x%08lX\n", g_svc_mp.c_str(), (unsigned long)st);
        if (st == STATUS_OBJECT_NAME_COLLISION || st == STATUS_ACCESS_DENIED ||
            st == STATUS_SHARING_VIOLATION) {
            fprintf(stderr,
                "[fe] 盘符 %s 已被占用或不可用（NTSTATUS 0x%08lX）。\n"
                "[fe] 请先卸载占用该盘符的设备，或换一个盘符重新挂载。\n",
                g_svc_mp.c_str(), (unsigned long)st);
        }
        FspFileSystemDelete(fs);
        return st;
    }
    if (g_svc_rw) g_wapi.mount_rw(g_wh, g_svc_mp.c_str());
    else          g_wapi.mount_readonly(g_wh, g_svc_mp.c_str());
    if (getenv("FE_MOUNT_DEBUG")) FspFileSystemSetDebugLog(fs, (UINT32)-1);
    st = FspFileSystemStartDispatcher(fs, 0);
    if (!NT_SUCCESS(st)) { FspFileSystemDelete(fs); return st; }
    g_wfs = fs; Service->UserContext = fs;
    g_wsvc = Service;
    // 卸载
    g_ipc_eject_hook = []() { if (g_wsvc) FspServiceStop(g_wsvc); };
    // P0-2 盘符稳定映射
    // mount_point 只是单向记录
    // 跨重启/换接口
    {
        const char* la = getenv("LOCALAPPDATA");
        if (la) {
            std::string dir = std::string(la) + "\\FileEncryptor";
            CreateDirectoryW(utf8_to_wide(dir).c_str(), nullptr);
            std::string sub = dir + "\\mount";
            CreateDirectoryW(utf8_to_wide(sub).c_str(), nullptr);
            uint64_t hsh = 0xcbf29ce484222325ULL;
            for (char c : g_svc_vault) { hsh ^= (unsigned char)c; hsh *= 0x100000001b3ULL; }
            char nm[80]; snprintf(nm, sizeof nm, "vault_%016llx.txt", (unsigned long long)hsh);
            std::string path = sub + "\\" + nm;
            // 防符号链接劫持
            FILE* fp = fe_open_write_nofollow(path, false);
            if (fp) {
                fprintf(fp, "vault=%s\nmount=%s\nrw=%d\npid=%lu\n",
                        g_svc_vault.c_str(), g_svc_mp.c_str(), g_svc_rw ? 1 : 0,
                        (unsigned long)GetCurrentProcessId());
                fclose(fp);
            }
            // 挂载成功即登记
            // 即使 GUI 侧漏调 vaults add
            std::string reg_err;
            vaults_add(g_svc_vault, reg_err);
        }
    }
    printf("MOUNTED at %s (unlocked=%d)\n", g_svc_mp.c_str(), g_ipc_unlocked.load() ? 1 : 0); fflush(stdout);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SvcStop(FSP_SERVICE* Service) {
    FSP_FILE_SYSTEM* fs = (FSP_FILE_SYSTEM*)Service->UserContext;
    if (fs) { FspFileSystemStopDispatcher(fs); FspFileSystemDelete(fs); }
    g_fg_stop = true;                              // 停前台快照线程
    if (g_fg_thread.joinable()) g_fg_thread.join();
    g_ipc_stop = true;
    // 低危 B 组
    if (g_watchdog_thread.joinable()) g_watchdog_thread.join();
    power_unregister();                            // P2-2
    {   // M6
        std::lock_guard<std::mutex> lk(fe_vdisk_call_mutex());
        if (g_wv && g_wh) { g_wv->unmount(g_wh); g_wv->close(g_wh); g_wh = nullptr; }
    }
    g_wfs = nullptr;
    g_wsvc = nullptr;
    return STATUS_SUCCESS;
}

int fe_winmount_service() {
    if (g_svc_mp.empty()) { fprintf(stderr, "[fe] winmount needs a drive letter\n"); return 1; }
    if (!NT_SUCCESS(FspLoad(nullptr))) { fprintf(stderr, "[fe] FspLoad failed: is the WinFSP driver running?\n"); return 8; }
    g_wf_iface.GetVolumeInfo = wf_GetVolumeInfo;
    g_wf_iface.GetSecurityByName = wf_GetSecurityByName;
    g_wf_iface.GetSecurity = wf_GetSecurity;
    g_wf_iface.SetSecurity = wf_SetSecurity;
    g_wf_iface.SetBasicInfo = wf_SetBasicInfo;
    g_wf_iface.Flush = wf_Flush;
    g_wf_iface.Create = wf_Create;   // 可写
    g_wf_iface.Open = wf_Open;
    g_wf_iface.Overwrite = wf_Overwrite;
    g_wf_iface.Cleanup = wf_Cleanup;
    g_wf_iface.Close = wf_Close;
    g_wf_iface.Read = wf_Read;
    g_wf_iface.Write = wf_Write;            // M6 写支持
    g_wf_iface.SetFileSize = wf_SetFileSize;
    g_wf_iface.GetFileInfo = wf_GetFileInfo;
    g_wf_iface.GetDirInfoByName = wf_GetDirInfoByName;
    g_wf_iface.ReadDirectory = wf_ReadDirectory;
    g_wf_iface.CanDelete = wf_CanDelete;   // 仅预检
    g_wf_iface.SetVolumeLabel = wf_SetVolumeLabel;
    g_wf_iface.Rename = wf_Rename;   // 重命名 / 移动
    // 必须 FspServiceRun
    // 不能换 FspServiceLoop它只建
    // 显式转 PWSTR
    FspServiceRun(const_cast<PWSTR>(L"FE-Mount"), wf_SvcStart, wf_SvcStop, nullptr);
    return 0;
}
#endif // FE_HAVE_WINFSP
