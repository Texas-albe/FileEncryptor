// fe_winfsp：Windows 只读挂载（WinFSP 原生 API，设计文档 M3）。
// 「进程本身即服务」：SvcStart 自给自足——从服务命令行(g_svc_*)加载 libvdisk、打开/
// 解锁 vault、起 IPC、挂载，不依赖 main 提前解锁的进程内全局。
#include "fe_common.h"
#if FE_HAVE_WINFSP
// TOKEN_USER 等需 _WIN32_WINNT >= 0x0500 才在 winnt.h 中可见（windows.h 的版本守卫会拦）
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#  define WINVER 0x0601
#endif
#include <winfsp.h>
#include <sddl.h>
#include <windows.h>
#include <winnt.h>      // TOKEN_USER / LPTOKEN_USER（windows.h 已带守卫，此处显式补）
#include <tlhelp32.h>   // CreateToolhelp32Snapshot：检测 GUI 进程是否存活
#include <Wtsapi32.h>   // WTSGetActiveConsoleSessionId：交互会话探测（前台判定用）
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
#pragma comment(lib, "user32.lib")     // EnumWindows / GetForegroundWindow / IsWindowVisible
#pragma comment(lib, "wtsapi32.lib")   // WTSGetActiveConsoleSessionId

// 调试输出（FE_MOUNT_DEBUG=1 时打印每次回调，定位 0xC0000010 等）
#define WFDBG(...) do { if (getenv("FE_MOUNT_DEBUG")) fprintf(stderr, __VA_ARGS__); } while (0)

std::string g_svc_vault, g_svc_pass, g_svc_mp, g_svc_lib;
bool g_svc_rw = false;            // M6 可写挂载开关
uint32_t g_svc_idle = 0;          // M5 前台活动自动锁窗口秒数（0=关闭，winmount --idle-timeout；IPC idle 可运行时改）

// 单调时钟毫秒，供空闲守护计时
static uint64_t wf_now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
// 权威锁定态：g_ipc_unlocked 为 false 即锁定（IPC lock / 空闲自动锁 / 锁定启动）
static bool fe_is_locked() { return !g_ipc_unlocked.load(std::memory_order_relaxed); }

// ---- M5 前台活动判定（自动锁只认前台程序）----
// 「前台程序」= 交互会话里拥有可见顶层窗口的进程（资源管理器/播放器/编辑器…）；
// 后台服务与托盘程序（只有隐藏窗口+通知图标，如 GUI 托盘态）没有可见顶层窗口，
// 它们对盘内文件的访问不刷新自动锁计时。mounter 由 GUI 在用户会话内 detached 拉起时
// EnumWindows 能看到用户窗口，按窗口判定；SCM 服务场景（session 0）枚举不到别会话
// 窗口，退化为「调用方与 mounter 同会话即前台」的近似（宁漏锁，不误锁）。
static std::mutex g_idle_mtx;                  // 保护「刷新活动 ↔ 上锁决策」临界区
static std::mutex g_fg_snap_mtx;               // 单独保护前台快照（与 I/O 热路径解耦）
static DWORD     g_my_session = 0;             // mounter 自身所在会话
static bool      g_fg_can_enum = false;        // 能否枚举本会话窗口（= 在交互会话内）
static std::atomic<bool> g_fg_stop{false};     // 前台快照线程退出标志
static std::thread g_fg_thread;                // 后台周期刷新前台窗口快照

// 可见顶层窗口进程集合 + 前台窗口进程。由独立后台线程每 ~1s 刷新，
// I/O 热路径只读取、不再调用 EnumWindows，避免窗口枚举阻塞所有并发文件操作
// （大量文件滚动时，原本每次 I/O 在锁内 EnumWindows 会串行化 Explorer，表现为卡顿/未响应）。
struct FgSnapshot {
    DWORD                     foreground_pid = 0;
    std::unordered_set<DWORD> visible_pids;
};
static FgSnapshot g_fg_snap;

static BOOL CALLBACK fg_enum_cb(HWND h, LPARAM param) {
    FgSnapshot* s = reinterpret_cast<FgSnapshot*>(param);
    if (!IsWindowVisible(h)) return TRUE;                              // 隐藏窗（托盘程序）不计
    if (GetWindowLongPtrW(h, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) return TRUE;   // 工具/浮动窗不计
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid) s->visible_pids.insert(pid);
    return TRUE;
}

// 在「局部」快照上枚举：EnumWindows 遍历全部顶层窗口，耗时不可控（挂起窗口会拖长）。
// 关键：绝不能在持 g_fg_snap_mtx 时调用它——I/O 热路径的 pid_is_fg_locked 要取同一把锁，
// 一旦被窗口枚举压住，所有文件操作会一起排队等锁，表现为「卡住/任何操作都无效」。
// 因此先在无锁状态下把快照建好，再只做一次极短的持锁换入（swap）。
static FgSnapshot fg_build_snapshot() {
    FgSnapshot s;
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowThreadProcessId(fg, &s.foreground_pid);
    EnumWindows(fg_enum_cb, reinterpret_cast<LPARAM>(&s));
    return s;
}

// 后台线程：周期刷新快照，从 I/O 热路径彻底移除 EnumWindows
static void fg_snapshot_thread() {
    while (!g_fg_stop.load(std::memory_order_relaxed)) {
        FgSnapshot s = fg_build_snapshot();   // 无锁枚举
        { std::lock_guard<std::mutex> lk(g_fg_snap_mtx); g_fg_snap = std::move(s); }
        for (int i = 0; i < 10 && !g_fg_stop.load(std::memory_order_relaxed); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// 会话探测：在交互会话内才做窗口枚举，否则退化为会话比较。须在首个 I/O 回调前调用。
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

// 判定进程是否为「前台程序」（调用方须持有 g_idle_mtx）。
// PID=0（请求未带 PID）时保守判前台：宁可不锁，不可误锁。
// 快照由后台线程维护，此处只读取、不触发 EnumWindows。
static bool pid_is_fg_locked(DWORD pid) {
    if (pid == 0) return true;
    if (pid == GetCurrentProcessId()) return false;   // mounter 自身 I/O 不算活动
    DWORD sess = 0;
    if (!ProcessIdToSessionId(pid, &sess)) return true;
    if (!g_fg_can_enum) return sess == g_my_session;  // 服务态：同会话即前台（近似）
    if (sess != g_my_session) return false;           // 别会话进程（服务等）一律后台
    // 锁内直接判定：不拷贝整个集合（大文件连续读写时每次 I/O 都走这里）
    std::lock_guard<std::mutex> lk(g_fg_snap_mtx);
    if (pid == g_fg_snap.foreground_pid) return true;
    return g_fg_snap.visible_pids.count(pid) > 0;
}

// 前台访问则把自动锁起算时刻推到当前（滑动窗口——窗口期内任何前台访问都会取消/推迟
// 本次锁定）。判定+记录在同一临界区内完成：watchdog 的上锁决策持同一把锁，
// 杜绝「判定为前台、尚未记录」的间隙里被 watchdog 夹着执行上锁。
static void fe_note_if_fg(DWORD pid) {
    std::lock_guard<std::mutex> lk(g_idle_mtx);
    if (pid_is_fg_locked(pid))
        g_last_fg_activity_ms.store(wf_now_ms(), std::memory_order_relaxed);
}
static VDiskApi    g_wapi;          // 静态存储，回调经 g_wv=&g_wapi 访问（避免局部悬垂）
static VDiskApi*    g_wv = nullptr;
static VDiskHandle* g_wh = nullptr;
static FSP_FILE_SYSTEM* g_wfs = nullptr;
static FSP_FILE_SYSTEM_INTERFACE g_wf_iface = {};
static FSP_SERVICE*     g_wsvc = nullptr;   // 卸载用：FspServiceStop 需服务句柄

// WinFSP 路径（\a\b）→ vdisk 虚拟路径（/a/b）
static std::string wfspath_to_vpath(const WCHAR* FileName) {
    std::string raw = wide_to_utf8(FileName);
    std::string out;
    for (char c : raw) {
        if (c == '\\' || c == '/') { if (out.empty() || out.back() != '/') out += '/'; }
        else out += c;
    }
    if (out.empty()) out = "/";
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    return out;
}

static void wf_fill_fileinfo(FSP_FSCTL_FILE_INFO* fi, bool isdir, uint64_t size, uint64_t mtime) {
    memset(fi, 0, sizeof(*fi));
    fi->FileAttributes  = isdir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    fi->ReparseTag      = 0;
    fi->AllocationSize  = isdir ? 0 : size;
    fi->FileSize        = size;
    UINT64 ft = ((UINT64)mtime + 11644473600ULL) * 10000000ULL;   // unix 秒 → FILETIME
    fi->CreationTime = ft; fi->LastAccessTime = ft; fi->LastWriteTime = ft; fi->ChangeTime = ft;
    fi->IndexNumber = 0; fi->HardLinks = 0; fi->EaSize = 0;
}

void fe_notify_locked_access();   // 前向声明（下方定义，wf_st 中调用）
static void launch_gui_if_needed();   // 前向声明：锁定访问时拉起 GUI（若未运行）
static NTSTATUS wf_st(VDiskStatus st) {
    if (st == VDISK_OK) return STATUS_SUCCESS;
    // 锁定态一律拒绝访问（而非 DEVICE_NOT_READY）：让 Explorer 明确报「拒绝访问」，
    // 避免「设备未就绪」被当可重试而误以为盘可开。盘符仍可见、双击即拒。
    if (st == VDISK_E_LOCKED) {
        fe_notify_locked_access();   // 写事件文件，GUI 轮询后弹「解锁」提示
        return STATUS_ACCESS_DENIED;
    }
    if (st == VDISK_E_NOTFOUND) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (st == VDISK_E_NOTIMPL) return STATUS_NOT_SUPPORTED;
    if (st == VDISK_E_RO) return STATUS_MEDIA_WRITE_PROTECTED;   // 只读挂载拒绝写
    return FspNtStatusFromWin32(ERROR_READ_FAULT);
}

// 解锁通知的用户输入活跃窗：仅当用户近期有键鼠输入时才认为本次锁定访问是主动操作。
// Explorer 后台刷（索引/缩略图/杀软实时扫描）与主动双击走同一 Open/Read 路径，
// 但后台刷发生时用户没有输入活动，借此区分，杜绝「莫名其妙弹解锁窗」。
static const uint32_t kNotifyIdleWindowMs = 30000;
static bool user_recently_active(uint32_t max_idle_ms) {
    LASTINPUTINFO li;
    li.cbSize = sizeof(li);
    if (!GetLastInputInfo(&li)) return true;   // 取失败保守放行（宁弹不漏）
    // dwTime 与 GetTickCount 同源，DWORD 无符号回绕下差值仍正确
    return (GetTickCount() - li.dwTime) < max_idle_ms;
}

// 锁定态被访问时写事件文件，GUI 轮询据此弹出「解锁」提示（替代无法拦截的资源管理器双击）。
// 8 秒节流，避免一次双击/枚举刷出大量事件；文件名用 vault 哈希，避免路径字符非法。
static std::mutex                g_locked_notify_mtx;
static std::unordered_map<std::string, uint64_t> g_last_locked_notify;  // vault -> 上次写毫秒
void fe_notify_locked_access() {
    const std::string vault = g_svc_vault;
    if (vault.empty()) return;
    // 用户近期无输入 = 后台程序触发的锁定访问，不打扰（置于节流前，省一次哈希表操作）
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
    CreateDirectoryW(utf8_to_wide(dir).c_str(), nullptr);  // 已存在则忽略
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : vault) { h ^= (unsigned char)c; h *= 0x100000001b3ULL; }
    char nm[64]; snprintf(nm, sizeof nm, "fe_locked_%016llx.event", (unsigned long long)h);
    std::string path = dir + "\\" + nm;
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "vault=%s\nmount=%s\n", vault.c_str(), g_svc_mp.c_str()); fclose(f); }
    // 事件已落盘：若 GUI 未运行则拉起它（双击锁定盘也能弹解锁框，无需 GUI 事先常驻）
    launch_gui_if_needed();
}

// 检测 GUI 进程是否存活（按 exe 名，并校验映像路径 basename 反伪造同名伪进程）
static bool gui_process_running() {
    bool found = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe; memset(&pe, 0, sizeof pe); pe.dwSize = sizeof pe;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"FileEncryptorGUI.WinUI3.exe") != 0) continue;
            // 反伪造：校验进程映像路径 basename 确为该名（同名伪进程拿不到真实映像）
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                wchar_t img[MAX_PATH] = {0}; DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, img, &sz) && sz > 0) {
                    std::wstring s(img, sz);
                    auto p = s.find_last_of(L"\\/");
                    std::wstring base = (p == std::wstring::npos) ? s : s.substr(p + 1);
                    if (_wcsicmp(base.c_str(), L"FileEncryptorGUI.WinUI3.exe") == 0) found = true;
                } else {
                    found = true;   // 查询失败不阻断（可用性优先，避免漏判重复拉起）
                }
                CloseHandle(h);
            } else {
                found = true;       // 打不开也按命中
            }
            if (found) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// 校验待拉起的 GUI 路径是否可信：必须落在 Program Files 或 mounter 自身所在目录。
// 防止同用户预设 FE_GUI_PATH 指向任意 exe 借「锁定访问」自动执行。
static bool gui_path_allowed(const std::wstring& wp) {
    auto lower = [](std::wstring s) { for (auto& c : s) c = (wchar_t)towlower(c); return s; };
    std::wstring p = lower(wp);
    std::vector<std::wstring> allowed;
    wchar_t buf[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"ProgramFiles", buf, MAX_PATH)) allowed.push_back(lower(buf));
    wchar_t buf86[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", buf86, MAX_PATH)) allowed.push_back(lower(buf86));
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

// 锁定访问时确保 GUI 在前台可用：未运行则启动（路径优先 FE_GUI_PATH，回退安装目录）。
// 同一用户会话下启动，不会提权；路径不可信时回退默认安装位置。GUI 已运行则跳过。
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

struct FeCtx { bool is_dir; std::string vpath; PVOID dir_buffer; DWORD owner_pid; };

// 自相对 SD，给「当前用户 + Administrators + SYSTEM」完全控制。
// 去掉 WD(Everyone)：解锁态下盘上是明文，Everyone-FA 等于同机任何用户可读。
// O:BAG:BA 不能省：FSD 访问检查需要合法 Owner，缺则判 STATUS_INVALID_SECURITY_DESCR。
static PSECURITY_DESCRIPTOR wf_build_sd() {
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        DWORD sz = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &sz);   // 首次必失败，仅取大小
        // TOKEN_USER 的首字段即 PSID；手动偏移取，避开该类型的 SDK 版本守卫（winfsp.h 锁了低版本）
        if (sz >= sizeof(void*) * 2 && sz <= 1024) {
            std::vector<BYTE> buf(sz);
            if (GetTokenInformation(tok, TokenUser, buf.data(), sz, &sz) && sz >= sizeof(void*) * 2) {
                void* sid = *reinterpret_cast<void**>(buf.data());
                wchar_t* sidbuf = nullptr;
                if (sid && ConvertSidToStringSidW(sid, &sidbuf)) {
                    // 给 Everyone(WD) 授 FA：解锁后的挂载卷对交互用户可读/可执行/枚举，
                    // 不依赖 FE-Mounter 以何种身份（用户/服务）运行。解密挂载卷本就等同明文，
                    // 授权范围与 Veracrypt/BitLocker 挂载盘一致。
                    std::wstring sddl = std::wstring(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)(A;;FA;;;")
                                      + sidbuf + L")";
                    LocalFree(sidbuf);
                    PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;
                    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            sddl.c_str(), SDDL_REVISION_1, &sd, &need)) {
                        CloseHandle(tok);
                        return sd;   // 调用方接管（LocalAlloc）
                    }
                }
            }
        }
        CloseHandle(tok);
    }
    PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;   // 取不到用户 SID 时的保守兜底
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)", SDDL_REVISION_1, &sd, &need)) return nullptr;
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

// 资源管理器显示的卷标（盘符后括号里的名字）。固定值：SetVolumeLabel 不支持改名。
static const wchar_t* const kVolumeLabel = L"加密磁盘";

// 库内元数据文件占用：这些不进虚拟盘（不该让用户看见），但真实占磁盘，
// 计算「盘容量 = 盘内内容大小」时必须一并计入，否则属性页会比实际占用小。
static uint64_t wf_file_size(const std::string& utf8_path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(utf8_to_wide(utf8_path).c_str(), GetFileExInfoStandard, &fad)) return 0;
    return ((uint64_t)fad.nFileSizeHigh << 32) | (uint64_t)fad.nFileSizeLow;
}

static NTSTATUS wf_GetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo) {
    WFDBG("[fe] GetVolumeInfo\n");
    // 容量口径：下限 64MiB，按已用量 2 倍留增长余量（与 stat_space 一致）。
    // 必须给非零 FreeSize：报告 0 可用空间会让资源管理器把卷当成「盘满」，
    // 枚举/访问行为异常，且对 M6 可写挂载是直接损坏（无法写入）。
    uint64_t used = 0, total = 0;
    if (!g_wv->stat_space || g_wv->stat_space(g_wh, &used, &total) != VDISK_OK || total == 0) {
        total = 64ull << 20;
        used = 0;
    }
    // 元数据（.feindex / vault.meta）真实占盘，计入已用，使容量与真实占用对齐
    if (!g_svc_vault.empty())
        used += wf_file_size(g_svc_vault + "/.feindex") + wf_file_size(g_svc_vault + "/vault.meta");
    if (total < used) total = used + (64ull << 20);   // 防元数据把已用顶过总量
    VolumeInfo->TotalSize = total;
    VolumeInfo->FreeSize  = (total > used) ? (total - used) : 0;
    // VolumeLabelLength 单位是「字节」（WinFSP 契约，同官方 memfs 样例）。
    // 此前误按字符数填，中文标签被截成半个字（资源管理器里只显示「加」）。
    VolumeInfo->VolumeLabelLength = (UINT16)(wcslen(kVolumeLabel) * sizeof(WCHAR));
    wcscpy_s(VolumeInfo->VolumeLabel, sizeof VolumeInfo->VolumeLabel / sizeof(WCHAR), kVolumeLabel);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetSecurityByName(FSP_FILE_SYSTEM*, PWSTR FileName, PUINT32 PFileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize) {
    std::string vp = wfspath_to_vpath(FileName);
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
    // 锁定态：根目录 getattr 返回 OK，靠它拦不住。此处显式拒访并触发解锁提示。
    if (fe_is_locked()) { fe_notify_locked_access(); return STATUS_ACCESS_DENIED; }
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (getenv("FE_MOUNT_DEBUG"))
        fprintf(stderr, "[fe] open '%s' opts=0x%lX acc=0x%lX getattr=%d\n",
                vp.c_str(), (unsigned long)CreateOptions, (unsigned long)GrantedAccess, (int)st);
    if (st != VDISK_OK) return wf_st(st);
    FeCtx* c = new (std::nothrow) FeCtx{ isdir != 0, vp, nullptr, 0 };
    if (!c) return STATUS_INSUFFICIENT_RESOURCES;
    // Create/Open 请求的 AccessToken 带调用方 PID（FspFileSystemOperationProcessId 仅这两类有效），
    // 记到上下文上：Read/Write 等回调拿不到 PID，靠它做前台归属。
    c->owner_pid = (DWORD)FspFileSystemOperationProcessId();
    // 前台程序打开盘内文件/目录即算一次访问，刷新自动锁计时
    fe_note_if_fg(c->owner_pid);
    *PFileContext = c;
    if (FileInfo) wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Open(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    return wf_open_common(FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
}
// Create 与 Open 签名不同（多 FileAttributes/SecurityDescriptor/AllocationSize）。
// 可写挂载：文件不存在则创建（O_CREAT 语义，CREATE_NEW 时已存在应返 STATUS_OBJECT_NAME_COLLISION）。
// 只读挂载：存在即只读打开，不存在返 NOT_FOUND（等价 Open）。
static NTSTATUS wf_Create(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    UINT32 FileAttributes, PSECURITY_DESCRIPTOR, UINT64 AllocationSize,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    WFDBG("[fe] Create '%s' rw=%d dir=%d\n", vp.c_str(), g_svc_rw ? 1 : 0,
          (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0);
    bool is_dir = (FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    bool exists = (g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr) == VDISK_OK);
    if (!exists) {
        if (!g_svc_rw) return STATUS_OBJECT_NAME_NOT_FOUND;   // 只读：不可创建
        // 目录：只登记目录条目（不建 .ptd）；文件：建随机名 .ptd。保留挂载盘目录树。
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
// 重命名 / 移动：库层 vdisk_rename 已处理文件改名与目录递归（含 .ptd 搬运）。
static NTSTATUS wf_Rename(FSP_FILE_SYSTEM*, PVOID FileContext, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists) {
    std::string old_vp = wfspath_to_vpath(FileName);
    std::string new_vp = wfspath_to_vpath(NewFileName);
    WFDBG("[fe] Rename '%s' -> '%s' replace=%d\n", old_vp.c_str(), new_vp.c_str(), ReplaceIfExists ? 1 : 0);
    if (!g_svc_rw) return STATUS_ACCESS_DENIED;   // 只读拒绝
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
    // 删除的唯一执行点：Flags 含 FspCleanupDelete 表示 FSD 已标记该文件删除、现在真正删。
    // （SDK winfsp.h:364 三阶段协议；CanDelete/SetDelete 都只做预检、绝不删）
    WFDBG("[fe] Cleanup '%s' flags=0x%lX\n", c->vpath.c_str(), (unsigned long)Flags);
    if ((Flags & FspCleanupDelete) && g_svc_rw) {
        // 前台程序发起删除同样算访问（删除前刷新，删除本身即活动）
        fe_note_if_fg(c->owner_pid);
        // 目录也走这里：库层 delete_file 删索引条目 + 擦除其下 .ptd。
        // 此前用 !c->is_dir 拦掉目录 → CanDelete 放行但实际不删，explorer 报「成功」而目录仍在（E2）。
        VDiskStatus st = g_wv->delete_file(g_wh, c->vpath.c_str());
        WFDBG("[fe] Cleanup delete '%s' (dir=%d) -> %s\n", c->vpath.c_str(), c->is_dir ? 1 : 0,
              st == VDISK_OK ? "ok" : g_wv->strerror(st));
    }
    if (c->dir_buffer) FspFileSystemDeleteDirectoryBuffer(&c->dir_buffer);
    delete c;
}
static VOID wf_Close(FSP_FILE_SYSTEM*, PVOID FileContext) {
    (void)FileContext;  // context lifetime is managed in Cleanup
}
static NTSTATUS wf_Read(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, PULONG PBytesTransferred) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    fe_note_if_fg(c->owner_pid);
    uint64_t len = Length;
    VDiskStatus st = g_wv->read_file(g_wh, c->vpath.c_str(), Offset, (uint8_t*)Buffer, &len);
    if (st != VDISK_OK) return wf_st(st);
    *PBytesTransferred = (ULONG)len;
    return STATUS_SUCCESS;
}
// M6 写支持：覆盖写 / 扩展（删除见 wf_CanDelete + wf_Cleanup 的 FspCleanupDelete 分支）
static NTSTATUS wf_Write(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, BOOLEAN, BOOLEAN, PULONG PBytesTransferred,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    fe_note_if_fg(c->owner_pid);
    VDiskStatus st = g_wv->write_file(g_wh, c->vpath.c_str(), Offset, (const uint8_t*)Buffer, (uint64_t)Length);
    if (st != VDISK_OK) return wf_st(st);
    *PBytesTransferred = Length;
    if (FileInfo) {  // 回填 FileInfo 让系统看到新大小
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
    if (!SetAllocationSize) {  // 仅 EOF 调整改文件大小；AllocationSize 仅预留则忽略
        VDiskStatus st = g_wv->truncate_file(g_wh, c->vpath.c_str(), NewSize);
        if (st != VDISK_OK) return wf_st(st);
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
    // 锁定态拒访（getattr 对根目录返回 OK，不看锁态会漏过）。
    // 注意：此处不发解锁通知——GetFileInfo 是资源管理器后台刷空闲空间/属性的高频调用，
    // 会误触发弹窗；真正的解锁提示只在 Open / ReadDirectory / 文件读写(wf_st) 时发出。
    if (fe_is_locked()) { return STATUS_ACCESS_DENIED; }
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    g_wv->getattr(g_wh, c->vpath.c_str(), &size, &mtime, &isdir);
    wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetDirInfoByName(FSP_FILE_SYSTEM*, PVOID, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo) {
    std::string vp = wfspath_to_vpath(FileName);
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
// 目录枚举缓存已移除：曾按 TTL 缓存 readdir 结果，但挂载盘内容可被库外路径改动，
// 缓存过期窗口内 Explorer 看到的是不一致快照（表现为「目录无效」/内容与实盘对不上）。
// 卡顿的真实根因是窗口枚举串行化 I/O（见 fg_build_snapshot），已单独修复，不再用缓存兜底。

static NTSTATUS wf_ReadDirectory(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext0, PWSTR, PWSTR Marker,
    PVOID Buffer, ULONG BufferLength, PULONG PBytesTransferred) {
    FeCtx* c = (FeCtx*)FileContext0;
    WFDBG("[fe] ReadDirectory '%s'\n", c ? c->vpath.c_str() : "?");
    if (!c || !c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    // 锁定态：资源管理器双击盘符必经此处。此前 readdir 返回 VDISK_E_LOCKED 却被
    // 「== VDISK_OK」判空后照常返回 SUCCESS，Explorer 只看到空目录、且从不进 wf_st，
    // 导致解锁提示永不触发。锁定即拒访并通知 GUI 弹解锁窗。
    if (fe_is_locked()) { fe_notify_locked_access(); return STATUS_ACCESS_DENIED; }
    // 浏览目录同样算前台活动：只翻目录、不打开任何文件时 g_last_fg_activity_ms 不刷新，
    // M5 空闲守护会在窗口到期后误锁，紧接着读文件就变成「无权限」。
    fe_note_if_fg(c->owner_pid);
    // 首页（Marker==NULL）才查询并填充；后续分页直接复用已填缓冲，避免重复填充。
    bool first_page = (Marker == NULL);
    std::vector<VDiskEntry> ents;
    if (first_page) {
        uint64_t n = 0;
        if (g_wv->readdir(g_wh, c->vpath.c_str(), nullptr, &n) == VDISK_OK && n > 0) {
            ents.resize((size_t)n);
            VDiskEntry* parr = ents.data();
            if (g_wv->readdir(g_wh, c->vpath.c_str(), &parr, &n) == VDISK_OK) ents.resize((size_t)n);
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
                // 防御：本地定长缓冲 FileNameBuf 仅 512 WCHAR，超长文件名（畸形/被投毒的索引）
                // 若按实际长度填 di->Size 会栈溢出。超长直接跳过该条目（Windows 组件名上限 255，正常不会触发）。
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
// 删除：CanDelete 仅做预检（绝不删文件，SDK winfsp.h:586 明确要求）。
// 真正删除在 Cleanup 且 Flags 含 FspCleanupDelete 时执行——这是 WinFsp 的三阶段协议
// （打开 → CanDelete 预检 → Cleanup 删除），与官方 memfs 样例一致。
static NTSTATUS wf_CanDelete(FSP_FILE_SYSTEM*, PVOID, PWSTR FileName) {
    if (!g_svc_rw) { WFDBG("[fe] CanDelete denied (read-only)\n"); return STATUS_MEDIA_WRITE_PROTECTED; }
    std::string vp = wfspath_to_vpath(FileName);
    return (g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr) == VDISK_OK)
        ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

// 已打开句柄的安全查询（dir/Explorer 打开目录后会走 GetSecurity 而非 GetSecurityByName）。
// 不实现时落 NULL 槽位 → WinFsp 返回 STATUS_INVALID_DEVICE_REQUEST(0xC0000010) → "函数不正确"。
static NTSTATUS wf_GetSecurity(FSP_FILE_SYSTEM*, PVOID,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize) {
    WFDBG("[fe] GetSecurity\n");
    return wf_fill_sd(SecurityDescriptor, PSecurityDescriptorSize);
}
static NTSTATUS wf_SetSecurity(FSP_FILE_SYSTEM*, PVOID, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) {
    WFDBG("[fe] SetSecurity (ignored, read-only)\n");
    return STATUS_SUCCESS;   // 只读库：忽略安全修改
}
static NTSTATUS wf_SetBasicInfo(FSP_FILE_SYSTEM*, PVOID, UINT32, UINT64, UINT64, UINT64, UINT64,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    WFDBG("[fe] SetBasicInfo (ignored)\n");
    (void)FileInfo;
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Flush(FSP_FILE_SYSTEM*, PVOID, FSP_FSCTL_FILE_INFO*) {
    WFDBG("[fe] Flush\n");
    // 卷刷新 (FileContext==NULL)：容量由 wf_GetVolumeInfo 提供，无需在此回填
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
    return STATUS_INVALID_DEVICE_REQUEST;   // 不支持改卷标，与 passthrough 一致
}

// M5 前台活动守护：只有「前台程序」的真实文件访问（打开/读/写/改大小/重命名/删除）
// 才刷新 g_last_fg_activity_ms；后台程序与托盘程序的访问不算活动。距最近一次前台访问
// 达 g_svc_idle 秒即上锁——滑动窗口天然实现「1 分钟等待窗口期内，任何前台访问都会
// 取消/推迟本次锁定」。上锁执行前在临界区内复查一次活动时刻：轮询睡眠期间到来的
// 前台访问同样能取消本次锁定，不允许带着刚发生的访问上锁。
// 轮询间隔 1s：锁的时机误差 ≤1s，可接受；不 busy-wait。
void idle_watchdog_thread() {
    while (!g_ipc_stop.load()) {
        bool done = false;
        for (int i = 0; i < 10 && !done; ++i) {   // 每秒醒一次，中途可被 stop 打断
            if (g_ipc_stop.load()) { done = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (done) break;
        if (!g_ipc_unlocked.load() || !g_wv || !g_wh || !g_wapi.lock) continue;
        if (g_svc_idle == 0) continue;   // IPC `idle 0` 可运行时关闭自动锁
        // 库可能在 I/O 路径上自行超时锁定（touch_activity/check_idle_only）而没同步 IPC 标志：
        // 锁态下 idle_remaining 返回 UINT32_MAX，借此把 g_ipc_unlocked 纠回 false。
        if (g_wapi.idle_remaining && g_wapi.idle_remaining(g_wh) == UINT32_MAX) {
            g_ipc_unlocked = false;
            std::lock_guard<std::mutex> lk(g_idle_mtx);
            g_last_fg_activity_ms.store(0, std::memory_order_relaxed);
            continue;
        }
        std::lock_guard<std::mutex> lk(g_idle_mtx);   // 与 fe_note_if_fg 互斥
        if (!g_ipc_unlocked.load()) continue;
        const uint64_t now = wf_now_ms();
        uint64_t last = g_last_fg_activity_ms.load(std::memory_order_relaxed);
        if (last == 0) {   // 解锁后尚未记录活动：以当前时刻起算一个完整窗口
            g_last_fg_activity_ms.store(now, std::memory_order_relaxed);
            continue;
        }
        if (now - last < (uint64_t)g_svc_idle * 1000ull) continue;   // 窗口期内不到点不锁
        g_wapi.lock(g_wh);
        g_ipc_unlocked = false;
        g_last_fg_activity_ms.store(0, std::memory_order_relaxed);
        fprintf(stderr, "[fe] idle timeout: auto-locked (no foreground access for %u s)\n",
                (unsigned)g_svc_idle);
    }
}

static NTSTATUS wf_SvcStart(FSP_SERVICE* Service, ULONG, PWSTR*) {
    // 自给自足：从服务命令行加载 vdisk、打开/解锁 vault、起 IPC、挂载
    std::string err;
    if (!vdisk_load(g_wapi, g_svc_lib, err)) { fprintf(stderr, "[fe] load libvdisk: %s\n", err.c_str()); return STATUS_UNSUCCESSFUL; }
    g_wv = &g_wapi;
    g_wh = g_wapi.open(g_svc_vault.c_str());
    if (!g_wh) { fprintf(stderr, "[fe] open vault failed: %s\n", g_svc_vault.c_str()); return STATUS_UNSUCCESSFUL; }
    if (!g_svc_pass.empty()) {
        if (g_wapi.unlock(g_wh, g_svc_pass.c_str(), 0) != VDISK_OK) { fprintf(stderr, "[fe] unlock failed\n"); g_wapi.close(g_wh); g_wh = nullptr; return STATUS_UNSUCCESSFUL; }
        g_ipc_unlocked = true;
        g_last_fg_activity_ms.store(wf_now_ms(), std::memory_order_relaxed);   // 解锁即起算一个完整自动锁窗口
        secure_zero(g_svc_pass.data(), g_svc_pass.size());   // 解锁后即清，不在内存长期驻留（§4.1）
        g_svc_pass.clear();
    } else {
        g_ipc_unlocked = false;   // 无密码：锁定启动，等 IPC unlock（§4.1 默认锁定）
    }
    // M2 读缓存（默认开启）：顺序读（缩略图/连续解码）命中预读段，免去每次重新解密。
    // Windows 挂载此前漏开（仅 Linux FUSE 路径启用），导致大量图片/文件滚动时极卡。
    // 64MB 上限：256MB 会让首次访问时集中分配/预热，表现为「初次读取卡几十秒」。
    // 卡顿真因是窗口枚举串行化 I/O（已由 fg_build_snapshot 无锁化修复），不靠放大缓存解决。
    if (g_wapi.set_read_cache) g_wapi.set_read_cache(g_wh, 64ull << 20, 8);   // 64MB 上限 / 预读 8 段(每段 64KB)
    g_ipc_v = g_wv; g_ipc_h = &g_wh; g_ipc_stop = false;
    // M5 前台活动自动锁：GUI 挂载固定传 60（1 分钟无前台访问就自动锁），必须在解锁后设，
    // 否则立刻被计时。库侧计时器保留作兜底（库会在 I/O 路径自行超时锁定），前台 watchdog 总是先到。
    if (g_svc_idle > 0 && g_wapi.set_idle_timeout) g_wapi.set_idle_timeout(g_wh, g_svc_idle);
    fg_init_session();   // 前台判定依赖会话探测，须在首个 I/O 回调与 watchdog 前完成
    std::thread(ipc_server_thread).detach();
    // 前台活动守护：库的超时判定是「惰性」的，只在有 I/O 到来时才检查；且它认所有 I/O
    // （含后台程序），不满足「仅前台访问续期」。这里独立起定时器按秒主动查前台活动时刻，
    // 到点直接锁。
    if (g_svc_idle > 0 && g_wapi.lock)
        std::thread(idle_watchdog_thread).detach();

    FSP_FSCTL_VOLUME_PARAMS vol; memset(&vol, 0, sizeof vol);
    FILETIME nowft; GetSystemTimeAsFileTime(&nowft);
    vol.Version = sizeof(FSP_FSCTL_VOLUME_PARAMS);
    vol.SectorSize = 512; vol.SectorsPerAllocationUnit = 1; vol.MaxComponentLength = 255;
    vol.VolumeCreationTime = ((PLARGE_INTEGER)&nowft)->QuadPart;
    vol.VolumeSerialNumber = 0x20261005;
    vol.FileInfoTimeout = 1000; vol.CaseSensitiveSearch = 0; vol.CasePreservedNames = 1;
    // PostCleanupWhenModifiedOnly 必须为 0：置 1 时 FSD 只在文件被修改/删除时才投递 Cleanup，
    // 纯读取（浏览目录、打开文件看）根本不会回调，FeCtx 每次打开都泄漏。关闭此优化换取 Cleanup 必定投递。
    vol.UnicodeOnDisk = 1; vol.PersistentAcls = 1; vol.PostCleanupWhenModifiedOnly = 0;
    vol.PassQueryDirectoryPattern = 1; vol.FlushAndPurgeOnCleanup = 1; vol.UmFileContextIsUserContext2 = 1;
    // 删除链路必需：让 FSD 把 Disposition（删除请求）投递到 Cleanup，Cleanup 才能收到
    // FspCleanupDelete 并执行删除。缺此项则 del 静默不生效。
    vol.PostDispositionWhenNecessaryOnly = 1;
    if (!g_svc_rw) vol.ReadOnlyVolume = 1;
    // FileSystemName 是属性页「文件系统」那一行（不是卷标）。保持产品标识 FE-Vault。
    wcscpy_s(vol.FileSystemName, sizeof vol.FileSystemName / sizeof(WCHAR), L"FE-Vault");
    FSP_FILE_SYSTEM* fs = nullptr;
    // 显式转 PWSTR：DeviceName 形参非 const，/Zc:strictStrings 下字面量是 const
    NTSTATUS st = FspFileSystemCreate(const_cast<PWSTR>(L"" FSP_FSCTL_DISK_DEVICE_NAME),
                                      &vol, &g_wf_iface, &fs);
    if (!NT_SUCCESS(st)) { fprintf(stderr, "[fe] FspFileSystemCreate failed 0x%08lX\n", (unsigned long)st); return st; }
    std::wstring mount_w = utf8_to_wide(g_svc_mp);
    st = FspFileSystemSetMountPoint(fs, (PWSTR)mount_w.c_str());
    if (!NT_SUCCESS(st)) { fprintf(stderr, "[fe] SetMountPoint(%s) failed 0x%08lX\n", g_svc_mp.c_str(), (unsigned long)st); FspFileSystemDelete(fs); return st; }
    if (g_svc_rw) g_wapi.mount_rw(g_wh, g_svc_mp.c_str());
    else          g_wapi.mount_readonly(g_wh, g_svc_mp.c_str());
    if (getenv("FE_MOUNT_DEBUG")) FspFileSystemSetDebugLog(fs, (UINT32)-1);
    st = FspFileSystemStartDispatcher(fs, 0);
    if (!NT_SUCCESS(st)) { FspFileSystemDelete(fs); return st; }
    g_wfs = fs; Service->UserContext = fs;
    g_wsvc = Service;
    // 卸载：停服务 → FspServiceRun 返回 → 进程退出，盘符随之释放
    g_ipc_eject_hook = []() { if (g_wsvc) FspServiceStop(g_wsvc); };
    printf("MOUNTED at %s (unlocked=%d)\n", g_svc_mp.c_str(), g_ipc_unlocked.load() ? 1 : 0); fflush(stdout);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SvcStop(FSP_SERVICE* Service) {
    FSP_FILE_SYSTEM* fs = (FSP_FILE_SYSTEM*)Service->UserContext;
    if (fs) { FspFileSystemStopDispatcher(fs); FspFileSystemDelete(fs); }
    g_fg_stop = true;                              // 停前台快照线程
    if (g_fg_thread.joinable()) g_fg_thread.join();
    g_ipc_stop = true;
    if (g_wv && g_wh) { g_wv->unmount(g_wh); g_wv->close(g_wh); g_wh = nullptr; }
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
    g_wf_iface.Create = wf_Create;   // 可写：不存在则创建；只读：不存在返 NOT_FOUND
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
    g_wf_iface.CanDelete = wf_CanDelete;   // 仅预检；实际删除在 Cleanup(FspCleanupDelete)
    g_wf_iface.SetVolumeLabel = wf_SetVolumeLabel;
    g_wf_iface.Rename = wf_Rename;   // 重命名 / 移动
    // 必须 FspServiceRun：控制台调试模式自动走 Mount Manager 全局盘符，跨窗口可见。
    // 不能换 FspServiceLoop——它只建会话盘符，其他窗口 I/O 在内核层即失败(0xC0000010)。
    // 显式转 PWSTR：FspServiceRun 收非 const 指针，字符串字面量在 /Zc:strictStrings 下是 const。
    FspServiceRun(const_cast<PWSTR>(L"FE-Mount"), wf_SvcStart, wf_SvcStop, nullptr);
    return 0;
}
#endif // FE_HAVE_WINFSP
