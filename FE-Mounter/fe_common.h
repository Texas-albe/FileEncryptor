// FE-Mounter 公共头：跨模块共享的类型、函数声明与全局状态。
// 模块划分：fe_vdisk(加载/工具) fe_ipc(§5.1 控制面) fe_service(服务注册) fe_winfsp(Windows 挂载) main(CLI+FUSE)
#pragma once
// vdisk.h（libvdisk 的 C ABI 类型与状态码）通常在 CLI/include 下。
// 回退路径覆盖「本目录被单独抽出编译」的场景（IDE 当独立工程打开、只同步了
// FE-Mounter 一个目录）；都找不到时给出可读报错，而非编译器的 No such file。
#if __has_include("vdisk.h")
#  include "vdisk.h"
#elif __has_include("../CLI/include/vdisk.h")
#  include "../CLI/include/vdisk.h"
#elif __has_include("../../CLI/include/vdisk.h")
#  include "../../CLI/include/vdisk.h"
#else
#  error "vdisk.h not found: keep FE-Mounter beside CLI, or pass -DFE_MOUNT_CLI_DIR=<path to CLI>"
#endif

#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <cstdio>    // FILE*（fe_open_write_nofollow 返回类型）
#include <mutex>     // M6/M7 跨文件互斥访问器

#ifdef _WIN32
#  include <windows.h>   // 不要 WIN32_LEAN_AND_MEAN：会排除 NTSTATUS/PNTSTATUS 所在头，WinFSP 原生 API 编译不过
#else
#  include <dlfcn.h>
#  include <unistd.h>    // readlink / getuid（fe_vdisk.self_dir、fe_ipc peer uid 校验）
#  include <sys/types.h>
#endif

// ---- 平台能力宏 ----
// FE_HAVE_FUSE 可由 CMake 显式定义（探测到 fuse3 时）；否则回落到 __has_include 自检。
#if defined(FE_HAVE_FUSE)
#elif defined(__linux__)
#  if __has_include(<fuse3/fuse.h>)
#    define FE_HAVE_FUSE 1
#  else
#    define FE_HAVE_FUSE 0
#  endif
#else
#  define FE_HAVE_FUSE 0
#endif

#ifndef FE_HAVE_WINFSP
#define FE_HAVE_WINFSP 0
#endif

// ---- libvdisk 动态加载 API 表 ----
struct VDiskApi {
    void* lib = nullptr;
    VDiskHandle* (*open)(const char*) = nullptr;
    void         (*close)(VDiskHandle*) = nullptr;
    VDiskStatus  (*unlock)(VDiskHandle*, const char*, int) = nullptr;
    VDiskStatus  (*lock)(VDiskHandle*) = nullptr;
    void         (*purge_on_suspend)(VDiskHandle*) = nullptr;
    VDiskStatus  (*reindex)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*mount_readonly)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*unmount)(VDiskHandle*) = nullptr;
    VDiskStatus  (*readdir)(VDiskHandle*, const char*, VDiskEntry**, uint64_t*) = nullptr;
    VDiskStatus  (*getattr)(VDiskHandle*, const char*, uint64_t*, uint64_t*, uint8_t*) = nullptr;
    VDiskStatus  (*read_file)(VDiskHandle*, const char*, uint64_t, uint8_t*, uint64_t*) = nullptr;
    VDiskStatus  (*write_file)(VDiskHandle*, const char*, uint64_t, const uint8_t*, uint64_t) = nullptr;
    const char*  (*strerror)(VDiskStatus) = nullptr;
    // M4 恢复密钥（§4.4）
    VDiskStatus  (*recovery_gen)(char*, uint64_t) = nullptr;
    VDiskStatus  (*recovery_create)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*recovery_open)(VDiskHandle*, const char*, char*, uint64_t*) = nullptr;
    VDiskStatus  (*recovery_remove)(VDiskHandle*) = nullptr;
    // M5 增强
    VDiskStatus  (*set_idle_timeout)(VDiskHandle*, uint32_t) = nullptr;
    uint32_t     (*idle_remaining)(VDiskHandle*) = nullptr;
    VDiskStatus  (*set_read_cache)(VDiskHandle*, uint64_t, uint32_t) = nullptr;
    // M6 写支持（可写挂载）
    VDiskStatus  (*mount_rw)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*create_file)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*create_file_ex)(VDiskHandle*, const char*, int) = nullptr;  // 目录感知创建
    VDiskStatus  (*delete_file)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*truncate_file)(VDiskHandle*, const char*, uint64_t) = nullptr;
    VDiskStatus  (*rename)(VDiskHandle*, const char*, const char*) = nullptr; // 重命名 / 移动
    VDiskStatus  (*stat_space)(VDiskHandle*, uint64_t*, uint64_t*) = nullptr;
};

// ---- 共享资源上限与跨文件互斥（M5/M6/M7 + low A/C） ----
// M5：索引驱动的分配上限。恶意/损坏 .feindex 可令条目数/文件大小变成天文数字，直接 resize/assign 即 bad_alloc，异常穿到 WinFSP 回调链外会 terminate 整个进程。
inline constexpr uint64_t kFeMaxDirEntries = 10000000;   // 目录项数上限（1000 万）
inline constexpr uint64_t kFeMaxFileSize   = 1ull << 40; // 单文件大小上限（1 TiB）
// M6：libvdisk 调用互斥。IPC 线程、watchdog、SvcStop 并发操作同一 g_wh（库层非线程安全），控制面命令在临界区内完成「判空→调用」。
std::mutex& fe_vdisk_call_mutex();
// M7：解锁成功置位 g_ipc_unlocked 与 watchdog 上锁决策须互斥，否则交叉时出现「IPC 显示已解锁、库实际已锁」的不一致态。锁定义于 fe_ipc.cpp，跨文件经此取。
std::mutex& fe_idle_decision_mutex();
// 低危（A 组）：防符号链接劫持的写打开。Windows: CreateFileW + FILE_FLAG_OPEN_REPARSE_POINT 并复查重解析点；POSIX: O_NOFOLLOW。失败（含遇 symlink）返回 nullptr。
FILE* fe_open_write_nofollow(const std::string& path, bool append);
// 低危（C 组）：进程存活探测（挂载态文件内 pid 校验用；Windows 打不开且非拒绝访问时判死）。
bool fe_pid_alive(long pid);

// ---- fe_vdisk ----
#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s);
std::string  wide_to_utf8(const WCHAR* w);
#endif
std::string self_dir();
std::string default_lib_path();
bool vdisk_load(VDiskApi& v, const std::string& path, std::string& err);
bool read_pass_file(const std::string& path, std::string& out);
uint64_t fnv1a64(const uint8_t* p, size_t n);
void secure_zero(void* p, size_t n);
// M5 多库：已知库注册表（每行一个绝对路径），供 vaults list/add/remove
std::string vaults_registry_path();
bool vaults_add(const std::string& dir, std::string& err);
bool vaults_remove(const std::string& dir, std::string& err);
std::vector<std::string> vaults_list();

// P1-2 多盘批量：聚合注册表里全部盘的 IPC 状态（JSON），或对全部盘扇出 lock/eject。
int vaults_status_json();
int vaults_batch(const std::string& cmd);
bool read_whole(const VDiskApi& v, VDiskHandle* h, const std::string& vpath,
                std::vector<uint8_t>& out, std::string& err);
void walk(const VDiskApi& v, VDiskHandle* h, const std::string& vpath);

// ---- fe_ipc（§5.1 控制面）----
extern std::string   g_ipc_vault;              // 管道名由 vault 路径派生
extern VDiskApi*     g_ipc_v;                  // 服务端绑定的 vdisk API
extern VDiskHandle** g_ipc_h;                  // 指向当前句柄（lock 置空）
extern std::atomic<bool> g_ipc_unlocked;
extern std::atomic<bool> g_ipc_stop;
// M5 前台活动自动锁（Windows）：最近一次「前台程序」文件访问时刻（单调时钟毫秒，0=无记录）。
// 后台程序/托盘程序（无可见顶层窗口或非交互会话）的访问不刷新它。定义在 fe_ipc.cpp，
// 供 fe_winfsp 的 I/O 回调刷新、watchdog 读取、IPC 解锁时重置。
extern std::atomic<uint64_t> g_last_fg_activity_ms;
// 卸载（eject）：收到后由各挂载后端接管——停服务/退进程，释放盘符
extern void (*g_ipc_eject_hook)();
std::string ipc_pipe_name(const std::string& vault);
std::string hex_encode(const std::string& s);
std::string hex_decode(const std::string& s);
void        ipc_server_thread();               // 阻塞循环，g_ipc_stop 退出
std::string ipc_call(const std::string& vault, const std::string& req);  // 客户端

// ---- fe_power（休眠/待机/快速启动的锁一致性）----
// 休眠会把内存换到磁盘：进休眠前必须主动上锁，否则恢复后明文密钥随休眠镜像落盘。
// 电源回调线程不能阻塞，故只置标记，由 idle_watchdog 实际执行锁定。
extern std::atomic<bool> g_power_suspend_pending;  // 已收到休眠通知，待 watchdog 锁定
extern std::atomic<bool> g_power_resumed;          // 已恢复，watchdog 须清活动时刻并上锁
void power_register();                              // 注册电源通知（幂等）
void power_unregister();
void power_request_lock(const char* reason);        // 主动请求上锁（休眠/测试）

// ---- fe_harden（进程加固）----
// P0-1：收紧自身进程对象 DACL 为「当前用户+SYSTEM+Administrators」，阻断同机其他非特权用户
// 读内存（口令/KEK/明文）或注入。失败静默；POSIX 为空实现。
void fe_harden_process_dacl();
// P1-2：镜像加载策略（禁远程/低 IL 镜像，系统 DLL 强制走 System32）。失败静默。
void fe_harden_image_load_policy();
// P1-3：把自身排除出 WER，不产生崩溃转储（dump 会带走内存里的口令/KEK）。失败静默。
void fe_harden_no_crash_dump();

// ---- fe_service（常驻：Windows 服务 / Linux systemd user unit）----// 两侧同名命令 install-service / uninstall-service，参数与语义一致。
#if defined(_WIN32)
extern const char* kSvcName;                   // = "FE-Mount"，须与 FspServiceRun 一致
bool install_service(const std::string& vault, const std::string& drive,
                     const std::string& passfile, const char* svcname, std::string& err);
bool uninstall_service(const char* svcname, std::string& err);
#else
// Linux：写 ~/.config/systemd/user/fe-mount-<hash>.service（Type=simple，Restart=on-failure）。
// mountpoint 是挂载点目录（Linux 无盘符概念）；无 systemd 时返回失败并给出提示。
bool install_service(const std::string& vault, const std::string& mountpoint,
                     const std::string& passfile, std::string& err);
bool uninstall_service(const std::string& vault, std::string& err);
#endif

// ---- fe_winfsp（Windows 只读挂载）----
#if FE_HAVE_WINFSP
extern std::string g_svc_vault, g_svc_pass, g_svc_mp, g_svc_lib;  // 服务命令行参数
extern bool        g_svc_rw;                     // M6 可写挂载开关（winmount --rw）
extern uint32_t    g_svc_idle;                   // M5 空闲超时自动锁秒数（0=关闭，winmount --idle-timeout）
int  fe_winmount_service();                      // FspLoad + FspServiceRun（进程本身即服务）
#endif
