// FE-Mounter 公共头
// 模块划分
#pragma once
// vdisk.h
// 回退路径覆盖「本
// FE-Mounter 一个目录）
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
#include <cstdio>    // FILE*
#include <mutex>     // M6/M7 跨文件互斥访问

#ifdef _WIN32
#  include <windows.h>   // 不要
#else
#  include <dlfcn.h>
#  include <unistd.h>    // readlink / getuid
#  include <sys/types.h>
#endif

// 平台能力宏
// FE_HAVE_FUSE 可由 CMake 显式定义；否
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

// libvdisk 动态加载 API 表
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
    // M4 恢复密钥
    VDiskStatus  (*recovery_gen)(char*, uint64_t) = nullptr;
    VDiskStatus  (*recovery_create)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*recovery_open)(VDiskHandle*, const char*, char*, uint64_t*) = nullptr;
    VDiskStatus  (*recovery_remove)(VDiskHandle*) = nullptr;
    // M5 增强
    VDiskStatus  (*set_idle_timeout)(VDiskHandle*, uint32_t) = nullptr;
    uint32_t     (*idle_remaining)(VDiskHandle*) = nullptr;
    VDiskStatus  (*set_read_cache)(VDiskHandle*, uint64_t, uint32_t) = nullptr;
    // M6 写支持
    VDiskStatus  (*mount_rw)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*create_file)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*create_file_ex)(VDiskHandle*, const char*, int) = nullptr;  // 目录感知创建
    VDiskStatus  (*delete_file)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus  (*truncate_file)(VDiskHandle*, const char*, uint64_t) = nullptr;
    VDiskStatus  (*rename)(VDiskHandle*, const char*, const char*) = nullptr; // 重命名 / 移动
    VDiskStatus  (*stat_space)(VDiskHandle*, uint64_t*, uint64_t*) = nullptr;
    // M5+ 忙闲续期
    // 外部进程
    // is_unlocked 查真实锁态
    void         (*note_activity)(VDiskHandle*) = nullptr;
    uint64_t     (*index_stamp)(VDiskHandle*) = nullptr;
    int          (*is_unlocked)(VDiskHandle*) = nullptr;
};

// 共享资源上限
// M5
inline constexpr uint64_t kFeMaxDirEntries = 10000000;   // 目录项数上限
inline constexpr uint64_t kFeMaxFileSize   = 1ull << 40; // 单文件大小上限
// M6
std::mutex& fe_vdisk_call_mutex();
// M7
std::mutex& fe_idle_decision_mutex();
// 低危
FILE* fe_open_write_nofollow(const std::string& path, bool append);
// 低危
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
// M5 多库
std::string vaults_registry_path();
bool vaults_add(const std::string& dir, std::string& err);
bool vaults_remove(const std::string& dir, std::string& err);
std::vector<std::string> vaults_list();

// P1-2 多盘批量
int vaults_status_json();
int vaults_batch(const std::string& cmd);
bool read_whole(const VDiskApi& v, VDiskHandle* h, const std::string& vpath,
                std::vector<uint8_t>& out, std::string& err);
void walk(const VDiskApi& v, VDiskHandle* h, const std::string& vpath);

// fe_ipc
extern std::string   g_ipc_vault;              // 管道名
extern VDiskApi*     g_ipc_v;                  // 服务端绑定
extern VDiskHandle** g_ipc_h;                  // 指向当前句柄
extern std::atomic<bool> g_ipc_unlocked;
extern std::atomic<bool> g_ipc_stop;
// M5 前台活动自动锁
// 后台程序/托盘程
// 供 fe_winfsp
extern std::atomic<uint64_t> g_last_fg_activity_ms;
extern std::atomic<int64_t> g_suspend_until_ms;   // M8
// 卸载
extern void (*g_ipc_eject_hook)();
std::string ipc_pipe_name(const std::string& vault);
std::string hex_encode(const std::string& s);
std::string hex_decode(const std::string& s);
void        ipc_server_thread();               // 阻塞循环
std::string ipc_call(const std::string& vault, const std::string& req);  // 客户端

// fe_power
// 休眠
// 电源回调线程
extern std::atomic<bool> g_power_suspend_pending;  // 已收到休眠通知
extern std::atomic<bool> g_power_resumed;          // 已恢复
void power_register();                              // 注册电源通知
void power_unregister();
void power_request_lock(const char* reason);        // 主动请求上锁

// fe_harden
// P0-1
// 读内存
void fe_harden_process_dacl();
// P1-2
void fe_harden_image_load_policy();
// P1-3
void fe_harden_no_crash_dump();

// fe_service
#if defined(_WIN32)
extern const char* kSvcName;                   // = "FE-Mount"
bool install_service(const std::string& vault, const std::string& drive,
                     const std::string& passfile, const char* svcname, std::string& err);
bool uninstall_service(const char* svcname, std::string& err);
#else
// Linux
// mountpoint 是挂载点目录；无
bool install_service(const std::string& vault, const std::string& mountpoint,
                     const std::string& passfile, std::string& err);
bool uninstall_service(const std::string& vault, std::string& err);
#endif

// fe_winfsp
#if FE_HAVE_WINFSP
extern std::string g_svc_vault, g_svc_pass, g_svc_mp, g_svc_lib;  // 服务命令行参数
extern bool        g_svc_rw;                     // M6 可写挂载开关
int  fe_winmount_service();                      // FspLoad + FspServiceRun
#endif
// M5 空闲超时自动锁（跨平台：ipc / main / watchdog 共用）。C++17 inline 变量，跨 TU 唯一定义，
// 避免 Linux 下 g_svc_idle 定义被 fe_winfsp.cpp 的 #if FE_HAVE_WINFSP 块吞掉导致链接失败。
inline uint32_t    g_svc_idle = 0;
