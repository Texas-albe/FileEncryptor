// 电源事件（休眠/待机/快速启动）与锁状态的一致性。
//
// 语义目标（对齐 BitLocker）：
//   1) 进入休眠/待机前主动上锁——休眠会把内存换到磁盘，若此刻盘仍解锁，
//      恢复后明文密钥就随休眠镜像落盘了。必须主动清。
//   2) 恢复后强制上锁并清活动时刻——防止「休眠前刚访问过、未到自动锁阈值」
//      的窗口带着解锁态恢复（watchdog 恢复瞬间的超时上锁是副作用，不是有意行为）。
//   3) 快速启动（Fast Startup）：休眠镜像保存的是「上次的会话」，FE-Mounter
//      进程可能被一并冻结并恢复。恢复事件里强制上锁可覆盖这一路径。
//
// 实现说明：RegisterSuspendResumeNotification 在 winnt.h 是模板重载且本机 SDK 头
// 不可见，签名易错。改用 GetProcAddress 从 PowrProf.dll 动态取，避开编译期绑定。
//
// 回调约束（电源通知线程，STILL_ACTIVE）：
//   - 必须有限时间内返回，不能做重活；
//   - 锁库调用可能阻塞，故只置「待上锁」标记，由 watchdog 线程实际执行锁定。
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <powrprof.h>
#else
#include <atomic>
#include <cstdio>
#endif

#include "fe_common.h"

// 休眠/恢复的跨模块状态（fe_winfsp 的 watchdog 消费）
std::atomic<bool> g_power_suspend_pending{false};   // 已收到休眠通知，待 watchdog 执行锁定
std::atomic<bool> g_power_resumed{false};           // 已从休眠恢复，需清活动时刻

#if defined(_WIN32)

// 回调 ABI 固定为 DeviceNotifyCallbackRoutine(PVOID Context, ULONG Type, PVOID Setting)
// ——三参数版本。RegisterSuspendResumeNotification 的回调形态只接受此签名；传单/双参数
// 版本或把裸函数指针当参数传入都会注册失败（返回 NULL + GetLastError()=87）。
using PSRNSuspendType = ULONG;
using PSRNCallback = ULONG (CALLBACK*)(PVOID, ULONG, PVOID);

// 与系统 DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS 同布局：{ Callback, Context }。
// 自行声明以避开部分工具链下不可见的 SDK 定义；ABI 必须与此完全一致。
struct PSRNSubscribe {
    PSRNCallback Callback;
    PVOID       Context;
};

#ifndef DEVICE_NOTIFY_CALLBACK
#define DEVICE_NOTIFY_CALLBACK 0x00000002
#endif

// APM 事件常量（PBT_APM* 枚举值，见 winbase.h）
static constexpr PSRNSuspendType PBT_APMQUERYSUSPEND_V      = 0x0000;
static constexpr PSRNSuspendType PBT_APMQUERYSUSPENDFAILED_V = 0x0002;
static constexpr PSRNSuspendType PBT_APMSUSPEND_V           = 0x0004;

static ULONG CALLBACK fe_pwr_callback(PVOID, ULONG type, PVOID) {
    PSRNSuspendType t = type;
    if (t == PBT_APMQUERYSUSPEND_V) {
        return 0;   // 系统在问「能否休眠」；真正锁在 PBT_APMSUSPEND
    }
    if (t == PBT_APMQUERYSUSPENDFAILED_V) {
        g_power_suspend_pending = false;   // 休眠被取消，无需锁
        return 0;
    }
    if (t == PBT_APMSUSPEND_V) {
        // 进休眠前最后窗口：置标记，watchdog 立即上锁
        // 回调内只置原子标志：fprintf 移出——stderr 重定向到无人读的管道时会阻塞，违反电源通知必须立即返回的约束；实际锁定与日志都在 watchdog 侧（低危 B 组）。
        g_power_suspend_pending = true;
        return 0;
    }
    // 恢复类事件（Normal / Critical / SuspendToIdle 等）：强制上锁
    // 回调内只置原子标志：fprintf 移出——stderr 重定向到无人读的管道时会阻塞，违反电源通知必须立即返回的约束；实际锁定与日志都在 watchdog 侧（低危 B 组）。
    g_power_resumed = true;
    g_power_suspend_pending = false;
    return 0;
}

// 直接声明原型并静态链接（延迟加载到调用时）。
// RegisterSuspendResumeNotification 是 API Set 转发函数：它在 PowrProf.dll 导出表里可见，
// 但 GetProcAddress 拿不到（转发项不作普通导出暴露），而静态链接由链接器按契约名解析，
// 是官方推荐做法。delay-load 保证老系统上不因缺 API 而加载失败。
// 注册函数指针：签名 (HANDLE, PVOID) -> HANDLE
typedef HANDLE (WINAPI* PSRNRegFn)(HANDLE, PVOID);
typedef BOOL   (WINAPI* PSRNUnregFn)(void*);

static PSRNRegFn   g_reg_fn   = nullptr;
static PSRNUnregFn g_unreg_fn = nullptr;
static void*       g_power_notify = nullptr;
static PSRNSubscribe g_sub{};   // 订阅参数须常驻，供 OS 回调引用

// 注册电源通知（回调形态）：首参 = 指向订阅参数的指针，次参 = DEVICE_NOTIFY_CALLBACK(2)。
// 这是 RegisterSuspendResumeNotification 回调模式的固定用法——首参传 NULL、次参传裸函数
// 指针都会触发 ERROR_INVALID_PARAMETER(87)。
void power_register() {
    g_reg_fn = (PSRNRegFn)&::RegisterSuspendResumeNotification;
    if (!g_reg_fn) {
        const wchar_t* mods[] = { L"api-ms-win-powerbase-l2-1-0.dll", L"PowrProf.dll" };
        for (const wchar_t* name : mods) {
            HMODULE mod = GetModuleHandleW(name);
            if (!mod) mod = LoadLibraryW(name);
            if (!mod) continue;
            void* p = (void*)GetProcAddress(mod, "RegisterSuspendResumeNotification");
            if (p) { g_reg_fn = (PSRNRegFn)p; break; }
        }
    }
    if (!g_reg_fn) {
        fprintf(stderr, "[fe] power: unavailable, suspend-lock disabled\n");
        return;
    }
    g_sub.Callback = fe_pwr_callback;
    g_sub.Context  = nullptr;
    g_power_notify = g_reg_fn((HANDLE)&g_sub, (PVOID)(UINT_PTR)DEVICE_NOTIFY_CALLBACK);
    DWORD err = g_power_notify ? 0 : GetLastError();
    for (const wchar_t* name : { L"api-ms-win-powerbase-l2-1-0.dll", L"PowrProf.dll" }) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod) mod = LoadLibraryW(name);
        if (!mod) continue;
        void* u = (void*)GetProcAddress(mod, "UnregisterSuspendResumeNotification");
        if (u) { g_unreg_fn = (PSRNUnregFn)u; break; }
    }
    fprintf(stderr, "[fe] power notifications registered (%s, err=%lu)\n",
            g_power_notify ? "ok" : "failed", (unsigned long)err);
}

void power_unregister() {
    if (g_power_notify && g_unreg_fn) g_unreg_fn(g_power_notify);
    g_power_notify = nullptr;
}

#else // ---- Linux：暂无对应机制，走 no-op（systemd 停服务，天然等价于卸载）----

void power_register() {}
void power_unregister() {}

#endif

// 供休眠路径/测试主动调用：立即请求上锁
void power_request_lock(const char* reason) {
    fprintf(stderr, "[fe] power: lock requested (%s)\n", reason);
    g_power_suspend_pending = true;
}
