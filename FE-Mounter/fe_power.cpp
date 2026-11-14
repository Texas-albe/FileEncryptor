// 电源事件
// 语义目标
// 进入休眠/待机
// 恢复后明文密钥
// 恢复后强制上锁
// 的窗口带着解锁
// 快速启动
// 进程可能
// 实现说明
// 不可见，签名易错
// 回调约束
// 必须有限时间内
// 锁库调用可能阻
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <powrprof.h>
#else
#include <atomic>
#include <cstdio>
#endif

#include "fe_common.h"

// 休眠/恢复
std::atomic<bool> g_power_suspend_pending{false};   // 已收到休眠通知
std::atomic<bool> g_power_resumed{false};           // 已从休眠恢复

#if defined(_WIN32)

// 回调 ABI 固定
// 三参数版本
// 版本
using PSRNSuspendType = ULONG;
using PSRNCallback = ULONG (CALLBACK*)(PVOID, ULONG, PVOID);

// 与系统
// 自行声明
struct PSRNSubscribe {
    PSRNCallback Callback;
    PVOID       Context;
};

#ifndef DEVICE_NOTIFY_CALLBACK
#define DEVICE_NOTIFY_CALLBACK 0x00000002
#endif

// APM 事件常量
static constexpr PSRNSuspendType PBT_APMQUERYSUSPEND_V      = 0x0000;
static constexpr PSRNSuspendType PBT_APMQUERYSUSPENDFAILED_V = 0x0002;
static constexpr PSRNSuspendType PBT_APMSUSPEND_V           = 0x0004;

static ULONG CALLBACK fe_pwr_callback(PVOID, ULONG type, PVOID) {
    PSRNSuspendType t = type;
    if (t == PBT_APMQUERYSUSPEND_V) {
        return 0;   // 系统
    }
    if (t == PBT_APMQUERYSUSPENDFAILED_V) {
        g_power_suspend_pending = false;   // 休眠
        return 0;
    }
    if (t == PBT_APMSUSPEND_V) {
        // 进休眠
        // 回调内只置原子
        g_power_suspend_pending = true;
        return 0;
    }
    // 恢复类事件
    // 回调内只置原子
    g_power_resumed = true;
    g_power_suspend_pending = false;
    return 0;
}

// 声明原型并静态
// RegisterSuspendResumeNot
// 但 GetProcAddress 拿不到
// 是官方推荐做法
// 注册函数指针
typedef HANDLE (WINAPI* PSRNRegFn)(HANDLE, PVOID);
typedef BOOL   (WINAPI* PSRNUnregFn)(void*);

static PSRNRegFn   g_reg_fn   = nullptr;
static PSRNUnregFn g_unreg_fn = nullptr;
static void*       g_power_notify = nullptr;
static PSRNSubscribe g_sub{};   // 订阅参数须常驻

// 注册电源通知
// 指针
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

#else // Linux

void power_register() {}
void power_unregister() {}

#endif

// 供休眠路径/测试
void power_request_lock(const char* reason) {
    fprintf(stderr, "[fe] power: lock requested (%s)\n", reason);
    g_power_suspend_pending = true;
}
