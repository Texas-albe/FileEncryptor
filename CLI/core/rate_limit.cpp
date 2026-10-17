#include "rate_limit.hpp"

#include <chrono>
#include <mutex>
#include <thread>

// 令牌桶状态只在本模块可见，外部一律经 init_rate_limiter / fe_throttle_consume 访问。
namespace {
std::mutex                            g_rl_mutex;
uint64_t                              g_rl_max_bps = 0;   // 0 = 不限速
int64_t                               g_rl_allowance = 0; // 当前窗口剩余可写字节
std::chrono::steady_clock::time_point g_rl_last;
}

void init_rate_limiter(uint64_t max_bytes_per_sec) {
    std::lock_guard<std::mutex> lock(g_rl_mutex);
    g_rl_max_bps = max_bytes_per_sec;
    g_rl_allowance = (int64_t)max_bytes_per_sec;   // 起始满桶
    g_rl_last = std::chrono::steady_clock::now();
}

void fe_throttle_consume(uint64_t n) {
    if (g_rl_max_bps == 0) return;   // 不限速
    std::lock_guard<std::mutex> lock(g_rl_mutex);
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - g_rl_last).count();
    if (elapsed > 0) {
        int64_t refill = (int64_t)(elapsed * (double)g_rl_max_bps);
        g_rl_allowance += refill;
        if (g_rl_allowance > (int64_t)g_rl_max_bps) g_rl_allowance = (int64_t)g_rl_max_bps;
        g_rl_last = now;
    }
    g_rl_allowance -= (int64_t)n;
    if (g_rl_allowance < 0) {
        // 透支：休眠补足（最小 1ms，避免忙等抖动）
        double deficit = (double)(-g_rl_allowance) / (double)g_rl_max_bps;
        if (deficit > 0) {
            std::this_thread::sleep_for(std::chrono::duration<double>(deficit));
            g_rl_last = std::chrono::steady_clock::now();
            g_rl_allowance = 0;
        }
    }
}
