// 进程级令牌桶限速：由 YAML max_speed 驱动（0 = 不限速）。
// 数据块写出前消费配额，配额不足时按缺口休眠补足，避免忙等把 CPU 占满。
#pragma once
#include <cstdint>

// 设置限速上限（字节/秒）；0 = 不限速。调用后起始为满桶。
void init_rate_limiter(uint64_t max_bytes_per_sec);

// 消费 n 字节配额。超限时休眠补足（最小 1ms 粒度，避免忙等抖动）。
void fe_throttle_consume(uint64_t n);
