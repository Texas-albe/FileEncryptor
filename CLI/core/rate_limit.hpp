// 进程级令牌桶限
// 数据块写出前消
#pragma once
#include <cstdint>

// 设置限速上限
void init_rate_limiter(uint64_t max_bytes_per_sec);

// 消费 n 字节配额
void fe_throttle_consume(uint64_t n);
