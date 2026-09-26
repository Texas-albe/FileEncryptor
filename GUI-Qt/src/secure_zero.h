// secure_zero - 安全擦除（GUI 公共头）
// 用 volatile 指针逐字节写零，避免 memset 被编译器优化为 dead store 而失效，导致口令明文残留堆上（审计问题 9）
#pragma once
#include <cstddef>

inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
}
