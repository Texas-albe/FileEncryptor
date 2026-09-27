#pragma once
#include <cstddef>

// 安全擦除：volatile 指针逐字节写零，避免编译器把 memset 优化为 dead store 导致敏感数据残留。
inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
}
