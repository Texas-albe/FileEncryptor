// 安全擦除公共实现
// volatile 写零防优化
#pragma once
#include <cstddef>

inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
}
