// secure_zero - 安全擦除（GUI 公共头）
// std::memset 紧跟释放/clear 会被编译器判定为 dead store 而优化掉，口令明文因此
// 长期残留在堆上（审计问题 9）。用 volatile 指针逐字节写零可确保真正落到内存。
#pragma once
#include <cstddef>

inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
}
