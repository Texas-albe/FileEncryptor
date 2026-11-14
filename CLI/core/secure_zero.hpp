#pragma once
#include <cstddef>
#include <sodium.h>

// 安全擦除
inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    sodium_memzero(p, n);
}
