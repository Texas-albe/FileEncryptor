#pragma once
#include <cstddef>
#include <sodium.h>

// 安全擦除：统一委托 libsodium（编译器屏障 + 平台最优实现），避免与 sodium_memzero 双实现不一致。
inline void secure_zero(void* p, size_t n) {
    if (!p || n == 0) return;
    sodium_memzero(p, n);
}
