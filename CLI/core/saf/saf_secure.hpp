// SAF 内部：锁定内存缓冲（mlock/VirtualLock + 显式清零），不依赖 libsodium。
// 用于承载明文/中间块中转，降低被换页到 pagefile 的风险；析构前逐字节清零。
// 分叉警告（审计低危项）：本类与 CLI/core/secure_buffer.hpp 的 SecureBuffer 是两套并行实现，
// 差异点：本类 zero() 只清零不归还内存（saf_pump/saf_vault 的锁定窗口需要「清零后继续复用」）；
// SecureBuffer::clear() 清零并强制释放底层缓冲，另具移动语义与 mlock 失败告警，语义不兼容故暂不合并。
// 任一侧改动务必同步评估另一侧，避免只改一边造成行为分叉。
#pragma once

#include <cstddef>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#endif

class SecureBuf {
public:
    explicit SecureBuf(size_t n) : n_(n ? n : 1) {
        p_ = static_cast<unsigned char*>(::operator new(n_));
        lock_();
    }
    ~SecureBuf() {
        zero();
        unlock_();
        ::operator delete(p_);
        p_ = nullptr;
    }
    SecureBuf(const SecureBuf&) = delete;
    SecureBuf& operator=(const SecureBuf&) = delete;

    unsigned char* data() { return p_; }
    size_t size() const { return n_; }
    void zero() { secure_zero_(p_, n_); }

private:
    void lock_() {
#ifdef _WIN32
        VirtualLock(p_, n_);
#else
        ::mlock(p_, n_);   // 失败（RLIMIT_MEMLOCK 小）不致命，安全性由 zero 兜底
#endif
    }
    void unlock_() {
#ifdef _WIN32
        VirtualUnlock(p_, n_);
#else
        ::munlock(p_, n_);
#endif
    }
    // 用 volatile 写清零，任何标准/平台都不会被编译器优化掉（等价 explicit_bzero 语义）
    static void secure_zero_(void* p, size_t n) {
#ifdef _WIN32
        SecureZeroMemory(p, n);
#else
        volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
        for (size_t i = 0; i < n; ++i) vp[i] = 0;
#endif
    }
    unsigned char* p_ = nullptr;
    size_t         n_ = 0;
};
