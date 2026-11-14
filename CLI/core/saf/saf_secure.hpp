// SAF 内部
// 用于承载明文/
// 分叉警告
// 差异点
// SecureBuffer
// 任一侧改动务必
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
        ::mlock(p_, n_);   // 失败
#endif
    }
    void unlock_() {
#ifdef _WIN32
        VirtualUnlock(p_, n_);
#else
        ::munlock(p_, n_);
#endif
    }
    // 用 volatile 写清零
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
