#pragma once
#include <vector>
#include <cstring>
#include <sodium.h>

// SecureBuffer：敏感数据（密码/密钥/派生中间密钥）的 RAII 容器。构造时 mlock 防换出，
// 析构时 memzero 清零并 munlock；禁拷贝允许移动。任何退出路径都不遗留明文密钥。

// mlock 失败告警钩子（由 FileEncryptor.cpp 提供定义，避免本头文件耦合日志模块）。
// 仅在首次失败时提示一次，不刷屏。
extern void fe_report_mlock_warning_once();

class SecureBuffer {
    std::vector<unsigned char> data_;
    bool locked_ = false;

    void wipe() {
        if (!data_.empty()) {
            sodium_memzero(data_.data(), data_.size());
            if (locked_) sodium_munlock(data_.data(), data_.size());
            // 强制释放底层缓冲：clear()+shrink_to_fit() 不保证归还内存，
            // 可能保留旧明文副本；用 swap 与一个空 vector 确保立即释放。
            std::vector<unsigned char>().swap(data_);
        }
        locked_ = false;
    }

public:
    SecureBuffer() = default;

    explicit SecureBuffer(size_t n) {
        if (n > 0) {
            data_.resize(n);
            if (sodium_mlock(data_.data(), n) == 0) locked_ = true;
            else fe_report_mlock_warning_once();  // 锁页失败：密钥可能换出到 swap
        }
    }

    SecureBuffer(const unsigned char* p, size_t n) : SecureBuffer(n) {
        if (p && n > 0) std::memcpy(data_.data(), p, n);
    }

    SecureBuffer(const char* p, size_t n) : SecureBuffer(n) {
        if (p && n > 0) std::memcpy(data_.data(), (const unsigned char*)p, n);
    }

    SecureBuffer(const std::vector<char>& v) : SecureBuffer(v.data(), v.size()) {}

    ~SecureBuffer() { wipe(); }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& o) noexcept
        : data_(std::move(o.data_)), locked_(o.locked_) {
        o.locked_ = false;
    }

    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) {
            wipe();
            data_ = std::move(o.data_);
            locked_ = o.locked_;
            o.locked_ = false;
        }
        return *this;
    }

    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    const char* cdata() const { return reinterpret_cast<const char*>(data_.data()); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void clear() { wipe(); }
};
