#pragma once
#include <vector>
#include <cstring>
#include <sodium.h>

// SecureBuffer：敏感数据（密码 / 密钥 / 派生中间密钥）的 RAII 安全容器。
// - 构造时尝试 sodium_mlock（锁定内存页，防换出到磁盘 / core dump）；
// - 析构时无论正常返回还是异常展开，都先 sodium_memzero 清零再 sodium_munlock；
// - 禁止拷贝，允许移动（所有权转移，原容器置空，避免双清零）。
// 这样任何退出路径（return / 异常）都不会遗留明文密钥在堆内存中。
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
