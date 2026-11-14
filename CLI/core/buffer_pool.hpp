#pragma once
#include <vector>
#include <mutex>
#include "secure_zero.hpp"

// 固定大小缓冲区
class BufferPool {
    std::vector<std::vector<unsigned char>> pool_;
    size_t buf_size_;
    bool zero_;
    size_t max_;
    mutable std::mutex mutex_;   // pooled_count

public:
    // zero_on_release
    // 高并发下每线程
    explicit BufferPool(size_t buf_size, bool zero_on_release = true, size_t max_retained = 8)
        : buf_size_(buf_size), zero_(zero_on_release), max_(max_retained) {}

    std::vector<unsigned char> acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!pool_.empty()) {
            auto buf = std::move(pool_.back());
            pool_.pop_back();
            return buf;
        }
        return std::vector<unsigned char>(buf_size_);
    }

    void release(std::vector<unsigned char>& buf) {
        if (buf.size() != buf_size_) return;
        if (zero_) secure_zero(buf.data(), buf.size());
        std::lock_guard<std::mutex> lock(mutex_);
        if (pool_.size() >= max_) return;   // 超出保留上限直
        pool_.push_back(std::move(buf));
    }

    size_t buffer_size() const { return buf_size_; }
    // 与 acquire/release 共用
    size_t pooled_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pool_.size();
    }
};
