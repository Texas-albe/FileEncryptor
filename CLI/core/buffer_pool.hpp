#pragma once
#include <vector>
#include <mutex>
#include "secure_zero.hpp"

// 固定大小缓冲区的线程安全复用池。acquire 从池取（或新建），release 归还并清零。
class BufferPool {
    std::vector<std::vector<unsigned char>> pool_;
    size_t buf_size_;
    std::mutex mutex_;

public:
    explicit BufferPool(size_t buf_size) : buf_size_(buf_size) {}

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
        secure_zero(buf.data(), buf.size());
        if (buf.size() != buf_size_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(std::move(buf));
    }

    size_t buffer_size() const { return buf_size_; }
    size_t pooled_count() const { return pool_.size(); }
};
