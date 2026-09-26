#pragma once
#include <vector>
#include <mutex>
#include <cstring>

// BufferPool：固定大小缓冲区的线程安全复用池，减少加解密期的重复分配/释放。
// 适用于 1 MiB 读写缓冲等高频分配场景。acquire 从池取（或新建），release 归还清零。
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
        if (buf.size() != buf_size_) return;
        std::memset(buf.data(), 0, buf.size());
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(std::move(buf));
    }

    size_t buffer_size() const { return buf_size_; }
    size_t pooled_count() const { return pool_.size(); }
};
