// 对象存储后端
#pragma once

#include "saf.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

// 对象存储宿主
class SafObjectStore {
public:
    virtual ~SafObjectStore() = default;

    virtual bool writable() const = 0;

    // 列出 prefix
    virtual SafStatus list(const std::string& prefix,
                           std::vector<std::pair<std::string, uint64_t>>& out) = 0;

    // 区间读
    virtual SafStatus get(const std::string& key, uint64_t offset, uint64_t len,
                          std::vector<uint8_t>& out, uint64_t* out_read) = 0;

    // 整对象写
    virtual SafStatus put(const std::string& key, const std::vector<uint8_t>& data) = 0;

    virtual SafStatus remove(const std::string& key) = 0;
};

struct SafCloudOptions {
    std::string prefix;             // 统一 key 前缀
    uint64_t    chunk = 1u << 20;   // 区间读分块大小
};

// 逻辑路径 ⇄ object key：目录
std::shared_ptr<StorageBackend> saf_open_cloud(std::shared_ptr<SafObjectStore> store,
                                               const SafCloudOptions& opt);
