// 对象存储后端：云盘 / S3 / OSS / WebDAV 等统一薄适配层
#pragma once

#include "saf.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

// 对象存储宿主：接一家新云只需实现下面五个方法
class SafObjectStore {
public:
    virtual ~SafObjectStore() = default;

    virtual bool writable() const = 0;

    // 列出 prefix 下的对象；prefix 为空表示全部。返回 <key, size>
    virtual SafStatus list(const std::string& prefix,
                           std::vector<std::pair<std::string, uint64_t>>& out) = 0;

    // 区间读：offset 起最多 len 字节；len=0 表示读到尾
    virtual SafStatus get(const std::string& key, uint64_t offset, uint64_t len,
                          std::vector<uint8_t>& out, uint64_t* out_read) = 0;

    // 整对象写：覆盖式（并发语义由实现决定）
    virtual SafStatus put(const std::string& key, const std::vector<uint8_t>& data) = 0;

    virtual SafStatus remove(const std::string& key) = 0;
};

struct SafCloudOptions {
    std::string prefix;             // 统一 key 前缀，非空时自动补 '/'
    uint64_t    chunk = 1u << 20;   // 区间读分块大小
};

// 逻辑路径 ⇄ object key：目录按前缀模拟，不存在空目录对象
std::shared_ptr<StorageBackend> saf_open_cloud(std::shared_ptr<SafObjectStore> store,
                                               const SafCloudOptions& opt);
