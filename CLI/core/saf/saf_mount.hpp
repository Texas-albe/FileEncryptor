// 挂载点后端
#pragma once

#include "saf.hpp"

#include <memory>
#include <string>

struct SafMountOptions {
    // 打开时校验确实
    bool require_mount = true;
    bool writable      = true;
};

SafStatus saf_open_mount_fs(const std::string& mount_point,
                            const SafMountOptions& opt,
                            std::shared_ptr<StorageBackend>& out);

// 挂载点判定
bool saf_is_mount_point(const std::string& path);

// 存活复查
// 要复查「是否仍
bool saf_mount_alive(const std::string& path);
