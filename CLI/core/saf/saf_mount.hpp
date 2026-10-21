// 挂载点后端：FUSE / WinFSP / Dokany 挂载目录，底层仍是本地 fs
#pragma once

#include "saf.hpp"

#include <memory>
#include <string>

struct SafMountOptions {
    // 打开时校验确实是挂载点（卷/设备号与父目录不同），否则返回 SAF_E_BADARG
    bool require_mount = true;
    bool writable      = true;
};

SafStatus saf_open_mount_fs(const std::string& mount_point,
                            const SafMountOptions& opt,
                            std::shared_ptr<StorageBackend>& out);

// 挂载点判定：与父目录不在同一卷/设备即为挂载点；无父目录（盘根）恒真
bool saf_is_mount_point(const std::string& path);

// 存活复查：路径仍可访问（盘被卸载 / 目录被删后为 false）。业务层据此改报 SAF_E_GONE
// 要复查「是否仍是挂载点」用上面的 saf_is_mount_point
bool saf_mount_alive(const std::string& path);
