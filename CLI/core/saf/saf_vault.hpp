// 加密盘后端
#pragma once

#include "saf.hpp"

// 宿主接口
class VaultHost {
public:
    virtual ~VaultHost() = default;

    virtual bool writable() const = 0;

    // vpath 为空表示盘根
    virtual SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) = 0;
    virtual SafStatus getattr(const std::string& vpath, uint64_t* out_size,
                              uint64_t* out_mtime, bool* out_is_dir) = 0;

    // 读：*len 传入容量、回填
    virtual SafStatus read(const std::string& vpath, uint64_t offset,
                           uint8_t* out, uint64_t* len) = 0;
    virtual SafStatus write(const std::string& vpath, uint64_t offset,
                            const uint8_t* in, uint64_t len) = 0;

    virtual SafStatus create_file(const std::string& vpath) = 0;
    virtual SafStatus delete_file(const std::string& vpath) = 0;
    virtual SafStatus truncate_file(const std::string& vpath, uint64_t new_size) = 0;

    // 主动锁盘
    virtual SafStatus lock() { return SAF_E_NOTIMPL; }

    // M5 续期下沉钩子
    // vdisk 宿主内部已
    // → 上层 SAF_E_LOCKED），故此处默认
    virtual void note_activity() {}
};

// 用宿主构造加密
std::shared_ptr<StorageBackend> saf_open_vault(std::shared_ptr<VaultHost> host);

// vdisk 宿主
struct VaultVdiskOptions {
    std::string lib_path;        // 留空
    bool        writable = false;     // 写时置位
    bool        use_recovery = false; // passphrase 传的是 48 位恢复码
};

SafStatus saf_open_vault_vdisk(const std::string& library_dir,
                               const std::string& passphrase,
                               const VaultVdiskOptions& opt,
                               std::shared_ptr<StorageBackend>& out);
