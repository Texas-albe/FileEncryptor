// 加密盘后端：虚拟文件树 ⇄ 宿主，免挂载直接读写库内文件
#pragma once

#include "saf.hpp"

// 宿主接口：具体加密盘能力由实现提供（vdisk 动态库 / 注入的测试替身）
class VaultHost {
public:
    virtual ~VaultHost() = default;

    virtual bool writable() const = 0;

    // vpath 为空表示盘根；未找到返回 SAF_E_NOTFOUND
    virtual SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) = 0;
    virtual SafStatus getattr(const std::string& vpath, uint64_t* out_size,
                              uint64_t* out_mtime, bool* out_is_dir) = 0;

    // 读：*len 传入容量、回填实际字节数
    virtual SafStatus read(const std::string& vpath, uint64_t offset,
                           uint8_t* out, uint64_t* len) = 0;
    virtual SafStatus write(const std::string& vpath, uint64_t offset,
                            const uint8_t* in, uint64_t len) = 0;

    virtual SafStatus create_file(const std::string& vpath) = 0;
    virtual SafStatus delete_file(const std::string& vpath) = 0;
    virtual SafStatus truncate_file(const std::string& vpath, uint64_t new_size) = 0;

    // 主动锁盘（清密钥）；实现不支持时保持默认
    virtual SafStatus lock() { return SAF_E_NOTIMPL; }

    // M5 续期下沉钩子：读数据前调用，宿主可刷新空闲计时 / 记录活动。
    // vdisk 宿主内部已按 vdisk_set_idle_timeout 自行空闲锁（到点返回 VDISK_E_LOCKED
    // → 上层 SAF_E_LOCKED），故此处默认空实现；测试替身可借此计数/模拟超时。
    virtual void note_activity() {}
};

// 用宿主构造加密盘后端
std::shared_ptr<StorageBackend> saf_open_vault(std::shared_ptr<VaultHost> host);

// ---- vdisk 宿主：运行时加载 CLI 的 vdisk.dll / libvdisk.so ----
struct VaultVdiskOptions {
    std::string lib_path;        // 留空按 FE_VDISK_LIB → 库目录 → 系统名查找
    bool        writable = false;     // 需要写时置位（只置可写标志，不真挂载）
    bool        use_recovery = false; // passphrase 传的是 48 位恢复码
};

SafStatus saf_open_vault_vdisk(const std::string& library_dir,
                               const std::string& passphrase,
                               const VaultVdiskOptions& opt,
                               std::shared_ptr<StorageBackend>& out);
