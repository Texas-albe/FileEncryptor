// SAF 公共接口
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// 状态码
enum SafStatus {
    SAF_OK         = 0,
    SAF_E_BADARG   = -1,    // 参数非法
    SAF_E_AUTH     = -2,    // 密码 / 恢复码错误
    SAF_E_LOCKED   = -3,    // 后端未解锁
    SAF_E_NOMEM    = -4,
    SAF_E_IO       = -5,
    SAF_E_NOTIMPL  = -7,    // 该后端不支持
    SAF_E_NOTFOUND = -8,
    SAF_E_RO       = -9,    // 后端只读
    SAF_E_EXIST    = -10,   // 独占创建撞已存
    SAF_E_GONE     = -11,   // 挂载点已消失
    SAF_E_INTERNAL = -99
};

const char* saf_strerror(SafStatus st);

// 目录项
struct SafEntry {
    std::string name;       // 项名
    bool        is_dir = false;
    bool        is_symlink = false;  // 符号链接
    uint64_t    size   = 0;
    uint64_t    mtime  = 0; // Unix 秒
    uint32_t    mode   = 0; // 权限位
};

// 字节流
class Stream {
public:
    virtual ~Stream() = default;
    virtual SafStatus read(uint8_t* out, uint64_t* len) = 0;
    virtual SafStatus write(const uint8_t* in, uint64_t len) = 0;
    virtual SafStatus seek(uint64_t) { return SAF_E_NOTIMPL; }
    virtual SafStatus tell(uint64_t* out_pos) = 0;
    virtual SafStatus flush() { return SAF_OK; }
    virtual SafStatus close() = 0;
};

// 存储后端
class StorageBackend {
public:
    virtual ~StorageBackend() = default;

    virtual const char* scheme() const = 0;
    virtual bool can_write() const = 0;
    virtual bool can_list() const = 0;

    // 元数据
    virtual SafStatus stat(const std::string& vpath,
                           uint64_t* out_size, uint64_t* out_mtime,
                           bool* out_is_dir,
                           bool* out_is_symlink = nullptr,
                           uint32_t* out_mode = nullptr) = 0;

    // mode
    virtual SafStatus open(const std::string& vpath, char mode,
                           std::shared_ptr<Stream>& out) = 0;

    virtual SafStatus readdir(const std::string& vpath,
                              std::vector<SafEntry>& out) = 0;

    // 写语义
    virtual SafStatus create_file(const std::string&) { return SAF_E_NOTIMPL; }
    virtual SafStatus mkdir(const std::string&) { return SAF_E_NOTIMPL; }
    virtual SafStatus delete_file(const std::string&) { return SAF_E_NOTIMPL; }
    virtual SafStatus truncate_file(const std::string&, uint64_t) { return SAF_E_NOTIMPL; }
    virtual SafStatus rename_file(const std::string&, const std::string&) { return SAF_E_NOTIMPL; }

    // 通用能力增强
    // 创建符号链接
    // 不支持
    virtual SafStatus symlink(const std::string& target, const std::string& vpath) {
        (void)target; (void)vpath; return SAF_E_NOTIMPL;
    }
    // 读符号链接目标
    virtual SafStatus readlink(const std::string& vpath, std::string& out_target) {
        (void)vpath; (void)out_target; return SAF_E_NOTIMPL;
    }
    // 改权限位
    virtual SafStatus chmod(const std::string& vpath, uint32_t mode) {
        (void)vpath; (void)mode; return SAF_E_NOTIMPL;
    }

    // 能力声明
    virtual bool can_symlink() const { return false; }
    virtual bool can_chmod()  const { return false; }
    virtual bool can_seek()   const { return false; }   // 流支持 seek

    // 完整性校验能力
    // 置 true 表示上层可依
    virtual bool can_integrity_check() const { return false; }
    // 安全擦除能力
    virtual bool can_secure_wipe() const { return false; }
};

// 逻辑路径规范化
bool saf_path_normalize(const std::string& in, std::string& out);

// URI 拆分
bool saf_uri_split(const std::string& uri, std::string& scheme, std::string& rest);

// 本地文件系统
std::shared_ptr<StorageBackend> saf_open_local_fs(const std::string& root);

// 打开单个本
SafStatus saf_open_native_file(const std::string& path, char mode,
                               std::shared_ptr<Stream>& out);

// 管道 / 流式传输原
struct SafPumpProgress {
    std::function<void(uint64_t)> on_bytes;   // 实际写出
    std::function<bool()>         cancelled;  // 返回 true 立即中止
    uint64_t                      chunk = 1u << 20;
};
// stdio 流
SafStatus saf_open_stdio(char mode, std::shared_ptr<Stream>& out);
// 内存流
SafStatus saf_open_memory_read(const uint8_t* data, uint64_t n, std::shared_ptr<Stream>& out);
SafStatus saf_open_memory_write(std::vector<uint8_t>& sink, std::shared_ptr<Stream>& out);
// 通用分块泵送
SafStatus saf_pump(Stream& src, Stream& dst, uint64_t src_skip,
                   const SafPumpProgress& prog, uint64_t* out_copied);

// 按 URI 选后端
// vault
SafStatus saf_open_backend(const std::string& uri, std::shared_ptr<StorageBackend>& out);
SafStatus saf_open_backend_with_password(const std::string& uri,
                                         const std::string& passphrase,
                                         std::shared_ptr<StorageBackend>& out);

// 编码工具
std::wstring saf_utf8_to_wide(const std::string& s);
std::string saf_wide_to_utf8(const std::wstring& w);
