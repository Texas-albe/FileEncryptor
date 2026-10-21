// SAF 公共接口：状态码 / 目录项 / 流 / 后端 / 工厂
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// 状态码（负数为错，借鉴 vdisk.h 的编码风格）
enum SafStatus {
    SAF_OK         = 0,
    SAF_E_BADARG   = -1,    // 参数非法（含危险逻辑路径）
    SAF_E_AUTH     = -2,    // 密码 / 恢复码错误
    SAF_E_LOCKED   = -3,    // 后端未解锁
    SAF_E_NOMEM    = -4,
    SAF_E_IO       = -5,
    SAF_E_NOTIMPL  = -7,    // 该后端不支持
    SAF_E_NOTFOUND = -8,
    SAF_E_RO       = -9,    // 后端只读
    SAF_E_EXIST    = -10,   // 独占创建撞已存在
    SAF_E_GONE     = -11,   // 挂载点已消失（盘被卸载 / 换盘）
    SAF_E_INTERNAL = -99
};

const char* saf_strerror(SafStatus st);

// 目录项
struct SafEntry {
    std::string name;       // 项名，不含路径，UTF-8
    bool        is_dir = false;
    bool        is_symlink = false;  // 符号链接（不穿透，单独查询目标）
    uint64_t    size   = 0;
    uint64_t    mtime  = 0; // Unix 秒
    uint32_t    mode   = 0; // 权限位：Unix 用 st_mode 低 12 位；Windows 仅只读位有意义
};

// 字节流：读写均为分块流式，不要求一次到齐
class Stream {
public:
    virtual ~Stream() = default;
    // 读：最多 *len 字节，回填实际字节数；EOF 时 *len=0 且返回 SAF_OK
    virtual SafStatus read(uint8_t* out, uint64_t* len) = 0;
    virtual SafStatus write(const uint8_t* in, uint64_t len) = 0;
    virtual SafStatus seek(uint64_t) { return SAF_E_NOTIMPL; }
    virtual SafStatus tell(uint64_t* out_pos) = 0;
    virtual SafStatus flush() { return SAF_OK; }
    virtual SafStatus close() = 0;
};

// 存储后端：只搬字节与寻址，不触碰任何密钥材料
class StorageBackend {
public:
    virtual ~StorageBackend() = default;

    virtual const char* scheme() const = 0;
    virtual bool can_write() const = 0;
    virtual bool can_list() const = 0;

    // 元数据；vpath 为空表示后端根。out_is_symlink / out_mode 为 nullptr 时忽略
    virtual SafStatus stat(const std::string& vpath,
                           uint64_t* out_size, uint64_t* out_mtime,
                           bool* out_is_dir,
                           bool* out_is_symlink = nullptr,
                           uint32_t* out_mode = nullptr) = 0;

    // mode: 'r' 读 / 'w' 独占创建写 / 'a' 追加写
    virtual SafStatus open(const std::string& vpath, char mode,
                           std::shared_ptr<Stream>& out) = 0;

    virtual SafStatus readdir(const std::string& vpath,
                              std::vector<SafEntry>& out) = 0;

    // 写语义（只读后端保持默认 SAF_E_NOTIMPL）
    virtual SafStatus create_file(const std::string&) { return SAF_E_NOTIMPL; }
    virtual SafStatus mkdir(const std::string&) { return SAF_E_NOTIMPL; }
    virtual SafStatus delete_file(const std::string&) { return SAF_E_NOTIMPL; }
    virtual SafStatus truncate_file(const std::string&, uint64_t) { return SAF_E_NOTIMPL; }
    virtual SafStatus rename_file(const std::string&, const std::string&) { return SAF_E_NOTIMPL; }

    // ---- 通用能力增强：符号链接 / 权限位 / 随机写 ----
    // 创建符号链接：vpath（后端内路径）指向 target（同后端内的相对或绝对路径）。
    // 不支持的后端（对象存储 / 加密盘 / 归档）保持默认 SAF_E_NOTIMPL。
    virtual SafStatus symlink(const std::string& target, const std::string& vpath) {
        (void)target; (void)vpath; return SAF_E_NOTIMPL;
    }
    // 读符号链接目标；out_target 回填 target 字符串
    virtual SafStatus readlink(const std::string& vpath, std::string& out_target) {
        (void)vpath; (void)out_target; return SAF_E_NOTIMPL;
    }
    // 改权限位；只改后端能映射的位（Windows 仅只读位）。不支持者保持默认
    virtual SafStatus chmod(const std::string& vpath, uint32_t mode) {
        (void)vpath; (void)mode; return SAF_E_NOTIMPL;
    }

    // 能力声明：默认 false，支持的后端（本地 / 挂载 / 加密盘 / 归档）覆写 true
    virtual bool can_symlink() const { return false; }
    virtual bool can_chmod()  const { return false; }
    virtual bool can_seek()   const { return false; }   // 流支持 seek（随机读/写/截断）

    // 完整性校验能力：后端对读取数据做逐块校验（加密盘底层 AEAD，篡改即失败）。
    // 置 true 表示上层可依赖「读到即已校验」，无需再自查。
    virtual bool can_integrity_check() const { return false; }
    // 安全擦除能力：后端提供 secure_wipe 语义（当前仅本地后端未来支持）。
    virtual bool can_secure_wipe() const { return false; }
};

// 逻辑路径规范化：'/' 分隔、无前导分隔符、拒绝 ".." 与空段
bool saf_path_normalize(const std::string& in, std::string& out);

// URI 拆分：无 scheme 视为本地裸路径
bool saf_uri_split(const std::string& uri, std::string& scheme, std::string& rest);

// 本地文件系统后端（root 为逻辑根，UTF-8）
std::shared_ptr<StorageBackend> saf_open_local_fs(const std::string& root);

// 直接打开单个本地文件：不经逻辑根，绝对路径原样使用
SafStatus saf_open_native_file(const std::string& path, char mode,
                               std::shared_ptr<Stream>& out);

// ---- 管道 / 流式传输原语（管道是「流」而非「后端」，无路径语义）----
struct SafPumpProgress {
    std::function<void(uint64_t)> on_bytes;   // 每次实际写出的字节数
    std::function<bool()>         cancelled;  // 返回 true 立即中止
    uint64_t                      chunk = 1u << 20;
};
// stdio 流：mode 'r'=stdin 'w'/'a'=stdout；非 seek，二进制模式
SafStatus saf_open_stdio(char mode, std::shared_ptr<Stream>& out);
// 内存流：读给定缓冲（调用方保活）/ 写进 vector；可 seek
SafStatus saf_open_memory_read(const uint8_t* data, uint64_t n, std::shared_ptr<Stream>& out);
SafStatus saf_open_memory_write(std::vector<uint8_t>& sink, std::shared_ptr<Stream>& out);
// 通用分块泵送：src→dst；src_skip>0 跳过源前缀（续传）；回填实际搬运字节数
SafStatus saf_pump(Stream& src, Stream& dst, uint64_t src_skip,
                   const SafPumpProgress& prog, uint64_t* out_copied);

// 按 URI 选后端：file://、裸路径 → 本地；archive:// → 归档只读
// vault:// 需密码才能解锁，走下面的带密码重载
SafStatus saf_open_backend(const std::string& uri, std::shared_ptr<StorageBackend>& out);
SafStatus saf_open_backend_with_password(const std::string& uri,
                                         const std::string& passphrase,
                                         std::shared_ptr<StorageBackend>& out);

// 编码工具：Windows 走宽字符，POSIX 原样透传
std::wstring saf_utf8_to_wide(const std::string& s);
std::string saf_wide_to_utf8(const std::wstring& w);
