#pragma once
#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <atomic>
#include <mutex>
#include <cstdio>
#include "secure_buffer.hpp"
#include "source_handling.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#define FE_VERSION_MAJOR 2
#define FE_VERSION_MINOR 4
#define FE_VERSION_PATCH 0
#define FE_VERSION_STRING "2.4.0"

enum class CryptoMode: unsigned char {
    AES_GCM=0,   // 仅用于解密旧格式（v1/v2）文件；新加密不再使用
    XCHACHA20=1, // 默认模式
    AEGIS256=2   // 取代 AES-GCM 的新选项（AEAD，32 字节 nonce / 32 字节 tag）
};

// ---------- 进程级限速器（v1.7.2） ----------
// 用 YAML 配置 max_speed（字节/秒，支持 KB/MB/GB 单位）初始化；0 = 不限速。
// 加/解密主循环按处理字节数记账，超出速率则休眠。必须在启动期、加载配置后调用一次。
void init_rate_limiter(uint64_t max_bytes_per_sec);

// ---------- 文件名 / 扩展名混淆（v1.7.0） ----------
// 生成 "<16 位十六进制>.<混淆扩展名>" 基名（不含 .ptd），由口令与输入路径确定性派生：
// 同一口令 + 同一输入路径得到同一名字，故续传仍能命中原输出文件。
std::string make_obfuscated_basename(const std::string& in_path,const SecureBuffer& password);

// 从密文末尾的加密信封恢复原始文件名（需口令派生密钥）；无尾部/密钥错返回 false。
// pre_kek/pre_kek_len：外部已派生 KEK（32 字节）时传入，跳过内部昂贵 Argon2 KDF（批量解密复用）。
// out_kek：非空时把本次 KEK 拷回，供调用方缓存复用。
bool read_original_name(const std::string& ptd_path,std::string& out_name,const SecureBuffer& password,
    const unsigned char* pre_kek = nullptr, size_t pre_kek_len = 0,
    std::vector<unsigned char>* out_kek = nullptr);

// 把路径的最后一段替换为 newbase（保留目录部分）
std::string replace_basename(const std::string& path,const std::string& newbase);

// 递归创建目录
bool create_directory_recursive(const std::string& path);

// 判断路径是否为已存在的目录（供单文件 -e/-d 拒绝目录输入时使用）
bool fe_path_is_directory(const std::string& path);

// 路径穿越检测：拒绝任何包含 ".." 组件（前缀或中间）的路径。
// 1.5.2 起同时供 CLI 输出目录校验、目录创建与白名单校验复用。
bool path_has_traversal(const std::string& p);

// 判断路径是否为符号链接 / 重解析点（已存在才报告，不存在返回 false）。
// 用于写入前拒绝"通过既有链接写穿到别处"（对称路径三处守卫 + v2.1.2 起 rage 路径）。
bool path_is_symlink(const std::string& path);

// 依据全局 YAML 配置校验输入输出路径（路径穿越 / 长度上限 / 白名单根目录）。
// 返回 true 表示允许；false 表示被策略拒绝（并在 !silent 时打印原因）。
// v2.1.2 起对外暴露：此前只有 encrypt_file / decrypt_file 内部调用，
// 导致 `-m rage` 分支完全绕过白名单与长度策略（高危）。
bool validate_io_paths(const std::string& in_path,const std::string& out_path,bool silent);

// UTF-8 安全的原子替换（Windows: MoveFileExW REPLACE_EXISTING；POSIX: rename）。
// 用于「先写 .prt 再落盘」，避免半截明文残留。
bool replace_file_utf8(const std::string& from,const std::string& to);

// 清除 Windows 只读属性位（覆盖写入前调用；POSIX 无此概念，空操作）。
// v2.1.1 及更早用 _chmod(_S_IREAD) "收紧权限"，实际只是把文件标成只读，
// 导致二次 -g / -G 写入时 Cannot write（误伤）。覆盖前先清掉。
void clear_readonly_attribute(const std::string& path);

// 收紧密钥文件权限：仅拥有者可读取，避免私钥/派生盐以明文落盘后被其它用户读取。
// Windows 写入真正的 DACL（只保留当前用户 + SYSTEM，PROTECTED_DACL 阻断继承），
// 达到 0600 语义；POSIX 即 chmod 0600。ACL 失败时静默回退（宁可不收紧，
// 也不把文件变成只读而弄坏后续写入）。
void tighten_file_permissions(const std::string& path);

// 加密文件（支持续传）
// compress_level: 0 = 不压缩；>0 / <0 = zstd 压缩级别（参照 zstd，1..22 常规，负数 -1..-5 为快速档）。
//   非 0 时磁盘格式升级为 v5（头部含压缩标记字节），解密端按头部标记自动解压。
//   构建时若未集成 zstd（FE_WITHOUT_ZSTD），非 0 值会被调用方拒绝。
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool resume=false,
    int compress_level=0);

// 解密文件（支持续传）
// ext_key: 可选，外部已派生的最终密钥（自校验用），非 nullptr 时直接复用、跳过 KDF 与解裹。
// ext_kek: 可选，外部已派生的 KEK（批量解密每文件复用），非 nullptr 时跳过昂贵 Argon2id，
//          仍按版本正常解裹 DEK（v6）/直接使用（v1-v5）。
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool silent=false,
    bool resume=false,
    const unsigned char* ext_key=nullptr,
    const unsigned char* ext_kek=nullptr, size_t ext_kek_len=0);

// ---------- 只读元数据 / 校验（功能2 / 功能3） ----------
// 不解密、不校验密钥，纯元数据预览（功能2 文件头信息查看器）。
struct PtdMeta {
    unsigned char version=0;
    CryptoMode    mode=CryptoMode::XCHACHA20;
    unsigned int  opslimit=0;
    uint32_t      memlimit_kb=0;
    std::string   salt_hex;          // 32 字节 salt 的十六进制
    std::string   iv_hex;            // nonce 的十六进制
    uint64_t      orig_size=0;       // 明文原始大小（头部之后的块元数据，非头部字段）
    uint32_t      chunk_size=0;      // 块大小（同上）
    uint32_t      total_chunks=0;    // 总块数（同上）
    std::string   plaintext_hash_hex; // 明文 Blake2b（v3/v4 头部字段），空=旧格式无
    bool          has_name_footer=false; // 密文尾部是否带（加密）文件名信封
    bool          valid=false;       // 文件是否为本程序合法产出（magic + 已知版本）
    unsigned char compression=0;     // 压缩方式：0=无；1=zstd（v5+）
    unsigned char comp_level=0;     // zstd 压缩级别（仅 compression==1 时有效）
    bool          dek_wrapped=false; // v6+：DEK 由 KEK 包裹（可密钥轮换）
    uint32_t      key_version=0;    // v6+：密钥版本（轮换自增，大端解析）
};
bool read_ptd_metadata(const std::string& ptd_path, PtdMeta& meta);

// 完整性校验（功能3：只验不解）：解密到临时文件比对明文 Blake2b，不落盘最终明文。
// 成功（密钥正确且内容完整）返回 true；密钥错/损坏/失败返回 false。
bool verify_ptd(const std::string& ptd_path, const SecureBuffer& password);

// SHA-256 校验单（功能10）：启用后加密成功生成 <out>.ptd.sha256。
void set_write_sha256(bool b);
bool write_sha256_enabled();
void write_sha256_sidecar(const std::string& file);

// 批量处理（支持并行）
// restore_name：批量解密时是否还原完整原始文件名。默认 false —— 为省去每文件昂贵的
//   Argon2id KDF（仅用于还原文件名），仅保留输出文件扩展名（混淆名自带扩展名）；
//   置 true 时调用 read_original_name 还原完整文件名（性能较差，经 GUI 警告后由用户选择）。
bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const SecureBuffer& password,
    CryptoMode mode,
    bool encrypt,
    int source_action=0,
    bool force_overwrite=false,
    int num_threads=0,
    bool restore_name=false,
    int compress_level=0);

// 认证失败详细输出开关（由 CLI -v/--verbose 设置）。
// 关闭时所有认证失败只输出通用错误，避免向潜在攻击者泄露细节（最小信息泄露原则）。
void set_verbose(bool v);

void anti_debug_check();

// 运行时探测 AEGIS-256 是否可用（缺 AES-NI 的 CPU 上不可用）
bool aegis256_supported();

// 判断标准输入是否为交互终端（用于决定是否就 AEGIS-256 降级询问用户）。
// GUI 经管道传参、--key-stdin、cron 等非 TTY 场景均返回 false。
bool stdin_is_interactive();

// 加密模式解析：若请求 AEGIS-256 但当前 CPU 不支持（缺 AES-NI）：
//   - 交互终端：提示用户 (Y/n) 是否降级到 XChaCha20-Poly1305；
//   - 非交互（GUI 管道 / --key-stdin / cron）：禁止自动降级，refuse=true，
//     调用方应中止并给出明确警告（CLI 退出非零；GUI 弹窗），两端行为一致。
// 返回最终使用的加密模式；refuse=true 时其值与 requested 相同（未改变）。
CryptoMode resolve_encrypt_mode(CryptoMode requested, bool interactive,
    bool& refuse, std::string& message);

// ---------- 密钥轮换 / rewrap（可扩展加密容器 v6） ----------
// 用 old_password 解开 v6 容器中的 wrapped DEK，再以 new_password 派生的新 KEK 重新
// 包裹 DEK（key_version 自增），重写头部容器区与 header_hmac；载荷密文保持不变。
// 仅对 v6 及以上容器有效；旧格式（v4/v5）返回 false 并说明需全量重加密。
// new_password 经 new_key_path（密钥文件）或非交互 stdin 提供；old_password 经既有
// 密码通道（-k / --key-stdin / ENCRYPTOR_KEY）提供。
bool rewrap_file(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const std::string& new_key_path,
    bool new_key_from_stdin);

// ---------- 跨平台路径打开辅助 ----------
#ifdef _WIN32
static inline std::wstring utf8_to_wstring(const std::string& str) {
    if(str.empty()) return std::wstring();
    int len=MultiByteToWideChar(CP_UTF8,0,str.c_str(),(int)str.size(),NULL,0);
    std::wstring wstr(len,0);
    MultiByteToWideChar(CP_UTF8,0,str.c_str(),(int)str.size(),&wstr[0],len);
    return wstr;
}
static inline std::string wstring_to_utf8(const std::wstring& wstr) {
    if(wstr.empty()) return std::string();
    int len=WideCharToMultiByte(CP_UTF8,0,wstr.c_str(),(int)wstr.size(),NULL,0,NULL,NULL);
    std::string str(len,0);
    WideCharToMultiByte(CP_UTF8,0,wstr.c_str(),(int)wstr.size(),&str[0],len,NULL,NULL);
    return str;
}
#endif

template<typename T>
static inline bool open_stream(T& stream,const std::string& path,std::ios::openmode mode) {
#ifdef _WIN32
    std::wstring wpath=utf8_to_wstring(path);
    stream.open(wpath.c_str(),mode);
    return stream.is_open();
#else
    stream.open(path,mode);
    return stream.is_open();
#endif
}

// UTF-8 安全的文件删除
static inline bool remove_file_utf8(const std::string& path) {
#ifdef _WIN32
    return _wremove(utf8_to_wstring(path).c_str())==0;
#else
    return std::remove(path.c_str())==0;
#endif
}