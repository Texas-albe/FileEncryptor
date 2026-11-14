#pragma once
#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <iostream>
#include <atomic>
#include <mutex>
#include <cstdio>
#include "secure_buffer.hpp"
#include "source_handling.hpp"
#include "watermark.hpp"
#include "rate_limit.hpp"
#include "fileio_util.hpp"
#include "resume.hpp"
#include "output_lock.hpp"
#include "name_obfuscate.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#define FE_VERSION_MAJOR 3
#define FE_VERSION_MINOR 1
#define FE_VERSION_PATCH 1
#define FE_VERSION_STRING "3.1.1"

// -force-decrypt
extern bool g_force_decrypt;

enum class CryptoMode: unsigned char {
    AES_GCM=0,   // AES-256-GCM
    XCHACHA20=1, // 默认模式
    AEGIS256=2,  // AEAD
    SM4=3        // 国密 SM4-GCM
};

// 进程级限速器
// 用 YAML max_speed

// 生成 "<16 位十六进制>.<
// 故续传仍能命
std::string make_obfuscated_basename(const std::string& in_path,const SecureBuffer& password);

// 声明见 ptd_meta.hpp

// 把路径
std::string replace_basename(const std::string& path,const std::string& newbase);

// 递归创建目录

// 非帧模式
// progress_out 指定输出流，默认
void print_progress(size_t processed,size_t total,
    std::chrono::steady_clock::time_point start, bool finish=false,
    std::ostream* progress_out=&std::cout);

// 管道数据通道
// 绕开 std
// 会导致字节丢失/
struct RawStreamBuf : std::streambuf {
    FILE* fp=nullptr;
    explicit RawStreamBuf(FILE* f): fp(f) {}
protected:
    int_type overflow(int_type c) override {
        if(c==traits_type::eof()) return traits_type::not_eof(c);
        return (fputc((char)c,fp)!=EOF) ? c : traits_type::eof();
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        return (std::streamsize)fwrite(s,1,(size_t)n,fp);
    }
    int sync() override { return fflush(fp)==0 ? 0 : -1; }
};

// 判断路径是否
bool fe_path_is_directory(const std::string& path);

// 路径穿越检测
// 5.2 起同时供 CLI 输出目
bool path_has_traversal(const std::string& p);

// 判断路径是否
// 用于写入前拒绝"
bool path_is_symlink(const std::string& path);

// 依据全局 YAML 配置校
// v2.1.2 起对外暴露
bool validate_io_paths(const std::string& in_path,const std::string& out_path,bool silent);

// UTF-8 安全原子替换
// 用于「失败即安全
bool replace_file_utf8(const std::string& from,const std::string& to);

// 原子输出守卫
// 进程
// 只留可辨识
// 续传
class AtomicOutput {
public:
    explicit AtomicOutput(const std::string& final_path);
    ~AtomicOutput();
    // 当前应写入
    const std::string& path() const { return committed_ ? final_ : tmp_; }
    // 自校验等全部通
    bool commit();
    AtomicOutput(const AtomicOutput&) = delete;
    AtomicOutput& operator=(const AtomicOutput&) = delete;
private:
    std::string final_;
    std::string tmp_;
    bool committed_ = false;
};

// 清除 Windows 只读属性位
// 旧版用 _chmod
void clear_readonly_attribute(const std::string& path);

// 收紧密钥文件权
// 达 0600 语义
void tighten_file_permissions(const std::string& path);

// 自动试压
inline constexpr int FE_COMPRESS_AUTO = 100;
int fe_probe_compress_level(const unsigned char* data, size_t len);

// 支持续传
// FE_COMPRESS_AUTO=自动试压；未集
// in_stream/out_stream 为 fd 等可 seek 流时走流
// 管道/stdout 等不可 seek 流退
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool resume=false,
    int compress_level=0,
    bool asym_mode=false,
    const std::vector<std::string>* asym_recipients=nullptr,
    const WatermarkSpec* wm=nullptr,    // 非空且 enabled
    const unsigned char* ext_salt=nullptr,  // 外部预生成盐
    const unsigned char* ext_kek=nullptr,   // 外部预派生 KEK
    uint32_t chunk_override=0,              // 非 0 且
    std::istream* in_stream=nullptr,        // 非空时明文来自
    std::ostream* out_stream=nullptr,       // 非空时密文直写
    // 写入名字信封
    // 库内入库/改写场
    // 重建索引只能回
    const std::string* footer_name=nullptr);

// 解密文件
// ext_kek
// asym_identity
// in_stream
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool silent=false,
    bool resume=false,
    const unsigned char* ext_key=nullptr,
    const unsigned char* ext_kek=nullptr, size_t ext_kek_len=0,
    bool verify_only=false,
    size_t preview_bytes=0,
    const std::string& asym_identity=std::string(),
    bool force_overwrite=false,
    std::ostream* out_stream=nullptr,  // 非空时明文直写
    std::istream* in_stream=nullptr);  // 非空时密文来自

// 只读元数据 / 校验
// 不解密、不校验密
struct PtdMeta {
    unsigned char version=0;
    CryptoMode    mode=CryptoMode::XCHACHA20;
    unsigned int  opslimit=0;
    uint32_t      memlimit_kb=0;
    std::string   salt_hex;          // 32 字节 salt
    std::string   iv_hex;            // nonce 的十六进制
    uint64_t      orig_size=0;       // 明文原始大小
    uint32_t      chunk_size=0;      // 块大小
    uint32_t      total_chunks=0;    // 总块数
    std::string   plaintext_hash_hex; // 明文 Blake2b
    bool          has_name_footer=false; // 密文尾部是否带
    bool          valid=false;       // 文件是否
    unsigned char compression=0;     // 压缩方式
    unsigned char comp_level=0;     // zstd 压缩级别
    bool          dek_wrapped=false; // v6+
    uint32_t      key_version=0;    // v6+
};

// 元数据 / 改密 / 水印
#include "ptd_meta.hpp"

// 随机读
// 压缩文件成功
// out_full 非空且文件
// pre_kek
// 非空
bool random_read_ptd(const std::string& ptd_path,
    const SecureBuffer& password,
    uint64_t offset, uint64_t len,
    std::vector<unsigned char>& out,
    bool* out_compressed = nullptr,
    bool silent = false,
    const unsigned char* pre_kek = nullptr,
    std::vector<unsigned char>* out_full = nullptr);

// 会话式随机读
// 之后 read 只剩 pread+解密，消
// 压缩或旧格式文
struct PtdReadSession;
bool ptd_session_open(const std::string& ptd_path,
    const SecureBuffer& password,
    const unsigned char* pre_kek,
    bool silent,
    PtdReadSession** out);
bool ptd_session_read(PtdReadSession* s,
    uint64_t offset, uint64_t len,
    std::vector<unsigned char>& out,
    bool silent = true);
void ptd_session_destroy(PtdReadSession* s);

// 派生某 .ptd
// 与 random_read_ptd
bool fe_ptd_argon2_key(const std::string& ptd_path,
    const SecureBuffer& password,
    unsigned char out[32]);

// 完整性校验

// SHA-256 校验单
void set_write_sha256(bool b);
bool write_sha256_enabled();
void write_sha256_sidecar(const std::string& file);

// 批量处理
// 为省去每文件昂
bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const SecureBuffer& password,
    CryptoMode mode,
    bool encrypt,
    int source_action=0,
    bool force_overwrite=false,
    int num_threads=0,
    bool restore_name=false,
    int compress_level=0,
    const WatermarkSpec* wm=nullptr,     // 批量加密时每
    uint64_t split_bytes=0);             // >0 时加密后切分卷


// 认证失败详细输
// 关闭时所有认证
void set_verbose(bool v);

// 最近一次 decrypt_file 失败
// 供 C ABI 细化错误码
bool fe_last_fail_auth();

void anti_debug_check();

// 运行时探测 AEGIS-256 是否
bool aegis256_supported();

// 探测 SM4-GCM 可用性
bool sm4_supported();

// 运行时探测 AES-256-GCM 是否
// 数据块大小
static constexpr size_t   CHUNK_SIZE     = 1 * 1024 * 1024;
static constexpr uint32_t MIN_CHUNK_SIZE = 4096;
static constexpr uint32_t MAX_CHUNK_SIZE = CHUNK_SIZE;

// 各加密模式
size_t tag_size_for_mode(CryptoMode m);

bool aes_gcm_supported();
// 探测密文尾部加

// 运行时探测后量
bool pqc_supported();

// 判断标准输入
// GUI 经管道传参、--key-stdin、cron
bool stdin_is_interactive();

// 加密模式解析
// 非交互
CryptoMode resolve_encrypt_mode(CryptoMode requested, bool interactive,
    bool& refuse, std::string& message);

// rewrap_file / rewrap_file_with ：声明见

// 跨平台路径打开
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

// UTF-8 安全
// （原 static inline 定义
