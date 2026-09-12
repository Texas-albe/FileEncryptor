#pragma once
#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <atomic>
#include <mutex>
#include <cstdio>
#include "secure_buffer.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#define FE_VERSION_MAJOR 2
#define FE_VERSION_MINOR 1
#define FE_VERSION_PATCH 1
#define FE_VERSION_STRING "2.1.1"

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
bool read_original_name(const std::string& ptd_path,std::string& out_name,const SecureBuffer& password);

// 把路径的最后一段替换为 newbase（保留目录部分）
std::string replace_basename(const std::string& path,const std::string& newbase);

// 递归创建目录
bool create_directory_recursive(const std::string& path);

// 路径穿越检测：拒绝任何包含 ".." 组件（前缀或中间）的路径。
// 1.5.2 起同时供 CLI 输出目录校验、目录创建与白名单校验复用。
bool path_has_traversal(const std::string& p);

// 加密文件（支持续传）
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool resume=false);

// 解密文件（支持续传）
// ext_key: 可选，外部已派生的 32 字节密钥。非 nullptr 时跳过内部 crypto_pwhash，
//          直接复用（用于加密后的自校验，避免每文件重复昂贵的 Argon2 KDF）。
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool silent=false,
    bool resume=false,
    const unsigned char* ext_key=nullptr);

// 批量处理（支持并行）
// restore_name：批量解密时是否还原完整原始文件名。默认 false —— 为省去每文件昂贵的
//   Argon2id KDF（仅用于还原文件名），仅保留输出文件扩展名（混淆名自带扩展名）；
//   置 true 时调用 read_original_name 还原完整文件名（性能较差，经 GUI 警告后由用户选择）。
bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const SecureBuffer& password,
    CryptoMode mode,
    bool encrypt,
    bool delete_source=false,
    bool force_overwrite=false,
    int num_threads=0,
    bool restore_name=false);

// 认证失败详细输出开关（由 CLI -v/--verbose 设置）。
// 关闭时所有认证失败只输出通用错误，避免向潜在攻击者泄露细节（最小信息泄露原则）。
void set_verbose(bool v);

void anti_debug_check();

// 运行时探测 AEGIS-256 是否可用（缺 AES-NI 的 CPU 上不可用）
bool aegis256_supported();

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