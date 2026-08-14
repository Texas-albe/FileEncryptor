#pragma once
#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <atomic>
#include <mutex>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#endif

#define FE_VERSION_MAJOR 1
#define FE_VERSION_MINOR 3
#define FE_VERSION_PATCH 0
#define FE_VERSION_STRING "1.3.0"

enum class CryptoMode: unsigned char {
    AES_GCM=0,   // 仅用于解密旧格式（v1/v2）文件；新加密不再使用
    XCHACHA20=1, // 默认模式
    AEGIS256=2   // 取代 AES-GCM 的新选项（AEAD，32 字节 nonce / 32 字节 tag）
};

// 递归创建目录
bool create_directory_recursive(const std::string& path);

// 加密文件（支持续传）
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::vector<char>& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool resume=false);

// 解密文件（支持续传）
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::vector<char>& password,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool silent=false,
    bool resume=false);

// 批量处理（支持并行）
bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const std::vector<char>& password,
    CryptoMode mode,
    bool encrypt,
    bool delete_source=false,
    bool force_overwrite=false,
    int num_threads=0);

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