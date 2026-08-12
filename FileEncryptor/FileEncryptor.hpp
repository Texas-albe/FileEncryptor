#pragma once
#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <atomic>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#endif

enum class CryptoMode: unsigned char {
    AES_GCM=0,
    XCHACHA20=1
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

// ---------- 跨平台路径打开辅助 ----------
#ifdef _WIN32
static inline std::wstring utf8_to_wstring(const std::string& str) {
    if(str.empty()) return std::wstring();
    int len=MultiByteToWideChar(CP_UTF8,0,str.c_str(),(int)str.size(),NULL,0);
    std::wstring wstr(len,0);
    MultiByteToWideChar(CP_UTF8,0,str.c_str(),(int)str.size(),&wstr[0],len);
    return wstr;
}
#endif

template<typename T>
static inline bool open_stream(T& stream,const std::string& path,std::ios::openmode mode) {
#ifdef _WIN32
    std::wstring wpath=utf8_to_wstring(path);
    stream.open(wpath,mode);
    return stream.is_open();
#else
    stream.open(path,mode);
    return stream.is_open();
#endif
}