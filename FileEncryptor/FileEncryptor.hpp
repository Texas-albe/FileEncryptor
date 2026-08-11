#pragma once
#include <string>
#include <vector>
#include <functional>

enum class CryptoMode: unsigned char {
    AES_GCM=0,
    XCHACHA20=1
};

// 加密文件
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::string& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback=nullptr);

// 解密文件（silent = true 时抑制错误输出）
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::string& password,
    std::function<void(size_t,size_t)> progress_callback=nullptr,
    bool silent=false);

// 批量处理
bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const std::string& password,
    CryptoMode mode,
    bool encrypt,
    bool delete_source=false);

// 强制更新 Pepper（重新生成）
bool update_pepper();

// 反调试检测（程序入口调用）
void anti_debug_check();