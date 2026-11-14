// 续传进度
// .prs 记录已完成
// 内容摘要）
#pragma once
#include <string>
#include <cstdint>

#include <sodium.h>

static const uint32_t PROGRESS_MAGIC   = 0x504F5247;   // "PROG"
static const uint32_t PROGRESS_VERSION = 2;

// 断点进度结构
// HMAC
#pragma pack(push, 1)
struct ProgressInfo {
    uint32_t      magic;
    uint32_t      version;
    uint64_t      processed_chunks;
    uint64_t      processed_bytes;
    unsigned char hmac[crypto_auth_BYTES];
};
#pragma pack(pop)
static constexpr size_t PROGRESS_SIZE = sizeof(ProgressInfo);

// 已存
// in_size_hint
// header_ok
bool fe_is_complete_output(const std::string& out_path, bool encrypt, const std::string& in_path,
                           int64_t in_size_hint = -1, bool* header_ok = nullptr);

// 是否
bool fe_is_file_valid(const std::string& path);

// 读取 .prs 并校验结构
bool fe_load_progress(const std::string& out_path, ProgressInfo& info);

// 校验 .prs
bool fe_verify_progress_hmac(const ProgressInfo& info, const unsigned char* auth_key,
                             const std::string& binding);

// 计算并写入带 HMAC
bool fe_save_progress(const std::string& out_path, uint64_t processed_chunks,
                      uint64_t processed_bytes, const unsigned char* auth_key,
                      const std::string& binding);

// 删除 .prs
void fe_remove_progress(const std::string& out_path);

// 源文件绑定标识
std::string fe_compute_progress_binding(const std::string& in_path);
