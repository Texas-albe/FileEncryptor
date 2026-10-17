// 续传进度（.prs）：断点续传的进度记账与校验。
//
// .prs 记录已完成的块数与字节数，并用 HMAC 绑定源文件（规范化路径 + 大小 + mtime +
// 内容摘要），使旧进度无法被重放到另一个文件——防续传劫持，也防重放攻击。
#pragma once
#include <string>
#include <cstdint>

#include <sodium.h>

static const uint32_t PROGRESS_MAGIC   = 0x504F5247;   // "PROG"
static const uint32_t PROGRESS_VERSION = 2;

// 断点进度结构（v2：带 HMAC 认证，防续传劫持）
// HMAC（crypto_auth = HMAC-SHA512/256，32 字节）覆盖前 24 字节（magic+version+chunks+bytes）
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

// 已存在的输出是否「完整且有效」，可安全跳过。
// in_size_hint：调用方已 stat 过的源尺寸（批量预扫描的 size_cache），传入可省一次 stat。
// header_ok：顺带报告「输出头部是否有效」，使预扫描不必再单独开一次文件。
bool fe_is_complete_output(const std::string& out_path, bool encrypt, const std::string& in_path,
                           int64_t in_size_hint = -1, bool* header_ok = nullptr);

// 是否为有效密文（magic + 版本号 + 头长）
bool fe_is_file_valid(const std::string& path);

// 读取 .prs 并校验结构（magic / version）；HMAC 需密钥，由调用方派生后另行验证。
bool fe_load_progress(const std::string& out_path, ProgressInfo& info);

// 校验 .prs 的 HMAC：覆盖前 24 字节（magic+version+chunks+bytes）外加源文件绑定标识。
bool fe_verify_progress_hmac(const ProgressInfo& info, const unsigned char* auth_key,
                             const std::string& binding);

// 计算并写入带 HMAC 的进度：先写 <out>.prs.tmp 再原子替换，保证每块后都能覆盖更新。
bool fe_save_progress(const std::string& out_path, uint64_t processed_chunks,
                      uint64_t processed_bytes, const unsigned char* auth_key,
                      const std::string& binding);

// 删除 .prs（任务正常完成后清理）
void fe_remove_progress(const std::string& out_path);

// 源文件绑定标识（防重放）：规范化路径 + 大小 + mtime + 内容摘要
std::string fe_compute_progress_binding(const std::string& in_path);
