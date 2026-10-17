#pragma once
#include <string>
#include <vector>
#include <fstream>

#include "FileEncryptor.hpp"   // PtdMeta / SecureBuffer / 其余公共声明
#include "watermark.hpp"       // WatermarkInfo / WatermarkSpec

// 从密文末尾加密信封恢复原始文件名（实现见 ptd_meta.cpp）
// pre_kek：外部已派生 KEK 时传入跳过内部 KDF（批量复用）；out_kek 非空时拷回供缓存。
bool read_original_name(const std::string& ptd_path, std::string& out_name, const SecureBuffer& password,
    const unsigned char* pre_kek = nullptr, size_t pre_kek_len = 0,
    std::vector<unsigned char>* out_kek = nullptr,
    const std::string& asym_identity = std::string());  // 非对称容器用身份私钥恢复 DEK

bool read_ptd_metadata(const std::string& ptd_path, PtdMeta& meta);

// 完整性校验（功能3：只验不解）
bool verify_ptd(const std::string& ptd_path, const SecureBuffer& password,
                const std::string& asym_identity = std::string());

// 读取尾部水印记录（无需密码）。pub_pem 非空时按 pqc 指定的算法验签；无水印返回 false。
bool read_watermark(const std::string& ptd_path, WatermarkInfo& out, const std::string& pub_pem,
                    bool pqc = true);

// 追加水印区到文件尾（须在名字尾部之前写，尾部总长由 peek_name_footer_len 统一计算）
bool fe_append_watermark_tail(std::fstream& fout, const WatermarkSpec& spec);

// 用 old_password 解开 v6 的 wrapped DEK，再以 new_password 派生的新 KEK 重新包裹
// （key_version 自增），重写容器区与 header_hmac；载荷密文不变。旧格式返回 false。
bool rewrap_file(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const std::string& new_key_path,
    bool new_key_from_stdin);

// 同上，但新密码已在内存中（库改密用；避免把新密码落临时文件）
bool rewrap_file_with(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const SecureBuffer& new_pw,
    bool quiet = false);
