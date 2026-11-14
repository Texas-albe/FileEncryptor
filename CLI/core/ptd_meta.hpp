#pragma once
#include <string>
#include <vector>
#include <fstream>

#include "FileEncryptor.hpp"   // PtdMeta / SecureBuffer / 其余公共声明
#include "watermark.hpp"       // WatermarkInfo / WatermarkSpec

// 从密文末尾加密
// pre_kek
bool read_original_name(const std::string& ptd_path, std::string& out_name, const SecureBuffer& password,
    const unsigned char* pre_kek = nullptr, size_t pre_kek_len = 0,
    std::vector<unsigned char>* out_kek = nullptr,
    const std::string& asym_identity = std::string());  // 非对称容器用身

bool read_ptd_metadata(const std::string& ptd_path, PtdMeta& meta);

// 完整性校验
bool verify_ptd(const std::string& ptd_path, const SecureBuffer& password,
                const std::string& asym_identity = std::string());

// 读取尾部水印记
bool read_watermark(const std::string& ptd_path, WatermarkInfo& out, const std::string& pub_pem,
                    bool pqc = true);

// 追加水印区到文
bool fe_append_watermark_tail(std::fstream& fout, const WatermarkSpec& spec);

// 用 old_password 解开 v6
// （key_version 自增），重写容器区
bool rewrap_file(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const std::string& new_key_path,
    bool new_key_from_stdin);

bool rewrap_file_with(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const SecureBuffer& new_pw,
    bool quiet = false);
