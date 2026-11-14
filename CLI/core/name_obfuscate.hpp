// 文件名保护
// 明文尾部
// 尾部元数据未认
#pragma once
#include <string>
#include <fstream>

#include <sodium.h>

#include "secure_buffer.hpp"

// 文件名混淆 / 尾部
inline constexpr size_t XCHACHA20_IV_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
inline constexpr char OBFUSCATED_ALPHA[] = "abcdefghijklmnopqrstuvwxyz";
inline constexpr char NAME_FOOTER_MAGIC[4]     = {'F','E','N','M'}; // 旧版明文尾部
inline constexpr char NAME_FOOTER_MAGIC_ENC[4] = {'F','E','N','X'}; // 新版加密尾部
inline constexpr size_t NAME_FOOTER_HDR = 8;                 // magic(4) + name_len(4)
inline constexpr uint32_t NAME_FOOTER_MAX_NAME = 1024;
inline constexpr size_t NAME_ENV_TAG = crypto_aead_xchacha20poly1305_ietf_ABYTES; 

// 探测尾部
// wm_len_out 返回水印记录长
bool fe_peek_name_footer_len(const std::string& ptd_path, uint64_t& footer_len,
                             uint32_t* wm_len_out = nullptr);

// 流版探测
// 成功后流位置
bool fe_peek_name_footer_len_stream(std::istream& f, uint64_t sz, uint64_t& footer_len);

// 把原始文件名加
bool fe_append_encrypted_name_footer(std::ostream& fout, const std::string& in_path,
                                     const unsigned char* master_key,
                                     const unsigned char* salt);

// 读取并解密尾部
bool fe_decrypt_name_footer(const std::string& ptd_path, std::string& out_name,
                            const unsigned char* master_key, const unsigned char* salt);

// 还原出
bool fe_sanitize_restored_name(const std::string& n);

// 用密码
std::string make_obfuscated_basename(const std::string& in_path, const SecureBuffer& password);

// 替换路径
std::string replace_basename(const std::string& p, const std::string& newbase);
