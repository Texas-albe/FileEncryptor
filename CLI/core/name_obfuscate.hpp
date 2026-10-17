// 文件名保护：把原始文件名加密后作为「名字信封」追加在密文尾部（FENX）。
//
// 明文尾部（旧版 FENM）仍可读取，但读取结果一律经 sanitize 净化——
// 尾部元数据未认证，还原前必须防越权路径与 Windows 保留设备名。
#pragma once
#include <string>
#include <fstream>

#include <sodium.h>

#include "secure_buffer.hpp"

// 文件名混淆 / 尾部信封 常量
inline constexpr size_t XCHACHA20_IV_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
inline constexpr char OBFUSCATED_ALPHA[] = "abcdefghijklmnopqrstuvwxyz";
inline constexpr char NAME_FOOTER_MAGIC[4]     = {'F','E','N','M'}; // 旧版明文尾部（仅兼容读取）
inline constexpr char NAME_FOOTER_MAGIC_ENC[4] = {'F','E','N','X'}; // 新版加密尾部
inline constexpr size_t NAME_FOOTER_HDR = 8;                 // magic(4) + name_len(4)
inline constexpr uint32_t NAME_FOOTER_MAX_NAME = 1024;
inline constexpr size_t NAME_ENV_TAG = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

// 探测尾部（加密名信封 / 明文名 / 水印区）的总长度，无需密钥。
// wm_len_out 返回水印记录长度（0 表示无水印）。
bool fe_peek_name_footer_len(const std::string& ptd_path, uint64_t& footer_len,
                             uint32_t* wm_len_out = nullptr);

// 把原始文件名加密后追加到 fout 末尾（写主密文之后调用）
bool fe_append_encrypted_name_footer(std::fstream& fout, const std::string& in_path,
                                     const unsigned char* master_key,
                                     const unsigned char* salt);

// 读取并解密尾部文件名（需主密钥 + salt）。失败返回 false（密钥错/被篡改/无尾部）。
bool fe_decrypt_name_footer(const std::string& ptd_path, std::string& out_name,
                            const unsigned char* master_key, const unsigned char* salt);

// 还原出的文件名是否安全可用（拒绝隐藏文件、穿越组件、控制字符、Windows 保留名）
bool fe_sanitize_restored_name(const std::string& n);

// 用密码把路径派生成混淆名（<16 位 hex>.<3 位小写字母>）
std::string make_obfuscated_basename(const std::string& in_path, const SecureBuffer& password);

// 替换路径的最后一段为 newbase
std::string replace_basename(const std::string& p, const std::string& newbase);
