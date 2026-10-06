#pragma once
// 把 32 字节 DEK 用 AES-256-KWP/AES-KW 藏进小文件。包装的是密钥而非数据，
// 与载荷加密正交，故不属于 -m。
// blob：magic[4]="FEKW" ver(1) alg(1) eph_len(2) salt_len(2) flags(2) salt eph cipher
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// 未编译 OpenSSL 时包装层不可用
bool keywrap_available();

bool keywrap_read_file(const std::string& path, std::vector<unsigned char>& out);
// 独占创建；已存在则截断覆盖（调用方须先经用户确认 -y）
bool keywrap_write_file_exclusive(const std::string& path, const unsigned char* p, size_t n);

// alg 字符串 <-> 内部编号（kwp / aes-kw / pubkey）
uint8_t keywrap_alg_from_name(const std::string& s);
const char* keywrap_alg_name(uint8_t by);

// 包装 DEK。kwp/aes-kw 路线 kek 与 salt 必填（salt 写入头部供解包复现），to_pub 忽略。
// pubkey 路线 to_pub 必填，复用非对称层的 stanza，故 X25519/X448/ML-KEM 都支持，
// 不需要密码与 KDF。
bool keywrap_pack(const unsigned char* dek, size_t dek_len,
                  const unsigned char* kek, uint8_t by,
                  const std::string& to_pub,
                  const unsigned char* salt, size_t salt_len,
                  std::vector<unsigned char>& out_blob,
                  std::string& error);

// 解包 DEK。kwp/aes-kw 给 kek，pubkey 给身份私钥串。
// 失败文案不区分密码错与数据被改，避免侧信道。
bool keywrap_unpack(const unsigned char* blob, size_t blob_len,
                    const unsigned char* kek,
                    const std::string& identity,
                    std::vector<unsigned char>& out_dek,
                    uint8_t& out_alg,
                    std::string& error);