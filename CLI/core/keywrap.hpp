#pragma once
// 把 32 字节 DEK 用 AES-256
// 与载荷加密正交
// blob 布局
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// 未编译 OpenSSL 时包装层
bool keywrap_available();

bool keywrap_read_file(const std::string& path, std::vector<unsigned char>& out);
// 独占创建
bool keywrap_write_file_exclusive(const std::string& path, const unsigned char* p, size_t n);

// alg 字符串 <-> 内部编号
uint8_t keywrap_alg_from_name(const std::string& s);
const char* keywrap_alg_name(uint8_t by);

// 包装 DEK
// pubkey 路线 to_pub 必填，复用非
// 不需要密码
bool keywrap_pack(const unsigned char* dek, size_t dek_len,
                  const unsigned char* kek, uint8_t by,
                  const std::string& to_pub,
                  const unsigned char* salt, size_t salt_len,
                  std::vector<unsigned char>& out_blob,
                  std::string& error);

// 解包 DEK
// 失败文案不区分
bool keywrap_unpack(const unsigned char* blob, size_t blob_len,
                    const unsigned char* kek,
                    const std::string& identity,
                    std::vector<unsigned char>& out_dek,
                    uint8_t& out_alg,
                    std::string& error);