#pragma once
// 密码派生模块
#include <cstddef>
#include <sodium.h>
#include "ptd_format.hpp"   // HEADER_HMAC_SIZE

inline constexpr size_t ARGON2_OUTPUT_LEN = 32;

// Argon2id 参数
inline constexpr unsigned int ARGON2_OPS_LEGACY    = 3;
inline constexpr unsigned int ARGON2_MEM_LEGACY_KB = (unsigned int)(crypto_pwhash_MEMLIMIT_INTERACTIVE/1024);
inline constexpr unsigned int ARGON2_OPS_DEFAULT   = 4;
inline constexpr unsigned int ARGON2_MEM_DEFAULT_KB = 128*1024;

// KDF 参数安全上界
// 不加界时恶意 .ptd
inline constexpr unsigned int KDF_OPS_LIMIT_MAX     = 10;
inline constexpr size_t       KDF_MEM_LIMIT_MAX_BYTES = size_t(1)<<30;  // 1 GiB

// KDF 参数业务下限：挡住弱保护密文（opslimit=1/memlimit=8KB）
// 低于合法预设 fast(3/64MB)，存量文件不受影响
inline constexpr unsigned int KDF_OPS_LIMIT_MIN      = 2;
inline constexpr size_t       KDF_MEM_LIMIT_MIN_BYTES = 8ULL*1024*1024;  // 8 MiB

// 加密强度预设
void kdf_preset_params(int preset, unsigned int& ops, unsigned int& mem_kb);

// 主密钥派生
// 降级仍
bool derive_key(const unsigned char* password, size_t pwd_len,
    const unsigned char* salt,
    unsigned char* key,
    unsigned int opslimit,
    size_t memlimit,
    size_t key_len=ARGON2_OUTPUT_LEN);

// 进程级 KDF 并发上限
// 批量调度据此开
int kdf_max_concurrency();

// 由主密钥域分离
void derive_progress_auth_key(const unsigned char* master_key,
    unsigned char auth_key[crypto_auth_KEYBYTES]);

// 由主密钥域分离
void derive_header_auth_key(const unsigned char* master_key,
    unsigned char auth_key[HEADER_HMAC_SIZE]);

// 明文哈希密钥（keyed BLAKE2b）
// 消除无密钥明文哈希的离线探测预言机
void derive_plain_hash_key(const unsigned char* master_key,
    unsigned char hash_key[HASH_SIZE]);
