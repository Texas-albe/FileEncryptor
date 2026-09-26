#pragma once
// 口令派生模块：Argon2id 主密钥派生（唯一入口，含参数上界与并发内存预算），
// 以及由主密钥域分离派生的子密钥（进度认证 / 文件头认证）。
#include <cstddef>
#include <sodium.h>
#include "ptd_format.hpp"   // HEADER_HMAC_SIZE

inline constexpr size_t ARGON2_OUTPUT_LEN = 32;

// Argon2id 参数：v1 旧格式写死交互档；v2+ 把参数存入文件头以便增强且兼容旧文件
inline constexpr unsigned int ARGON2_OPS_LEGACY    = 3;
inline constexpr unsigned int ARGON2_MEM_LEGACY_KB = (unsigned int)(crypto_pwhash_MEMLIMIT_INTERACTIVE/1024);
inline constexpr unsigned int ARGON2_OPS_DEFAULT   = 4;
inline constexpr unsigned int ARGON2_MEM_DEFAULT_KB = 128*1024;

// KDF 参数安全上界：头里 opslimit/memlimit 攻击者可控，而 header_hmac 在 KDF 后才能校验；
// 不加界时恶意 .ptd 可让解密方跑数百秒并吃数 GB 内存。本程序写头恒为 ops=4/mem=128MB，上界留余量。
inline constexpr unsigned int KDF_OPS_LIMIT_MAX     = 10;
inline constexpr size_t       KDF_MEM_LIMIT_MAX_BYTES = size_t(1)<<30;  // 1 GiB

// 加密强度预设：0=fast(ops3/64MB) 1=standard(ops4/128MB,默认) 2=strong(ops6/512MB)
void kdf_preset_params(int preset, unsigned int& ops, unsigned int& mem_kb);

// 主密钥派生（唯一入口）。校验攻击者可控的 KDF 参数：超界直接拒绝而非降级——
// 降级仍会白跑一次大内存 Argon2，拒绝则零资源消耗。
bool derive_key(const unsigned char* password, size_t pwd_len,
    const unsigned char* salt,
    unsigned char* key,
    unsigned int opslimit,
    size_t memlimit,
    size_t key_len=ARGON2_OUTPUT_LEN);

// 由主密钥域分离派生进度认证子密钥（.prs HMAC 与 AEAD 使用不同子密钥）
void derive_progress_auth_key(const unsigned char* master_key,
    unsigned char auth_key[crypto_auth_KEYBYTES]);

// 由主密钥域分离派生文件头认证子密钥（与进度认证、AEAD 密钥互不相同）
void derive_header_auth_key(const unsigned char* master_key,
    unsigned char auth_key[HEADER_HMAC_SIZE]);
