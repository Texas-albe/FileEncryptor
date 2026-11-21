#pragma once
// .ptd 头部结构
#include <cstddef>
#include <cstring>
#include <sodium.h>
#include "util/byte_io.hpp"

// 转发 util/byte_io.hpp
using fe::util::put_le32;
using fe::util::get_le32;
using fe::util::put_be32;
using fe::util::get_be32;

// 格式级长度常量
inline constexpr size_t ARGON2_SALT_LEN  = crypto_pwhash_SALTBYTES;  
inline constexpr size_t HASH_SIZE        = crypto_generichash_BYTES; // 32
inline constexpr size_t HEADER_HMAC_SIZE = crypto_auth_BYTES;        

extern const unsigned char MAGIC[4];          // 'FENC'
inline constexpr unsigned char VERSION = 4;   // 基础头部版本字

// v1 头部
#pragma pack(push, 1)
struct FileHeaderV1 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[24];
};
#pragma pack(pop)

// v2
// HEADER_SIZE_V2 一致，读取侧不访
#pragma pack(push, 1)
struct FileHeaderV2 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[24];
    unsigned char reserved[16];
};
#pragma pack(pop)

// v3 头部
#pragma pack(push, 1)
struct FileHeaderV3 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char plaintext_hash[HASH_SIZE];
};
#pragma pack(pop)

// v4 头部
// 使整个文件头成
#pragma pack(push, 1)
struct FileHeaderV4 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char plaintext_hash[HASH_SIZE];
    unsigned char header_hmac[HEADER_HMAC_SIZE];
};
#pragma pack(pop)

// v5 头部
// 仅启用压缩时写
#pragma pack(push, 1)
struct FileHeaderV5 {
    unsigned char magic[4];
    unsigned char version;        
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char compression;    // 0=无
    unsigned char comp_level;     // zstd 级别
    unsigned char plaintext_hash[HASH_SIZE];
    unsigned char header_hmac[HEADER_HMAC_SIZE];
};
#pragma pack(pop)

// v6 容器
// KEK包裹
#pragma pack(push, 1)
struct FileHeaderV6 {
    unsigned char magic[4];
    unsigned char version;        
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char compression;
    unsigned char comp_level;
    uint32_t container_len;       // 容器扩展区字节
    unsigned char dek_nonce[24];  // DEK 包裹 nonce
    unsigned char dek_box[64];    // XChaCha20-Poly1305 密文：明文 = MARKER[16] ||
    uint32_t key_version;         // 大端
    unsigned char reserved[33];   // 预留扩展
    unsigned char plaintext_hash[HASH_SIZE];
    unsigned char header_hmac[HEADER_HMAC_SIZE];
};
#pragma pack(pop)

inline constexpr size_t HEADER_SIZE_V1 = sizeof(FileHeaderV1);
inline constexpr size_t HEADER_SIZE_V2 = 69;  // 历史盘面常量
inline constexpr size_t HEADER_SIZE_V3 = sizeof(FileHeaderV3);
inline constexpr size_t HEADER_SIZE_V4 = sizeof(FileHeaderV4); 
inline constexpr size_t HEADER_SIZE_V5 = sizeof(FileHeaderV5); 
inline constexpr size_t HEADER_SIZE_V6 = sizeof(FileHeaderV6); 

// header_hmac 覆盖前缀
inline constexpr size_t HEADER_HMAC_COVER    = HEADER_SIZE_V4 - HASH_SIZE - HEADER_HMAC_SIZE; 
inline constexpr size_t HEADER_HMAC_COVER_V5 = HEADER_SIZE_V5 - HASH_SIZE - HEADER_HMAC_SIZE; 
inline constexpr size_t HEADER_HMAC_COVER_V6 = HEADER_SIZE_V6 - HASH_SIZE - HEADER_HMAC_SIZE; 
inline constexpr size_t V6_CONTAINER_LEN = 24 + 64 + 4 + 33; // dek_nonce+dek_box+key_version+reserved

// v6 reserved[4] 明文哈希标志：0=裸 BLAKE2b（存量），1=keyed（防探测）
// reserved[4] 位于 header_hmac 覆盖区（前 192B），篡改会被校验拦下
inline constexpr size_t V6_HASH_FLAG_OFF = 4;
inline constexpr unsigned char V6_HASH_FLAG_KEYED = 1;

// 载荷 AAD 只覆盖稳定
// 即使 DEK 不变
inline constexpr size_t HEADER_AAD_COVER_V6 = HEADER_HMAC_COVER_V5; 

static_assert(HEADER_SIZE_V2 == sizeof(FileHeaderV2), "v2 struct must match on-disk 69B layout");
static_assert(HEADER_SIZE_V4 == 125 && HEADER_SIZE_V5 == 127, "v4/v5 header sizes");
static_assert(HEADER_SIZE_V6 == 256, "v6 header size must be 256");
static_assert(HEADER_HMAC_COVER == 61 && HEADER_HMAC_COVER_V5 == 63, "hmac cover sizes");

// 校验缓冲区前 4 字
bool verify_magic(const unsigned char* buf);

// 按版本返回头部
size_t header_size_for_version(unsigned char ver);

// 按版本返回 header_hmac 覆盖
size_t header_hmac_cover(unsigned char ver);

// 明文 = 16 字节固定标
bool wrap_dek(const unsigned char* dek, const unsigned char* kek,
              unsigned char nonce[24], unsigned char box[64]);
bool unwrap_dek(const unsigned char* box, const unsigned char* kek,
                const unsigned char* nonce, unsigned char dek[32]);

// 非对称收件人
// 插在 v6 固定头 256B
// recip_len）
// blob 不进 header_hmac
// DEK 包装故无害
inline constexpr uint8_t RECIP_ALGO_X25519 = 1;
inline constexpr uint8_t RECIP_ALGO_X448   = 2;
inline constexpr uint8_t RECIP_ALGO_MLKEM  = 3;   // X25519 + ML-KEM-768 手工混合
inline constexpr size_t   RECIP_KEY_X25519 = 32;   // 原始公钥/私钥字
inline constexpr size_t   RECIP_KEY_X448   = 56;
inline constexpr size_t   RECIP_WRAP_LEN   = 48;   // DEK

// 混合收件人
// eph_pub = 临时 X25519 || KEM
// 封装密文必须随
inline constexpr size_t   RECIP_KEY_MLKEM_PUB  = 32 + 1184;   
inline constexpr size_t   RECIP_KEY_MLKEM_PRIV = 32 + 2400;   
inline constexpr size_t   RECIP_EPH_MLKEM_CT   = 32 + 1088;   

// 静态公钥字节数
size_t recip_static_len(uint8_t algo);
size_t recip_eph_len(uint8_t algo);

// 单条收件人 stanza
struct RecipientStanza {
    uint8_t algo = RECIP_ALGO_X25519;
    std::vector<unsigned char> recip_pub;   // 收件人静态公钥
    std::vector<unsigned char> eph_pub;     // 临时公钥
    std::vector<unsigned char> wrapped_dek; // RECIP_WRAP_LEN 字节
};

// 序列化/反序列化
bool serialize_recipients(const std::vector<RecipientStanza>& stanzas,
                          std::vector<unsigned char>& blob);
bool parse_recipients(const unsigned char* data, size_t len,
                     std::vector<RecipientStanza>& stanzas);

// 读写固定头 reserved[0..3]
inline uint32_t get_recip_len(const unsigned char reserved[33]) {
    return get_be32(reinterpret_cast<const unsigned char*>(reserved));
}
inline void put_recip_len(unsigned char reserved[33], uint32_t n) {
    put_be32(reinterpret_cast<unsigned char*>(reserved), n);
}

// 禁止
// memcpy 到本
template<typename T>
inline T load_header(const unsigned char* buf) {
    T h;
    std::memcpy(&h, buf, sizeof(T));
    return h;
}
