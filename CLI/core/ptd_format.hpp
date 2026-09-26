#pragma once
// 盘面格式模块：.ptd 头部结构（v1..v6）、布局常量与 DEK 包裹原语。
// 只描述字节布局与格式级操作，不包含加解密流程；所有常量取值与既有盘面严格一致。
#include <cstddef>
#include <cstring>
#include <sodium.h>

// 格式级长度常量（libsodium 定值）
inline constexpr size_t ARGON2_SALT_LEN  = crypto_pwhash_SALTBYTES;  // 16
inline constexpr size_t HASH_SIZE        = crypto_generichash_BYTES; // 32（明文 Blake2b）
inline constexpr size_t HEADER_HMAC_SIZE = crypto_auth_BYTES;        // 32

extern const unsigned char MAGIC[4];          // 'FENC'
inline constexpr unsigned char VERSION = 4;   // 基础头部版本字段值（v4 布局）

// v1 头部（47 字节），仅解密时按版本解析
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

// v2 头部：Argon2 参数写入文件头，iv 缓冲扩到 24 字节
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
};
#pragma pack(pop)

// v3 头部：iv 扩到 32 字节（容纳 AEGIS-256 nonce），新增 plaintext_hash
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

// v4 头部：v3 前缀 + 末尾 32 字节 header_hmac（由独立于 AEAD 的元数据认证密钥计算），
// 使整个文件头成为可认证信封，防文件头篡改。
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

// v5 头部：v4 + iv 之后 2 字节压缩描述（compression / comp_level）。
// 仅启用压缩时写出；每数据块额外带 4 字节小端"压缩帧长度"前缀（变长块）。
#pragma pack(push, 1)
struct FileHeaderV5 {
    unsigned char magic[4];
    unsigned char version;        // 5
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char compression;    // 0=无；1=zstd
    unsigned char comp_level;     // zstd 级别（1..22 常规；负数 -1..-5 快速档）
    unsigned char plaintext_hash[HASH_SIZE];
    unsigned char header_hmac[HEADER_HMAC_SIZE];
};
#pragma pack(pop)

// v6 容器：v5 前缀（magic..comp_level，字节布局完全一致）之后追加固定大小的容器扩展区。
// 载荷由随机"数据加密密钥（DEK）"加密，DEK 再用口令派生的"密钥加密密钥（KEK，
// Argon2id(password,salt)）"包裹写入。该结构解耦口令与密文，是密钥轮换（rewrap）
// 零重加密的基础；plaintext_hash 与 header_hmac 置于结构末尾，使 HMAC 覆盖整段容器区。
#pragma pack(push, 1)
struct FileHeaderV6 {
    unsigned char magic[4];
    unsigned char version;        // 6
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char compression;
    unsigned char comp_level;
    uint32_t container_len;       // 容器扩展区字节数（大端；v6.0 固定 V6_CONTAINER_LEN）
    unsigned char dek_nonce[24];  // DEK 包裹 nonce
    unsigned char dek_box[64];    // XChaCha20-Poly1305 密文：明文 = MARKER[16] || DEK[32]
    uint32_t key_version;         // 大端；轮换自增
    unsigned char reserved[33];   // 预留扩展（多接收方 / 分块头等）；凑整 256 字节
    unsigned char plaintext_hash[HASH_SIZE];
    unsigned char header_hmac[HEADER_HMAC_SIZE];
};
#pragma pack(pop)

inline constexpr size_t HEADER_SIZE_V1 = sizeof(FileHeaderV1);
inline constexpr size_t HEADER_SIZE_V2 = 69;  // 历史盘面常量（v2 兼容读取，勿按 sizeof 改写）
inline constexpr size_t HEADER_SIZE_V3 = sizeof(FileHeaderV3);
inline constexpr size_t HEADER_SIZE_V4 = sizeof(FileHeaderV4); // 141
inline constexpr size_t HEADER_SIZE_V5 = sizeof(FileHeaderV5); // 143
inline constexpr size_t HEADER_SIZE_V6 = sizeof(FileHeaderV6); // 256

// header_hmac 覆盖区域：头部前缀（不含 plaintext_hash 与 header_hmac 自身）。
// 刻意排除 plaintext_hash——它在加密结束、明文哈希算出后才可知；排除后写头瞬间即可算出
// 合法 HMAC，被中断的半成品 .ptd 也能通过续传时的"文件头篡改校验"。
inline constexpr size_t HEADER_HMAC_COVER    = HEADER_SIZE_V4 - HASH_SIZE - HEADER_HMAC_SIZE; // 61
inline constexpr size_t HEADER_HMAC_COVER_V5 = HEADER_SIZE_V5 - HASH_SIZE - HEADER_HMAC_SIZE; // 63
inline constexpr size_t HEADER_HMAC_COVER_V6 = HEADER_SIZE_V6 - HASH_SIZE - HEADER_HMAC_SIZE; // 192
inline constexpr size_t V6_CONTAINER_LEN = 24 + 64 + 4 + 33; // dek_nonce+dek_box+key_version+reserved

// v6 载荷 AEAD 的 AAD 只覆盖稳定前缀（magic..comp_level，即 v5 的 HMAC 覆盖区）：
// 容器区（dek_nonce/dek_box/key_version）会被 rewrap 改写，若纳入载荷 AAD，
// 密钥轮换后即使 DEK 不变，载荷 AEAD 校验也会失败（零重加密即失效）。
// header_hmac 仍覆盖整段前缀（含容器区），rewrap 时随容器一并重算。
inline constexpr size_t HEADER_AAD_COVER_V6 = HEADER_HMAC_COVER_V5; // 63

static_assert(HEADER_SIZE_V4 == 125 && HEADER_SIZE_V5 == 127, "v4/v5 header sizes");
static_assert(HEADER_SIZE_V6 == 256, "v6 header size must be 256");
static_assert(HEADER_HMAC_COVER == 61 && HEADER_HMAC_COVER_V5 == 63, "hmac cover sizes");

// 按版本返回头部大小；未知版本按 v4 处理（调用方须先校验版本合法性）
size_t header_size_for_version(unsigned char ver);

// 按版本返回 header_hmac 覆盖字节数
size_t header_hmac_cover(unsigned char ver);

// v6 DEK 包裹/解裹：明文 = 16 字节固定标记 || 32 字节 DEK，XChaCha20-Poly1305 AEAD。
// 标记用于以恒定时间校验口令正确性。box 固定 64 字节，nonce 24 字节。
bool wrap_dek(const unsigned char* dek, const unsigned char* kek,
              unsigned char nonce[24], unsigned char box[64]);
bool unwrap_dek(const unsigned char* box, const unsigned char* kek,
                const unsigned char* nonce, unsigned char dek[32]);

// 32 位整数的小端 / 大端字节序原语（压缩块长度前缀用小端，容器字段用大端）
inline void put_le32(unsigned char* p, uint32_t v) {
    p[0]=(unsigned char)(v&0xFF);
    p[1]=(unsigned char)((v>>8)&0xFF);
    p[2]=(unsigned char)((v>>16)&0xFF);
    p[3]=(unsigned char)((v>>24)&0xFF);
}
inline uint32_t get_le32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
inline void put_be32(unsigned char* p, uint32_t v) {
    p[0]=(unsigned char)((v>>24)&0xFF);
    p[1]=(unsigned char)((v>>16)&0xFF);
    p[2]=(unsigned char)((v>>8)&0xFF);
    p[3]=(unsigned char)(v&0xFF);
}
inline uint32_t get_be32(const unsigned char* p) {
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | (uint32_t)p[3];
}

// 从字节缓冲装载磁盘头结构（strict-aliasing 安全）。
// 禁止把 char[] 缓冲直接 reinterpret_cast 成 FileHeaderV* 读取——GCC/Clang
// -fstrict-aliasing 下这是未定义行为（MSVC /GL 不 exploiting 此 UB 才未出错，
// 属审计记录的 GCC/Clang 移植加固项）。memcpy 到本地 POD 结构后再读字段，
// 布局与值完全一致。调用方须保证 buf 至少含 sizeof(T) 字节且已读入完整头部。
template<typename T>
inline T load_header(const unsigned char* buf) {
    T h;
    std::memcpy(&h, buf, sizeof(T));
    return h;
}
