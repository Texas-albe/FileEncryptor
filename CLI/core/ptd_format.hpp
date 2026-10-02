#pragma once
// 盘面格式模块：.ptd 头部结构（v1..v6）、布局常量与 DEK 包裹原语。
// 只描述字节布局与格式级操作，不包含加解密流程；所有常量取值与既有盘面严格一致。
#include <cstddef>
#include <cstring>
#include <sodium.h>
#include "util/byte_io.hpp"

// 字节序原语统一由 util/byte_io.hpp 提供，提前转发到当前命名空间供后续函数直接调用。
using fe::util::put_le32;
using fe::util::get_le32;
using fe::util::put_be32;
using fe::util::get_be32;

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
// 磁盘实际占 69 字节：前 53 字节为已用字段，尾部 16 字节为历史保留区（v2 写入时的预留填充，读取不访问）。
// reserved 凑入结构体使 sizeof 与 HEADER_SIZE_V2 一致，避免按 sizeof 误算。
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

// v6 容器：v5 前缀之后追加固定容器扩展区。载荷由随机 DEK 加密，DEK 再用口令派生的
// KEK（Argon2id）包裹；解耦口令与密文，是密钥轮换（rewrap）零重加密的基础。
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
inline constexpr size_t HEADER_SIZE_V4 = sizeof(FileHeaderV4); // 125
inline constexpr size_t HEADER_SIZE_V5 = sizeof(FileHeaderV5); // 143
inline constexpr size_t HEADER_SIZE_V6 = sizeof(FileHeaderV6); // 256

// header_hmac 覆盖头部前缀（不含 plaintext_hash 与 header_hmac 自身）。刻意排除
// plaintext_hash 它在加密结束后才可知；排除后写头瞬间即可算出合法 HMAC。
inline constexpr size_t HEADER_HMAC_COVER    = HEADER_SIZE_V4 - HASH_SIZE - HEADER_HMAC_SIZE; // 61
inline constexpr size_t HEADER_HMAC_COVER_V5 = HEADER_SIZE_V5 - HASH_SIZE - HEADER_HMAC_SIZE; // 63
inline constexpr size_t HEADER_HMAC_COVER_V6 = HEADER_SIZE_V6 - HASH_SIZE - HEADER_HMAC_SIZE; // 192
inline constexpr size_t V6_CONTAINER_LEN = 24 + 64 + 4 + 33; // dek_nonce+dek_box+key_version+reserved

// v6 载荷 AEAD 的 AAD 只覆盖稳定前缀（magic..comp_level）：容器区会被 rewrap 改写，
// 若纳入载荷 AAD，密钥轮换后即使 DEK 不变 AEAD 也会失败。header_hmac 仍覆盖整段前缀。
inline constexpr size_t HEADER_AAD_COVER_V6 = HEADER_HMAC_COVER_V5; // 63

static_assert(HEADER_SIZE_V2 == sizeof(FileHeaderV2), "v2 struct must match on-disk 69B layout");
static_assert(HEADER_SIZE_V4 == 125 && HEADER_SIZE_V5 == 127, "v4/v5 header sizes");
static_assert(HEADER_SIZE_V6 == 256, "v6 header size must be 256");
static_assert(HEADER_HMAC_COVER == 61 && HEADER_HMAC_COVER_V5 == 63, "hmac cover sizes");

// 校验缓冲区前 4 字节是否为 FENC magic；调用方在按版本解析头部前先调此函数
bool verify_magic(const unsigned char* buf);

// 按版本返回头部大小；未知版本返回 size_t(-1) 哨兵（调用方须先校验版本合法性）
size_t header_size_for_version(unsigned char ver);

// 按版本返回 header_hmac 覆盖字节数
size_t header_hmac_cover(unsigned char ver);

// v6 DEK 包裹/解裹：明文 = 16 字节固定标记 || 32 字节 DEK，XChaCha20-Poly1305 AEAD。
// 标记用于以恒定时间校验口令正确性。box 固定 64 字节，nonce 24 字节。
bool wrap_dek(const unsigned char* dek, const unsigned char* kek,
              unsigned char nonce[24], unsigned char box[64]);
bool unwrap_dek(const unsigned char* box, const unsigned char* kek,
                const unsigned char* nonce, unsigned char dek[32]);

// ---------------------------------------------------------------------------
// 非对称收件人（OpenSSL X25519/X448）
// v6 固定头 256 字节之后、16 字节块元数据之前，可选追加一段"收件人 blob"；
// 收件人数量与总字节数记入固定头 reserved[0..3]（大端 recip_len）。recip_len=0
// 表示纯对称 v6（字节布局与旧版完全一致，保持向后兼容）。
// blob 本身不含在 header_hmac / 载荷 AAD 内：篡改只影响"哪些密钥能解裹 DEK"，
// 不危及载荷机密性（伪造 stanza 因缺少正确 DEK 包装而无用）。
// ---------------------------------------------------------------------------
inline constexpr uint8_t RECIP_ALGO_X25519 = 1;
inline constexpr uint8_t RECIP_ALGO_X448   = 2;
inline constexpr uint8_t RECIP_ALGO_MLKEM  = 3;   // X25519 + ML-KEM-768 手工混合
inline constexpr size_t   RECIP_KEY_X25519 = 32;   // 原始公钥/私钥字节数
inline constexpr size_t   RECIP_KEY_X448   = 56;
inline constexpr size_t   RECIP_WRAP_LEN   = 48;   // DEK(32) + Poly1305 tag(16)，零 nonce

// 混合收件人（algo=3）的分段长度：公钥串 = X25519(32) || ML-KEM-768(1184)。
// stanza 内 recip_pub 与用户串同构，eph_pub 则是 临时 X25519(32) || KEM 密文(1088)：
// ML-KEM 是 KEM 而非签名，封装密文必须随 stanza 一起传给解压方才能解裹。
inline constexpr size_t   RECIP_KEY_MLKEM_PUB  = 32 + 1184;   // 1216
inline constexpr size_t   RECIP_KEY_MLKEM_PRIV = 32 + 2400;   // 2432
inline constexpr size_t   RECIP_EPH_MLKEM_CT   = 32 + 1088;   // 1120

// 静态公钥字节数（stanza.recip_pub）与临时公钥区字节数（stanza.eph_pub）。
size_t recip_static_len(uint8_t algo);
size_t recip_eph_len(uint8_t algo);

// 单条收件人 stanza（内存表示）。pub_len/eph_len 由向量长度隐式给出。
struct RecipientStanza {
    uint8_t algo = RECIP_ALGO_X25519;
    std::vector<unsigned char> recip_pub;   // 收件人静态公钥（用户可见标识，对应 age1.../X448-...）
    std::vector<unsigned char> eph_pub;     // 临时公钥（ECDH 用）
    std::vector<unsigned char> wrapped_dek; // RECIP_WRAP_LEN 字节
};

// 序列化/反序列化整段收件人 blob（变长，每条含算法与长度前缀）。
bool serialize_recipients(const std::vector<RecipientStanza>& stanzas,
                          std::vector<unsigned char>& blob);
bool parse_recipients(const unsigned char* data, size_t len,
                     std::vector<RecipientStanza>& stanzas);

// 读写固定头 reserved[0..3] 中的 recip_len（大端）。
inline uint32_t get_recip_len(const unsigned char reserved[33]) {
    return get_be32(reinterpret_cast<const unsigned char*>(reserved));
}
inline void put_recip_len(unsigned char reserved[33], uint32_t n) {
    put_be32(reinterpret_cast<unsigned char*>(reserved), n);
}

// 从字节缓冲装载磁盘头结构（strict-aliasing 安全）：禁止直接 reinterpret_cast
// char[] 为 FileHeaderV*（GCC/Clang -fstrict-aliasing 下是 UB），memcpy 到本地 POD 后再读。
template<typename T>
inline T load_header(const unsigned char* buf) {
    T h;
    std::memcpy(&h, buf, sizeof(T));
    return h;
}
