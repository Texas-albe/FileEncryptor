#pragma once
// 水印
// 记录不进 header_hmac
// 签名算法
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

inline constexpr size_t WM_RECORD_FIXED = 48;  // magic..sig_len 的固定长度
inline constexpr size_t WM_MAX_SIG = 4096;     // 签名上限

// 水印记录
#pragma pack(push, 1)
struct WmRecord {
    char     magic[4];        // "FEWM"
    uint8_t  version;
    uint8_t  flags;           
    uint64_t timestamp;       // Unix 秒
    uint8_t  machine_id[16];
    uint8_t  nonce[16];       // 随机
    uint16_t sig_len;         // 签名字节数
};
#pragma pack(pop)

struct WatermarkInfo {
    uint64_t    timestamp = 0;
    uint8_t     flags = 0;
    bool        has_signature = false;
    bool        verify_attempted = false;  // 给了公钥并实际
    bool        verify_ok = false;   // 已验签且通
    std::string machine_id_hex;      // 32 字符
    std::string nonce_hex;
    std::string error;               // 解析/验签失败原
};

// 组装水印记录并
// priv_pem_path 为空或读不到私
// pqc=true 用 ML-DSA-65 签名
bool wm_sign_and_serialize(uint64_t timestamp,
                           const unsigned char machine_id[16],
                           uint8_t flags,
                           const std::string& priv_pem_path,
                           bool pqc,
                           std::vector<unsigned char>& blob,
                           std::string& error);

// 解析尾部落Blob
// 长度不足 / magic 不符 / 版
bool wm_parse_blob(const unsigned char* data, size_t len,
                   bool pqc,
                   const std::string* pub_pem_path,
                   WatermarkInfo& out);

// 生成签名密钥
// pqc=true 生成 ML-DSA-65，否
bool wm_generate_keypair(const std::string& priv_pem_path, bool pqc,
                         std::string& pub_pem, std::string& error);

// Unix 秒 → 本
std::string wm_timestamp_text(uint64_t ts);

// 加密时是否附带
// pqc 跟随全局后量子
struct WatermarkSpec {
    bool enabled = false;
    bool pqc = true;
    std::string sign_key;
};
