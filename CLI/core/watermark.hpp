#pragma once
// 水印：加密文件尾部追加一条「机器指纹 + 时间戳 + 签名」记录，泄露后可用公钥验签追溯。
// 记录不进 header_hmac（尾部区在完整性校验里按整段长度处理），签名即防篡改手段。
// 签名算法由 pqc 开关决定：开启用 ML-DSA-65（后量子），关闭退回 RSA（PKCS#1 v1.5 / SHA-256）。
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

inline constexpr size_t WM_RECORD_FIXED = 48;  // magic..sig_len 的固定长度
inline constexpr size_t WM_MAX_SIG = 4096;     // 签名上限（ML-DSA-65 实际约 3309）

// 水印记录（含随后的签名字节）。字段一律大端，跨平台解析一致。
#pragma pack(push, 1)
struct WmRecord {
    char     magic[4];        // "FEWM"
    uint8_t  version;
    uint8_t  flags;           // bit0=MAC 命中 bit1=主板序列号命中（来自 MachineId）
    uint64_t timestamp;       // Unix 秒
    uint8_t  machine_id[16];
    uint8_t  nonce[16];       // 随机，防止同机多次加密产出同一条水印
    uint16_t sig_len;         // 签名字节数；0=未签名
};
#pragma pack(pop)

struct WatermarkInfo {
    uint64_t    timestamp = 0;
    uint8_t     flags = 0;
    bool        has_signature = false;
    bool        verify_attempted = false;  // 给了公钥并实际做了验签
    bool        verify_ok = false;   // 已验签且通过
    std::string machine_id_hex;      // 32 字符
    std::string nonce_hex;
    std::string error;               // 解析/验签失败原因（静默场景可不展示）
};

// 组装水印记录并追加签名，产出可直接落盘的尾部落Blob（记录 + 签名）。
// priv_pem_path 为空或读不到私钥时按未签名记录返回（不阻断加密）。
// pqc=true 用 ML-DSA-65 签名，否则用 RSA；私钥类型与开关不符时视为读不到私钥。
bool wm_sign_and_serialize(uint64_t timestamp,
                           const unsigned char machine_id[16],
                           uint8_t flags,
                           const std::string& priv_pem_path,
                           bool pqc,
                           std::vector<unsigned char>& blob,
                           std::string& error);

// 解析尾部落Blob；pub_pem_path 非空时按 pqc 指定的算法验签并写入 verify_ok/error。
// 长度不足 / magic 不符 / 版本号未知一律返回 false。
bool wm_parse_blob(const unsigned char* data, size_t len,
                   bool pqc,
                   const std::string* pub_pem_path,
                   WatermarkInfo& out);

// 生成签名密钥对并写入 PEM 文件；公钥以 PEM（SPKI）文本写回 pub_pem。
// pqc=true 生成 ML-DSA-65，否则生成 RSA-3072。
bool wm_generate_keypair(const std::string& priv_pem_path, bool pqc,
                         std::string& pub_pem, std::string& error);

// Unix 秒 → 本地时间文本（"YYYY-MM-DD HH:MM:SS"）
std::string wm_timestamp_text(uint64_t ts);

// 加密时是否附带水印。sign_key 为空表示只写记录、不签名（不阻断加密）。
// pqc 跟随全局后量子开关，决定签名算法（ML-DSA-65 / RSA）。
struct WatermarkSpec {
    bool enabled = false;
    bool pqc = true;
    std::string sign_key;
};
