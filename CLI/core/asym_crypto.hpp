#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include "ptd_format.hpp"

// 非对称封装：随机 DEK 以收件人公钥包装，收件人条目写入 .ptd v6 容器。
// 底层 OpenSSL EVP_PKEY；X25519 沿用 age 的 Bech32 串格式以兼容既有密钥。
// RECIP_ALGO_MLKEM（X25519 + ML-KEM-768 手工混合）：两份共享密钥经 HMAC-SHA256
// 合流成 KEK，抗量子且保留 X25519 的长期可用性。
struct AsymOutcome {
    bool ok = false;
    std::string error;
};

// algo = X25519 / X448 / MLKEM。前缀：age1 / X448- / MLKEM1-，私钥侧对应
// AGE-SECRET-KEY- / X448SEC- / MLKEM1SEC-。priv 均敏感，调用方用后清零。
AsymOutcome fe_generate_keypair(uint8_t algo, std::string& pub, std::string& priv);

// 把 DEK(32) 包装成 stanza 列表（写入 blob 前先 serialize_recipients）
AsymOutcome fe_wrap_dek_to_recipients(const unsigned char* dek,
                                      const std::vector<std::string>& recipient_pubs,
                                      std::vector<RecipientStanza>& stanzas);

// 命中任一匹配 stanza 即成功；全不匹配返回错误
AsymOutcome fe_recover_dek_from_stanzas(const std::vector<RecipientStanza>& stanzas,
                                        const std::string& identity_priv,
                                        unsigned char dek[32]);

// 以下两个是纯本地计算（Bech32 + X25519 + Argon2id），不依赖 OpenSSL，始终可用

// 身份私钥（"AGE-SECRET-KEY-..."）反推收件人公钥（"age1..."）
AsymOutcome fe_identity_to_recipient(const std::string& identity, std::string& pub);

// Argon2id → 私钥 → 公钥，确定性派生。salt 空则内部生成，同密码+同盐 ⇒ 同密钥对。
// priv 敏感，调用方负责清零。
AsymOutcome fe_derive_keypair(const char* pw, size_t pw_len,
                              std::vector<unsigned char>& salt,
                              std::string& pub, std::string& priv);
