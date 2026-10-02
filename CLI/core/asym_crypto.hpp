#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include "ptd_format.hpp"

// 非对称加密封装层：随机 DEK 以收件人公钥包装到各收件人，
// 收件人条目写入 .ptd v6 容器。底层用 OpenSSL EVP_PKEY；X25519 沿用 age 的
// Bech32 串格式（age1... / AGE-SECRET-KEY-...）以兼容既有密钥。
// 另有 RECIP_ALGO_MLKEM（X25519 + ML-KEM-768 手工混合）：两份共享密钥经
// HMAC-SHA256 合流成 KEK，抗量子且保留 X25519 的长期可用性；
// 公钥串前缀 "MLKEM1-" / "MLKEM1SEC-"+base64。
struct AsymOutcome {
    bool ok = false;
    std::string error;
};

// 生成密钥对。algo = RECIP_ALGO_X25519 / RECIP_ALGO_X448 / RECIP_ALGO_MLKEM。
// X25519：pub="age1..."，priv="AGE-SECRET-KEY-..."（敏感，调用方用后清零）。
// X448  ：pub="X448-<b64>"，priv="X448SEC-<b64>"（敏感）。
// MLKEM  ：pub="MLKEM1-<b64>"，priv="MLKEM1SEC-<b64>"（敏感）。
AsymOutcome fe_generate_keypair(uint8_t algo, std::string& pub, std::string& priv);

// 用一组收件人公钥把 DEK(32) 包装成收件人 stanza 列表（写入 blob 前先 serialize_recipients）。
AsymOutcome fe_wrap_dek_to_recipients(const unsigned char* dek,
                                      const std::vector<std::string>& recipient_pubs,
                                      std::vector<RecipientStanza>& stanzas);

// 用身份私钥从 stanza 列表恢复 DEK(32)。命中匹配的 stanza 即成功；全不匹配返回错误。
AsymOutcome fe_recover_dek_from_stanzas(const std::vector<RecipientStanza>& stanzas,
                                        const std::string& identity_priv,
                                        unsigned char dek[32]);

// 以下两个函数是纯本地计算（Bech32 + X25519 + Argon2id），不依赖 OpenSSL，始终可用。

// 由身份私钥（"AGE-SECRET-KEY-..."）反推对应的收件人公钥（"age1..."）。
AsymOutcome fe_identity_to_recipient(const std::string& identity, std::string& pub);

// 由口令确定性派生 X25519 密钥对（Argon2id → 私钥 → 公钥）。salt 为空时内部生成；
// 非空时按其值派生（同口令+同盐 ⇒ 相同密钥对）。priv 为敏感串，调用方负责清零。
AsymOutcome fe_derive_keypair(const char* pw, size_t pw_len,
                              std::vector<unsigned char>& salt,
                              std::string& pub, std::string& priv);
