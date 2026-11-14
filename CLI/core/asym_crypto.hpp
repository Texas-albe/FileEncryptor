#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include "ptd_format.hpp"

// 非对称封装
// 底层 OpenSSL
// RECIP_ALGO_MLKEM
// 合流成 KEK
struct AsymOutcome {
    bool ok = false;
    std::string error;
};

// algo = X25519 / X448 /
// AGE-SECRET-KEY- / X448SEC- /
AsymOutcome fe_generate_keypair(uint8_t algo, std::string& pub, std::string& priv);

// 把 DEK
AsymOutcome fe_wrap_dek_to_recipients(const unsigned char* dek,
                                      const std::vector<std::string>& recipient_pubs,
                                      std::vector<RecipientStanza>& stanzas);

// 命中任一匹配 stanza 即
AsymOutcome fe_recover_dek_from_stanzas(const std::vector<RecipientStanza>& stanzas,
                                        const std::string& identity_priv,
                                        unsigned char dek[32]);

// 以下两个是纯本

// 身份私钥
AsymOutcome fe_identity_to_recipient(const std::string& identity, std::string& pub);

// Argon2id → 私钥 → 公钥，确定性
// priv 敏感，调用方负责
AsymOutcome fe_derive_keypair(const char* pw, size_t pw_len,
                              std::vector<unsigned char>& salt,
                              std::string& pub, std::string& priv);
