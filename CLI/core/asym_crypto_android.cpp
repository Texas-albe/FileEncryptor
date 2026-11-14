// Android 非对称降级实现
// Android 侧未交叉编译 OpenSSL，公
// 接口
#include "asym_crypto.hpp"

static AsymOutcome fe_asym_unsupported(const char* what)
{
    AsymOutcome o;
    o.ok = false;
    o.error = std::string("Android 端不支持") + what;
    return o;
}

AsymOutcome fe_generate_keypair(uint8_t /*algo*/, std::string& /*pub*/, std::string& /*priv*/)
{
    return fe_asym_unsupported("生成密钥对");
}

AsymOutcome fe_wrap_dek_to_recipients(const unsigned char* /*dek*/,
                                      const std::vector<std::string>& /*recipient_pubs*/,
                                      std::vector<RecipientStanza>& /*stanzas*/)
{
    return fe_asym_unsupported("公钥封装");
}

AsymOutcome fe_recover_dek_from_stanzas(const std::vector<RecipientStanza>& /*stanzas*/,
                                        const std::string& /*identity_priv*/,
                                        unsigned char /*dek*/[32])
{
    return fe_asym_unsupported("私钥解封");
}

AsymOutcome fe_identity_to_recipient(const std::string& /*identity*/, std::string& /*pub*/)
{
    return fe_asym_unsupported("身份反推公钥");
}

AsymOutcome fe_derive_keypair(const char* /*pw*/, size_t /*pw_len*/,
                              std::vector<unsigned char>& /*salt*/,
                              std::string& /*pub*/, std::string& /*priv*/)
{
    return fe_asym_unsupported("派生密钥对");
}
