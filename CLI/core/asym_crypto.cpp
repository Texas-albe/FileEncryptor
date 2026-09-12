// asym_crypto 实现：转发到 rage/age 的 C-ABI 封装 (fe_age)。
// 仅在 FE_WITH_AGE 时链接真实实现；否则提供安全降级。
#include "asym_crypto.hpp"

#include <sodium.h>

#include <cstring>
#include <string>

#ifdef FE_WITH_AGE
#include "fe_age.h"

static AsymOutcome run_ffi(int rc, char* err) {
    AsymOutcome o;
    o.ok = (rc == 0);
    if (!o.ok) {
        if (err) {
            o.error = err;
            fe_age_free_string(err);
        } else {
            o.error = "fe_age call failed";
        }
    }
    return o;
}

AsymOutcome fe_generate_keypair(std::string& pub, std::string& priv) {
    char* cpub = nullptr;
    char* cpriv = nullptr;
    int rc = fe_age_generate_keypair(&cpub, &cpriv);
    AsymOutcome o;
    o.ok = (rc == 0);
    if (o.ok) {
        if (cpub) { pub = cpub; fe_age_free_string(cpub); }
        if (cpriv) { priv = cpriv; fe_age_free_string(cpriv); }
    } else {
        o.error = "fe_age_generate_keypair failed";
    }
    return o;
}

AsymOutcome fe_asym_encrypt(const std::vector<std::string>& recipients,
                            const std::string& in_path,
                            const std::string& out_path) {
    std::vector<const char*> c_recip;
    c_recip.reserve(recipients.size() + 1);
    for (const auto& r : recipients) c_recip.push_back(r.c_str());
    c_recip.push_back(nullptr);
    char* err = nullptr;
    int rc = fe_age_encrypt_file(c_recip.data(), recipients.size(),
                                 in_path.c_str(), out_path.c_str(), &err);
    return run_ffi(rc, err);
}

AsymOutcome fe_asym_decrypt(const std::string& identity,
                            const std::string& in_path,
                            const std::string& out_path) {
    const char* c_idents[2] = { identity.c_str(), nullptr };
    char* err = nullptr;
    int rc = fe_age_decrypt_file(c_idents, 1, in_path.c_str(), out_path.c_str(), &err);
    return run_ffi(rc, err);
}

#else // !FE_WITH_AGE

static const char* kNoAge = "asymmetric (age) support was not compiled into this build (FE_WITH_AGE)";
AsymOutcome fe_generate_keypair(std::string&, std::string&) {
    return {false, kNoAge};
}
AsymOutcome fe_asym_encrypt(const std::vector<std::string>&,
                            const std::string&, const std::string&) {
    return {false, kNoAge};
}
AsymOutcome fe_asym_decrypt(const std::string&, const std::string&, const std::string&) {
    return {false, kNoAge};
}

#endif

// ===========================================================================
// 以下为纯本地实现（不依赖 fe_age）：Bech32 编解码 + X25519 + Argon2id。
// ---------------------------------------------------------------------------
// Bech32（BIP-173，const = 1），与 rage/age 使用的编码一致：
//   收件人公钥 : hrp = "age"              -> "age1<小写数据+6位校验>"
//   身份私钥   : hrp = "AGE-SECRET-KEY-"  -> 编码后整体转成大写
// ---------------------------------------------------------------------------
namespace {

const char kBech32Charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t bech32_polymod(const std::vector<unsigned char>& values) {
    static const uint32_t kGen[5] = {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u
    };
    uint32_t chk = 1;
    for(unsigned char v: values) {
        const uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffffu) << 5) ^ ((uint32_t)v & 31u);
        for(int i=0; i<5; ++i) {
            if((top >> i) & 1u) chk ^= kGen[i];
        }
    }
    return chk;
}

std::vector<unsigned char> bech32_hrp_expand(const std::string& hrp) {
    std::vector<unsigned char> out;
    out.reserve(hrp.size()*2+1);
    for(char c: hrp) out.push_back((unsigned char)(((unsigned char)c) >> 5));
    out.push_back(0);
    for(char c: hrp) out.push_back((unsigned char)(((unsigned char)c) & 31u));
    return out;
}

// from/to 位宽转换。pad=true 时补齐残余位；pad=false 时残余位必须为零。
bool bech32_convert_bits(std::vector<unsigned char>& out,
                         const unsigned char* data, size_t len,
                         int from, int to, bool pad) {
    if(from < 1 || from > 8 || to < 1 || to > 8) return false;
    const uint32_t maxv = (1u << to) - 1u;
    uint32_t acc = 0;
    int bits = 0;
    out.clear();
    for(size_t i=0; i<len; ++i) {
        acc = (acc << from) | data[i];
        bits += from;
        while(bits >= to) {
            bits -= to;
            out.push_back((unsigned char)((acc >> bits) & maxv));
        }
    }
    if(pad) {
        if(bits) out.push_back((unsigned char)((acc << (to - bits)) & maxv));
    } else if(bits >= from || ((acc << (to - bits)) & maxv)) {
        return false;   // 非填充模式不允许非零残余位
    }
    return true;
}

// 校验和必须按**小写** HRP 展开计算（Bech32 规范：HRP 大小写不敏感，参与运算时取小写）。
// rage/age 的私钥串是 bech32_encode(HRP="AGE-SECRET-KEY-") 之后整体 to_uppercase()，
// 其校验和正是按小写 HRP 算的；若按大写 HRP 展开，age 会拒绝该串。
std::string bech32_lower(const std::string& s) {
    std::string r = s;
    for(char& c: r) {
        if(c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    }
    return r;
}

bool bech32_encode(std::string& out, const std::string& hrp,
                   const unsigned char* data, size_t len) {
    std::vector<unsigned char> d5;
    if(!bech32_convert_bits(d5,data,len,8,5,true)) return false;
    std::vector<unsigned char> chk = bech32_hrp_expand(bech32_lower(hrp));
    chk.insert(chk.end(),d5.begin(),d5.end());
    chk.insert(chk.end(),6,0);
    const uint32_t plm = bech32_polymod(chk) ^ 1u;
    std::string s = hrp;
    s += '1';
    for(unsigned char b: d5) s += kBech32Charset[b & 31u];
    for(int i=0; i<6; ++i) s += kBech32Charset[(plm >> (5*(5-i))) & 31u];
    out.swap(s);
    return true;
}

bool bech32_decode(const std::string& str, std::string& hrp,
                   std::vector<unsigned char>& data) {
    if(str.size() < 8 || str.size() > 90) return false;   // BIP-173 长度约束
    bool has_lower = false, has_upper = false;
    for(char c: str) {
        const unsigned char u = (unsigned char)c;
        if(u >= 'a' && u <= 'z') has_lower = true;
        else if(u >= 'A' && u <= 'Z') has_upper = true;
        else if(u < 33 || u > 126) return false;
    }
    if(has_lower && has_upper) return false;              // 禁止大小写混用
    std::string s = str;
    for(char& c: s) {
        if(c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    }
    const size_t pos = s.rfind('1');
    if(pos == std::string::npos || pos == 0 || pos + 7 > s.size()) return false;
    hrp = s.substr(0,pos);
    std::vector<unsigned char> d5;
    for(size_t i = pos + 1; i < s.size(); ++i) {
        const char* p = std::strchr(kBech32Charset, s[i]);
        if(!p) return false;
        d5.push_back((unsigned char)(p - kBech32Charset));
    }
    std::vector<unsigned char> chk = bech32_hrp_expand(hrp);
    chk.insert(chk.end(),d5.begin(),d5.end());
    if(bech32_polymod(chk) != 1u) return false;           // 校验和不匹配
    if(d5.size() < 6) return false;
    d5.resize(d5.size() - 6);
    return bech32_convert_bits(data,d5.data(),d5.size(),5,8,false);
}

inline void wipe(std::vector<unsigned char>& v) {
    if(!v.empty()) sodium_memzero(v.data(),v.size());
}
inline void wipe(std::string& s) {
    if(!s.empty()) sodium_memzero((void*)s.data(),s.size());
}

} // namespace

AsymOutcome fe_identity_to_recipient(const std::string& identity, std::string& pub) {
    AsymOutcome o;
    std::string hrp;
    std::vector<unsigned char> secret;
    if(!bech32_decode(identity,hrp,secret)) {
        o.error = "invalid identity (not a well-formed Bech32 AGE-SECRET-KEY-... string)";
        return o;
    }
    if(hrp != "age-secret-key-") {
        o.error = "not an age identity (expected the AGE-SECRET-KEY- prefix)";
        wipe(secret);
        return o;
    }
    if(secret.size() != 32) {
        o.error = "identity must decode to 32 bytes";
        wipe(secret);
        return o;
    }
    unsigned char pk[32];
    if(crypto_scalarmult_base(pk,secret.data()) != 0) {
        o.error = "X25519 base point multiplication failed";
        wipe(secret);
        return o;
    }
    if(!bech32_encode(pub,"age",pk,32)) {
        o.error = "failed to encode the derived public key";
        wipe(secret);
        sodium_memzero(pk,sizeof(pk));
        return o;
    }
    wipe(secret);
    sodium_memzero(pk,sizeof(pk));
    o.ok = true;
    return o;
}

AsymOutcome fe_derive_keypair(const char* pw, size_t pw_len,
                              std::vector<unsigned char>& salt,
                              std::string& pub, std::string& priv) {
    AsymOutcome o;
    if(!pw || pw_len == 0) { o.error = "empty derivation password"; return o; }
    if(salt.empty()) {
        salt.assign((size_t)crypto_pwhash_SALTBYTES,0);
        randombytes_buf(salt.data(),salt.size());
    }
    if(salt.size() < (size_t)crypto_pwhash_SALTBYTES) {
        o.error = "salt must be at least 16 bytes";
        return o;
    }

    unsigned char seed[32];
    if(crypto_pwhash(seed,sizeof(seed),
                     pw,(unsigned long long)pw_len,
                     salt.data(),
                     crypto_pwhash_OPSLIMIT_MODERATE,
                     crypto_pwhash_MEMLIMIT_MODERATE,
                     crypto_pwhash_ALG_ARGON2ID13) != 0) {
        o.error = "Argon2id derivation failed (likely out of memory)";
        sodium_memzero(seed,sizeof(seed));
        return o;
    }
    // 规范成 X25519 钳位（clamp）形式，与 rage/age 内部表示保持一致
    seed[0]  &= 248;
    seed[31] &= 127;
    seed[31] |= 64;

    unsigned char pk[32];
    if(crypto_scalarmult_base(pk,seed) != 0) {
        o.error = "X25519 base point multiplication failed";
        sodium_memzero(seed,sizeof(seed));
        return o;
    }

    std::string secret_str;
    const bool enc_pub = bech32_encode(pub,"age",pk,32);
    const bool enc_priv = bech32_encode(secret_str,"AGE-SECRET-KEY-",seed,32);
    sodium_memzero(seed,sizeof(seed));
    sodium_memzero(pk,sizeof(pk));
    if(!enc_pub || !enc_priv) {
        o.error = "failed to encode the derived keypair";
        wipe(secret_str);
        return o;
    }
    for(char& c: secret_str) {
        if(c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');   // age 的私钥全大写
    }
    priv.swap(secret_str);
    wipe(secret_str);
    o.ok = true;
    return o;
}
