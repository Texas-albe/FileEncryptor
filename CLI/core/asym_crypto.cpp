// asym_crypto 实现：基于 OpenSSL EVP_PKEY 的 X25519/X448 密钥对与 DEK 封装。
// 密钥串格式：X25519 沿用 age 的 Bech32（age1... / AGE-SECRET-KEY-...）；
// X448 用 "X448-<b64>" / "X448SEC-<b64>"。DEK 包装用 XChaCha20-Poly1305（零 nonce）。
#include "asym_crypto.hpp"

#include <sodium.h>

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include <cstring>
#include <string>
#include <vector>

// ECDH 共享密钥 → 32 字节 KEK 的提取盐（HMAC-SHA256 的 key 角色）。
static const unsigned char kRecipInfoKey[32] = {
    'F','E','R','E','C','I','P','-','W','R','A','P','-','K','E','K',
    '-','v','1','-','0','0','0','0','0','0','0','0','0','0','0','1' };

// 混合 KEM（X25519 + ML-KEM-768）的 KEK 提取盐与域分隔串。
// 域串刻意与古典 ECDH 不同，保证同一种子不会同时开出两套 KEK。
static const unsigned char kPqcKekKey[32] = {
    'F','E','R','E','C','I','P','-','W','R','A','P','-','K','E','K',
    '-','v','2','-','p','q','c','-','x','2','5','5','1','9','+','k' };
static const char kPqcDomain[] = "PQKEM1-X25519-MLKEM768-hybrid";

// Bech32 编解码定义在本文件后半段（同一无名命名空间），此处提前声明供 encode_key/decode_key 调用。
namespace {
bool bech32_encode(std::string& out, const std::string& hrp,
                   const unsigned char* data, size_t len);
bool bech32_decode(const std::string& str, std::string& hrp,
                   std::vector<unsigned char>& data);
} // namespace

namespace {

// base64 编码（OpenSSL，尾部按长度补 '='）
bool b64_encode(const unsigned char* raw, size_t rawlen, std::string& out) {
    std::string s((rawlen+2)/3*4, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&s[0]), raw, (int)rawlen);
    if(n<=0) return false;
    s.resize((size_t)n);
    out.swap(s);
    return true;
}

// base64 解码。EVP_DecodeBlock 对末尾 '=' 填充的计数不可靠（可能多算 1~2 字节），
// 这里按标准 base64 规则先算真实长度，再取二者较小值截断，避免长度校验误判。
bool b64_decode(const std::string& s, std::vector<unsigned char>& out) {
    if(s.empty()) return false;
    size_t want = s.size()/4*3;
    if(s[s.size()-1]=='=') --want;
    if(s.size()>=2 && s[s.size()-2]=='=') --want;
    std::vector<unsigned char> buf((size_t)EVP_DECODE_LENGTH((int)s.size()), 0);
    int n = EVP_DecodeBlock(buf.data(), reinterpret_cast<const unsigned char*>(s.data()), (int)s.size());
    if(n<=0) return false;
    size_t got = (size_t)n < want ? (size_t)n : want;
    buf.resize(got);
    out.swap(buf);
    return true;
}

// 把 X25519/X448 原始密钥编成用户串：X25519→Bech32；X448→"X448-"/"X448SEC-"+base64。
bool encode_key(uint8_t algo, const unsigned char* raw, size_t rawlen,
                bool is_private, std::string& out) {
    if(algo==RECIP_ALGO_MLKEM) {
        std::string b;
        if(!b64_encode(raw, rawlen, b)) return false;
        out = is_private ? "MLKEM1SEC-" : "MLKEM1-";
        out += b;
        return true;
    }
    if(algo==RECIP_ALGO_X25519) {
        std::string s;
        if(!bech32_encode(s, is_private ? "AGE-SECRET-KEY-" : "age", raw, rawlen))
            return false;
        if(is_private) {
            for(char& c: s) if(c>='a'&&c<='z') c=(char)(c-'a'+'A'); // age 私钥全大写
        }
        out.swap(s);
        return true;
    }
    if(algo==RECIP_ALGO_X448) {
        unsigned char b64[96];
        int n=EVP_EncodeBlock(b64, raw, (int)rawlen);
        if(n<=0) return false;
        out = is_private ? "X448SEC-" : "X448-";
        out.append(reinterpret_cast<char*>(b64), (size_t)n);
        return true;
    }
    return false;
}

// 解析用户串 → (algo, 原始密钥字节)。is_private 仅影响前缀期望。
bool decode_key(const std::string& s, bool is_private, uint8_t& algo,
               std::vector<unsigned char>& raw) {
    if(!is_private && s.rfind("age1",0)==0) {
        std::string hrp; std::vector<unsigned char> d;
        if(!bech32_decode(s,hrp,d)) return false;
        if(hrp!="age" || d.size()!=RECIP_KEY_X25519) return false;
        algo=RECIP_ALGO_X25519; raw.swap(d); return true;
    }
    if(is_private && s.rfind("AGE-SECRET-KEY-",0)==0) {
        std::string hrp; std::vector<unsigned char> d;
        if(!bech32_decode(s,hrp,d)) return false;
        if(hrp!="age-secret-key-" || d.size()!=RECIP_KEY_X25519) return false;
        algo=RECIP_ALGO_X25519; raw.swap(d); return true;
    }
    {
        const std::string prefix = is_private ? "MLKEM1SEC-" : "MLKEM1-";
        if(s.rfind(prefix,0)==0) {
            std::vector<unsigned char> d;
            if(!b64_decode(s.substr(prefix.size()), d)) return false;
            if(d.size() != (is_private ? RECIP_KEY_MLKEM_PRIV : RECIP_KEY_MLKEM_PUB)) return false;
            algo=RECIP_ALGO_MLKEM; raw.swap(d); return true;
        }
    }
    const std::string pub_pfx="X448-", priv_pfx="X448SEC-";
    const std::string& pfx = is_private ? priv_pfx : pub_pfx;
    if(s.rfind(pfx,0)==0) {
        std::string b = s.substr(pfx.size());
        // EVP_DecodeBlock 对末尾 '=' 填充的计数随版本而异（可能多算 1~2 字节），
        // 这里按标准 base64 规则自行算出真实长度后再截断，避免长度校验误判。
        size_t want = b.size()/4*3;
        if(want>0 && !b.empty() && b[b.size()-1]=='=') --want;
        if(want>0 && b.size()>=2 && b[b.size()-2]=='=') --want;
        std::vector<unsigned char> buf((size_t)EVP_DECODE_LENGTH((int)b.size()), 0);
        int n = EVP_DecodeBlock(buf.data(),
            reinterpret_cast<const unsigned char*>(b.data()), (int)b.size());
        if(n<=0) return false;
        size_t got=(size_t)n;
        if(got>want) got=want;          // 剔除填充多算的字节
        buf.resize(got);
        if(buf.size()!=RECIP_KEY_X448) return false;
        algo=RECIP_ALGO_X448; raw.swap(buf); return true;
    }
    return false;
}

// ECDH（OpenSSL）：共享密钥 = DH(priv_raw, pub_raw)。algo 决定曲线。
bool ecdh(uint8_t algo, const unsigned char* priv_raw, size_t priv_len,
          const unsigned char* pub_raw, size_t pub_len,
          std::vector<unsigned char>& shared) {
    int type = (algo==RECIP_ALGO_X448) ? EVP_PKEY_X448 : EVP_PKEY_X25519;
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(type, nullptr, priv_raw, priv_len);
    EVP_PKEY* pub  = EVP_PKEY_new_raw_public_key(type, nullptr, pub_raw, pub_len);
    if(!priv || !pub) { EVP_PKEY_free(priv); EVP_PKEY_free(pub); return false; }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    bool ok=false;
    if(ctx && EVP_PKEY_derive_init(ctx)==1 && EVP_PKEY_derive_set_peer(ctx,pub)==1) {
        size_t slen=0;
        if(EVP_PKEY_derive(ctx, nullptr, &slen)==1 && slen>0) {
            shared.resize(slen);
            if(EVP_PKEY_derive(ctx, shared.data(), &slen)==1) ok=true;
        }
    }
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv); EVP_PKEY_free(pub);
    return ok;
}

// 共享密钥 → 32 字节 KEK（HMAC-SHA256 提取，key=kRecipInfoKey）。
void shared_to_kek(const unsigned char* shared, size_t slen, unsigned char kek[32]) {
    crypto_auth(kek, shared, (unsigned long long)slen, kRecipInfoKey);
}

// 用 KEK 把 DEK(32) 包装为 48 字节箱（零 nonce，XChaCha20-Poly1305）。
bool wrap_dek_recip(const unsigned char* dek, const unsigned char* kek,
                    unsigned char box[48]) {
    unsigned char nonce[24]={0};
    unsigned long long clen=0;
    int rc=crypto_aead_xchacha20poly1305_ietf_encrypt(box,&clen,dek,32,
        nullptr,0,nullptr,nonce,kek);
    return (rc==0 && clen==48);
}

// 用 KEK 解裹 48 字节箱 → DEK(32)。
bool unwrap_dek_recip(const unsigned char* box, const unsigned char* kek,
                      unsigned char dek[32]) {
    unsigned char nonce[24]={0};
    unsigned long long mlen=0;
    int rc=crypto_aead_xchacha20poly1305_ietf_decrypt(dek,&mlen,nullptr,box,48,
        nullptr,0,nonce,kek);
    return (rc==0 && mlen==32);
}

// ML-KEM-768 封装。注意 OpenSSL 4.x 的参数序是「密文在前、共享密钥在后」，
// 与 3.x 相反；写反会得到 output buffer too small。
bool mlkem_encapsulate(const unsigned char* pub, size_t publen,
                       std::vector<unsigned char>& ct,
                       std::vector<unsigned char>& shared) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(NID_ML_KEM_768, nullptr, pub, publen);
    EVP_PKEY_CTX* c = k ? EVP_PKEY_CTX_new(k, nullptr) : nullptr;
    bool ok=false;
    size_t ctl=0, shl=0;
    if(c && EVP_PKEY_encapsulate_init(c,nullptr)==1 &&
       EVP_PKEY_encapsulate(c,nullptr,&ctl,nullptr,&shl)==1 && ctl>0 && shl>0) {
        ct.assign(ctl,0); shared.assign(shl,0);
        size_t a=ctl, b=shl;   // 先按探测长度分配，再按返回长度校验
        ok = EVP_PKEY_encapsulate(c, ct.data(), &a, shared.data(), &b)==1 && a==ctl && b==shl;
    }
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(k);
    return ok;
}

// ML-KEM-768 解裹：用收件人私钥消化 stanza 里的封装密文。
bool mlkem_decapsulate(const unsigned char* priv, size_t privlen,
                       const unsigned char* ct, size_t ctlen,
                       std::vector<unsigned char>& shared) {
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(NID_ML_KEM_768, nullptr, priv, privlen);
    EVP_PKEY_CTX* c = k ? EVP_PKEY_CTX_new(k, nullptr) : nullptr;
    bool ok=false;
    size_t shl=0;
    if(c && EVP_PKEY_decapsulate_init(c,nullptr)==1 &&
       EVP_PKEY_decapsulate(c,nullptr,&shl,ct,ctlen)==1 && shl>0) {
        shared.assign(shl,0);
        ok = EVP_PKEY_decapsulate(c, shared.data(), &shl, ct, ctlen)==1;
    }
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(k);
    return ok;
}

// 混合 KEK = HMAC-SHA256(kPqcKekKey, domain || ML-KEM 共享 || ECDH 共享 || KEM 密文)。
// 密文参与提取，使同一密钥下换一份密文也开不出同一个 KEK（绑定封装）。
void hybrid_kek(const unsigned char* ml_shared, size_t n1,
                const unsigned char* ecdh_shared, size_t n2,
                const unsigned char* ct, size_t n3, unsigned char kek[32]) {
    unsigned char buf[sizeof(kPqcDomain)-1 + 32 + 32 + 1088];
    size_t off=0;
    for(size_t i=0; i<sizeof(kPqcDomain)-1; ++i) buf[off++]=(unsigned char)kPqcDomain[i];
    memcpy(buf+off, ml_shared, n1);      off+=n1;
    memcpy(buf+off, ecdh_shared, n2);    off+=n2;
    if(n3 && ct) { memcpy(buf+off, ct, n3); off+=n3; }
    crypto_auth(kek, buf, (unsigned long long)off, kPqcKekKey);
    sodium_memzero(buf, sizeof(buf));
}

} // namespace

namespace {

// 取原始密钥对字节（OpenSSL keygen → get_raw_*）；失败时 out 内容不保留。
bool raw_keypair(int type, std::vector<unsigned char>& pub_raw,
                 std::vector<unsigned char>& priv_raw) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(type, nullptr);
    EVP_PKEY* pkey = nullptr;
    if(!kctx || EVP_PKEY_keygen_init(kctx)!=1 || EVP_PKEY_keygen(kctx,&pkey)!=1) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    EVP_PKEY_CTX_free(kctx);
    size_t rlen=0;
    EVP_PKEY_get_raw_private_key(pkey, nullptr, &rlen);
    priv_raw.assign(rlen, 0);
    EVP_PKEY_get_raw_private_key(pkey, priv_raw.data(), &rlen);
    rlen=0;
    EVP_PKEY_get_raw_public_key(pkey, nullptr, &rlen);
    pub_raw.assign(rlen, 0);
    EVP_PKEY_get_raw_public_key(pkey, pub_raw.data(), &rlen);
    EVP_PKEY_free(pkey);
    return true;
}

// 混合密钥对：X25519 与 ML-KEM-768 各生成一份，按「X25519 || ML-KEM」拼接后整体编码。
bool hybrid_keypair(std::vector<unsigned char>& pub_raw,
                    std::vector<unsigned char>& priv_raw) {
    std::vector<unsigned char> x_pub, x_priv, m_pub, m_priv;
    if(!raw_keypair(EVP_PKEY_X25519, x_pub, x_priv)) return false;
    if(!raw_keypair(NID_ML_KEM_768, m_pub, m_priv)) {
        sodium_memzero(x_priv.data(), x_priv.size());
        return false;
    }
    pub_raw.clear(); priv_raw.clear();
    pub_raw.reserve(x_pub.size()+m_pub.size());
    pub_raw.insert(pub_raw.end(), x_pub.begin(), x_pub.end());
    pub_raw.insert(pub_raw.end(), m_pub.begin(), m_pub.end());
    priv_raw.reserve(x_priv.size()+m_priv.size());
    priv_raw.insert(priv_raw.end(), x_priv.begin(), x_priv.end());
    priv_raw.insert(priv_raw.end(), m_priv.begin(), m_priv.end());
    sodium_memzero(x_priv.data(), x_priv.size());
    sodium_memzero(m_priv.data(), m_priv.size());
    return true;
}

} // namespace

AsymOutcome fe_generate_keypair(uint8_t algo, std::string& pub, std::string& priv) {
    AsymOutcome o;
    std::vector<unsigned char> pub_raw, priv_raw;
    if(algo==RECIP_ALGO_MLKEM) {
        if(!hybrid_keypair(pub_raw, priv_raw)) { o.error="OpenSSL hybrid keygen failed"; return o; }
    } else if(algo==RECIP_ALGO_X25519 || algo==RECIP_ALGO_X448) {
        int type = (algo==RECIP_ALGO_X448) ? EVP_PKEY_X448 : EVP_PKEY_X25519;
        if(!raw_keypair(type, pub_raw, priv_raw)) { o.error="OpenSSL keygen failed"; return o; }
    } else {
        o.error="unsupported asymmetric algorithm"; return o;
    }
    if(!encode_key(algo, pub_raw.data(), pub_raw.size(), false, pub) ||
       !encode_key(algo, priv_raw.data(), priv_raw.size(), true, priv) ||
       pub_raw.empty() || priv_raw.empty()) {
        sodium_memzero(priv_raw.data(), priv_raw.size());
        o.error="failed to encode keypair"; return o;
    }
    sodium_memzero(priv_raw.data(), priv_raw.size());
    o.ok=true; return o;
}

// 混合（algo=3）封装：ML-KEM 封装密文 + ECDH 共享密钥合流出 KEK，密文随 stanza 下发。
// 临时 X25519 用于 ECDH，ML-KEM 侧无需临时密钥（封装内部自取随机数）。
static bool pqc_wrap_dek(const unsigned char* dek, const unsigned char* recip_pub,
                         std::vector<unsigned char>& eph_pub, unsigned char box[48]) {
    const unsigned char* x_pub = recip_pub;                            // 32
    const unsigned char* ml_pub = recip_pub + RECIP_KEY_X25519;        // 1184
    std::vector<unsigned char> ct, ml_shared;
    if(!mlkem_encapsulate(ml_pub, RECIP_KEY_MLKEM_PUB - RECIP_KEY_X25519, ct, ml_shared)) return false;

    std::vector<unsigned char> eph_pub_raw, eph_priv_raw;
    if(!raw_keypair(EVP_PKEY_X25519, eph_pub_raw, eph_priv_raw)) return false;
    std::vector<unsigned char> shared_ecdh;
    bool ok = ecdh(RECIP_ALGO_X25519, eph_priv_raw.data(), eph_priv_raw.size(),
                   x_pub, RECIP_KEY_X25519, shared_ecdh);
    sodium_memzero(eph_priv_raw.data(), eph_priv_raw.size());
    if(!ok) return false;

    unsigned char kek[32];
    hybrid_kek(ml_shared.data(), ml_shared.size(), shared_ecdh.data(), shared_ecdh.size(),
               ct.data(), ct.size(), kek);
    sodium_memzero(shared_ecdh.data(), shared_ecdh.size());
    bool good = wrap_dek_recip(dek, kek, box);
    sodium_memzero(kek, sizeof(kek));
    if(!good) return false;

    eph_pub.assign(eph_pub_raw.size() + ct.size(), 0);
    memcpy(eph_pub.data(), eph_pub_raw.data(), eph_pub_raw.size());
    memcpy(eph_pub.data() + eph_pub_raw.size(), ct.data(), ct.size());
    return true;
}

// 混合（algo=3）恢复：身份私钥 = X25519(32) || ML-KEM(2400)，stanza 临时区 = X25519(32) || 密文(1088)。
static bool pqc_recover_dek(const std::vector<unsigned char>& id_priv,
                            const std::vector<unsigned char>& eph_pub,
                            const unsigned char* box, unsigned char dek[32]) {
    if(id_priv.size()!=RECIP_KEY_MLKEM_PRIV || eph_pub.size()!=RECIP_EPH_MLKEM_CT) return false;
    const unsigned char* x_priv = id_priv.data();
    const unsigned char* ml_priv = id_priv.data() + RECIP_KEY_X25519;
    const unsigned char* ct = eph_pub.data() + RECIP_KEY_X25519;

    std::vector<unsigned char> shared_ecdh, ml_shared;
    if(!ecdh(RECIP_ALGO_X25519, x_priv, RECIP_KEY_X25519, eph_pub.data(), RECIP_KEY_X25519, shared_ecdh))
        return false;
    if(!mlkem_decapsulate(ml_priv, RECIP_KEY_MLKEM_PRIV - RECIP_KEY_X25519, ct,
                          RECIP_EPH_MLKEM_CT - RECIP_KEY_X25519, ml_shared))
        return false;

    unsigned char kek[32];
    hybrid_kek(ml_shared.data(), ml_shared.size(), shared_ecdh.data(), shared_ecdh.size(),
               ct, RECIP_EPH_MLKEM_CT - RECIP_KEY_X25519, kek);
    sodium_memzero(shared_ecdh.data(), shared_ecdh.size());
    bool good = unwrap_dek_recip(box, kek, dek);
    sodium_memzero(kek, sizeof(kek));
    return good;
}

AsymOutcome fe_wrap_dek_to_recipients(const unsigned char* dek,
                                      const std::vector<std::string>& recipient_pubs,
                                      std::vector<RecipientStanza>& stanzas) {
    AsymOutcome o;
    if(recipient_pubs.empty()) { o.error="no recipients"; return o; }
    stanzas.clear();
    for(const auto& pub_str : recipient_pubs) {
        uint8_t algo; std::vector<unsigned char> recip_pub;
        if(!decode_key(pub_str, false, algo, recip_pub)) {
            o.error="invalid recipient public key: "+pub_str.substr(0,16); return o;
        }
        if(algo==RECIP_ALGO_MLKEM) {
            unsigned char box[48];
            std::vector<unsigned char> eph;
            if(!pqc_wrap_dek(dek, recip_pub.data(), eph, box)) {
                o.error="hybrid (ML-KEM) DEK wrap failed"; return o;
            }
            RecipientStanza s;
            s.algo = algo;
            s.recip_pub = recip_pub;
            s.eph_pub = std::move(eph);
            s.wrapped_dek.assign(box, box+48);
            stanzas.push_back(std::move(s));
            continue;
        }
        // 生成临时密钥对做 ECDH
        int type = (algo==RECIP_ALGO_X448) ? EVP_PKEY_X448 : EVP_PKEY_X25519;
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(type, nullptr);
        EVP_PKEY* eph = nullptr;
        if(!kctx || EVP_PKEY_keygen_init(kctx)!=1 || EVP_PKEY_keygen(kctx,&eph)!=1) {
            EVP_PKEY_CTX_free(kctx); o.error="ephemeral keygen failed"; return o;
        }
        EVP_PKEY_CTX_free(kctx);
        size_t elen=0; EVP_PKEY_get_raw_public_key(eph, nullptr, &elen);
        std::vector<unsigned char> eph_pub(elen);
        EVP_PKEY_get_raw_public_key(eph, eph_pub.data(), &elen);

        std::vector<unsigned char> shared;
        // ECDH: 临时私钥 × 收件人公钥
        {
            size_t prlen=0; EVP_PKEY_get_raw_private_key(eph, nullptr, &prlen);
            std::vector<unsigned char> eph_priv(prlen);
            EVP_PKEY_get_raw_private_key(eph, eph_priv.data(), &prlen);
            if(!ecdh(algo, eph_priv.data(), prlen, recip_pub.data(), recip_pub.size(), shared)) {
                EVP_PKEY_free(eph); sodium_memzero(eph_priv.data(), eph_priv.size());
                o.error="ECDH failed"; return o;
            }
            sodium_memzero(eph_priv.data(), eph_priv.size());
        }
        EVP_PKEY_free(eph);

        unsigned char kek[32]; shared_to_kek(shared.data(), shared.size(), kek);
        sodium_memzero(shared.data(), shared.size());

        unsigned char box[48];
        if(!wrap_dek_recip(dek, kek, box)) {
            sodium_memzero(kek, sizeof(kek)); o.error="DEK wrap failed"; return o;
        }
        sodium_memzero(kek, sizeof(kek));

        RecipientStanza s;
        s.algo = algo;
        s.recip_pub = recip_pub;
        s.eph_pub = eph_pub;
        s.wrapped_dek.assign(box, box+48);
        stanzas.push_back(std::move(s));
    }
    o.ok=true; return o;
}

AsymOutcome fe_recover_dek_from_stanzas(const std::vector<RecipientStanza>& stanzas,
                                        const std::string& identity_priv,
                                        unsigned char dek[32]) {
    AsymOutcome o;
    uint8_t algo; std::vector<unsigned char> id_priv;
    if(!decode_key(identity_priv, true, algo, id_priv)) {
        o.error="invalid identity private key"; return o;
    }
    for(const auto& s : stanzas) {
        if(s.algo != algo) continue;
        if(s.algo==RECIP_ALGO_MLKEM) {
            if(pqc_recover_dek(id_priv, s.eph_pub, s.wrapped_dek.data(), dek)) {
                sodium_memzero(id_priv.data(), id_priv.size());
                o.ok=true; return o;
            }
            continue;   // 逐条试，一条失败不代表整批失败
        }
        if(s.recip_pub.size() != id_priv.size()) continue;
        // 身份公钥应等于 stanza.recip_pub；用本地 bech32 反推校验（X25519）
        // 直接比对 ECDH 结果更稳：shared = DH(id_priv, eph_pub)
        std::vector<unsigned char> shared;
        if(!ecdh(algo, id_priv.data(), id_priv.size(),
                 s.eph_pub.data(), s.eph_pub.size(), shared)) continue;
        unsigned char kek[32]; shared_to_kek(shared.data(), shared.size(), kek);
        sodium_memzero(shared.data(), shared.size());
        if(unwrap_dek_recip(s.wrapped_dek.data(), kek, dek)) {
            sodium_memzero(kek, sizeof(kek));
            sodium_memzero(id_priv.data(), id_priv.size());
            o.ok=true; return o;
        }
        sodium_memzero(kek, sizeof(kek));
    }
    sodium_memzero(id_priv.data(), id_priv.size());
    o.error="no matching recipient / wrong identity"; return o;
}

// 以下为纯本地实现（不依赖 OpenSSL）：Bech32（BIP-173）编解码 + X25519 + Argon2id。
// 收件人公钥 hrp="age"；身份私钥 hrp="AGE-SECRET-KEY-"，编码后整体转大写。
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

// 校验和须按小写 HRP 展开计算（Bech32 规范）；X25519 私钥串编码后整体转大写，
// 但校验和仍按小写 HRP 计算，按大写展开会得到无效串。
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
    if(!v.empty()) {
        sodium_memzero(v.data(),v.size());
        // 强制释放底层缓冲：clear()/shrink_to_fit() 不保证归还内存，
        // 可能残留旧私钥副本；用 swap 与一个空 vector 确保立即释放（对齐 SecureBuffer）。
        std::vector<unsigned char>().swap(v);
    }
}
inline void wipe(std::string& s) {
    if(!s.empty()) {
        sodium_memzero((void*)s.data(),s.size());
        // 同上：擦除后强制释放缓冲，避免旧明文（身份私钥）残留在 std::string 容量中。
        std::string().swap(s);
    }
}

} // namespace

namespace {
// ML-KEM 段（纯原始私钥）→ 原始公钥；失败时 pub_raw 内容不保留。
bool mlkem_pub_from_priv(const unsigned char* priv_raw, size_t len,
                         std::vector<unsigned char>& pub_raw) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(NID_ML_KEM_768, nullptr,
                    const_cast<unsigned char*>(priv_raw), len);
    if(!pkey) { ERR_clear_error(); return false; }
    size_t n = 0;
    if(EVP_PKEY_get_raw_public_key(pkey, nullptr, &n)!=1 || n==0) {
        ERR_clear_error(); EVP_PKEY_free(pkey); return false;
    }
    pub_raw.assign(n, 0);
    const bool got = EVP_PKEY_get_raw_public_key(pkey, pub_raw.data(), &n)==1 && n==pub_raw.size();
    EVP_PKEY_free(pkey);
    return got;
}

// 由原始私钥推出收件人公钥；成功时把结果编成用户串写入 out。
bool derive_pub_from_raw(uint8_t algo, const std::vector<unsigned char>& priv_raw,
                         std::string& out) {
    if(algo==RECIP_ALGO_MLKEM) {
        // 混合串是「X25519(32) ‖ ML-KEM」拼接，两端各推对应公钥后按原布局拼回
        if(priv_raw.size()!=RECIP_KEY_MLKEM_PRIV) return false;
        unsigned char xpub[32];
        if(crypto_scalarmult_base(xpub, priv_raw.data())!=0) return false;
        std::vector<unsigned char> mpub;
        const bool ok = mlkem_pub_from_priv(priv_raw.data()+32,
                            RECIP_KEY_MLKEM_PRIV-32, mpub);
        if(!ok) { sodium_memzero(xpub,sizeof(xpub)); return false; }
        std::vector<unsigned char> blob;
        blob.reserve(sizeof(xpub)+mpub.size());
        blob.insert(blob.end(), xpub, xpub+sizeof(xpub));
        blob.insert(blob.end(), mpub.begin(), mpub.end());
        sodium_memzero(xpub,sizeof(xpub));
        return encode_key(algo, blob.data(), blob.size(), false, out);
    }
    const int type = (algo==RECIP_ALGO_X25519) ? EVP_PKEY_X25519 : EVP_PKEY_X448;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(type, nullptr,
                    const_cast<unsigned char*>(priv_raw.data()), priv_raw.size());
    if(!pkey) { ERR_clear_error(); return false; }
    size_t n = 0;
    if(EVP_PKEY_get_raw_public_key(pkey, nullptr, &n)!=1 || n==0) {
        ERR_clear_error(); EVP_PKEY_free(pkey); return false;
    }
    std::vector<unsigned char> pub_raw(n, 0);
    const bool got = EVP_PKEY_get_raw_public_key(pkey, pub_raw.data(), &n)==1 && n==pub_raw.size();
    EVP_PKEY_free(pkey);
    return got && encode_key(algo, pub_raw.data(), pub_raw.size(), false, out);
}
} // namespace

AsymOutcome fe_identity_to_recipient(const std::string& identity, std::string& pub) {
    AsymOutcome o;
    // 混合密钥（MLKEM1SEC-...）与 X448SEC-... 不走 bech32，先按原始密钥识别
    uint8_t algo = 0;
    std::vector<unsigned char> raw;
    if(decode_key(identity, true, algo, raw)) {
        if(!derive_pub_from_raw(algo, raw, pub)) {
            o.error = "cannot derive the public key from the given identity";
        } else {
            o.ok = true;
        }
        wipe(raw);
        return o;
    }
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
    // 规范成 X25519 钳位（clamp）形式，与标准 X25519 表示一致
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

