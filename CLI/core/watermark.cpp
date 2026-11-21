// 水印实现
// 签名对象固定
// ML-DSA 是纯签名算法
// 因此这里
#include "watermark.hpp"

#include "FileEncryptor.hpp"
#include "keyfile_crypt.hpp"

#include <sodium.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif
#include <ctime>
#include <string>
#include <vector>

namespace {

constexpr char kMagic[4] = {'F', 'E', 'W', 'M'};
constexpr uint8_t kVersion = 1;

void put_be64(unsigned char* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (unsigned char)((v >> (56 - 8 * i)) & 0xff);
}
uint64_t get_be64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
void put_be16(unsigned char* p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

std::string to_hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

// 读私钥/公钥 PEM
// 支持 FEPK1 加密私钥
bool load_private_key(const std::string& path, bool pqc, EVP_PKEY*& pkey) {
    std::string pem;
    bool was_plain = false;
    std::string err;
    if (!fe_keyfile::read_protected(path, pem, fe_keyfile::PURPOSE_WM, was_plain, err))
        return false;
    if (was_plain) {
        std::fprintf(stderr,
            "Warning: %s is a plaintext private key on disk; consider re-saving it encrypted.\n",
            path.c_str());
    }
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    pkey = bio ? PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr) : nullptr;
    if (bio) BIO_free(bio);
    sodium_memzero(pem.data(), pem.size());
    if (!pkey) return false;
    const bool type_ok = EVP_PKEY_is_a(pkey, pqc ? "ML-DSA-65" : "RSA");
    if (!type_ok) {
        ERR_clear_error();
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    return type_ok;
}

bool load_public_key(const std::string& path, bool pqc, EVP_PKEY*& pkey) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) return false;
    pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    if (!pkey) return false;
    const bool type_ok = EVP_PKEY_is_a(pkey, pqc ? "ML-DSA-65" : "RSA");
    if (!type_ok) {
        ERR_clear_error();
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    return type_ok;
}

// 摘要长度恒
static const EVP_MD* wm_digest_fn(bool pqc) { return pqc ? nullptr : EVP_sha256(); }

// 签名长度
size_t sig_length(EVP_PKEY* key, bool pqc) {
    if (!key) return 0;
    size_t len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    const bool ok = EVP_DigestSignInit(ctx, nullptr, wm_digest_fn(pqc), nullptr, key) == 1 &&
                    EVP_DigestSign(ctx, nullptr, &len, nullptr, 32) == 1 && len > 0;
    EVP_MD_CTX_free(ctx);
    ERR_clear_error();
    return ok ? len : 0;
}

// 对 32 字节摘要做签
size_t sign_digest(EVP_PKEY* key, bool pqc, const unsigned char* digest,
                   unsigned char* sig, size_t cap) {
    size_t len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    bool ok = EVP_DigestSignInit(ctx, nullptr, wm_digest_fn(pqc), nullptr, key) == 1 &&
              EVP_DigestSign(ctx, nullptr, &len, digest, 32) == 1 && len > 0 && len <= cap &&
              EVP_DigestSign(ctx, sig, &len, digest, 32) == 1;
    EVP_MD_CTX_free(ctx);
    ERR_clear_error();
    return ok ? len : 0;
}

bool verify_digest(EVP_PKEY* key, bool pqc, const unsigned char* digest,
                   const unsigned char* sig, size_t sig_len) {
    bool ok = false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        if (EVP_DigestVerifyInit(ctx, nullptr, wm_digest_fn(pqc), nullptr, key) == 1) {
            ok = EVP_DigestVerify(ctx, sig, sig_len, digest, 32) == 1;
        }
        EVP_MD_CTX_free(ctx);
    }
    ERR_clear_error();
    return ok;
}

// 摘要
bool digest_record(const unsigned char* rec, unsigned char out[32]) {
    return SHA256(rec, WM_RECORD_FIXED, out) != nullptr;
}

}

bool wm_sign_and_serialize(uint64_t timestamp,
                           const unsigned char machine_id[16],
                           uint8_t flags,
                           const std::string& priv_pem_path,
                           bool pqc,
                           std::vector<unsigned char>& blob,
                           std::string& error) {
    blob.clear();
    unsigned char rec[WM_RECORD_FIXED] = {0};
    memcpy(rec, kMagic, 4);
    rec[4] = kVersion;
    rec[5] = flags;
    put_be64(rec + 6, timestamp);
    memcpy(rec + 14, machine_id, 16);
    randombytes_buf(rec + 30, 16);   // nonce
    put_be16(rec + 46, 0);           // sig_len 签名后回填
    if (priv_pem_path.empty()) {
        blob.assign(rec, rec + WM_RECORD_FIXED);
        return true;                          // 未给私钥
    }

    EVP_PKEY* pkey = nullptr;
    if (!load_private_key(priv_pem_path, pqc, pkey)) {
        error = std::string("watermark: cannot read ")
              + (pqc ? "ML-DSA-65" : "RSA") + " private key: " + priv_pem_path;
        return false;
    }
    unsigned char digest[32];
    if (!digest_record(rec, digest)) {
        EVP_PKEY_free(pkey);
        error = "watermark: digest failed";
        return false;
    }
    // sig_len 参与摘要
    // 验签端读到
    const size_t sig_len = sig_length(pkey, pqc);
    if (sig_len == 0 || sig_len > WM_MAX_SIG || sig_len > 0xffff) {
        EVP_PKEY_free(pkey);
        error = std::string("watermark: ")
              + (pqc ? "ML-DSA-65" : "RSA") + " sign failed (unsupported key)";
        return false;
    }
    put_be16(rec + 46, (uint16_t)sig_len);
    if (!digest_record(rec, digest)) {
        EVP_PKEY_free(pkey);
        error = "watermark: digest failed";
        return false;
    }
    unsigned char sig[WM_MAX_SIG];
    const size_t n = sign_digest(pkey, pqc, digest, sig, sizeof(sig));
    EVP_PKEY_free(pkey);
    if (n != sig_len) {
        error = "watermark: signature length mismatch";
        return false;
    }
    // 签名写
    blob.resize(WM_RECORD_FIXED + sig_len);
    memcpy(blob.data(), rec, WM_RECORD_FIXED);
    memcpy(blob.data() + WM_RECORD_FIXED, sig, sig_len);
    return true;
}

bool wm_parse_blob(const unsigned char* data, size_t len,
                   bool pqc,
                   const std::string* pub_pem_path,
                   WatermarkInfo& out) {
    out = WatermarkInfo();
    if (!data || len < WM_RECORD_FIXED) return false;
    if (memcmp(data, kMagic, 4) != 0) return false;
    if (data[4] != kVersion) return false;
    const uint64_t ts = get_be64(data + 6);
    const uint16_t sig_len = (uint16_t)((data[46] << 8) | data[47]);
    if (WM_RECORD_FIXED + sig_len > len) return false;

    out.timestamp = ts;
    out.flags = data[5];
    out.machine_id_hex = to_hex(data + 14, 16);
    out.nonce_hex = to_hex(data + 30, 16);
    out.has_signature = sig_len > 0;
    if (!out.has_signature) return true;
    if (sig_len > WM_MAX_SIG) {
        out.error = "signature too long";
        return true;
    }

    unsigned char digest[32];
    if (!digest_record(data, digest)) {
        out.error = "digest failed";
        return true;
    }
    if (!pub_pem_path || pub_pem_path->empty()) return true;   // 不给公钥只展示
    // 验签前两种算法
    // 变成「读不到公钥」
    const bool   try_pqc[2] = { pqc, !pqc };
    const char*  try_name[2] = { "ML-DSA-65", "RSA" };
    EVP_PKEY* pkey = nullptr;
    std::string load_err;
    for (int i = 0; i < 2; ++i) {
        if (load_public_key(*pub_pem_path, try_pqc[i], pkey)) break;
        ERR_clear_error();
        load_err = std::string("cannot read ") + try_name[i] + " public key: " + *pub_pem_path;
    }
    if (!pkey) {
        out.error = load_err;
        out.verify_attempted = true;
        return true;
    }
    // 以载入密钥
    const bool key_is_pqc = EVP_PKEY_is_a(pkey, "ML-DSA-65") == 1;
    const bool ok = verify_digest(pkey, key_is_pqc, digest, data + WM_RECORD_FIXED, sig_len);
    EVP_PKEY_free(pkey);
    out.verify_attempted = true;
    out.verify_ok = ok;
    if (!ok) out.error = "signature mismatch (tampered or wrong public key)";
    return true;
}

// 生成签名密钥
bool wm_generate_keypair(const std::string& priv_pem_path, bool pqc,
                         std::string& pub_pem, std::string& error) {
    EVP_PKEY* pkey = nullptr;
    if (pqc) {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(NID_ML_DSA_65, nullptr);
        if (!kctx || EVP_PKEY_keygen_init(kctx) != 1 || EVP_PKEY_keygen(kctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(kctx);
            ERR_clear_error();
            error = "watermark: ML-DSA-65 keygen failed";
            return false;
        }
        EVP_PKEY_CTX_free(kctx);
    } else {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!kctx || EVP_PKEY_keygen_init(kctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072) != 1 ||
            EVP_PKEY_keygen(kctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(kctx);
            ERR_clear_error();
            error = "watermark: RSA-3072 keygen failed";
            return false;
        }
        EVP_PKEY_CTX_free(kctx);
    }

    // 覆盖保护保持
    if (std::FILE* probe = std::fopen(priv_pem_path.c_str(), "rb")) {
        std::fclose(probe);
        EVP_PKEY_free(pkey);
        ERR_clear_error();
        error = "watermark: private key file already exists (refusing to overwrite): "
                + priv_pem_path;
        return false;
    }

    // PEM 编码进内存
    BIO* pbio = BIO_new(BIO_s_mem());
    if (!pbio || PEM_write_bio_PrivateKey(pbio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        if (pbio) BIO_free(pbio);
        EVP_PKEY_free(pkey);
        ERR_clear_error();
        error = "watermark: cannot encode private key PEM";
        return false;
    }
    char* pmem = nullptr;
    const long pn = BIO_get_mem_data(pbio, &pmem);
    if (pn <= 0 || !pmem) {
        BIO_free(pbio);
        EVP_PKEY_free(pkey);
        ERR_clear_error();
        error = "watermark: cannot read private key PEM";
        return false;
    }
    std::string priv_pem(pmem, (size_t)pn);
    BIO_free(pbio);
    ERR_clear_error();

    // FEPK1 加密落盘
    std::string werr;
    const bool wok = fe_keyfile::write_protected(priv_pem_path, priv_pem,
                                                 fe_keyfile::PURPOSE_WM, werr);
    sodium_memzero(priv_pem.data(), priv_pem.size());
    if (!wok) {
        EVP_PKEY_free(pkey);
        error = "watermark: " + werr;
        return false;
    }

    // 公钥走 BIO +
    // 返回 0
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        if (bio) BIO_free(bio);
        ERR_clear_error();
        EVP_PKEY_free(pkey);
        error = "watermark: cannot encode public key";
        return false;
    }
    char* mem = nullptr;
    const long n = BIO_get_mem_data(bio, &mem);
    if (n <= 0 || !mem) {
        BIO_free(bio);
        ERR_clear_error();
        EVP_PKEY_free(pkey);
        error = "watermark: cannot read public key PEM";
        return false;
    }
    // BIO 缓冲可能有前导
    std::string raw(mem, (size_t)n);
    BIO_free(bio);
    const size_t b = raw.find("-----BEGIN PUBLIC KEY-----");
    const size_t e = raw.find("-----END PUBLIC KEY-----");
    if (b == std::string::npos || e == std::string::npos) {
        EVP_PKEY_free(pkey);
        error = "watermark: malformed public key PEM";
        return false;
    }
    pub_pem = raw.substr(b, e + strlen("-----END PUBLIC KEY-----") - b) + "\n";
    EVP_PKEY_free(pkey);
    return true;
}

std::string wm_timestamp_text(uint64_t ts) {
    const std::time_t t = static_cast<std::time_t>(ts);
    std::tm tm_buf;
#ifdef _WIN32
    if (localtime_s(&tm_buf, &t) != 0) return std::string();
#else
    if (localtime_r(&t, &tm_buf) == nullptr) return std::string();
#endif
    char buf[64];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) return std::string();
    return std::string(buf);
}
