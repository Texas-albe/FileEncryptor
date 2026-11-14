// Cipher 工厂实现
#include "cipher.hpp"
#include <sodium.h>
#include <vector>
#include <cstring>

#ifdef FE_WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

namespace {

class XChaCha20Cipher final : public Cipher {
public:
    CryptoMode mode() const override { return CryptoMode::XCHACHA20; }
    size_t key_size() const override { return crypto_aead_xchacha20poly1305_ietf_KEYBYTES; }
    size_t nonce_size() const override { return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; }
    size_t tag_size() const override { return crypto_aead_xchacha20poly1305_ietf_ABYTES; }
    int encrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) override {
        return crypto_aead_xchacha20poly1305_ietf_encrypt(ct_out, &ct_len,
            pt, pt_len, aad, aad_len, nullptr, nonce, key);
    }
    int decrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) override {
        return crypto_aead_xchacha20poly1305_ietf_decrypt(pt_out, &pt_len, nullptr,
            ct, ct_len, aad, aad_len, nonce, key);
    }
};

class AEGIS256Cipher final : public Cipher {
public:
    CryptoMode mode() const override { return CryptoMode::AEGIS256; }
    size_t key_size() const override { return crypto_aead_aegis256_KEYBYTES; }
    size_t nonce_size() const override { return crypto_aead_aegis256_NPUBBYTES; }
    size_t tag_size() const override { return crypto_aead_aegis256_ABYTES; }
    int encrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) override {
        // AEGIS-256 同样依赖 AES-NI；libsodium 未提
        if(!aegis256_supported()) return -1;
        return crypto_aead_aegis256_encrypt(ct_out, &ct_len,
            pt, pt_len, aad, aad_len, nullptr, nonce, key);
    }
    int decrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) override {
        if(!aegis256_supported()) return -1;
        return crypto_aead_aegis256_decrypt(pt_out, &pt_len, nullptr,
            ct, ct_len, aad, aad_len, nonce, key);
    }
};

// AES-256-GCM
// 优先走 OpenSSL EVP
// CPU 是否带 AES-NI 限制）；未编
// 两条实现
class AesGcmCipher final : public Cipher {
public:
    CryptoMode mode() const override { return CryptoMode::AES_GCM; }
    size_t key_size() const override { return crypto_aead_aes256gcm_KEYBYTES; }
    size_t nonce_size() const override { return crypto_aead_aes256gcm_NPUBBYTES; }
    size_t tag_size() const override { return crypto_aead_aes256gcm_ABYTES; }
    int encrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) override {
#ifdef FE_WITH_OPENSSL
        if(EvpGcmEncrypt(pt, pt_len, aad, aad_len, nonce, key, ct_out, ct_len) == 0) return 0;
#endif
        // 无 AES-NI 时 libsodium
        if(crypto_aead_aes256gcm_is_available()==0) return -1;
        return crypto_aead_aes256gcm_encrypt(ct_out, &ct_len,
            pt, pt_len, aad, aad_len, nullptr, nonce, key);
    }
    int decrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) override {
#ifdef FE_WITH_OPENSSL
        if(EvpGcmDecrypt(ct, ct_len, aad, aad_len, nonce, key, pt_out, pt_len) == 0) return 0;
#endif
        if(crypto_aead_aes256gcm_is_available()==0) return -1;
        return crypto_aead_aes256gcm_decrypt(pt_out, &pt_len, nullptr,
            ct, ct_len, aad, aad_len, nonce, key);
    }

#ifdef FE_WITH_OPENSSL
private:
    static int EvpGcmEncrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) {
        EVP_CIPHER* aes = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
        if(!aes) return -1;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if(!ctx) { EVP_CIPHER_free(aes); return -1; }
        int rc = -1, len = 0;
        do {
            if(EVP_EncryptInit_ex(ctx, aes, nullptr, nullptr, nullptr) != 1) break;
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
            if(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
            if(aad && aad_len && EVP_EncryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) != 1) break;
            if(EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int)pt_len) != 1) break;
            int ct_off = len;
            if(EVP_EncryptFinal_ex(ctx, ct_out + ct_off, &len) != 1) break;
            ct_len = (unsigned long long)(ct_off + len);
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct_out + ct_len) != 1) break;
            ct_len += 16;
            rc = 0;
        } while(false);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(aes);
        return rc;
    }

    static int EvpGcmDecrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) {
        if(ct_len < 16) return -1;
        const size_t body = ct_len - 16;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if(!ctx) return -1;
        EVP_CIPHER* aes = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
        if(!aes) { EVP_CIPHER_CTX_free(ctx); return -1; }
        int rc = -1, len = 0;
        do {
            if(EVP_DecryptInit_ex(ctx, aes, nullptr, nullptr, nullptr) != 1) break;
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
            if(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
            if(aad && aad_len && EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) != 1) break;
            // tag 校验通
            std::vector<unsigned char> tmp(body ? body : 1);
            if(EVP_DecryptUpdate(ctx, tmp.data(), &len, ct, (int)body) != 1) break;
            int pt_off = len;
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                    const_cast<unsigned char*>(ct + body)) != 1) break;
            if(EVP_DecryptFinal_ex(ctx, tmp.data() + pt_off, &len) != 1) break;
            if(pt_off + len > 0) std::memcpy(pt_out, tmp.data(), (size_t)(pt_off + len));
            pt_len = (unsigned long long)(pt_off + len);
            rc = 0;
        } while(false);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(aes);
        return rc;
    }
#endif
};

// SM4-GCM
// nonce 12 字节、tag 16
// EVP_CIPHER_fetch 取提供者实现
#ifdef FE_WITH_OPENSSL
class Sm4GcmCipher final : public Cipher {
public:
    CryptoMode mode() const override { return CryptoMode::SM4; }
    size_t key_size() const override { return 16; }
    size_t nonce_size() const override { return 12; }
    size_t tag_size() const override { return 16; }
    int encrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) override {
        EVP_CIPHER* sm4 = EVP_CIPHER_fetch(nullptr, "SM4-GCM", nullptr);
        if(!sm4) return -1;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if(!ctx) { EVP_CIPHER_free(sm4); return -1; }
        int rc = -1, len = 0;
        do {
            if(EVP_EncryptInit_ex(ctx, sm4, nullptr, nullptr, nullptr) != 1) break;
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_size(), nullptr) != 1) break;
            if(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
            if(aad && aad_len && EVP_EncryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) != 1) break;
            if(EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int)pt_len) != 1) break;
            int ct_off = len;
            if(EVP_EncryptFinal_ex(ctx, ct_out + ct_off, &len) != 1) break;
            ct_len = (unsigned long long)(ct_off + len);
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size(),
                                    ct_out + ct_len) != 1) break;
            ct_len += tag_size();
            rc = 0;
        } while(false);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(sm4);
        return rc;
    }
    int decrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) override {
        if(ct_len < tag_size()) return -1;
        const size_t body = ct_len - tag_size();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if(!ctx) return -1;
        EVP_CIPHER* sm4 = EVP_CIPHER_fetch(nullptr, "SM4-GCM", nullptr);
        if(!sm4) { EVP_CIPHER_CTX_free(ctx); return -1; }
        int rc = -1, len = 0;
        do {
            if(EVP_DecryptInit_ex(ctx, sm4, nullptr, nullptr, nullptr) != 1) break;
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_size(), nullptr) != 1) break;
            if(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
            if(aad && aad_len && EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) != 1) break;
            // tag 认证通
            std::vector<unsigned char> tmp(body ? body : 1);
            if(EVP_DecryptUpdate(ctx, tmp.data(), &len, ct, (int)body) != 1) break;
            int pt_off = len;
            if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_size(),
                                    const_cast<unsigned char*>(ct + body)) != 1) break;
            if(EVP_DecryptFinal_ex(ctx, tmp.data() + pt_off, &len) != 1) break;
            if(pt_off + len > 0) std::memcpy(pt_out, tmp.data(), (size_t)(pt_off + len));
            pt_len = (unsigned long long)(pt_off + len);
            rc = 0;
        } while(false);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(sm4);
        return rc;
    }
};
#endif

}

std::unique_ptr<Cipher> create_cipher(CryptoMode mode) {
    switch (mode) {
        case CryptoMode::XCHACHA20: return std::make_unique<XChaCha20Cipher>();
        case CryptoMode::AEGIS256:  return std::make_unique<AEGIS256Cipher>();
        case CryptoMode::AES_GCM:   return std::make_unique<AesGcmCipher>();
#ifdef FE_WITH_OPENSSL
        case CryptoMode::SM4:       return std::make_unique<Sm4GcmCipher>();
#endif
    }
    return nullptr;
}
