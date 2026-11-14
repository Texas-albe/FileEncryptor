#pragma once
// 分块 AEAD 算法抽象
// libsodium 具体函数
// 递增策略仍
#include <cstddef>
#include <memory>
#include "FileEncryptor.hpp"   // CryptoMode

class Cipher {
public:
    virtual ~Cipher() = default;
    virtual CryptoMode mode() const = 0;
    virtual size_t key_size() const = 0;
    virtual size_t nonce_size() const = 0;
    virtual size_t tag_size() const = 0;
    // 单块 AEAD 加密
    virtual int encrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) = 0;
    // 单块 AEAD 解密
    virtual int decrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) = 0;
};

// 工厂
std::unique_ptr<Cipher> create_cipher(CryptoMode mode);
