#pragma once
// 分块 AEAD 算法抽象（多算法架构第一阶段）：加解密核心流程不再直接调用
// libsodium 具体函数，统一经工厂获取 Cipher 实例。密钥/ nonce 长度与 nonce
// 递增策略仍由格式层（FileEncryptor.cpp）管理，本接口只管单块加解密。
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
    // 单块 AEAD 加密；ct_out 容量须 ≥ pt_len + tag_size()。成功返回 0。
    virtual int encrypt(const unsigned char* pt, size_t pt_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* ct_out, unsigned long long& ct_len) = 0;
    // 单块 AEAD 解密；pt_out 容量须 ≥ ct_len - tag_size()。成功返回 0。
    virtual int decrypt(const unsigned char* ct, size_t ct_len,
        const unsigned char* aad, size_t aad_len,
        const unsigned char* nonce, const unsigned char* key,
        unsigned char* pt_out, unsigned long long& pt_len) = 0;
};

// 工厂：按头部 mode 字节创建对应算法实例；未知模式返回 nullptr（调用方拒绝）。
std::unique_ptr<Cipher> create_cipher(CryptoMode mode);
