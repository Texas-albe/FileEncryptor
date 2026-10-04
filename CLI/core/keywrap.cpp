// 密钥包装层：用 AES-256-KWP(RFC 5649) / AES-KW(RFC 3394) / 公钥封装把 DEK 藏起来。
// 与载荷加密正交——包装对象是密钥而非文件内容，故不进 -m。
//   口令路线：Argon2id 派生 KEK -> KWP 包装 DEK
//   公钥路线：复用非对称层的收件人 stanza，X25519 / X448 / ML-KEM 皆可，无需口令
//   AES-KW：RFC 3394 严格 8 字节倍数，供旧工具互操作
#include "keywrap.hpp"
#include "FileEncryptor.hpp"
#include "asym_crypto.hpp"
#include "ptd_format.hpp"

#include <sodium.h>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fstream>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

// 包装/解包都要落盘：DEK 与 blob 都不大，整块读写即可。
bool keywrap_read_file(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream f;
    if(!open_stream(f, path, std::ios::binary)) return false;
    f.seekg(0, std::ios::end);
    const std::streamoff n = f.tellg();
    if(n < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize((size_t)n);
    if(n > 0) f.read((char*)out.data(), n);
    return f.gcount() == n;
}

// 独占创建：blob 覆盖不会破坏既有包装文件，与私钥落盘同理
bool keywrap_write_file_exclusive(const std::string& path, const unsigned char* p, size_t n) {
    clear_readonly_attribute(path);
#ifdef _WIN32
    const std::wstring wp = utf8_to_wstring(path);
    int fd = _wopen(wp.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) {
        if (errno == EEXIST) {
            // 已存在：改用截断打开（调用方已先查过 -y，允许覆盖）
            fd = _wopen(wp.c_str(), _O_WRONLY | _O_TRUNC | _O_BINARY);
            if (fd < 0) return false;
        } else {
            return false;
        }
    }
    FILE* fp = _fdopen(fd, "wb");
    if (!fp) { _close(fd); return false; }
    const size_t wr = n ? fwrite(p, 1, n, fp) : 0;
    const bool ok = (wr == n);
    fclose(fp);
    return ok;
#else
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            fd = ::open(path.c_str(), O_WRONLY | O_TRUNC, 0600);
            if (fd < 0) return false;
        } else {
            return false;
        }
    }
    const bool ok = n ? (::write(fd, p, n) == (ssize_t)n) : true;
    ::close(fd);
    return ok;
#endif
}

#ifdef FE_WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

namespace {

constexpr char kMagic[4] = { 'F', 'E', 'K', 'W' };
constexpr uint8_t kVersion = 1;

constexpr uint8_t kByPass = 1;      // Argon2id KEK + KWP
constexpr uint8_t kByPubkey = 2;   // 收件人 stanza（X25519 / X448 / ML-KEM）
constexpr uint8_t kByAesKw = 3;    // AES-KW（严格 8 字节倍数）

constexpr size_t kDekLen = 32;
// magic(4) + version(1) + alg(1) + eph_len(2) + salt_len(2) + flags(2)
constexpr size_t kHdrFixed = 12;

void put_be16(std::vector<unsigned char>& v, size_t x) {
    v.push_back((unsigned char)(x >> 8));
    v.push_back((unsigned char)x);
}

} // namespace

const char* keywrap_alg_name(uint8_t by) {
    switch (by) {
        case kByAesKw:  return "aes-kw";
        case kByPubkey: return "pubkey";
        default:        return "kwp";
    }
}

uint8_t keywrap_alg_from_name(const std::string& s) {
    if (s == "aes-kw") return kByAesKw;
    if (s == "pubkey") return kByPubkey;
    return kByPass;
}

bool keywrap_available() {
#ifdef FE_WITH_OPENSSL
    return true;
#else
    return false;
#endif
}

#ifdef FE_WITH_OPENSSL
namespace {

// AES-KW（RFC 3394）：只接受 8 字节倍数，长度须 >= 16 字节（2 个半块）。
bool aes_kw_wrap(const unsigned char* kek, const unsigned char* in, size_t in_len,
                 std::vector<unsigned char>& out) {
    if (in_len < 16 || in_len % 8 != 0) return false;
    EVP_CIPHER* c = EVP_CIPHER_fetch(nullptr, "AES-256-WRAP", nullptr);
    if (!c) { ERR_clear_error(); return false; }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { EVP_CIPHER_free(c); return false; }
    out.assign(in_len + 16, 0);
    int total = 0, len = 0;
    bool rc = EVP_EncryptInit_ex(ctx, c, nullptr, kek, nullptr) == 1
           && EVP_EncryptUpdate(ctx, out.data(), &len, in, (int)in_len) == 1;
    if (rc) {
        total = len;
        rc = EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1;
        total += len;
    }
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    if (!rc) { ERR_clear_error(); return false; }
    out.resize((size_t)total);
    return true;
}

bool aes_kw_unwrap(const unsigned char* kek, const unsigned char* in, size_t in_len,
                   std::vector<unsigned char>& out) {
    if (in_len < 24 || in_len % 8 != 0) return false;
    EVP_CIPHER* c = EVP_CIPHER_fetch(nullptr, "AES-256-WRAP", nullptr);
    if (!c) { ERR_clear_error(); return false; }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { EVP_CIPHER_free(c); return false; }
    out.assign(in_len, 0);
    int total = 0, len = 0;
    bool rc = EVP_DecryptInit_ex(ctx, c, nullptr, kek, nullptr) == 1
           && EVP_DecryptUpdate(ctx, out.data(), &len, in, (int)in_len) == 1;
    if (rc) {
        total = len;
        rc = EVP_DecryptFinal_ex(ctx, out.data() + total, &len) == 1;
        total += len;
    }
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    if (!rc) { ERR_clear_error(); return false; }
    out.resize((size_t)total);
    return true;
}

// RFC 5649 AIV = A65959A6 || BE32(明文长度)
void kwp_aiv(uint8_t* aiv, size_t plain_len) {
    static const uint8_t head[4] = { 0xA6, 0x59, 0x59, 0xA6 };
    memcpy(aiv, head, 4);
    const uint32_t v = (uint32_t)plain_len;
    aiv[4] = (uint8_t)(v >> 24); aiv[5] = (uint8_t)(v >> 16);
    aiv[6] = (uint8_t)(v >> 8);  aiv[7] = (uint8_t)v;
}

// KWP 包任意长度：8 字节 AIV 前缀 + 明文补零到 8 的倍数，整体走 KW。
bool kwp_wrap(const unsigned char* kek, const unsigned char* in, size_t in_len,
              std::vector<unsigned char>& out) {
    if (in_len == 0 || in_len > 0x00FFFFFFu) return false;
    const size_t kw_in = 8 + ((in_len + 7) / 8) * 8;
    std::vector<unsigned char> buf(kw_in, 0);
    kwp_aiv(buf.data(), in_len);
    memcpy(buf.data() + 8, in, in_len);
    const bool rc = aes_kw_wrap(kek, buf.data(), kw_in, out);
    sodium_memzero(buf.data(), buf.size());
    return rc;
}

bool kwp_unwrap(const unsigned char* kek, const unsigned char* in, size_t in_len,
                std::vector<unsigned char>& out) {
    if (in_len < 24 || in_len % 8 != 0) return false;
    std::vector<unsigned char> plain;
    if (!aes_kw_unwrap(kek, in, in_len, plain)) return false;
    if (plain.size() < 8) return false;
    // AIV 头是固定标，KW 完整性检查之外的第二道
    static const uint8_t head[4] = { 0xA6, 0x59, 0x59, 0xA6 };
    if (memcmp(plain.data(), head, 4) != 0) return false;
    const size_t len = ((size_t)plain[4] << 24) | ((size_t)plain[5] << 16)
                     | ((size_t)plain[6] << 8) | (size_t)plain[7];
    if (len == 0 || len + 8 > plain.size()) return false;
    out.assign(plain.begin() + 8, plain.begin() + 8 + len);
    sodium_memzero(plain.data(), plain.size());
    return true;
}

} // namespace
#endif

bool keywrap_pack(const unsigned char* dek, size_t dek_len,
                  const unsigned char* kek, uint8_t by,
                  const std::string& to_pub,
                  const unsigned char* salt, size_t salt_len,
                  std::vector<unsigned char>& out_blob,
                  std::string& error) {
#ifndef FE_WITH_OPENSSL
    (void)dek; (void)dek_len; (void)kek; (void)by; (void)to_pub;
    (void)salt; (void)salt_len; (void)out_blob;
    error = "key wrap requires OpenSSL";
    return false;
#else
    if (dek_len != kDekLen) { error = "DEK must be 32 bytes"; return false; }

    std::vector<unsigned char> cipher;

    if (by == kByPubkey) {
        if (to_pub.empty()) { error = "--to <recipient public key> required"; return false; }
        // 复用非对称层的 stanza：三种算法（X25519/X448/ML-KEM）都已在那里实现并测试过
        std::vector<std::string> pubs{ to_pub };
        std::vector<RecipientStanza> stanzas;
        AsymOutcome w = fe_wrap_dek_to_recipients(dek, pubs, stanzas);
        if (!w.ok) { error = w.error; return false; }
        if (!serialize_recipients(stanzas, cipher)) { error = "recipient serialize failed"; return false; }
    } else {
        if (!kek) { error = "KEK required"; return false; }
        if (!salt || !salt_len) { error = "KDF salt required"; return false; }
        const bool rc = (by == kByAesKw) ? aes_kw_wrap(kek, dek, dek_len, cipher)
                                         : kwp_wrap(kek, dek, dek_len, cipher);
        if (!rc) { error = "AES wrap failed"; return false; }
    }

    std::vector<unsigned char> blob;
    blob.insert(blob.end(), kMagic, kMagic + 4);
    blob.push_back(kVersion);
    blob.push_back(by);
    // eph 恒为 0：公钥路线的临时公钥已包含在 recipient block 内，无需头部再放一份
    put_be16(blob, 0);
    put_be16(blob, (by == kByPass || by == kByAesKw) ? salt_len : 0);
    put_be16(blob, 0);
    if ((by == kByPass || by == kByAesKw) && salt && salt_len)
        blob.insert(blob.end(), salt, salt + salt_len);
    blob.insert(blob.end(), cipher.begin(), cipher.end());
    out_blob.swap(blob);
    return true;
#endif
}

bool keywrap_unpack(const unsigned char* blob, size_t blob_len,
                    const unsigned char* kek,
                    const std::string& identity,
                    std::vector<unsigned char>& out_dek,
                    uint8_t& out_alg,
                    std::string& error) {
#ifndef FE_WITH_OPENSSL
    (void)blob; (void)blob_len; (void)kek; (void)identity; (void)out_dek; (void)out_alg;
    error = "key wrap requires OpenSSL";
    return false;
#else
    if (blob_len < kHdrFixed) { error = "blob too short"; return false; }
    if (memcmp(blob, kMagic, 4) != 0) { error = "not a FEKW blob"; return false; }
    if (blob[4] != kVersion) { error = "unsupported version"; return false; }
    const uint8_t by = blob[5];
    const size_t eph = ((size_t)blob[6] << 8) | blob[7];
    const size_t sl  = ((size_t)blob[8] << 8) | blob[9];
    if (blob_len < kHdrFixed + eph + sl) { error = "blob truncated"; return false; }
    // 变长区在头部之后依次是 salt、ephemeral、密文
    const unsigned char* salt = blob + kHdrFixed;
    const unsigned char* cipher = salt + sl + eph;
    const size_t cipher_len = blob_len - kHdrFixed - eph - sl;
    out_alg = by;

    if (by == kByPubkey) {
        if (identity.empty()) {
            error = "--identity <private key> required for a pubkey blob";
            return false;
        }
        std::vector<RecipientStanza> stanzas;
        if (!parse_recipients(cipher, cipher_len, stanzas)) {
            error = "recipient block is corrupt";
            return false;
        }
        unsigned char dek[32];
        AsymOutcome r = fe_recover_dek_from_stanzas(stanzas, identity, dek);
        if (!r.ok) {
            sodium_memzero(dek, sizeof dek);
            error = "unwrap failed (wrong key or tampered blob)";
            return false;
        }
        out_dek.assign(dek, dek + kDekLen);
        sodium_memzero(dek, sizeof dek);
        return true;
    }

    if (!kek) { error = "KEK required"; return false; }
    const bool rc = (by == kByAesKw) ? aes_kw_unwrap(kek, cipher, cipher_len, out_dek)
                                     : kwp_unwrap(kek, cipher, cipher_len, out_dek);
    if (!rc) { error = "unwrap failed (wrong password or tampered blob)"; return false; }
    return true;
#endif
}