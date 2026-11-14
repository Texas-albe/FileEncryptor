#include "name_obfuscate.hpp"

#include <cctype>
#include <cstdio>
#include <vector>

#include <sodium.h>

#include "FileEncryptor.hpp"    // open_stream / utf8_to_wstring / 尾部常量
#include "fileio_util.hpp"      // fe_file_size
#include "ptd_format.hpp"       // ARGON2_SALT_LEN / put_le32
#include "kdf.hpp"               // ARGON2_OUTPUT_LEN
#include "util/hex.hpp"          // fe::util::to_hex

namespace {

// 文件名信封子密
struct NameKeyScope {
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[XCHACHA20_IV_LEN];
    ~NameKeyScope() {
        sodium_memzero(key, sizeof(key));
        sodium_memzero(nonce, sizeof(nonce));
    }
};

// 由主密钥派生文
void derive_name_key(const unsigned char* master_key,
                     unsigned char name_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    const char tag[] = "FE_name_v4";
    std::vector<unsigned char> in(tag, tag + sizeof(tag) - 1);
    in.insert(in.end(), master_key, master_key + ARGON2_OUTPUT_LEN);
    crypto_generichash(name_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        in.data(), in.size(), nullptr, 0);
    // in 内含主密钥堆副
    sodium_memzero(in.data(), in.size());
}

// 由文件 salt 派生文件
// nonce 派生不变量
void derive_name_nonce(const unsigned char* salt, size_t salt_len,
                       unsigned char nonce[XCHACHA20_IV_LEN]) {
    const char tag[] = "FE_name_nonce_v4";
    std::vector<unsigned char> in(tag, tag + sizeof(tag) - 1);
    in.insert(in.end(), salt, salt + salt_len);
    crypto_generichash(nonce, XCHACHA20_IV_LEN, in.data(), in.size(), nullptr, 0);
}

// SAF content
// 路径写进信封
static std::string uri_percent_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = hex(s[i + 1]), l = hex(s[i + 2]);
            if (h >= 0 && l >= 0) {
                out.push_back((char)((h << 4) | l));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

std::string path_basename_utf8(const std::string& p) {
    if (p.rfind("content://", 0) == 0) {
        std::string last = p;
        size_t pos = last.find_last_of("/\\");
        if (pos != std::string::npos) last = last.substr(pos + 1);
        last = uri_percent_decode(last);               
        pos = last.find_last_of(':');                  // document id 去 primary: 前缀
        if (pos != std::string::npos) last = last.substr(pos + 1);
        pos = last.find_last_of("/\\");                // Download/secret.txt -> secret.txt
        if (pos != std::string::npos) last = last.substr(pos + 1);
        return last;
    }
    size_t pos = p.find_last_of("/\\");
    return (pos != std::string::npos) ? p.substr(pos + 1) : p;
}

// Windows 保留设备名
bool is_windows_reserved_name(const std::string& name) {
#ifdef _WIN32
    // 取基名
    std::string base = name;
    size_t bs = base.find_last_of("/\\");
    if (bs != std::string::npos) base = base.substr(bs + 1);
    size_t dot = base.find('.');
    std::string stem = (dot != std::string::npos) ? base.substr(0, dot) : base;
    // 转大写比较
    std::string up;
    up.reserve(stem.size());
    for (unsigned char c : stem) up.push_back((char)std::toupper(c));
    if (up == "CON" || up == "PRN" || up == "AUX" || up == "NUL") return true;
    auto is_num = [&](const std::string& pre) {
        if (up.size() <= pre.size()) return false;
        if (up.compare(0, pre.size(), pre) != 0) return false;
        for (size_t i = pre.size(); i < up.size(); ++i)
            if (!std::isdigit((unsigned char)up[i])) return false;
        return true;
    };
    for (int i = 1; i <= 9; ++i) {
        if (is_num("COM" + std::to_string(i))) return true;
        if (is_num("LPT" + std::to_string(i))) return true;
    }
#else
    (void)name;
#endif
    return false;
}

}  // namespace

std::string replace_basename(const std::string& p, const std::string& newbase) {
    size_t pos = p.find_last_of("/\\");
    if (pos == std::string::npos) return newbase;
    return p.substr(0, pos + 1) + newbase;
}

std::string make_obfuscated_basename(const std::string& in_path, const SecureBuffer& password) {
    unsigned char key[32];
    crypto_generichash(key, sizeof(key), password.data(), password.size(), nullptr, 0);
    unsigned char seed[32];
    crypto_generichash(seed, sizeof(seed),
        reinterpret_cast<const unsigned char*>(in_path.data()), in_path.size(),
        key, sizeof(key));
    std::string ext;
    ext.reserve(3);
    for (int i = 8; i < 11; ++i) ext.push_back(OBFUSCATED_ALPHA[seed[i] % 26]);
    std::string result = fe::util::to_hex(seed, 8) + "." + ext;
    // key 为密码派生密钥
    sodium_memzero(key, sizeof(key));
    sodium_memzero(seed, sizeof(seed));
    return result;
}

// 用与主密文相同
// master_key 为 Argon2 派生主密钥；salt 取
bool fe_append_encrypted_name_footer(std::ostream& fout, const std::string& in_path,
                                     const unsigned char* master_key, const unsigned char* salt) {
    std::string base = path_basename_utf8(in_path);
    if (base.empty() || base.size() > NAME_FOOTER_MAX_NAME) return true; 
    NameKeyScope nk;
    derive_name_key(master_key, nk.key);
    derive_name_nonce(salt, ARGON2_SALT_LEN, nk.nonce);
    std::vector<unsigned char> env(base.size() + NAME_ENV_TAG);
    unsigned long long envlen = 0;
    // AAD 绑定本文件 salt
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        env.data(), &envlen,
        reinterpret_cast<const unsigned char*>(base.data()), base.size(),
        salt, ARGON2_SALT_LEN, nullptr, nk.nonce, nk.key);
    if (rc != 0 || envlen != (unsigned long long)env.size()) return false;
    unsigned char tail[NAME_FOOTER_HDR];
    memcpy(tail, NAME_FOOTER_MAGIC_ENC, 4);
    uint32_t n = (uint32_t)base.size();
    put_le32(tail + 4, n);
    // 文件流可能
    if(dynamic_cast<std::fstream*>(&fout)) fout.seekp(0, std::ios::end);
    fout.write(reinterpret_cast<const char*>(env.data()), (std::streamsize)envlen);
    fout.write(reinterpret_cast<const char*>(tail), NAME_FOOTER_HDR);
    fout.flush();
    return fout.good();
}

// 尾部元数据未认
bool fe_sanitize_restored_name(const std::string& n) {
    if (n.empty() || n.size() > 255) return false;
    if (n[0] == '.') return false;                       // 隐藏文件
    if (n.find("..") != std::string::npos) return false; // 路径穿越组件
    for (unsigned char c : n) {
        if (c < 0x20 || c == 0x7F) return false;        // 控制字符
        if (c == '/' || c == '\\' || c == ':') return false; // 路径分隔符 / 盘符
    }
#ifdef _WIN32
    // Windows 会静默剥离结尾
    // "a. .txt"
    if (n.back() == '.' || n.back() == ' ') return false;
    if (is_windows_reserved_name(n)) return false;       // CON/PRN/AUX/NUL/COMx/LPTx
#endif
    return true;
}

// 仅读取尾部结构
// 兼容加密尾部
// 核心实现接受 istream + 已
static bool peek_footer_len_impl(std::istream& f, uint64_t sz,
                                 uint64_t& footer_len, uint32_t* wm_len_out) {
    footer_len = 0;
    if (wm_len_out) *wm_len_out = 0;
    if (sz < (uint64_t)(NAME_FOOTER_HDR + 16)) return false;
    f.clear();
    f.seekg((std::streamoff)(sz - NAME_FOOTER_HDR), std::ios::beg);
    unsigned char tail[NAME_FOOTER_HDR];
    if (!f.read(reinterpret_cast<char*>(tail), NAME_FOOTER_HDR)) return false;
    bool enc = (memcmp(tail, NAME_FOOTER_MAGIC_ENC, 4) == 0);
    bool plain = (memcmp(tail, NAME_FOOTER_MAGIC, 4) == 0);
    if (!enc && !plain) return false;
    uint32_t n = 0;
    for (int i = 0; i < 4; ++i) n |= ((uint32_t)tail[4 + i]) << (i * 8);
    if (n == 0 || n > NAME_FOOTER_MAX_NAME) return false;
    uint64_t env = enc ? (uint64_t)n + NAME_ENV_TAG : (uint64_t)n;
    uint64_t total = env + NAME_FOOTER_HDR;
    if (sz < total) return false;
    // 尾部布局
    // wm_len 位于 FENX 信封起点
    const uint64_t tail_start = sz - total;
    if (tail_start >= 4) {
        unsigned char wm4[4] = {0};
        if (f.seekg((std::streamoff)(tail_start - 4), std::ios::beg) &&
            f.read(reinterpret_cast<char*>(wm4), 4) &&
            (wm4[0] | wm4[1] | wm4[2] | wm4[3]) != 0) {
            uint32_t wm = ((uint32_t)wm4[0] << 24) | ((uint32_t)wm4[1] << 16) |
                          ((uint32_t)wm4[2] << 8) | (uint32_t)wm4[3];
            if (wm > 0 && wm <= tail_start - 4 - total) {
                total += (uint64_t)4 + (uint64_t)wm;
                if (wm_len_out) *wm_len_out = wm;
            }
        }
    }
    footer_len = total;
    return true;
}

bool fe_peek_name_footer_len(const std::string& ptd_path, uint64_t& footer_len,
                             uint32_t* wm_len_out) {
    footer_len = 0;
    if (wm_len_out) *wm_len_out = 0;
    int64_t sz = fe_file_size(ptd_path);
    if (sz < (int64_t)(NAME_FOOTER_HDR + 16)) return false;
    std::ifstream f;
    if (!open_stream(f, ptd_path, std::ios::binary)) return false;
    bool ok = peek_footer_len_impl(f, (uint64_t)sz, footer_len, wm_len_out);
    f.close();
    return ok;
}

// 流版
bool fe_peek_name_footer_len_stream(std::istream& f, uint64_t sz, uint64_t& footer_len) {
    return peek_footer_len_impl(f, sz, footer_len, nullptr);
}

// 解密尾部
bool fe_decrypt_name_footer(const std::string& ptd_path, std::string& out_name,
                            const unsigned char* master_key, const unsigned char* salt) {
    out_name.clear();
    int64_t sz = fe_file_size(ptd_path);
    if (sz < (int64_t)(NAME_FOOTER_HDR + 16)) return false;
    std::ifstream f;
    if (!open_stream(f, ptd_path, std::ios::binary)) return false;
    f.seekg(-(std::streamoff)NAME_FOOTER_HDR, std::ios::end);
    unsigned char tail[NAME_FOOTER_HDR];
    if (!f.read(reinterpret_cast<char*>(tail), NAME_FOOTER_HDR)) return false;
    bool enc = (memcmp(tail, NAME_FOOTER_MAGIC_ENC, 4) == 0);
    bool plain = (memcmp(tail, NAME_FOOTER_MAGIC, 4) == 0);
    if (!enc && !plain) return false;
    uint32_t n = 0;
    for (int i = 0; i < 4; ++i) n |= ((uint32_t)tail[4 + i]) << (i * 8);
    if (n == 0 || n > NAME_FOOTER_MAX_NAME) return false;
    uint64_t env_len = enc ? (uint64_t)n + NAME_ENV_TAG : (uint64_t)n;
    uint64_t total = env_len + NAME_FOOTER_HDR;
    if ((uint64_t)sz < total) return false;
    f.seekg(-(std::streamoff)total, std::ios::end);
    if (plain) {
        // 旧版明文尾部
        std::string raw((size_t)n, '\0');
        if (!f.read(&raw[0], (std::streamsize)n)) return false;
        if (!fe_sanitize_restored_name(raw)) return false;
        out_name = raw;
        return true;
    }
    std::vector<unsigned char> env((size_t)env_len);
    if (!f.read(reinterpret_cast<char*>(env.data()), (std::streamoff)env_len)) return false;
    NameKeyScope nk;
    derive_name_key(master_key, nk.key);
    derive_name_nonce(salt, ARGON2_SALT_LEN, nk.nonce);
    std::vector<unsigned char> plain_out((size_t)n);
    unsigned long long mlen = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plain_out.data(), &mlen, nullptr,
        env.data(), env_len, salt, ARGON2_SALT_LEN, nk.nonce, nk.key);
    if (rc != 0) return false;            // 密钥错
    if (mlen != (unsigned long long)n) return false;
    std::string raw(reinterpret_cast<char*>(plain_out.data()), (size_t)mlen);
    if (!fe_sanitize_restored_name(raw)) return false;
    out_name = raw;
    return true;
}
