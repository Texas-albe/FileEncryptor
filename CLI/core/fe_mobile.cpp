// 移动端单文件加
// 铁律
// P/Invoke 按 C 名 GetProcAddress 静默失
#include "fe_mobile.h"

#include <cstring>
#include <cerrno>
#include <functional>
#include <istream>
#include <ostream>
#include <streambuf>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <cstdio>

#include <sodium.h>

#include "FileEncryptor.hpp"
#include "cipher.hpp"
#include "ptd_meta.hpp"
#include "asym_crypto.hpp"
#include "keywrap.hpp"
#include "kdf.hpp"
#include "ptd_format.hpp"

// libsodium 必须
// 本库
// 用库加载期
namespace {
struct SodiumAutoInit {
    SodiumAutoInit() { sodium_init(); }
};
static SodiumAutoInit g_sodium_autoinit;
}

#ifdef _WIN32
// Win32 兼容层
// 使同一份 fd 实现
// 注意
// 无效桌面侧验证
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
using fe_m_ssize_t = intptr_t;
using fe_m_stat = struct _stat64;
#define fe_m_read   _read
#define fe_m_write  _write
#define fe_m_close  _close
#define fe_m_lseek  _lseek
#define fe_m_fstat  _fstat64
#define fe_m_ftruncate(fd, len) (_chsize_s((fd), (__int64)(len)) == 0 ? 0 : -1)
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
using fe_m_ssize_t = ssize_t;
using fe_m_stat = struct stat;
#define fe_m_read  ::read
#define fe_m_write ::write
#define fe_m_close ::close
#define fe_m_lseek  ::lseek
#define fe_m_fstat  ::fstat
#define fe_m_ftruncate ::ftruncate
#endif

namespace {

// fd 输入流缓冲
// 上层据此回退全
class FdInBuf : public std::streambuf {
public:
    explicit FdInBuf(int fd) : fd_(fd) {}
protected:
    int_type underflow() override {
        if(gptr() < egptr()) return traits_type::to_int_type(*gptr());
        fe_m_ssize_t n = fe_m_read(fd_, rbuf_, sizeof(rbuf_));
        if(n <= 0) return traits_type::eof();
        char* b = reinterpret_cast<char*>(rbuf_);
        setg(b, b, b + n);
        return traits_type::to_int_type(*gptr());
    }
    pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                     std::ios_base::openmode which) override {
        if(!(which & std::ios_base::in)) return pos_type(off_type(-1));
        int whence = (dir == std::ios_base::beg) ? SEEK_SET
                 : (dir == std::ios_base::cur) ? SEEK_CUR : SEEK_END;
        intptr_t r = fe_m_lseek(fd_, (long)off, whence);
        if(r < 0) return pos_type(off_type(-1));
        setg(nullptr, nullptr, nullptr);   // 位置已变
        return pos_type(r);
    }
private:
    int fd_;
    unsigned char rbuf_[64 * 1024];
};

// fd 输出流缓冲
// seekp 走 lseek
class FdOutBuf : public std::streambuf {
public:
    explicit FdOutBuf(int fd) : fd_(fd) {}
protected:
    int_type overflow(int_type c) override {
        if(traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
        char ch = traits_type::to_char_type(c);
        if(fe_m_write(fd_, &ch, 1) != 1) return traits_type::eof();
        return traits_type::not_eof(c);
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        std::streamsize left = n;
        while(left > 0) {
            fe_m_ssize_t w = fe_m_write(fd_, s, (size_t)left);
            if(w <= 0) return n - left;
            s += w;
            left -= w;
        }
        return n;
    }
    int sync() override { return 0; }
    pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                     std::ios_base::openmode which) override {
        if(!(which & std::ios_base::out)) return pos_type(off_type(-1));
        int whence = (dir == std::ios_base::beg) ? SEEK_SET
                 : (dir == std::ios_base::cur) ? SEEK_CUR : SEEK_END;
        intptr_t r = fe_m_lseek(fd_, (long)off, whence);
        if(r < 0) return pos_type(off_type(-1));
        return pos_type(r);
    }
private:
    int fd_;
};

uint64_t fd_size(int fd) {
    fe_m_stat st{};
    if(fe_m_fstat(fd, &st) != 0) return 0;
    return (uint64_t)st.st_size;
}

// C 进度回调 → std
std::function<void(size_t, size_t)> wrap_progress(fe_m_progress_fn cb, void* user) {
    if(!cb) return [](size_t, size_t) {};
    return [cb, user](size_t done, size_t total) {
        cb((uint64_t)done, (uint64_t)total, user);
    };
}

// FileEncryptor 返回 bool；解密路径
// 其余
int to_code(bool ok, bool decrypt_path=false) {
    if(ok) return FE_M_OK;
    return (decrypt_path && fe_last_fail_auth()) ? FE_M_E_AUTH : FE_M_E_INT;
}

}  // namespace


// 以下导出函数均

uint32_t fe_m_abi_version(void) {
    return FE_M_ABI_VERSION;
}

const char* fe_m_strerror(int code) {
    switch(code) {
        case FE_M_OK:      return "ok";
        case FE_M_E_ARG:   return "invalid argument";
        case FE_M_E_IO:    return "io error";
        case FE_M_E_AUTH:  return "authentication failed (wrong password or tampered)";
        case FE_M_E_UNSUP: return "unsupported mode";
        case FE_M_E_MEM:   return "out of memory";
        case FE_M_E_HASH:  return "plaintext integrity check failed";
        case FE_M_E_INT:   return "internal error";
        default:           return "unknown error";
    }
}

int fe_m_mode_supported(int mode) {
    sodium_init();   // 兜底
    switch(mode) {
        case FE_M_MODE_XCHACHA20: return 1;
        case FE_M_MODE_AEGIS256:  return aegis256_supported() ? 1 : 0;
        case FE_M_MODE_AES_GCM:   return aes_gcm_supported() ? 1 : 0;
        case FE_M_MODE_SM4:       return sm4_supported() ? 1 : 0;
        default:                  return 0;
    }
}

int fe_m_encrypt_fd(int in_fd, uint64_t in_size, int out_fd,
                    const char* password, size_t pass_len,
                    int mode, int compress_level,
                    fe_m_progress_fn progress, void* user) {
    sodium_init();
    if(in_fd < 0 || out_fd < 0 || !password || pass_len == 0) return FE_M_E_ARG;
    if(mode != FE_M_MODE_XCHACHA20 && mode != FE_M_MODE_AEGIS256 &&
       mode != FE_M_MODE_AES_GCM && mode != FE_M_MODE_SM4) return FE_M_E_ARG;
    if(!fe_m_mode_supported(mode)) return FE_M_E_UNSUP;

    CryptoMode cm = (mode == FE_M_MODE_AEGIS256) ? CryptoMode::AEGIS256
                 : (mode == FE_M_MODE_AES_GCM)   ? CryptoMode::AES_GCM
                 : (mode == FE_M_MODE_SM4)       ? CryptoMode::SM4
                                                 : CryptoMode::XCHACHA20;

    FdInBuf in_buf(in_fd);
    std::istream in(&in_buf);
    FdOutBuf out_buf(out_fd);
    std::ostream out(&out_buf);
    // 输出
    if(fe_m_lseek(out_fd, 0, SEEK_SET) < 0) return FE_M_E_IO;

    // 明文大小
    uint64_t sz = in_size ? in_size : fd_size(in_fd);
    (void)sz;

    SecureBuffer pw(pass_len);
    std::memcpy(pw.data(), password, pass_len);

    bool ok = false;
    try {
        ok = encrypt_file(std::string(), std::string(), pw, cm,
                          wrap_progress(progress, user),
                          /*resume=*/false, compress_level,
                          /*asym_mode=*/false, nullptr, nullptr,
                          /*ext_salt=*/nullptr, /*ext_kek=*/nullptr,
                          /*chunk_override=*/0, &in, &out);
    } catch(const std::exception&) {
        ok = false;
    } catch(...) {
        ok = false;
    }
    out.flush();
    return to_code(ok);
}

// 解密公共实现
static int fe_m_decrypt_fd_impl(int in_fd, int out_fd,
                    const char* password, size_t pass_len,
                    const unsigned char* ext_kek, size_t ext_kek_len,
                    int force_overwrite, uint64_t preview_bytes,
                    fe_m_progress_fn progress, void* user) {
    sodium_init();
    if(in_fd < 0 || out_fd < 0 || !password || pass_len == 0) return FE_M_E_ARG;

    FdInBuf in_buf(in_fd);
    std::istream in(&in_buf);
    FdOutBuf out_buf(out_fd);
    std::ostream out(&out_buf);
    if(fe_m_lseek(out_fd, 0, SEEK_SET) < 0) {
        // 管道等不可 seek 输出
#ifdef _WIN32
        if(errno != ESPIPE) return FE_M_E_IO;
#else
        if(errno != ESPIPE) return FE_M_E_IO;
#endif
    } else if(fe_m_ftruncate(out_fd, 0) != 0) return FE_M_E_IO;

    SecureBuffer pw(pass_len);
    std::memcpy(pw.data(), password, pass_len);

    bool ok = false;
    try {
        ok = decrypt_file(std::string(), std::string(), pw,
                          wrap_progress(progress, user),
                          /*silent=*/false, /*resume=*/false,
                          /*ext_key=*/nullptr, ext_kek, ext_kek_len,
                          /*verify_only=*/false, preview_bytes,
                          /*asym_identity=*/std::string(),
                          /*force_overwrite=*/force_overwrite != 0,
                          &out, &in);
    } catch(const std::exception&) {
        ok = false;
    } catch(...) {
        ok = false;
    }
    out.flush();
    return to_code(ok, true);
}

int fe_m_decrypt_fd(int in_fd, int out_fd,
                    const char* password, size_t pass_len,
                    int force_overwrite, uint64_t preview_bytes,
                    fe_m_progress_fn progress, void* user) {
    return fe_m_decrypt_fd_impl(in_fd, out_fd, password, pass_len,
                                /*ext_kek=*/nullptr, /*ext_kek_len=*/0,
                                force_overwrite, preview_bytes, progress, user);
}

int fe_m_decrypt_fd_kek(int in_fd, int out_fd,
                    const char* password, size_t pass_len,
                    const unsigned char* ext_kek, size_t ext_kek_len,
                    int force_overwrite, uint64_t preview_bytes,
                    fe_m_progress_fn progress, void* user) {
    return fe_m_decrypt_fd_impl(in_fd, out_fd, password, pass_len,
                                ext_kek, ext_kek_len,
                                force_overwrite, preview_bytes, progress, user);
}

int fe_m_verify_fd(int in_fd, const char* password, size_t pass_len) {
    sodium_init();
    if(in_fd < 0 || !password || pass_len == 0) return FE_M_E_ARG;

    FdInBuf in_buf(in_fd);
    std::istream in(&in_buf);

    SecureBuffer pw(pass_len);
    std::memcpy(pw.data(), password, pass_len);

    bool ok = false;
    try {
        // verify_only
        ok = decrypt_file(std::string(), std::string(), pw,
                          [](size_t, size_t) {},
                          /*silent=*/true, /*resume=*/false,
                          nullptr, nullptr, 0,
                          /*verify_only=*/true, /*preview_bytes=*/0,
                          std::string(), /*force_overwrite=*/false,
                          /*out_stream=*/nullptr, &in);
    } catch(const std::exception&) {
        ok = false;
    } catch(...) {
        ok = false;
    }
    return to_code(ok, true);
}

int fe_m_hash_fd(int fd, uint64_t size, unsigned char* out32) {
    sodium_init();
    if(fd < 0 || !out32) return FE_M_E_ARG;
    uint64_t sz = size ? size : fd_size(fd);
    if(fe_m_lseek(fd, 0, SEEK_SET) < 0) return FE_M_E_IO;

    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, crypto_generichash_BYTES);
    std::vector<unsigned char> buf(1024 * 1024);
    uint64_t left = sz;
    while(left > 0) {
        size_t want = (size_t)std::min<uint64_t>(left, buf.size());
        fe_m_ssize_t n = fe_m_read(fd, buf.data(), want);
        if(n <= 0) { sodium_memzero(buf.data(), buf.size()); return FE_M_E_IO; }
        crypto_generichash_update(&st, buf.data(), (size_t)n);
        left -= (uint64_t)n;
    }
    sodium_memzero(buf.data(), buf.size());
    crypto_generichash_final(&st, out32, crypto_generichash_BYTES);
    return FE_M_OK;
}

// R58
// 复用 core/ptd_meta.cpp
// 物化到应用私有 cache
namespace {
static std::string ptd_meta_json(const PtdMeta& m) {
    std::ostringstream o;
    o << "{\"valid\":" << (m.valid ? "true" : "false")
      << ",\"version\":" << (unsigned)m.version
      << ",\"mode\":" << (int)m.mode
      << ",\"opslimit\":" << m.opslimit
      << ",\"memlimit_kb\":" << m.memlimit_kb
      << ",\"salt_hex\":\"" << m.salt_hex << "\""
      << ",\"iv_hex\":\"" << m.iv_hex << "\""
      << ",\"orig_size\":" << m.orig_size
      << ",\"chunk_size\":" << m.chunk_size
      << ",\"total_chunks\":" << m.total_chunks
      << ",\"plaintext_hash_hex\":\"" << m.plaintext_hash_hex << "\""
      << ",\"has_name_footer\":" << (m.has_name_footer ? "true" : "false")
      << ",\"compression\":" << (unsigned)m.compression
      << ",\"comp_level\":" << (unsigned)m.comp_level
      << ",\"dek_wrapped\":" << (m.dek_wrapped ? "true" : "false")
      << ",\"key_version\":" << m.key_version
      << "}";
    return o.str();
}
static int fe_m_copy_out(const std::string& s, char* out, size_t cap) {
    if (!out || cap == 0) return FE_M_E_ARG;
    if (s.size() + 1 > cap) return FE_M_E_MEM;
    std::memcpy(out, s.data(), s.size());
    out[s.size()] = '\0';
    return FE_M_OK;
}
}  // namespace

int fe_m_info(const char* ptd_path, char* out_json, size_t cap) {
    sodium_init();
    if (!ptd_path || !out_json || cap == 0) return FE_M_E_ARG;
    PtdMeta m;
    bool ok = false;
    try { ok = read_ptd_metadata(std::string(ptd_path), m); } catch (...) { ok = false; }
    if (!ok || !m.valid) return FE_M_E_INT;
    return fe_m_copy_out(ptd_meta_json(m), out_json, cap);
}

int fe_m_original_name(const char* ptd_path, const char* password, size_t pass_len,
                       char* out_name, size_t cap) {
    sodium_init();
    if (!ptd_path || !password || pass_len == 0 || !out_name || cap == 0) return FE_M_E_ARG;
    SecureBuffer pw(pass_len);
    std::memcpy(pw.data(), password, pass_len);
    std::string name;
    bool ok = false;
    try { ok = read_original_name(std::string(ptd_path), name, pw); } catch (...) { ok = false; }
    if (!ok || name.empty()) return FE_M_E_AUTH;
    return fe_m_copy_out(name, out_name, cap);
}

int fe_m_rewrap(const char* ptd_path, const char* old_password, size_t old_len,
                const char* new_password, size_t new_len) {
    sodium_init();
    if (!ptd_path || !old_password || old_len == 0 || !new_password || new_len == 0)
        return FE_M_E_ARG;
    SecureBuffer oldpw(old_len), newpw(new_len);
    std::memcpy(oldpw.data(), old_password, old_len);
    std::memcpy(newpw.data(), new_password, new_len);
    bool ok = false;
    try { ok = rewrap_file_with(std::string(ptd_path), oldpw, newpw, true); }
    catch (...) { ok = false; }
    return ok ? FE_M_OK : FE_M_E_AUTH;
}


// 非对称 / FEKW / 库 PQC 导出实
namespace {

// 按换行/逗号拆分
std::vector<std::string> split_recips(const char* p, size_t n) {
    std::vector<std::string> out;
    if (!p || n == 0) return out;
    std::string all(p, n);
    size_t start = 0;
    while (start <= all.size()) {
        size_t e = all.find_first_of("\n\r,", start);
        std::string s = all.substr(start, e == std::string::npos ? std::string::npos : e - start);
        size_t a = 0, b = s.size();
        while (a < b && (unsigned char)s[a] <= 0x20) ++a;
        while (b > a && (unsigned char)s[b - 1] <= 0x20) --b;
        s = s.substr(a, b - a);
        if (s.rfind("publickey:", 0) == 0) s = s.substr(10);
        if (!s.empty()) out.push_back(s);
        if (e == std::string::npos) break;
        start = e + 1;
    }
    return out;
}

void put_be32_vec(std::vector<unsigned char>& v, uint32_t x) {
    v.push_back((unsigned char)(x >> 24));
    v.push_back((unsigned char)(x >> 16));
    v.push_back((unsigned char)(x >> 8));
    v.push_back((unsigned char)x);
}

bool get_be32_vec(const unsigned char* p, uint32_t& x) {
    x = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return true;
}

// 密码路线 KDF
bool fekw_derive_kek(const char* pw, size_t pw_len,
                      const unsigned char* salt, size_t salt_len,
                      unsigned char kek[32]) {
    if (!pw || pw_len == 0 || !salt || salt_len != crypto_pwhash_SALTBYTES) return false;
    return derive_key((const unsigned char*)pw, pw_len, salt,
                      kek, ARGON2_OPS_DEFAULT, (size_t)ARGON2_MEM_DEFAULT_KB * 1024);
}

int copy_blob(const std::vector<unsigned char>& src,
              unsigned char* dst, size_t cap, size_t* out_len) {
    if (!dst || !out_len || src.size() > cap) return FE_M_E_MEM;
    if (!src.empty()) std::memcpy(dst, src.data(), src.size());
    *out_len = src.size();
    return FE_M_OK;
}

}  // namespace

int fe_m_asym_supported(void) {
    // 桩构建
    if (!keywrap_available()) return 0;
    std::string pub, priv;
    AsymOutcome o = fe_generate_keypair(RECIP_ALGO_MLKEM, pub, priv);
    if (!priv.empty()) sodium_memzero(&priv[0], priv.size());
    return o.ok ? 1 : 0;
}

int fe_m_generate_keypair(int algo, char* out_pub, size_t cap_pub,
                          char* out_priv, size_t cap_priv) {
    sodium_init();
    if (!out_pub || !out_priv || cap_pub == 0 || cap_priv == 0) return FE_M_E_ARG;
    if (algo != RECIP_ALGO_X25519 && algo != RECIP_ALGO_X448 &&
        algo != RECIP_ALGO_MLKEM) return FE_M_E_ARG;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    std::string pub, priv;
    AsymOutcome o = fe_generate_keypair((uint8_t)algo, pub, priv);
    int rc = FE_M_OK;
    if (!o.ok) rc = FE_M_E_UNSUP;
    else if (pub.size() + 1 > cap_pub || priv.size() + 1 > cap_priv) rc = FE_M_E_MEM;
    else {
        std::memcpy(out_pub, pub.data(), pub.size()); out_pub[pub.size()] = '\0';
        std::memcpy(out_priv, priv.data(), priv.size()); out_priv[priv.size()] = '\0';
    }
    if (!priv.empty()) sodium_memzero(&priv[0], priv.size());
    return rc;
}

int fe_m_encrypt_fd_asym(int in_fd, uint64_t in_size, int out_fd,
                         const char* recips, size_t recips_len,
                         int mode, int compress_level,
                         fe_m_progress_fn progress, void* user) {
    sodium_init();
    if (in_fd < 0 || out_fd < 0 || !recips || recips_len == 0) return FE_M_E_ARG;
    if (mode != FE_M_MODE_XCHACHA20 && mode != FE_M_MODE_AEGIS256 &&
        mode != FE_M_MODE_AES_GCM && mode != FE_M_MODE_SM4) return FE_M_E_ARG;
    if (!fe_m_mode_supported(mode)) return FE_M_E_UNSUP;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    std::vector<std::string> pubs = split_recips(recips, recips_len);
    if (pubs.empty()) return FE_M_E_ARG;

    CryptoMode cm = (mode == FE_M_MODE_AEGIS256) ? CryptoMode::AEGIS256
                  : (mode == FE_M_MODE_AES_GCM)  ? CryptoMode::AES_GCM
                  : (mode == FE_M_MODE_SM4)      ? CryptoMode::SM4
                                                 : CryptoMode::XCHACHA20;
    FdInBuf in_buf(in_fd);
    std::istream in(&in_buf);
    FdOutBuf out_buf(out_fd);
    std::ostream out(&out_buf);
    if (fe_m_lseek(out_fd, 0, SEEK_SET) < 0) return FE_M_E_IO;
    (void)in_size;

    SecureBuffer pw(0);
    bool ok = false;
    try {
        ok = encrypt_file(std::string(), std::string(), pw, cm,
                          wrap_progress(progress, user),
                          /*resume=*/false, compress_level,
                          /*asym_mode=*/true, &pubs, nullptr,
                          nullptr, nullptr, 0, &in, &out);
    } catch (const std::exception&) { ok = false; }
      catch (...) { ok = false; }
    out.flush();
    return to_code(ok);
}

int fe_m_decrypt_fd_asym(int in_fd, int out_fd,
                         const char* identity, size_t identity_len,
                         int force_overwrite, uint64_t preview_bytes,
                         fe_m_progress_fn progress, void* user) {
    sodium_init();
    if (in_fd < 0 || out_fd < 0 || !identity || identity_len == 0) return FE_M_E_ARG;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    std::string ident(identity, identity_len);
    // 去掉粘贴时常带
    while (!ident.empty() && (unsigned char)ident.back() <= 0x20) ident.pop_back();
    size_t skip = 0;
    while (skip < ident.size() && (unsigned char)ident[skip] <= 0x20) ++skip;
    if (skip) ident.erase(0, skip);
    if (ident.empty()) return FE_M_E_ARG;

    FdInBuf in_buf(in_fd);
    std::istream in(&in_buf);
    FdOutBuf out_buf(out_fd);
    std::ostream out(&out_buf);
    if (fe_m_lseek(out_fd, 0, SEEK_SET) < 0) {
        if (errno != ESPIPE) return FE_M_E_IO;
    } else if (fe_m_ftruncate(out_fd, 0) != 0) return FE_M_E_IO;

    SecureBuffer pw(0);
    bool ok = false;
    try {
        ok = decrypt_file(std::string(), std::string(), pw,
                          wrap_progress(progress, user),
                          /*silent=*/false, /*resume=*/false,
                          nullptr, nullptr, 0,
                          /*verify_only=*/false, preview_bytes,
                          ident, /*force_overwrite=*/force_overwrite != 0,
                          &out, &in);
    } catch (const std::exception&) { ok = false; }
      catch (...) { ok = false; }
    if (!ident.empty()) sodium_memzero(&ident[0], ident.size());
    out.flush();
    return to_code(ok, true);
}

int fe_m_keywrap_pack(const unsigned char* key, size_t key_len,
                      const char* secret, size_t secret_len, int alg,
                      unsigned char* out_blob, size_t cap, size_t* out_len) {
    sodium_init();
    if (!key || key_len != 32 || !secret || secret_len == 0 || !out_blob || !out_len)
        return FE_M_E_ARG;
    if (alg != 1 && alg != 2 && alg != 3) return FE_M_E_ARG;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    std::vector<unsigned char> blob;
    std::string err;
    unsigned char kek[32];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    bool have_kek = false;
    if (alg != 2) {
        randombytes_buf(salt, sizeof(salt));
        if (!fekw_derive_kek(secret, secret_len, salt, sizeof(salt), kek)) {
            sodium_memzero(kek, sizeof(kek));
            return FE_M_E_INT;
        }
        have_kek = true;
    }
    std::string pub(secret, secret_len);
    if (alg == 2) {
        while (!pub.empty() && (unsigned char)pub.back() <= 0x20) pub.pop_back();
    }
    bool ok = keywrap_pack(key, key_len, have_kek ? kek : nullptr, (uint8_t)alg,
                           alg == 2 ? pub : std::string(),
                           have_kek ? salt : nullptr,
                           have_kek ? sizeof(salt) : 0, blob, err);
    if (have_kek) sodium_memzero(kek, sizeof(kek));
    if (!ok) return FE_M_E_INT;
    return copy_blob(blob, out_blob, cap, out_len);
}

int fe_m_keywrap_unpack(const unsigned char* blob, size_t blob_len,
                        const char* secret, size_t secret_len,
                        unsigned char* out_key, size_t cap, size_t* out_len) {
    sodium_init();
    if (!blob || blob_len < 12 || !secret || secret_len == 0 || !out_key || !out_len)
        return FE_M_E_ARG;
    if (std::memcmp(blob, "FEKW", 4) != 0) return FE_M_E_ARG;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    const uint8_t by = blob[5];
    unsigned char kek[32];
    bool have_kek = false;
    if (by != 2) {
        const size_t salt_len = ((size_t)blob[8] << 8) | blob[9];
        if (salt_len != crypto_pwhash_SALTBYTES || blob_len < 12 + salt_len)
            return FE_M_E_ARG;
        if (!fekw_derive_kek(secret, secret_len, blob + 12, salt_len, kek)) {
            sodium_memzero(kek, sizeof(kek));
            return FE_M_E_INT;
        }
        have_kek = true;
    }
    std::string ident(secret, secret_len);
    if (by == 2) {
        while (!ident.empty() && (unsigned char)ident.back() <= 0x20) ident.pop_back();
    }
    std::vector<unsigned char> dek;
    uint8_t got = 0;
    std::string err;
    bool ok = keywrap_unpack(blob, blob_len, have_kek ? kek : nullptr,
                             by == 2 ? ident : std::string(), dek, got, err);
    if (have_kek) sodium_memzero(kek, sizeof(kek));
    if (!ok || dek.empty()) return FE_M_E_AUTH;
    int rc = copy_blob(dek, out_key, cap, out_len);
    if (!dek.empty()) sodium_memzero(dek.data(), dek.size());
    return rc;
}

int fe_m_pqc_seal(const char* pass, size_t pass_len,
                  const unsigned char* vault_salt, size_t salt_len,
                  unsigned char* out_blob, size_t cap, size_t* out_len,
                  char* out_priv, size_t cap_priv) {
    sodium_init();
    if (!pass || pass_len == 0 || !vault_salt || salt_len == 0 ||
        !out_blob || !out_len || !out_priv || cap_priv == 0) return FE_M_E_ARG;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    std::string pub, priv;
    AsymOutcome g = fe_generate_keypair(RECIP_ALGO_MLKEM, pub, priv);
    if (!g.ok) { if (!priv.empty()) sodium_memzero(&priv[0], priv.size()); return FE_M_E_UNSUP; }

    unsigned char dek[32];
    randombytes_buf(dek, sizeof(dek));
    std::vector<RecipientStanza> stanzas;
    std::vector<std::string> pubs{pub};
    AsymOutcome w = fe_wrap_dek_to_recipients(dek, pubs, stanzas);
    std::vector<unsigned char> recip;
    if (w.ok) w.ok = serialize_recipients(stanzas, recip);
    if (!w.ok) {
        sodium_memzero(dek, sizeof(dek));
        if (!priv.empty()) sodium_memzero(&priv[0], priv.size());
        return FE_M_E_INT;
    }

    std::vector<unsigned char> blob;
    const char magic[5] = {'F', 'E', 'P', 'Q', '1'};
    blob.assign(magic, magic + 5);
    blob.push_back((unsigned char)salt_len);
    blob.insert(blob.end(), vault_salt, vault_salt + salt_len);
    put_be32_vec(blob, (uint32_t)recip.size());
    blob.insert(blob.end(), recip.begin(), recip.end());
    const size_t ad_len = blob.size();

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    blob.insert(blob.end(), nonce, nonce + sizeof(nonce));
    const size_t clen = pass_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    blob.resize(blob.size() + clen);
    unsigned long long written = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            blob.data() + ad_len + sizeof(nonce), &written,
            (const unsigned char*)pass, (unsigned long long)pass_len,
            blob.data(), (unsigned long long)ad_len, nullptr, nonce, dek) != 0) {
        sodium_memzero(dek, sizeof(dek));
        if (!priv.empty()) sodium_memzero(&priv[0], priv.size());
        return FE_M_E_INT;
    }
    blob.resize(ad_len + sizeof(nonce) + (size_t)written);
    sodium_memzero(dek, sizeof(dek));

    int rc = FE_M_OK;
    if (priv.size() + 1 > cap_priv) rc = FE_M_E_MEM;
    else {
        std::memcpy(out_priv, priv.data(), priv.size());
        out_priv[priv.size()] = '\0';
    }
    if (!priv.empty()) sodium_memzero(&priv[0], priv.size());
    if (rc == FE_M_OK) rc = copy_blob(blob, out_blob, cap, out_len);
    return rc;
}

int fe_m_pqc_open(const unsigned char* blob, size_t blob_len,
                  const char* priv, size_t priv_len,
                  const unsigned char* vault_salt, size_t salt_len,
                  unsigned char* out_pass, size_t cap, size_t* out_pass_len) {
    sodium_init();
    if (!blob || !priv || priv_len == 0 || !vault_salt || !out_pass || !out_pass_len)
        return FE_M_E_ARG;
    if (!keywrap_available()) return FE_M_E_UNSUP;
    const char magic[5] = {'F', 'E', 'P', 'Q', '1'};
    if (blob_len < 5 + 1 + 4 + 24 + 16 ||
        std::memcmp(blob, magic, 5) != 0) return FE_M_E_ARG;
    const size_t got_salt_len = blob[5];
    if (got_salt_len != salt_len || blob_len < 6 + salt_len + 4) return FE_M_E_AUTH;
    if (sodium_memcmp(blob + 6, vault_salt, salt_len) != 0) return FE_M_E_AUTH;

    uint32_t rlen = 0;
    get_be32_vec(blob + 6 + salt_len, rlen);
    const size_t ad_len = 6 + salt_len + 4 + (size_t)rlen;
    if (rlen == 0 || blob_len < ad_len + 24 + 16) return FE_M_E_ARG;
    std::vector<RecipientStanza> stanzas;
    if (!parse_recipients(blob + 6 + salt_len + 4, rlen, stanzas)) return FE_M_E_AUTH;

    unsigned char dek[32];
    std::string ident(priv, priv_len);
    while (!ident.empty() && (unsigned char)ident.back() <= 0x20) ident.pop_back();
    AsymOutcome r = fe_recover_dek_from_stanzas(stanzas, ident, dek);
    if (!ident.empty()) sodium_memzero(&ident[0], ident.size());
    if (!r.ok) { sodium_memzero(dek, sizeof(dek)); return FE_M_E_AUTH; }

    const unsigned char* nonce = blob + ad_len;
    const unsigned char* ct = nonce + 24;
    const size_t ct_len = blob_len - ad_len - 24;
    if (ct_len < crypto_aead_xchacha20poly1305_ietf_ABYTES || ct_len - 16 > cap) {
        sodium_memzero(dek, sizeof(dek));
        return FE_M_E_MEM;
    }
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out_pass, &mlen, nullptr, ct, (unsigned long long)ct_len,
            blob, (unsigned long long)ad_len, nonce, dek) != 0) {
        sodium_memzero(dek, sizeof(dek));
        return FE_M_E_AUTH;
    }
    sodium_memzero(dek, sizeof(dek));
    *out_pass_len = (size_t)mlen;
    return FE_M_OK;
}

// 水印：临时文件 + 拷出辅助
namespace {

std::string wm_tmp_path() {
    unsigned char rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    char h[17];
    for (int i = 0; i < 8; ++i) std::snprintf(h + i * 2, 3, "%02x", rnd[i]);
    h[16] = '\0';
    std::error_code ec;
    std::filesystem::path p = std::filesystem::temp_directory_path(ec);
    if (ec) p = std::filesystem::path("/data/local/tmp");
    p /= (std::string("fe_wm_") + h + ".tmp");
    return p.string();
}

int wm_copy_file_to_fd(const std::string& path, int out_fd) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return FE_M_E_IO;
    std::vector<unsigned char> buf(1024 * 1024);
    while (true) {
        in.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
        std::streamsize got = in.gcount();
        if (got <= 0) break;
        size_t off = 0;
        while (off < (size_t)got) {
            fe_m_ssize_t w = fe_m_write(out_fd, buf.data() + off, got - off);
            if (w <= 0) return FE_M_E_IO;
            off += (size_t)w;
        }
        if (in.eof()) break;
    }
    return FE_M_OK;
}

// 把内存 PEM 文本落临时文件
// 水印签名/验签 API 只认文件路径
// 返回空串表示失败
std::string wm_write_pem_tmp(const std::string& pem) {
    if (pem.empty()) return std::string();
    std::string path = wm_tmp_path();
    {
        std::ofstream o(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!o) { std::error_code ec; std::filesystem::remove(path, ec); return std::string(); }
        o.write(pem.data(), (std::streamsize)pem.size());
        if (!o) { std::error_code ec; std::filesystem::remove(path, ec); return std::string(); }
    }
    return path;
}

void wm_drop(const std::string& path) {
    if (path.empty()) return;
    std::error_code ec; std::filesystem::remove(path, ec);
}

}  // namespace

int fe_m_encrypt_fd_wm(int in_fd, uint64_t in_size, int out_fd,
                       const char* password, size_t pass_len,
                       int mode, int compress_level,
                       const char* wm_priv_pem, int wm_pqc,
                       fe_m_progress_fn progress, void* user) {
    sodium_init();
    if (in_fd < 0 || out_fd < 0 || !password || pass_len == 0) return FE_M_E_ARG;
    if (mode != FE_M_MODE_XCHACHA20 && mode != FE_M_MODE_AEGIS256 &&
        mode != FE_M_MODE_AES_GCM && mode != FE_M_MODE_SM4) return FE_M_E_ARG;
    if (!fe_m_mode_supported(mode)) return FE_M_E_UNSUP;
    if (!wm_priv_pem || wm_priv_pem[0] == '\0') return FE_M_E_ARG;

    CryptoMode cm = (mode == FE_M_MODE_AEGIS256) ? CryptoMode::AEGIS256
                 : (mode == FE_M_MODE_AES_GCM)   ? CryptoMode::AES_GCM
                 : (mode == FE_M_MODE_SM4)       ? CryptoMode::SM4
                                                 : CryptoMode::XCHACHA20;

    FdInBuf in_buf(in_fd);
    std::istream in(&in_buf);
    if (fe_m_lseek(out_fd, 0, SEEK_SET) < 0) return FE_M_E_IO;
    (void)in_size;

    std::string tmp = wm_tmp_path();

    SecureBuffer pw(pass_len);
    std::memcpy(pw.data(), password, pass_len);

    // 签名私钥是 PEM 文本，水印实现只认文件路径，先落临时文件
    std::string priv_path = wm_write_pem_tmp(wm_priv_pem);
    if (priv_path.empty()) return FE_M_E_IO;

    WatermarkSpec wm;
    wm.enabled = true;
    wm.pqc = (wm_pqc != 0);
    wm.sign_key = priv_path;

    // 走文件模式：out_path 给临时文件，加密内部才会追加水印+名尾
    bool ok = false;
    try {
        ok = encrypt_file(std::string(), tmp, pw, cm,
                          wrap_progress(progress, user),
                          /*resume=*/false, compress_level,
                          /*asym_mode=*/false, nullptr, &wm,
                          /*ext_salt=*/nullptr, /*ext_kek=*/nullptr, 0,
                          &in, nullptr, /*footer_name=*/nullptr);
    } catch (const std::exception&) { ok = false; }
      catch (...) { ok = false; }
    int rc = FE_M_OK;
    if (!ok) { wm_drop(tmp); wm_drop(priv_path); return to_code(false); }
    rc = wm_copy_file_to_fd(tmp, out_fd);
    wm_drop(tmp);
    wm_drop(priv_path);
    return rc;
}

int fe_m_wm_verify(const char* ptd_path, const char* pub_pem, int pqc,
                   char* out_json, size_t cap) {
    sodium_init();
    if (!ptd_path || !out_json || cap == 0) return FE_M_E_ARG;
    WatermarkInfo info;
    // 公钥是 PEM 文本，验签 API 只认文件路径，先落临时文件
    std::string pub_path = (pub_pem && pub_pem[0] != '\0') ? wm_write_pem_tmp(pub_pem) : std::string();
    bool found = false;
    try { found = read_watermark(std::string(ptd_path), info, pub_path, pqc != 0); }
    catch (...) { found = false; }
    wm_drop(pub_path);
    if (!found) {
        std::string s = "{\"found\":false}";
        return fe_m_copy_out(s, out_json, cap);
    }
    std::ostringstream o;
    o << "{\"found\":true"
      << ",\"timestamp\":" << (unsigned long long)info.timestamp
      << ",\"flags\":" << (int)info.flags
      << ",\"has_signature\":" << (info.has_signature ? "true" : "false")
      << ",\"verify_attempted\":" << (info.verify_attempted ? "true" : "false")
      << ",\"verify_ok\":" << (info.verify_ok ? "true" : "false")
      << ",\"machine_id_hex\":\"" << info.machine_id_hex << "\""
      << ",\"nonce_hex\":\"" << info.nonce_hex << "\""
      << ",\"error\":\"" << info.error << "\"}";
    return fe_m_copy_out(o.str(), out_json, cap);
}

int fe_m_wm_generate_keypair(int pqc, char* out_pub, size_t cap_pub,
                             char* out_priv, size_t cap_priv) {
    sodium_init();
    if (!out_pub || !out_priv || cap_pub == 0 || cap_priv == 0) return FE_M_E_ARG;
    std::string tmp = wm_tmp_path();
    std::string pub, err;
    bool ok = wm_generate_keypair(tmp, pqc != 0, pub, err);
    if (!ok) { std::error_code ec; std::filesystem::remove(tmp, ec); return FE_M_E_INT; }
    std::ifstream fin(tmp, std::ios::binary);
    std::string priv((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    std::error_code ec; std::filesystem::remove(tmp, ec);
    if (pub.size() + 1 > cap_pub || priv.size() + 1 > cap_priv) return FE_M_E_MEM;
    std::memcpy(out_pub, pub.data(), pub.size()); out_pub[pub.size()] = '\0';
    std::memcpy(out_priv, priv.data(), priv.size()); out_priv[priv.size()] = '\0';
    return FE_M_OK;
}
