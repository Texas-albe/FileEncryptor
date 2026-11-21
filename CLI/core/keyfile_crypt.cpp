// FEPK1 私钥全文加密
// 明文只在内存
#include "keyfile_crypt.hpp"
#include "FileEncryptor.hpp"

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace fe_keyfile {

namespace {

// KDF 类型
constexpr unsigned char KDF_DPAPI  = 1;
constexpr unsigned char KDF_ARGON2 = 2;
constexpr unsigned char FORMAT_VER = 1;

// Argon 参数
constexpr unsigned int ARGON_OPS      = 3;
constexpr unsigned int ARGON_MEM_KB   = 64 * 1024;
constexpr unsigned int ARGON_OPS_MIN  = 2;
constexpr unsigned int ARGON_MEM_MIN  = 8 * 1024;
constexpr unsigned int ARGON_OPS_MAX  = 64;
constexpr unsigned int ARGON_MEM_MAX  = 1024 * 1024;

constexpr size_t SALT_LEN  = 16;
constexpr size_t NONCE_LEN = 24;
constexpr size_t KEY_LEN   = 32;
constexpr size_t TAG_LEN   = 16;
constexpr size_t MAX_FILE  = 1024 * 1024;

void put_u32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

uint32_t get_u32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// 用途派生域分隔
void purpose_entropy(const std::string& purpose, unsigned char out[KEY_LEN]) {
    std::string tag = "FE_KEYFILE_PROTECT|";
    tag += purpose;
    crypto_generichash(out, KEY_LEN,
        reinterpret_cast<const unsigned char*>(tag.data()), tag.size(), nullptr, 0);
}

// 读全文件
bool file_bytes(const std::string& path, std::vector<unsigned char>& out, std::string& err) {
    std::FILE* fp = nullptr;
#ifdef _WIN32
    const std::wstring wp = utf8_to_wstring(path);
    fp = _wfopen(wp.c_str(), L"rb");
#else
    fp = std::fopen(path.c_str(), "rb");
#endif
    if (!fp) { err = "Cannot open file: " + path; return false; }
    out.clear();
    unsigned char chunk[4096];
    size_t got;
    while ((got = std::fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        out.insert(out.end(), chunk, chunk + got);
        if (out.size() > MAX_FILE) {
            std::fclose(fp);
            err = "File too large (>1 MB): " + path;
            return false;
        }
    }
    const bool bad = std::ferror(fp) != 0;
    std::fclose(fp);
    if (bad) { err = "Read failed: " + path; return false; }
    return true;
}

// 终端判定
bool stdin_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) == 1;
#endif
}

// 无回显输入
bool read_hidden_line(const char* prompt, std::string& out, std::string& err) {
    std::fputs(prompt, stderr);
    std::fflush(stderr);
#ifdef _WIN32
    int ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == 0 || ch == 0xE0) { _getch(); continue; }
        if (ch == '\b') { if (!out.empty()) out.pop_back(); continue; }
        if (ch >= 32) out.push_back((char)(unsigned char)ch);
        if (out.size() > 1024) { err = "Passphrase too long"; return false; }
    }
    std::fputs("\n", stderr);
#else
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        err = "Cannot query the terminal";
        return false;
    }
    newt = oldt;
    newt.c_lflag &= ~((tcflag_t)ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        err = "Cannot disable terminal echo";
        return false;
    }
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 0x7F || ch == '\b') { if (!out.empty()) out.pop_back(); continue; }
        if (ch >= 32 && ch < 256) out.push_back((char)ch);
        if (out.size() > 1024) { err = "Passphrase too long"; break; }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::fputs("\n", stderr);
#endif
    if (out.empty()) { err = "Empty passphrase"; return false; }
    return true;
}

// 口令缓存
// 首读后抹环境
struct PassCache {
    std::string pass;
    std::string keyfile;
    bool scanned = false;
    ~PassCache() {
        if (!pass.empty()) sodium_memzero(pass.data(), pass.size());
    }
};
PassCache g_cache;

// 抹单个环境变量
void wipe_env_var(const char* name) {
#ifdef _WIN32
    _putenv_s(name, "");
#else
    unsetenv(name);
#endif
}

void scan_env_once() {
    if (g_cache.scanned) return;
    g_cache.scanned = true;
    if (const char* ep = std::getenv("FE_KEY_PASS"); ep && *ep) {
        g_cache.pass = ep;
        wipe_env_var("FE_KEY_PASS");
    }
    if (const char* kf = std::getenv("FE_KEY_FILE"); kf && *kf) {
        g_cache.keyfile = kf;
        wipe_env_var("FE_KEY_FILE");
    }
}

// 口令来源
bool collect_passphrase(std::string& pass, std::string& err) {
    scan_env_once();
    if (!g_cache.keyfile.empty()) {
        std::vector<unsigned char> raw;
        if (!file_bytes(g_cache.keyfile, raw, err)) {
            err = "FE_KEY_FILE: " + err;
            return false;
        }
        while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r')) raw.pop_back();
        if (raw.empty()) { err = "FE_KEY_FILE is empty"; return false; }
        pass.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        sodium_memzero(raw.data(), raw.size());
        return true;
    }
    if (!g_cache.pass.empty()) {
        pass = g_cache.pass;
        return true;
    }
    if (!stdin_is_tty()) {
        err = "A passphrase is required: set FE_KEY_PASS or FE_KEY_FILE "
              "(stdin is not a terminal).";
        return false;
    }
    std::string prompt = "Enter passphrase to protect the private key: ";
    if (!read_hidden_line(prompt.c_str(), pass, err)) return false;
    std::string again;
    prompt = "Confirm the same passphrase: ";
    const bool ok2 = read_hidden_line(prompt.c_str(), again, err);
    const bool same = ok2 && again == pass;
    sodium_memzero(again.data(), again.size());
    if (!same) {
        sodium_memzero(pass.data(), pass.size());
        pass.clear();
        err = "The two passphrases do not match.";
        return false;
    }
    sodium_memzero(again.data(), again.size());
    return true;
}

#ifdef _WIN32

// DPAPI 加密
bool dpapi_protect(const std::string& plain, const unsigned char ent[KEY_LEN],
                   std::vector<unsigned char>& blob, std::string& err) {
    DATA_BLOB in, out, entropy;
    in.pbData = (BYTE*)plain.data();
    in.cbData = (DWORD)plain.size();
    entropy.pbData = (BYTE*)ent;
    entropy.cbData = KEY_LEN;
    if (!CryptProtectData(&in, L"FEPK1", &entropy, nullptr, nullptr, 0, &out)) {
        err = "DPAPI CryptProtectData failed (error " +
              std::to_string(GetLastError()) + ")";
        return false;
    }
    blob.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

// DPAPI 解密
bool dpapi_unprotect(const unsigned char* blob, size_t blob_len,
                     const unsigned char ent[KEY_LEN],
                     std::string& plain, std::string& err) {
    DATA_BLOB in, out, entropy;
    in.pbData = (BYTE*)blob;
    in.cbData = (DWORD)blob_len;
    entropy.pbData = (BYTE*)ent;
    entropy.cbData = KEY_LEN;
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, 0, &out)) {
        err = "DPAPI CryptUnprotectData failed (wrong machine, user or purpose)";
        return false;
    }
    plain.assign(reinterpret_cast<const char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return true;
}

#endif

// 独占临时文件
bool write_tmp_exclusive(const std::string& path, const std::string& data, std::string& err) {
#ifdef _WIN32
    const std::wstring wp = utf8_to_wstring(path);
    int fd = _wopen(wp.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                    _S_IREAD | _S_IWRITE);
    if (fd < 0) { err = "Cannot create temp file: " + path; return false; }
#else
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { err = "Cannot create temp file: " + path; return false; }
#endif
    const size_t n = data.size();
    size_t off = 0;
    bool ok = true;
    while (off < n) {
        size_t want = n - off;
        if (want > (size_t)0x40000000) want = (size_t)0x40000000;
#ifdef _WIN32
        const int w = _write(fd, data.data() + off, (unsigned int)want);
#else
        const ssize_t w = (ssize_t)::write(fd, data.data() + off, want);
#endif
        if (w <= 0) { ok = false; break; }
        off += (size_t)w;
    }
    if (ok) {
#ifdef _WIN32
        ok = _commit(fd) == 0;
#else
        ok = ::fsync(fd) == 0;
#endif
    }
#ifdef _WIN32
    _close(fd);
#else
    ::close(fd);
#endif
    if (!ok) {
#ifdef _WIN32
        _wunlink(wp.c_str());
#else
        ::unlink(path.c_str());
#endif
        err = "Write failed: " + path;
        return false;
    }
    return true;
}

// 选 KDF
unsigned char pick_kdf(bool force_argon2) {
    if (force_argon2) return KDF_ARGON2;
    scan_env_once();
    if (!g_cache.pass.empty() || !g_cache.keyfile.empty()) return KDF_ARGON2;
#ifdef _WIN32
    return KDF_DPAPI;
#else
    return KDF_ARGON2;
#endif
}

}

bool write_protected(const std::string& path, const std::string& plaintext,
                     const char* purpose, std::string& err,
                     bool force_argon2) {
    if (!purpose || !*purpose) { err = "Empty purpose"; return false; }

    const unsigned char kdf = pick_kdf(force_argon2);
    unsigned char ent[KEY_LEN];
    purpose_entropy(purpose, ent);

    std::string out;
    out.reserve(plaintext.size() + 128);
    out.append("FEPK1", 5);
    out.push_back((char)FORMAT_VER);
    out.push_back((char)kdf);

    bool ok = false;
    do {
        if (kdf == KDF_DPAPI) {
#ifdef _WIN32
            std::vector<unsigned char> blob;
            if (!dpapi_protect(plaintext, ent, blob, err)) break;
            unsigned char lenb[4];
            put_u32(lenb, (uint32_t)blob.size());
            out.append(reinterpret_cast<const char*>(lenb), 4);
            out.append(reinterpret_cast<const char*>(blob.data()), blob.size());
            sodium_memzero(blob.data(), blob.size());
            ok = true;
#else
            err = "DPAPI-protected key files can only be written on Windows";
            break;
#endif
        } else {
            std::string pass;
            if (!collect_passphrase(pass, err)) break;

            unsigned char key[KEY_LEN];
            unsigned char salt[SALT_LEN];
            unsigned char nonce[NONCE_LEN];
            randombytes_buf(salt, sizeof(salt));
            randombytes_buf(nonce, sizeof(nonce));
            int rc = crypto_pwhash(key, KEY_LEN, pass.data(), pass.size(),
                                   salt, ARGON_OPS, (size_t)ARGON_MEM_KB * 1024,
                                   crypto_pwhash_ALG_ARGON2ID13);
            sodium_memzero(pass.data(), pass.size());
            pass.clear();
            if (rc != 0) { err = "Argon2id failed (not enough memory?)"; break; }

            std::vector<unsigned char> ct(plaintext.size() + TAG_LEN);
            unsigned long long clen = 0;
            std::string aad = "FEPK1|";
            aad += purpose;
            rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
                ct.data(), &clen,
                reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
                reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
                nullptr, nonce, key);
            sodium_memzero(key, sizeof(key));
            if (rc != 0) { err = "AEAD encryption failed"; break; }

            unsigned char hdr[8];
            put_u32(hdr, ARGON_OPS);
            put_u32(hdr + 4, ARGON_MEM_KB);
            out.append(reinterpret_cast<const char*>(hdr), 8);
            out.append(reinterpret_cast<const char*>(salt), SALT_LEN);
            out.append(reinterpret_cast<const char*>(nonce), NONCE_LEN);
            out.append(reinterpret_cast<const char*>(ct.data()), (size_t)clen);
            sodium_memzero(ct.data(), ct.size());
            ok = true;
        }
    } while (false);
    sodium_memzero(ent, sizeof(ent));
    if (!ok) return false;

    const std::string tmp = path + ".tmp";
    if (!write_tmp_exclusive(tmp, out, err)) return false;
    if (!replace_file_utf8(tmp, path)) {
        err = "Cannot finalize: " + path;
        remove_file_utf8(tmp);
        return false;
    }
    tighten_file_permissions(path);
    return true;
}

bool read_protected(const std::string& path, std::string& plaintext,
                    const char* purpose, bool& was_plain, std::string& err) {
    was_plain = false;
    if (!purpose || !*purpose) { err = "Empty purpose"; return false; }

    std::vector<unsigned char> raw;
    if (!file_bytes(path, raw, err)) return false;
    if (raw.empty()) { err = "File is empty: " + path; return false; }

    // 旧明文直通
    if (raw.size() < 6 || std::memcmp(raw.data(), "FEPK1", 5) != 0) {
        was_plain = true;
        plaintext.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        return true;
    }

    const unsigned char ver = raw[5];
    if (ver != FORMAT_VER) {
        err = "Unsupported FEPK1 version " + std::to_string((int)ver) + ": " + path;
        return false;
    }
    if (raw.size() < 7) { err = "Truncated FEPK1 file: " + path; return false; }
    const unsigned char kdf = raw[6];
    unsigned char ent[KEY_LEN];
    purpose_entropy(purpose, ent);

    bool ok = false;
    do {
        if (kdf == KDF_DPAPI) {
#ifdef _WIN32
            if (raw.size() < 11) { err = "Truncated FEPK1 file: " + path; break; }
            const uint32_t blob_len = get_u32(raw.data() + 7);
            if (blob_len < 1 || blob_len != raw.size() - 11) {
                err = "Corrupt FEPK1 DPAPI payload: " + path;
                break;
            }
            ok = dpapi_unprotect(raw.data() + 11, blob_len, ent, plaintext, err);
#else
            err = "This FEPK1 file is DPAPI-protected and can only be read on "
                  "the Windows machine and user account that wrote it";
            break;
#endif
        } else if (kdf == KDF_ARGON2) {
            // ops|mem|salt|nonce|ct
            if (raw.size() < 7 + 8 + SALT_LEN + NONCE_LEN + TAG_LEN) {
                err = "Truncated FEPK1 file: " + path;
                break;
            }
            const unsigned char* p = raw.data() + 7;
            const unsigned int ops = get_u32(p);
            const unsigned int mem_kb = get_u32(p + 4);
            if (ops < ARGON_OPS_MIN || ops > ARGON_OPS_MAX ||
                mem_kb < ARGON_MEM_MIN || mem_kb > ARGON_MEM_MAX) {
                err = "FEPK1 KDF parameters out of range (corrupt or hostile file): " + path;
                break;
            }
            const unsigned char* salt = p + 8;
            const unsigned char* nonce = salt + SALT_LEN;
            const unsigned char* ct = nonce + NONCE_LEN;
            const size_t ct_len = raw.size() - (size_t)(ct - raw.data());

            std::string pass;
            if (!collect_passphrase(pass, err)) break;

            unsigned char key[KEY_LEN];
            int rc = crypto_pwhash(key, KEY_LEN, pass.data(), pass.size(),
                                   salt, ops, (size_t)mem_kb * 1024,
                                   crypto_pwhash_ALG_ARGON2ID13);
            sodium_memzero(pass.data(), pass.size());
            pass.clear();
            if (rc != 0) { err = "Argon2id failed (not enough memory?)"; break; }

            std::string aad = "FEPK1|";
            aad += purpose;
            std::vector<unsigned char> plain(ct_len - TAG_LEN);
            unsigned long long plen = 0;
            rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
                plain.data(), &plen, nullptr,
                ct, (unsigned long long)ct_len,
                reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
                nonce, key);
            sodium_memzero(key, sizeof(key));
            if (rc != 0) {
                err = "FEPK1 authentication failed (wrong passphrase, wrong purpose "
                      "or tampered file): " + path;
                break;
            }
            plaintext.assign(reinterpret_cast<const char*>(plain.data()), (size_t)plen);
            sodium_memzero(plain.data(), plain.size());
            ok = true;
        } else {
            err = "Unknown FEPK1 KDF id " + std::to_string((int)kdf) + ": " + path;
        }
    } while (false);
    sodium_memzero(ent, sizeof(ent));
    return ok;
}

}
