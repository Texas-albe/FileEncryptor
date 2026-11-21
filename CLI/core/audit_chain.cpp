#include "audit_chain.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace fe {
namespace {

static const char* ZERO_MAC = "0000000000000000000000000000000000000000000000000000000000000000";

static std::string to_hex(const unsigned char* p, size_t n) {
    static const char h[] = "0123456789abcdef";
    std::string o;
    o.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        o.push_back(h[p[i] >> 4]);
        o.push_back(h[p[i] & 15]);
    }
    return o;
}

static bool all_hex(const std::string& s) {
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

static bool from_hex(const std::string& s, unsigned char* out, size_t n) {
    if (s.size() < n * 2) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; ++i) {
        int a = val(s[2 * i]), b = val(s[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        out[i] = static_cast<unsigned char>((a << 4) | b);
    }
    return true;
}

static void hmac256(const unsigned char key[32], const std::string& data, unsigned char out[32]) {
    crypto_auth_hmacsha256(out,
        reinterpret_cast<const unsigned char*>(data.data()), data.size(), key);
}

static void subkey(const unsigned char key[32], const char* domain, unsigned char out[32]) {
    hmac256(key, std::string("FE_AUDIT_SUBKEY|") + domain, out);
}

static std::string b64_encode(const unsigned char* p, size_t n) {
    size_t cap = sodium_base64_ENCODED_LEN(n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(cap, '\0');
    sodium_bin2base64(&out[0], cap, p, n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
}

static bool b64_decode(const std::string& s, unsigned char* out, size_t cap, size_t& n) {
    size_t got = 0;
    return sodium_base642bin(out, cap, s.data(), s.size(), nullptr,
                             &got, nullptr, sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0
           && got <= cap && (n = got, true);
}

static std::string path_hash(const unsigned char sub[32],
                             const std::string& op, const std::string& key) {
    unsigned char h[16] = {0};
    std::string msg = op;
    msg.push_back('\0');
    msg += key;
    crypto_generichash(h, sizeof(h),
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), sub, 32);
    std::string out = to_hex(h, sizeof(h));
    sodium_memzero(h, sizeof(h));
    return out;
}

static std::string path_encrypt(const unsigned char sub[32], const std::string& op,
                                std::uint64_t seq, const std::string& key) {
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};
    randombytes_buf(nonce, sizeof(nonce));
    std::vector<unsigned char> ct(key.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    std::string aad = "FE_AUDIT_PATH|" + std::to_string(seq) + "|" + op;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &clen,
        reinterpret_cast<const unsigned char*>(key.data()), key.size(),
        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
        nullptr, nonce, sub);
    if (rc != 0) return std::string();
    std::vector<unsigned char> blob(sizeof(nonce) + static_cast<size_t>(clen));
    std::memcpy(blob.data(), nonce, sizeof(nonce));
    std::memcpy(blob.data() + sizeof(nonce), ct.data(), static_cast<size_t>(clen));
    std::string out = b64_encode(blob.data(), blob.size());
    sodium_memzero(ct.data(), ct.size());
    sodium_memzero(blob.data(), blob.size());
    return out;
}

static bool path_decrypt(const unsigned char sub[32], const std::string& op,
                         std::uint64_t seq, const std::string& blob64, std::string& out) {
    std::vector<unsigned char> blob(512);
    size_t n = 0;
    if (blob64.empty() || blob64.size() > 512) return false;
    if (!b64_decode(blob64, blob.data(), blob.size(), n)) return false;
    constexpr size_t ns = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr size_t ab = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (n < ns + ab) return false;
    std::vector<unsigned char> plain(n - ns - ab);
    unsigned long long plen = 0;
    std::string aad = "FE_AUDIT_PATH|" + std::to_string(seq) + "|" + op;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plen, nullptr,
        blob.data() + ns, n - ns,
        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
        blob.data(), sub);
    if (rc != 0) return false;
    out.assign(reinterpret_cast<const char*>(plain.data()), static_cast<size_t>(plen));
    sodium_memzero(plain.data(), plain.size());
    return true;
}

static bool equal_mac(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char x[32] = {0}, y[32] = {0};
    if (!from_hex(a, x, 32) || !from_hex(b, y, 32)) return false;
    int d = 0;
    for (size_t i = 0; i < 32; ++i) d |= static_cast<int>(x[i] ^ y[i]);
    return d == 0;
}

static std::string jesc(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(c));
                o += b;
            } else {
                o += static_cast<char>(c);
            }
        }
    }
    return o;
}

static bool json_get(const std::string& line, const char* key, std::string& out) {
    std::string pat = "\"";
    pat += key;
    pat += "\"";
    size_t p = line.find(pat);
    if (p == std::string::npos) return false;
    p += pat.size();
    size_t c = line.find(':', p);
    if (c == std::string::npos) return false;
    p = c + 1;
    while (p < line.size() && std::isspace(static_cast<unsigned char>(line[p]))) ++p;
    if (p >= line.size()) return false;
    if (line[p] == '"') {
        ++p;
        std::string v;
        while (p < line.size()) {
            char ch = line[p++];
            if (ch == '"') { out = v; return true; }
            if (ch == '\\' && p < line.size()) {
                char e = line[p++];
                switch (e) {
                case '"':  v += '"'; break;
                case '\\': v += '\\'; break;
                case 'n':  v += '\n'; break;
                case 'r':  v += '\r'; break;
                case 't':  v += '\t'; break;
                case 'u': {
                    unsigned x = 0;
                    for (int i = 0; i < 4 && p < line.size(); ++i) {
                        char h = line[p++];
                        unsigned d = 0;
                        if (h >= '0' && h <= '9') d = static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') d = static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') d = static_cast<unsigned>(h - 'A' + 10);
                        x = (x << 4) | d;
                    }
                    if (x < 128) v.push_back(static_cast<char>(x));
                    else v.push_back('?');
                    break;
                }
                default: v += e; break;
                }
            } else {
                v.push_back(ch);
            }
        }
        return false;
    }
    size_t e = p;
    while (e < line.size() && line[e] != ',' && line[e] != '}' && line[e] != '\n') ++e;
    out = line.substr(p, e - p);
    return true;
}

static bool to_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty()) return false;
    try {
        out = static_cast<std::uint64_t>(std::stoull(s));
        return true;
    } catch (...) {
        return false;
    }
}

static bool atomic_write(const std::string& path, const std::string& data, std::string& err) {
    std::error_code ec;
    std::filesystem::path pp(path);
    if (!pp.parent_path().empty()) std::filesystem::create_directories(pp.parent_path(), ec);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) { err = "cannot create " + tmp; return false; }
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!f) { err = "write failed " + tmp; return false; }
    }
    std::filesystem::remove(path, ec);
    std::filesystem::rename(tmp, path, ec);
    if (ec) { err = "rename failed: " + ec.message(); return false; }
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    return true;
}

class FileLock {
public:
    FileLock(const std::string& path, std::string& err) {
#ifdef _WIN32
        h_ = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) { err = "cannot open audit lock"; return; }
        OVERLAPPED ov;
        std::memset(&ov, 0, sizeof(ov));
        if (!LockFileEx(h_, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov)) {
            err = "cannot lock audit file";
            CloseHandle(h_);
            h_ = INVALID_HANDLE_VALUE;
            return;
        }
#else
        fd_ = ::open(path.c_str(), O_CREAT | O_RDWR, 0600);
        if (fd_ < 0) { err = "cannot open audit lock"; return; }
        if (::flock(fd_, LOCK_EX) != 0) {
            err = "cannot lock audit file";
            ::close(fd_);
            fd_ = -1;
            return;
        }
#endif
        ok_ = true;
    }
    ~FileLock() {
#ifdef _WIN32
        if (h_ != INVALID_HANDLE_VALUE) {
            OVERLAPPED ov;
            std::memset(&ov, 0, sizeof(ov));
            UnlockFileEx(h_, 0, 1, 0, &ov);
            CloseHandle(h_);
        }
#else
        if (fd_ >= 0) { ::flock(fd_, LOCK_UN); ::close(fd_); }
#endif
    }
    bool ok() const { return ok_; }

private:
#ifdef _WIN32
    HANDLE h_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
    bool ok_ = false;
};

static bool open_append(std::string path, std::intptr_t& out, std::string& err) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { err = "cannot open audit log"; return false; }
    out = reinterpret_cast<std::intptr_t>(h);
#else
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) { err = "cannot open audit log"; return false; }
    out = static_cast<std::intptr_t>(fd);
#endif
    return true;
}

static bool write_all(std::intptr_t h, const std::string& data) {
#ifdef _WIN32
    DWORD n = 0;
    return WriteFile(reinterpret_cast<HANDLE>(h), const_cast<char*>(data.data()),
                     static_cast<DWORD>(data.size()), &n, nullptr) && n == data.size();
#else
    int fd = static_cast<int>(h);
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
#endif
}

static void sync_all(std::intptr_t h) {
#ifdef _WIN32
    FlushFileBuffers(reinterpret_cast<HANDLE>(h));
#else
    int fd = static_cast<int>(h);
    ::fsync(fd);
#endif
}

static void close_all(std::intptr_t h) {
    if (!h) return;
#ifdef _WIN32
    CloseHandle(reinterpret_cast<HANDLE>(h));
#else
    ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(h)));
#endif
}

static std::string canonical2(std::uint64_t seq, const std::string& prev,
    std::uint64_t ts, std::uint64_t mono, const std::string& boot,
    const std::string& session, const std::string& op, const std::string& key,
    int status, std::uint64_t bytes, std::uint64_t elapsed, int err,
    const std::string& dev) {
    std::string o = "FE_AUDIT2|";
    auto num = [&](const char* n, std::uint64_t v) {
        o += n; o += "="; o += std::to_string(v); o += "|";
    };
    auto str = [&](const char* n, const std::string& v) {
        o += n; o += "="; o += std::to_string(v.size()); o += ":"; o += v; o += "|";
    };
    num("seq", seq);
    str("prev", prev);
    num("ts", ts);
    num("mono", mono);
    str("boot", boot);
    str("session", session);
    str("op", op);
    str("key", key);
    num("status", static_cast<std::uint64_t>(static_cast<std::int64_t>(status)));
    num("bytes", bytes);
    num("elapsed", elapsed);
    num("err", static_cast<std::uint64_t>(static_cast<std::int64_t>(err)));
    str("dev", dev);
    return o;
}

static std::string canonical3(std::uint64_t seq, const std::string& prev,
    std::uint64_t ts, std::uint64_t mono, const std::string& boot,
    const std::string& session, const std::string& op, const std::string& kh,
    const std::string& kct, int status, std::uint64_t bytes,
    std::uint64_t elapsed, int err, const std::string& dev) {
    std::string o = "FE_AUDIT3|";
    auto num = [&](const char* n, std::uint64_t v) {
        o += n; o += "="; o += std::to_string(v); o += "|";
    };
    auto str = [&](const char* n, const std::string& v) {
        o += n; o += "="; o += std::to_string(v.size()); o += ":"; o += v; o += "|";
    };
    num("seq", seq);
    str("prev", prev);
    num("ts", ts);
    num("mono", mono);
    str("boot", boot);
    str("session", session);
    str("op", op);
    str("kh", kh);
    str("kct", kct);
    num("status", static_cast<std::uint64_t>(static_cast<std::int64_t>(status)));
    num("bytes", bytes);
    num("elapsed", elapsed);
    num("err", static_cast<std::uint64_t>(static_cast<std::int64_t>(err)));
    str("dev", dev);
    return o;
}

static std::string line2(const AuditEvent& ev, std::uint64_t seq, const std::string& prev,
    std::uint64_t mono, const std::string& boot, const std::string& session,
    const std::string& mac, const std::string& kid) {
    std::string o = "{\"schema\":2,\"seq\":" + std::to_string(seq)
        + ",\"prev\":\"" + prev + "\""
        + ",\"ts\":" + std::to_string(ev.ts)
        + ",\"mono\":" + std::to_string(mono)
        + ",\"boot\":\"" + boot + "\""
        + ",\"session\":\"" + session + "\""
        + ",\"op\":\"" + jesc(ev.op) + "\""
        + ",\"key\":\"" + jesc(ev.key) + "\""
        + ",\"status\":" + std::to_string(ev.status)
        + ",\"bytes\":" + std::to_string(ev.bytes)
        + ",\"elapsed_ms\":" + std::to_string(ev.elapsed_ms)
        + ",\"error_code\":" + std::to_string(ev.error_code)
        + ",\"device_id\":\"" + jesc(ev.device_id) + "\""
        + ",\"kid\":\"" + kid + "\""
        + ",\"mac\":\"" + mac + "\"}\n";
    return o;
}

static std::string line3(const AuditEvent& ev, std::uint64_t seq, const std::string& prev,
    std::uint64_t mono, const std::string& boot, const std::string& session,
    const std::string& kh, const std::string& kct,
    const std::string& mac, const std::string& kid) {
    std::string o = "{\"schema\":3,\"seq\":" + std::to_string(seq)
        + ",\"prev\":\"" + prev + "\""
        + ",\"ts\":" + std::to_string(ev.ts)
        + ",\"mono\":" + std::to_string(mono)
        + ",\"boot\":\"" + boot + "\""
        + ",\"session\":\"" + session + "\""
        + ",\"op\":\"" + jesc(ev.op) + "\""
        + ",\"key_h\":\"" + kh + "\""
        + ",\"key_ct\":\"" + kct + "\""
        + ",\"status\":" + std::to_string(ev.status)
        + ",\"bytes\":" + std::to_string(ev.bytes)
        + ",\"elapsed_ms\":" + std::to_string(ev.elapsed_ms)
        + ",\"error_code\":" + std::to_string(ev.error_code)
        + ",\"device_id\":\"" + jesc(ev.device_id) + "\""
        + ",\"kid\":\"" + kid + "\""
        + ",\"mac\":\"" + mac + "\"}\n";
    return o;
}

static std::string line1(const AuditEvent& ev) {
    std::string o = "{\"schema\":1,\"ts\":" + std::to_string(ev.ts)
        + ",\"op\":\"" + jesc(ev.op) + "\""
        + ",\"key\":\"" + jesc(ev.key) + "\""
        + ",\"status\":" + std::to_string(ev.status)
        + ",\"bytes\":" + std::to_string(ev.bytes)
        + ",\"elapsed_ms\":" + std::to_string(ev.elapsed_ms)
        + ",\"error_code\":" + std::to_string(ev.error_code)
        + ",\"device_id\":\"" + jesc(ev.device_id) + "\"}\n";
    return o;
}

static bool read_last_head(const std::string& path, std::uint64_t& seq,
                           std::string& mac, std::string& err) {
    seq = 0;
    mac = ZERO_MAC;
    std::ifstream f(path, std::ios::binary);
    if (!f) return true;
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    const std::streamoff win = 65536;
    std::streamoff off = sz > win ? sz - win : 0;
    f.seekg(off);
    std::string buf(static_cast<size_t>(sz - off), '\0');
    if (!buf.empty()) f.read(&buf[0], static_cast<std::streamsize>(buf.size()));
    size_t p = 0;
    if (off > 0) {
        size_t nl = buf.find('\n');
        if (nl == std::string::npos) return true;
        p = nl + 1;
    }
    while (p < buf.size()) {
        size_t q = buf.find('\n', p);
        if (q == std::string::npos) q = buf.size();
        std::string line = buf.substr(p, q - p);
        p = q + 1;
        std::string sch;
        if (!json_get(line, "schema", sch) || (sch != "2" && sch != "3")) continue;
        std::string ss, mm;
        std::uint64_t n = 0;
        if (json_get(line, "seq", ss) && to_u64(ss, n) &&
            json_get(line, "mac", mm) && mm.size() == 64) {
            seq = n;
            mac = mm;
        }
    }
    (void)err;
    return true;
}

static bool key_spec_env(std::string& spec) {
    const char* e = std::getenv("FE_AUDIT_KEY");
    if (e && *e) { spec = e; return true; }
    return false;
}

static bool load_key(std::string spec, unsigned char key[32],
                     std::string& kid, std::string& err) {
    if (spec.empty()) key_spec_env(spec);
    if (spec.empty()) { err = "no audit key"; return false; }
    std::ifstream f(spec, std::ios::binary);
    if (!f) { err = "cannot open audit key"; return false; }
    std::string b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (b.empty()) { err = "empty audit key"; return false; }
    static const char magic[] = "FEDP1";
    bool ok = false;
    if (b.size() > 5 && std::memcmp(b.data(), magic, 5) == 0) {
#ifdef _WIN32
        DATA_BLOB in;
        in.cbData = static_cast<DWORD>(b.size() - 5);
        in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(b.data() + 5));
        DATA_BLOB out = {0, nullptr};
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            err = "DPAPI unprotect failed";
            return false;
        }
        if (out.cbData < 32) {
            if (out.pbData) LocalFree(out.pbData);
            err = "bad DPAPI audit key";
            return false;
        }
        std::memcpy(key, out.pbData, 32);
        LocalFree(out.pbData);
        ok = true;
#else
        err = "DPAPI key on non-Windows";
        return false;
#endif
    } else if (b.size() >= 64 && all_hex(b.substr(0, 64))) {
        ok = from_hex(b.substr(0, 64), key, 32);
    } else if (b.size() >= 32) {
        std::memcpy(key, b.data(), 32);
        ok = true;
    }
    sodium_memzero(b.data(), b.size());
    if (!ok) { err = "invalid audit key"; return false; }
    unsigned char h[32] = {0};
    hmac256(key, "FE_AUDIT_KEY_ID", h);
    kid = to_hex(h, 8);
    sodium_memzero(h, 32);
    return true;
}

} // namespace

AuditWriter& audit_writer() {
    static AuditWriter w;
    return w;
}

AuditWriter::~AuditWriter() {
    if (inited_) {
        flush();
        close_all(fd_);
        fd_ = 0;
    }
    sodium_memzero(key_, 32);
}

bool AuditWriter::init(const std::string& log_path, const std::string& key_spec_in,
                       bool strict, bool sync_each, bool keep_path, std::string& err) {
    if (log_path.empty()) { err = "empty audit path"; return false; }
    path_ = log_path;
    strict_ = strict;
    sync_each_ = sync_each;
    keep_path_ = keep_path;
    std::string spec = key_spec_in;
    protected_ = load_key(spec, key_, kid_, err);
    if (!protected_) {
        if (strict_) return false;
        err.clear();
        mode_ = "plain";
    } else {
        mode_ = "protected";
    }
    std::error_code ec;
    std::filesystem::path pp(path_);
    if (!pp.parent_path().empty()) std::filesystem::create_directories(pp.parent_path(), ec);
    if (!open_append(path_, fd_, err)) return false;
    std::filesystem::permissions(path_,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);

    std::string e2;
    read_last_head(path_, head_seq_, head_mac_, e2);

    std::string boot_path = path_ + ".boot";
    std::ifstream bf(boot_path, std::ios::binary);
    if (bf) std::getline(bf, boot_id_);
    if (boot_id_.size() < 16) {
        unsigned char r[16];
        randombytes_buf(r, sizeof(r));
        boot_id_ = to_hex(r, sizeof(r));
        sodium_memzero(r, sizeof(r));
        std::string e3;
        atomic_write(boot_path, boot_id_ + "\n", e3);
    }
    unsigned char sid[16];
    randombytes_buf(sid, sizeof(sid));
    session_id_ = to_hex(sid, sizeof(sid));
    sodium_memzero(sid, sizeof(sid));
    inited_ = true;
    return true;
}

bool AuditWriter::append(const AuditEvent& ev, std::string& err) {
    if (!inited_) { err = "audit writer not initialized"; return false; }
    if (path_.empty()) { err = "empty audit path"; return false; }

    FileLock lock(path_ + ".lock", err);
    if (!lock.ok()) return false;

    std::uint64_t log_seq = 0;
    std::string log_mac = ZERO_MAC, e2;
    read_last_head(path_, log_seq, log_mac, e2);
    std::uint64_t state_seq = 0;
    std::ifstream sf(path_ + ".seq");
    if (sf) { std::string s; std::getline(sf, s); to_u64(s, state_seq); }
    std::uint64_t seq = (std::max)(log_seq, state_seq) + 1;

    std::string line;
    std::string new_mac;
    if (protected_) {
        std::uint64_t mono = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        unsigned char hsub[32] = {0}, esub[32] = {0};
        subkey(key_, "FE_AUDIT_KEYHASH", hsub);
        subkey(key_, "FE_AUDIT_KEYENC", esub);
        std::string kh = path_hash(hsub, ev.op, ev.key);
        std::string kct;
        if (keep_path_) kct = path_encrypt(esub, ev.op, seq, ev.key);
        std::string canon = canonical3(seq, log_mac, ev.ts, mono,
            boot_id_, session_id_, ev.op, kh, kct, ev.status,
            ev.bytes, ev.elapsed_ms, ev.error_code, ev.device_id);
        unsigned char m[32] = {0};
        hmac256(key_, canon, m);
        new_mac = to_hex(m, 32);
        sodium_memzero(m, 32);
        sodium_memzero(hsub, 32);
        sodium_memzero(esub, 32);
        line = line3(ev, seq, log_mac, mono, boot_id_, session_id_, kh, kct, new_mac, kid_);
    } else {
        line = line1(ev);
    }

    if (!write_all(fd_, line)) { err = "audit write failed"; return false; }
    head_seq_ = seq;
    if (protected_) head_mac_ = new_mac;
    ++pending_;
    if (sync_each_ || pending_ >= 16) flush();

    if (protected_) atomic_write(path_ + ".seq", std::to_string(seq), e2);
    return true;
}

void AuditWriter::flush() {
    if (inited_ && fd_) sync_all(fd_);
    pending_ = 0;
}

bool audit_keygen(const std::string& path, std::string& err) {
    if (path.empty()) { err = "empty key path"; return false; }
    unsigned char raw[32];
    randombytes_buf(raw, sizeof(raw));
    std::string blob;
#ifdef _WIN32
    DATA_BLOB in;
    in.cbData = 32;
    in.pbData = raw;
    DATA_BLOB out = {0, nullptr};
    if (!CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
        sodium_memzero(raw, 32);
        err = "DPAPI protect failed";
        return false;
    }
    blob = "FEDP1";
    blob.append(reinterpret_cast<const char*>(out.pbData), out.cbData);
    if (out.pbData) LocalFree(out.pbData);
#else
    blob.assign(reinterpret_cast<const char*>(raw), 32);
#endif
    sodium_memzero(raw, 32);
    return atomic_write(path, blob, err);
}

bool audit_verify(const std::string& path, const std::string& key_spec,
                  const std::string& anchor_path, AuditVerifyResult& out,
                  bool decrypt_path) {
    std::string spec = key_spec;
    unsigned char key[32] = {0};
    std::string kid;
    std::string err;
    bool have_key = load_key(spec, key, kid, err);

    std::ifstream f(path, std::ios::binary);
    if (!f) { out.err = "cannot open audit log"; return false; }

    std::uint64_t expected = 1;
    std::string prev = ZERO_MAC;
    std::uint64_t last_ts = 0;
    std::uint64_t last_mono = 0;
    std::string last_boot;
    std::string line;
    bool failed = false;
    bool saw_protected = false;

    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::string sch;
        if (!json_get(line, "schema", sch)) {
            out.err = "bad JSON line";
            failed = true;
            break;
        }
        if (sch == "1") { ++out.legacy_lines; continue; }
        if (sch != "2" && sch != "3") { out.err = "unknown schema: " + sch; failed = true; break; }
        saw_protected = true;
        if (sch == "3") ++out.schema3_lines;
        if (!have_key) { out.err = "audit key required"; failed = true; break; }

        std::string ss, mm, cv, sv, evs;
        std::uint64_t seq = 0;
        std::uint64_t ts = 0, mono = 0, bytes = 0, elapsed = 0;
        std::uint64_t st = 0, ec = 0;
        if (!json_get(line, "seq", ss) || !to_u64(ss, seq) ||
            !json_get(line, "mac", mm) || mm.size() != 64 ||
            !json_get(line, "prev", cv) ||
            !json_get(line, "ts", ss) || !to_u64(ss, ts) ||
            !json_get(line, "mono", ss) || !to_u64(ss, mono) ||
            !json_get(line, "status", sv) || !to_u64(sv, st) ||
            !json_get(line, "bytes", ss) || !to_u64(ss, bytes) ||
            !json_get(line, "elapsed_ms", ss) || !to_u64(ss, elapsed) ||
            !json_get(line, "error_code", evs) || !to_u64(evs, ec)) {
            out.err = "missing audit fields";
            failed = true;
            break;
        }
        int status = static_cast<int>(static_cast<std::int64_t>(st));
        int ecode = static_cast<int>(static_cast<std::int64_t>(ec));
        std::string op, keyf, boot, session, dev;
        if (!json_get(line, "op", op) ||
            !json_get(line, "boot", boot) || !json_get(line, "session", session) ||
            !json_get(line, "device_id", dev)) {
            out.err = "missing audit strings";
            failed = true;
            break;
        }
        std::string canon;
        if (sch == "3") {
            std::string kh, kct;
            if (!json_get(line, "key_h", kh) || kh.size() != 32 ||
                !json_get(line, "key_ct", kct)) {
                out.err = "missing audit key fields";
                failed = true;
                break;
            }
            canon = canonical3(seq, cv, ts, mono, boot, session, op, kh, kct,
                               status, bytes, elapsed, ecode, dev);
        } else {
            if (!json_get(line, "key", keyf)) {
                out.err = "missing audit key";
                failed = true;
                break;
            }
            canon = canonical2(seq, cv, ts, mono, boot, session, op, keyf,
                               status, bytes, elapsed, ecode, dev);
        }
        unsigned char h[32] = {0};
        hmac256(key, canon, h);
        if (!equal_mac(to_hex(h, 32), mm)) {
            out.first_bad_seq = seq;
            out.err = "MAC mismatch at seq " + std::to_string(seq);
            failed = true;
            break;
        }
        if (seq != expected || cv != prev) {
            out.first_bad_seq = seq;
            out.err = "chain break at seq " + std::to_string(seq);
            failed = true;
            break;
        }
        if (ts + 2 < last_ts || (!boot.empty() && boot == last_boot && mono < last_mono)) {
            out.first_bad_seq = seq;
            out.err = "time regression at seq " + std::to_string(seq);
            failed = true;
            break;
        }
        if (decrypt_path && sch == "3") {
            std::string kh, kct;
            json_get(line, "key_h", kh);
            json_get(line, "key_ct", kct);
            if (!kct.empty()) {
                unsigned char esub[32] = {0};
                subkey(key, "FE_AUDIT_KEYENC", esub);
                std::string plain;
                if (path_decrypt(esub, op, seq, kct, plain)) {
                    out.paths.push_back(std::to_string(seq) + "\t" + plain);
                } else {
                    out.err = "path decrypt failed at seq " + std::to_string(seq);
                    out.first_bad_seq = seq;
                    sodium_memzero(esub, 32);
                    sodium_memzero(key, 32);
                    failed = true;
                    break;
                }
                sodium_memzero(esub, 32);
            } else {
                out.paths.push_back(std::to_string(seq) + "\t<no path stored>");
            }
        }
        expected = seq + 1;
        prev = mm;
        last_ts = ts;
        last_mono = mono;
        last_boot = boot;
        out.head_seq = seq;
        out.head_mac = mm;
        out.has_head = true;
        ++out.checked_lines;
    }
    sodium_memzero(key, 32);
    if (failed) return false;
    if (!anchor_path.empty() && saw_protected) {
        std::ifstream af(anchor_path);
        std::string al, last;
        while (std::getline(af, al)) if (!al.empty()) last = al;
        if (last.empty()) { out.err = "empty anchor file"; return false; }
        std::string as, am, ak;
        if (!json_get(last, "seq", as) || !json_get(last, "mac", am) || !json_get(last, "kid", ak)) {
            out.err = "bad anchor line";
            return false;
        }
        std::uint64_t anchor_seq = 0;
        to_u64(as, anchor_seq);
        if (anchor_seq != out.head_seq || am != out.head_mac ||
            (!kid.empty() && ak != kid)) {
            out.err = "anchor mismatch: log rolled back or rechained";
            return false;
        }
    }
    out.kid = kid;
    out.ok = true;
    return true;
}

bool audit_write_anchor(const std::string& log_path, const std::string& key_spec,
                        const std::string& anchor_path, std::string& err) {
    std::uint64_t seq = 0;
    std::string mac, kid, e2;
    read_last_head(log_path, seq, mac, e2);
    if (seq == 0 || mac == ZERO_MAC) { err = "no protected audit head"; return false; }
    unsigned char key[32] = {0};
    if (!load_key(key_spec, key, kid, e2)) { err = e2; return false; }
    sodium_memzero(key, 32);
    std::string line = "{\"ts\":" + std::to_string(static_cast<unsigned long long>(std::time(nullptr)))
        + ",\"seq\":" + std::to_string(seq)
        + ",\"mac\":\"" + mac + "\",\"kid\":\"" + kid + "\"}\n";
    std::intptr_t h = 0;
    if (!open_append(anchor_path, h, err)) return false;
    bool ok = write_all(h, line);
    sync_all(h);
    close_all(h);
    if (!ok) err = "anchor write failed";
    return ok;
}

} // namespace fe
