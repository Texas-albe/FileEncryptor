// 加密盘索引模块
#include "vault_index.hpp"
#include "FileEncryptor.hpp"
#include "kdf.hpp"             
#include <sodium.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <map>
#include <set>
#include <atomic>
#include <chrono>
#include <filesystem>
#ifdef _WIN32
#  include <windows.h>
#endif

// 索引密钥缓存 hook
// holder
// 放文件顶层作用
static bool (*g_index_key_hook)(const SecureBuffer&, const VaultMeta&,
                                std::vector<unsigned char>&, std::string&) = nullptr;
static void (*g_index_key_drop)() = nullptr;

namespace fs = std::filesystem;

// 保留路径判定
bool rel_first_reserved(const std::string& rel) {
    size_t p = rel.find('/');
    std::string first = (p == std::string::npos) ? rel : rel.substr(0, p);
    if (first.size() != std::strlen(VDISK_RESERVED_TRASH)) return false;
    for (size_t i = 0; i < first.size(); ++i) {
        char x = first[i], y = VDISK_RESERVED_TRASH[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return false;
    }
    return true;
}

namespace {

const char kIdxMagic[6] = {'F','E','I','D','X','1'};
// FEIDX2
const char kIdxMagicV2[6] = {'F','E','I','D','X','2'};

// 小工具
std::string normsep(const std::string& s) {
#ifdef _WIN32
    std::string o = s;
    for (char& c : o) if (c == '\\') c = '/';
    return o;
#else
    return s;
#endif
}

// 绝对路径相对库
bool path_in_reserved(const fs::path& p, const fs::path& base) {
    std::error_code ec;
    fs::path r = fs::relative(p, base, ec);
    if (ec) return false;
    std::string rel = normsep(r.u8string());
    if (rel == "." || rel.empty()) return false;
    return rel_first_reserved(rel);
}

std::string to_hex(const std::vector<unsigned char>& b) {
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (unsigned char c : b) { s += h[c >> 4]; s += h[c & 0xF]; }
    return s;
}

std::vector<unsigned char> from_hex(const std::string& s) {
    std::vector<unsigned char> out; out.reserve(s.size() / 2);
    auto hv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = hv(s[i]), lo = hv(s[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return out;
}

std::string jstrlit(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\t': o += "\\t"; break;
            case '\r': o += "\\r"; break;
            default: o += c;
        }
    }
    o += "\"";
    return o;
}

// 极简 JSON
struct JVal {
    enum T { NUL, BL, NUM, ST, AR, OB } t = NUL;
    bool b = false;
    double n = 0;
    std::string raw;        // 数字原文
    std::string s;
    std::vector<JVal> a;
    std::vector<std::pair<std::string, JVal>> o;
    const JVal* at(const std::string& k) const {
        if (t != OB) return nullptr;
        for (const auto& p : o) if (p.first == k) return &p.second;
        return nullptr;
    }
};

void jskip(const std::string& s, size_t& i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
}

bool jstr(const std::string& s, std::string& out, std::string& err, size_t& i) {
    if (i >= s.size() || s[i] != '"') { err = "expected string"; return false; }
    i++; out.clear();
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') return true;
        if (c == '\\') {
            if (i >= s.size()) { err = "bad escape"; return false; }
            char e = s[i++];
            switch (e) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    if (i + 4 > s.size()) { err = "bad unicode"; return false; }
                    unsigned int cp = 0;
                    for (int k = 0; k < 4; k++) {
                        char h = s[i++]; cp <<= 4;
                        if (h >= '0' && h <= '9') cp += h - '0';
                        else if (h >= 'a' && h <= 'f') cp += h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') cp += h - 'A' + 10;
                        else { err = "bad unicode"; return false; }
                    }
                    if (cp < 0x80) out += (char)cp;
                    else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
                    else { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
                    break;
                }
                default: err = "bad escape"; return false;
            }
        } else out += c;
    }
    err = "unterminated string"; return false;
}

bool jnum(const std::string& s, double& out, std::string& raw, std::string& err, size_t& i) {
    size_t start = i;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) i++;
    while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '-' || s[i] == '+')) i++;
    if (i == start) { err = "expected number"; return false; }
    raw = s.substr(start, i - start);
    try { out = std::stod(raw); }
    catch (...) { err = "bad number"; return false; }
    return true;
}

// 整数取值一律走
uint64_t as_u64(const JVal* v, uint64_t def = 0) {
    if (!v || v->t != JVal::NUM) return def;
    if (!v->raw.empty()) {
        if (v->raw[0] == '-' || v->raw[0] == '+') return def;      // 无符号字段不接
        errno = 0;
        char* end = nullptr;
        unsigned long long x = std::strtoull(v->raw.c_str(), &end, 10);
        if (errno == ERANGE || !end || *end != '\0') return def;
        return (uint64_t)x;
    }
    return (uint64_t)v->n;
}

int64_t as_i64(const JVal* v, int64_t def = 0) {
    if (!v || v->t != JVal::NUM) return def;
    if (!v->raw.empty()) {
        errno = 0;
        char* end = nullptr;
        long long x = std::strtoll(v->raw.c_str(), &end, 10);
        if (errno == ERANGE || !end || *end != '\0') return def;
        return (int64_t)x;
    }
    return (int64_t)v->n;
}

bool jval(const std::string& s, JVal& v, std::string& err, size_t& i);

bool jarr(const std::string& s, JVal& v, std::string& err, size_t& i) {
    v.t = JVal::AR; v.a.clear(); i++;
    jskip(s, i);
    if (i < s.size() && s[i] == ']') { i++; return true; }
    while (true) {
        JVal el; if (!jval(s, el, err, i)) return false;
        v.a.push_back(std::move(el));
        jskip(s, i);
        if (i >= s.size()) { err = "unterminated array"; return false; }
        if (s[i] == ',') { i++; jskip(s, i); continue; }
        if (s[i] == ']') { i++; return true; }
        err = "expected , or ]"; return false;
    }
}

bool jobj(const std::string& s, JVal& v, std::string& err, size_t& i) {
    v.t = JVal::OB; v.o.clear(); i++;
    jskip(s, i);
    if (i < s.size() && s[i] == '}') { i++; return true; }
    while (true) {
        jskip(s, i);
        std::string key;
        if (!jstr(s, key, err, i)) return false;
        jskip(s, i);
        if (i >= s.size() || s[i] != ':') { err = "expected :"; return false; }
        i++; jskip(s, i);
        JVal val; if (!jval(s, val, err, i)) return false;
        v.o.emplace_back(std::move(key), std::move(val));
        jskip(s, i);
        if (i >= s.size()) { err = "unterminated object"; return false; }
        if (s[i] == ',') { i++; jskip(s, i); continue; }
        if (s[i] == '}') { i++; return true; }
        err = "expected , or }"; return false;
    }
}

bool jval(const std::string& s, JVal& v, std::string& err, size_t& i) {
    jskip(s, i);
    if (i >= s.size()) { err = "unexpected end"; return false; }
    char c = s[i];
    if (c == '{') return jobj(s, v, err, i);
    if (c == '[') return jarr(s, v, err, i);
    if (c == '"') { v.t = JVal::ST; return jstr(s, v.s, err, i); }
    if (c == 't') { if (s.compare(i, 4, "true") != 0) { err = "bad literal"; return false; } v.t = JVal::BL; v.b = true; i += 4; return true; }
    if (c == 'f') { if (s.compare(i, 5, "false") != 0) { err = "bad literal"; return false; } v.t = JVal::BL; v.b = false; i += 5; return true; }
    if (c == 'n') { if (s.compare(i, 4, "null") != 0) { err = "bad literal"; return false; } v.t = JVal::NUL; i += 4; return true; }
    if (c == '-' || c == '+' || isdigit((unsigned char)c)) { v.t = JVal::NUM; return jnum(s, v.n, v.raw, err, i); }
    err = "unexpected token"; return false;
}

// 文件 IO
bool read_file(const std::string& p, std::string& out) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss; ss << f.rdbuf(); out = ss.str();
    return true;
}

bool write_file_atomic(const std::string& p, const std::string& data, std::string& err) {
    std::string tmp = p + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) { err = "cannot write temp"; return false; }
        f.write(data.data(), (std::streamsize)data.size());
    }
    // 原子替换
    // 全走这里）
#ifdef _WIN32
    if (!MoveFileExW(utf8_to_wstring(tmp).c_str(), utf8_to_wstring(p).c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        err = "atomic replace failed"; return false;
    }
#else
    if (std::rename(tmp.c_str(), p.c_str()) != 0) { err = "rename failed"; return false; }
#endif
    return true;
}

// base64
static std::string to_b64(const std::vector<unsigned char>& b) {
    if (b.empty()) return std::string();
    size_t need = sodium_base64_ENCODED_LEN(b.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string out(need - 1, '\0');   // ENCODED_LEN 含结尾 NUL
    sodium_bin2base64(out.data(), need, b.data(), b.size(), sodium_base64_VARIANT_ORIGINAL);
    return out;
}
static std::vector<unsigned char> from_b64(const std::string& s) {
    std::vector<unsigned char> out;
    if (s.empty()) return out;
    out.resize(s.size());
    size_t outlen = 0;
    if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &outlen, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return std::vector<unsigned char>();
    out.resize(outlen);
    return out;
}

// 序列化
std::string meta_to_json(const VaultMeta& m) {
    std::ostringstream o;
    if (!m.encrypted) {
        // 旧明文格式
        o << "{\"format\":1"
          << ",\"salt\":\"" << to_hex(m.salt) << "\""
          << ",\"root\":" << jstrlit(m.root)
          << ",\"created\":" << m.created
          << ",\"opslimit\":" << m.opslimit
          << ",\"memlimit_kb\":" << m.memlimit_kb;
        if (!m.mount_point.empty()) o << ",\"mount_point\":" << jstrlit(m.mount_point);
        o << ",\"default_mode\":" << m.default_mode
          << ",\"compress_policy\":" << m.compress_policy << "}";
        return o.str();
    }
    o << "{\"format\":2"
      << ",\"salt\":\"" << to_hex(m.salt) << "\""
      << ",\"opslimit\":" << m.opslimit
      << ",\"memlimit_kb\":" << m.memlimit_kb;
    if (!m.mount_point.empty()) o << ",\"mount_point\":" << jstrlit(m.mount_point);
    o << ",\"default_mode\":" << m.default_mode
      << ",\"compress_policy\":" << m.compress_policy
      << ",\"meta_nonce\":\"" << to_hex(m.meta_nonce) << "\""
      << ",\"meta_enc\":\"" << to_b64(m.meta_enc) << "\"}";
    return o.str();
}

std::string entry_to_json(const VaultEntry& e) {
    std::ostringstream o;
    o << "{\"rel_path\":" << jstrlit(e.rel_path);
    // store 仅在随机命名
    if (!e.store.empty()) o << ",\"store\":" << jstrlit(e.store);
    o << ",\"orig_abs\":" << jstrlit(e.orig_abs)
      << ",\"size\":" << e.size
      << ",\"mtime\":" << e.mtime
      << ",\"enc_ts\":" << e.enc_ts
      << ",\"algo\":" << jstrlit(e.algo)
      << ",\"kdf\":" << jstrlit(e.kdf);
    if (e.is_dir) o << ",\"is_dir\":1";   // 目录条目
    o << "}";
    return o.str();
}

// 分目录索引
// 存储布局
// 每个 .idx = FEIDX1 +
// 旧版单一 <vault>/.feindex
std::string folder_rel_of(const std::string& rel_path) {
    size_t pos = rel_path.find_last_of('/');
    if (pos == std::string::npos) return std::string();   // 顶层 → 根目录 ""
    return rel_path.substr(0, pos);
}

std::string folder_index_name(const std::string& folder_rel) {
    if (folder_rel.empty()) return "__root__";
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(folder_rel.size() * 2);
    for (unsigned char c : folder_rel) { s += h[c >> 4]; s += h[c & 0xF]; }   // hex
    return s;
}

std::string shard_dir(const std::string& dir) { return dir + "/.feindex.d"; }

// store 分量安全
static bool store_name_safe(const std::string& s) {
    if (s.empty()) return true;                 // 空=旧盘语义
    if (s.find('/') != std::string::npos || s.find('\\') != std::string::npos) return false;
    if (s.find("..") != std::string::npos || s == ".") return false;
#ifdef _WIN32
    if (s.size() >= 2 &&
        ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':')
        return false;                           // 盘符绝对路径
#endif
    return true;
}

std::string folder_index_path(const std::string& dir, const std::string& folder_rel) {
    return shard_dir(dir) + "/" + folder_index_name(folder_rel) + ".idx";
}

// 分片集合版本戳
// 每写一次索引
// 判定「盘上索引变
// 靠目录 mtime
std::string index_stamp_path(const std::string& dir) {
    return shard_dir(dir) + "/.stamp";
}

void bump_index_stamp(const std::string& dir) {
    static std::atomic<uint64_t> seq{0};
    uint64_t v = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    v ^= (uint64_t)(seq.fetch_add(1) + 1) * 0x9E3779B97F4A7C15ULL;
    if (v == 0) v = 1;                       // 0 保留给「无戳」
    unsigned char b[8];
    for (int i = 0; i < 8; i++) b[i] = (unsigned char)(v >> (8 * i));
    std::string werr;
    write_file_atomic(index_stamp_path(dir), std::string((const char*)b, 8), werr);  // best-effort
}

bool read_index_stamp(const std::string& dir, uint64_t& out) {
    std::string s;
    if (!read_file(index_stamp_path(dir), s) || s.size() < 8) return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)(unsigned char)s[i] << (8 * i);
    if (v == 0) return false;
    out = v;
    return true;
}

// 把明文 JSON 封存到指
bool seal_to_path(const std::string& path, const VaultMeta& meta,
                  const SecureBuffer& password, const std::string& plaintext, std::string& err) {
    std::vector<unsigned char> key;
    if (!(g_index_key_hook ? g_index_key_hook(password, meta, key, err)
                           : derive_index_key(password, meta, key, err))) return false;
    // 索引 KEK 落入 SecureBuffer，并
    SecureBuffer sek(key.data(), key.size());
    sodium_memzero(key.data(), key.size());
    std::vector<unsigned char>().swap(key);
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<unsigned char> cipher(crypto_secretbox_MACBYTES + plaintext.size());
    if (crypto_secretbox_easy(cipher.data(),
                              (const unsigned char*)plaintext.data(), plaintext.size(),
                              nonce.data(), sek.data()) != 0) {
        err = "index seal failed";
        return false;
    }
    std::string blob;
    blob.append(kIdxMagicV2, 6);
    // 序号取写入时刻
    uint64_t seq = (uint64_t)time(nullptr);
    unsigned char seq8[8];
    for (int i = 0; i < 8; i++) seq8[i] = (unsigned char)(seq >> (56 - 8 * i));
    blob.append((const char*)seq8, 8);
    blob.append((const char*)nonce.data(), nonce.size());
    blob.append((const char*)cipher.data(), cipher.size());
    return write_file_atomic(path, blob, err);
}

// 从指定路径解出
bool open_from_path(const std::string& path, const VaultMeta& meta,
                    const SecureBuffer& password, std::string& text, std::string& err,
                    bool missing_ok) {
    std::string blob;
    if (!read_file(path, blob)) {
        // 读取失败须区分「
        std::error_code fec;
        if (fs::exists(fs::u8path(path), fec)) { err = "index unreadable"; return false; }
        if (missing_ok) { text = "[]"; return true; }
        err = "index not found"; return false;
    }
    // 分片布局版本
    size_t off;
    if (std::memcmp(blob.data(), kIdxMagic, 6) == 0) {
        off = 6;                       // 旧布局
    } else if (std::memcmp(blob.data(), kIdxMagicV2, 6) == 0) {
        off = 14;                      // 新布局
    } else { err = "bad index magic"; return false; }
    if (blob.size() < off + 24 + crypto_secretbox_MACBYTES) { err = "corrupt index"; return false; }
    std::vector<unsigned char> nonce(blob.data() + off, blob.data() + off + 24);
    const unsigned char* cph = (const unsigned char*)blob.data() + off + 24;
    size_t cph_len = blob.size() - off - 24;
    std::vector<unsigned char> key;
    if (!(g_index_key_hook ? g_index_key_hook(password, meta, key, err)
                           : derive_index_key(password, meta, key, err))) return false;
    // 索引 KEK 落入 SecureBuffer，并
    SecureBuffer sek(key.data(), key.size());
    sodium_memzero(key.data(), key.size());
    std::vector<unsigned char>().swap(key);
    std::vector<unsigned char> plain(cph_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plain.data(), cph, cph_len, nonce.data(), sek.data()) != 0) {
        err = "wrong password or corrupt index";
        return false;
    }
    text.assign((const char*)plain.data(), plain.size());
    return true;
}

bool write_folder_index(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const std::string& folder_rel,
                        const std::string& json, std::string& err) {
    return seal_to_path(folder_index_path(dir, folder_rel), meta, password, json, err);
}

bool read_folder_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& folder_rel,
                       std::string& text, std::string& err) {
    return open_from_path(folder_index_path(dir, folder_rel), meta, password, text, err, true);
}

// 把全量条目
bool shard_entries(const std::string& dir, const VaultMeta& meta,
                   const SecureBuffer& password, const std::vector<VaultEntry>& entries,
                   std::string& err) {
    std::map<std::string, std::vector<const VaultEntry*>> by_folder;
    for (const auto& e : entries) by_folder[folder_rel_of(e.rel_path)].push_back(&e);
    std::string sd = shard_dir(dir);
    std::error_code ec;
    fs::create_directories(fs::u8path(sd), ec);
    // 先写各目录分片
    for (auto& kv : by_folder) {
        std::ostringstream o; o << "[";
        const auto& v = kv.second;
        for (size_t i = 0; i < v.size(); i++) { if (i) o << ","; o << entry_to_json(*v[i]); }
        o << "]";
        if (!write_folder_index(dir, meta, password, kv.first, o.str(), err)) return false;
    }
    // 清掉
    if (fs::exists(fs::u8path(sd), ec)) {
        for (auto& e : fs::directory_iterator(fs::u8path(sd), ec)) {
            if (ec) break;
            if (!e.is_regular_file()) continue;
            std::string fn = e.path().filename().u8string();
            if (fn.size() < 4 || fn.substr(fn.size() - 4) != ".idx") continue;
            std::string stem = fn.substr(0, fn.size() - 4);
            // 反推 folder_rel
            std::string folder;
            if (stem != "__root__") {
                bool okhex = (stem.size() % 2 == 0) && !stem.empty();
                std::vector<unsigned char> bytes;
                for (size_t i = 0; okhex && i + 1 < stem.size(); i += 2) {
                    auto hv = [](char c) -> int {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                        return -1;
                    };
                    int hi = hv(stem[i]), lo = hv(stem[i + 1]);
                    if (hi < 0 || lo < 0) { okhex = false; break; }
                    bytes.push_back((unsigned char)((hi << 4) | lo));
                }
                if (!okhex) continue;   // 非分片命名
                folder.assign((const char*)bytes.data(), bytes.size());
            }
            if (!by_folder.count(folder)) {
                std::error_code rme;
                fs::remove(e.path(), rme);   // best-effort 清理
            }
        }
    }
    // 删除旧单 .feindex
    std::error_code rme;
    fs::remove(fs::u8path(dir + "/.feindex"), rme);
    bump_index_stamp(dir);   // 全量覆写同样要
    return true;
}

} // namespace

// 索引盘面版本戳
// 新库读 .stamp
uint64_t vault_index_stamp(const std::string& dir) {
    uint64_t v = 0;
    if (read_index_stamp(dir, v)) return v;
    std::error_code ec;
    auto p = fs::u8path(shard_dir(dir));
    auto t = fs::last_write_time(p, ec);
    if (!ec) return (uint64_t)t.time_since_epoch().count();
    auto q = fs::u8path(dir + "/.feindex");
    auto t2 = fs::last_write_time(q, ec);
    if (!ec) return ((uint64_t)t2.time_since_epoch().count() << 1) | 1ULL;
    return 0;
}


// 索引密钥缓存注
// holder
// 用函数指针

void set_index_key_cache_hook(
    bool (*fn)(const SecureBuffer&, const VaultMeta&, std::vector<unsigned char>&, std::string&),
    void (*drop)()) {
    g_index_key_hook = fn;
    g_index_key_drop = drop;
}
static void call_index_key_drop() { if (g_index_key_drop) g_index_key_drop(); }

void forget_cached_index_keys() { call_index_key_drop(); }

// 索引加解密
// 注：索引密钥
// 它与句柄
bool derive_index_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key, std::string& err) {
    key.assign(crypto_secretbox_KEYBYTES, 0);
    if (meta.salt.size() != crypto_pwhash_SALTBYTES) { err = "bad salt size"; return false; }
    // vault.meta 的 salt/ops/mem
    // 上界
    // 进程级 KDF 信号量
    if (meta.opslimit > KDF_OPS_LIMIT_MAX ||
        (size_t)meta.memlimit_kb * 1024 > KDF_MEM_LIMIT_MAX_BYTES) {
        err = "vault.meta 的 KDF 参数超出安全上界，库文件已损坏或被刻意构造，拒绝解锁";
        return false;
    }
    if (!derive_key(password.data(), password.size(), meta.salt.data(),
                    key.data(), meta.opslimit, (size_t)meta.memlimit_kb * 1024,
                    key.size())) {
        err = "argon2id derivation failed";
        return false;
    }
    return true;
}

// 公开 API

std::string vault_random_store_name() {
    unsigned char b[8];
    randombytes_buf(b, sizeof(b));
    static const char* kHex = "0123456789abcdef";
    std::string s; s.reserve(16);
    for (int i = 0; i < 8; ++i) { s.push_back(kHex[b[i] >> 4]); s.push_back(kHex[b[i] & 0xF]); }
    return s;
}

std::string vault_ptd_path(const std::string& dir, const std::string& rel, const std::string& store) {
    // 防御
    if (rel.find("..") != std::string::npos) return std::string();
    std::string subdir, base;
    size_t pos = rel.find_last_of('/');
    if (pos == std::string::npos) { base = rel; }
    else { subdir = rel.substr(0, pos); base = rel.substr(pos + 1); }
    if (!store.empty()) {
        // store 与 rel 同口径做分量
        if (!store_name_safe(store)) return std::string();
        base = store;
    }
    std::string p = dir;
    if (!subdir.empty()) p += "/" + subdir;
    p += "/" + base + ".ptd";
    return p;
}

std::string vault_mode_str(CryptoMode m) {
    switch (m) {
        case CryptoMode::XCHACHA20: return "XChaCha20";
        case CryptoMode::AEGIS256:  return "AEGIS-256";
        case CryptoMode::SM4:       return "SM4-GCM";
        case CryptoMode::AES_GCM:   return "AES-256-GCM";
    }
    return "unknown";
}

bool vault_meta_init(const std::string& dir, const std::string& root,
                     VaultMeta& out, std::string& err) {
    if (!create_directory_recursive(dir)) { err = "cannot create vault dir"; return false; }
    std::string mp = dir + "/vault.meta";
    {
        std::ifstream chk(mp);
        if (chk.good()) {
            chk.close();
            return vault_meta_load(dir, out, err);
        }
    }
    VaultMeta m;
    m.salt.resize(crypto_pwhash_SALTBYTES);
    randombytes_buf(m.salt.data(), m.salt.size());
    m.root = root.empty() ? dir : root;
    m.created = (uint64_t)time(nullptr);
    m.opslimit = 4;
    m.memlimit_kb = 65536;
    std::string js = meta_to_json(m);
    if (!write_file_atomic(mp, js, err)) return false;
    out = m;
    return true;
}

bool vault_meta_load(const std::string& dir, VaultMeta& out, std::string& err) {
    std::string mp = dir + "/vault.meta";
    std::string s;
    if (!read_file(mp, s)) { err = "vault.meta not found (not a vault)"; return false; }
    JVal v; size_t i = 0;
    if (!jval(s, v, err, i)) return false;
    if (v.t != JVal::OB) { err = "bad vault.meta"; return false; }
    const JVal* f = v.at("format"); if (!f) { err = "missing format"; return false; }
    const JVal* sl = v.at("salt"); if (!sl) { err = "missing salt"; return false; }
    out.format = (uint32_t)f->n;
    out.salt = from_hex(sl->s);
    if (auto* p = v.at("opslimit")) out.opslimit = (unsigned int)as_u64(p);
    if (auto* p = v.at("memlimit_kb")) out.memlimit_kb = (uint32_t)as_u64(p);
    if (auto* p = v.at("mount_point")) out.mount_point = p->s;   // 旧库无此字段→留
    out.default_mode = 1;        // 旧库缺字段→沿用
    out.compress_policy = 100;   // 旧库缺字段→自动
    // p->n 保留符号
    if (auto* p = v.at("default_mode")) out.default_mode = (int)p->n;
    if (auto* p = v.at("compress_policy")) out.compress_policy = (int)p->n;
    const JVal* enc = v.at("meta_enc");
    const JVal* nonce = v.at("meta_nonce");
    if (out.format == 2 && enc && nonce) {
        out.encrypted = true;
        out.meta_nonce = from_hex(nonce->s);
        out.meta_enc = from_b64(enc->s);
        return true;
    }
    // 旧明文格式
    const JVal* rt = v.at("root"); if (!rt) { err = "missing root"; return false; }
    out.root = rt->s;
    if (auto* p = v.at("created")) out.created = as_u64(p);
    return true;
}

bool vault_meta_save(const std::string& dir, const VaultMeta& m, std::string& err) {
    return write_file_atomic(dir + "/vault.meta", meta_to_json(m), err);
}

// 用索引密钥
bool vault_meta_save_encrypted(const std::string& dir, const VaultMeta& m,
                               const std::vector<unsigned char>& kek, std::string& err) {
    if (sodium_init() < 0) { err = "libsodium init failed"; return false; }
    if (kek.size() < crypto_secretbox_KEYBYTES) { err = "bad KEK"; return false; }
    VaultMeta e = m;
    e.encrypted = true;
    e.meta_nonce.resize(crypto_secretbox_NONCEBYTES);
    randombytes_buf(e.meta_nonce.data(), e.meta_nonce.size());
    // 明文载荷
    std::string pt = std::string("{\"root\":") + jstrlit(m.root)
                   + ",\"created\":" + std::to_string(m.created) + "}";
    std::vector<unsigned char> ct(crypto_secretbox_MACBYTES + pt.size());
    if (crypto_secretbox_easy(ct.data(), (const unsigned char*)pt.data(), pt.size(),
                              e.meta_nonce.data(), kek.data()) != 0) {
        err = "meta encrypt failed"; return false;
    }
    e.meta_enc = std::move(ct);
    return write_file_atomic(dir + "/vault.meta", meta_to_json(e), err);
}

bool vault_meta_decrypt(VaultMeta& m, const SecureBuffer& password, std::string& err) {
    if (!m.encrypted) return true;   // 明文无需解密
    if (m.meta_enc.size() < crypto_secretbox_MACBYTES ||
        m.meta_nonce.size() != crypto_secretbox_NONCEBYTES) {
        err = "bad encrypted meta"; return false;
    }
    std::vector<unsigned char> kek;
    if (!derive_index_key(password, m, kek, err)) return false;
    std::vector<unsigned char> pt(m.meta_enc.size() - crypto_secretbox_MACBYTES);
    bool ok = (crypto_secretbox_open_easy(pt.data(), m.meta_enc.data(), m.meta_enc.size(),
                                         m.meta_nonce.data(), kek.data()) == 0);
    sodium_memzero(kek.data(), kek.size());
    if (!ok) { err = "wrong password (meta)"; return false; }
    std::string s((const char*)pt.data(), pt.size());
    JVal v; size_t i = 0; std::string jerr;
    if (!jval(s, v, jerr, i) || v.t != JVal::OB) { err = "bad meta payload"; return false; }
    if (auto* p = v.at("root")) m.root = p->s;
    if (auto* p = v.at("created")) m.created = as_u64(p);
    return true;
}

bool vault_derive_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key32, std::string& err) {
    return derive_index_key(password, meta, key32, err);
}

// 防御
// 逃逸库目录去读
// 不可篡改），此处做
static bool rel_path_safe(const std::string& rel) {
    if (rel.empty()) return true;                 // 空 rel
    if (rel[0] == '/') return false;              // 绝对路径
#ifdef _WIN32
    if (rel.size() >= 2 &&
        ((rel[0] >= 'A' && rel[0] <= 'Z') || (rel[0] >= 'a' && rel[0] <= 'z')) && rel[1] == ':')
        return false;                             // 盘符绝对路径
#endif
    // 保留名
    {
        size_t slash = rel.find('/');
        std::string top = (slash == std::string::npos) ? rel : rel.substr(0, slash);
        if (top == ".feindex" || top == ".feindex.d" || top == ".fevault" || top == "vault.meta")
            return false;
    }
    size_t start = 0;
    while (start < rel.size()) {
        size_t slash = rel.find('/', start);
        size_t end = (slash == std::string::npos) ? rel.size() : slash;
        std::string comp = rel.substr(start, end - start);
        if (comp.empty() || comp == ".." || comp == ".") return false;  // 空段 / 上溯段一律
        start = (slash == std::string::npos) ? rel.size() : slash + 1;
    }
    return true;
}

// 解析索引 JSON 文本
static bool parse_index_text(const std::string& text, std::vector<VaultEntry>& out, std::string& err) {
    JVal v; size_t i = 0;
    if (!jval(text, v, err, i)) return false;
    if (v.t != JVal::AR) { err = "index is not an array"; return false; }
    for (auto& el : v.a) {
        if (el.t != JVal::OB) continue;
        VaultEntry e;
        if (auto* p = el.at("rel_path")) e.rel_path = p->s;
        if (auto* p = el.at("store")) e.store = p->s;   // 旧索引无此键→留
        // 投毒
        if (!e.store.empty() && !store_name_safe(e.store)) continue;
        if (auto* p = el.at("orig_abs")) e.orig_abs = p->s;
    // 旧版本曾
    if (auto* p = el.at("size")) { e.size = as_u64(p); if (e.size >= ((uint64_t)1 << 63)) e.size = 0; }
    if (auto* p = el.at("mtime")) e.mtime = as_i64(p);
    if (auto* p = el.at("enc_ts")) e.enc_ts = as_u64(p);
        if (auto* p = el.at("algo")) e.algo = p->s;
        if (auto* p = el.at("kdf")) e.kdf = p->s;
        if (auto* p = el.at("is_dir")) e.is_dir = (p->t == JVal::BL) ? p->b : (as_u64(p) != 0);
        if (!rel_path_safe(e.rel_path)) continue;   // 畸形/
        out.push_back(std::move(e));
    }
    return true;
}

bool vault_read_index(const std::string& dir, const VaultMeta& meta,
                      const SecureBuffer& password, std::vector<VaultEntry>& out,
                      std::string& err) {
    out.clear();
    std::error_code ec;
    std::string sd = shard_dir(dir);
    if (fs::exists(fs::u8path(sd), ec)) {
        // 分目录模式
        for (auto& e : fs::directory_iterator(fs::u8path(sd), ec)) {
            if (ec) break;
            if (!e.is_regular_file()) continue;
            std::string fn = e.path().filename().u8string();
            if (fn.size() < 4 || fn.substr(fn.size() - 4) != ".idx") continue;
            std::string stem = fn.substr(0, fn.size() - 4);
            if (stem != "__root__") {
                // 仅承认合法分片
                bool okhex = (stem.size() % 2 == 0) && !stem.empty();
                for (size_t k = 0; okhex && k < stem.size(); ++k) {
                    char c = stem[k];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                        okhex = false;
                }
                if (!okhex) continue;   // 非分片命名
            }
            std::string text;
            if (!open_from_path(e.path().u8string(), meta, password, text, err, true)) return false;
            std::vector<VaultEntry> part;
            if (!parse_index_text(text, part, err)) return false;
            for (auto& x : part) out.push_back(std::move(x));
        }
        return true;
    }
    // 未分目录
    std::string legacy = dir + "/.feindex";
    if (fs::exists(fs::u8path(legacy), ec)) {
        std::string text;
        if (!open_from_path(legacy, meta, password, text, err, false)) return false;
        std::vector<VaultEntry> all;
        if (!parse_index_text(text, all, err)) return false;
        out = all;
        std::string merr;
        shard_entries(dir, meta, password, all, merr);   // 迁移失败不致命
        return true;
    }
    return true;   // 既无分目录
}

// 索引内存镜像
// append/upsert/remove 只需解密/加密「
// 写操作改内存
namespace {
std::mutex g_mtx;
std::string g_mir_dir;                       // 镜像所属库目录
std::map<std::string, std::string> g_mir;    // folder_rel → 明文 JSON
std::set<std::string> g_mir_dirty;           // 待落盘目录集
// 每个目录「载入/落
// 本进程
std::map<std::string, uint64_t> g_mir_stamp;
// flush=false 期间挂
// 重载前必须先落
std::map<std::string, std::vector<std::string>> g_mir_pending;
bool g_mir_sharded = false;                  // 当前库是否已确

// 0 = 每次改动
const uint64_t kMirrorAutoFlushMs = 0;
uint64_t g_mir_last_flush_ms = 0;

uint64_t now_ms_mirror() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}  // namespace

// 前向声明
static uint64_t folder_stamp_of(const std::string& dir, const std::string& folder);

// 前向声明
static bool mirror_load_folder_locked(const std::string& dir, const VaultMeta& meta,
                                      const SecureBuffer& password, const std::string& folder,
                                      std::string& err);

// 库已分目录
static bool ensure_sharded_locked(const std::string& dir, const VaultMeta& meta,
                                  const SecureBuffer& password, std::string& err) {
    if (g_mir_sharded && g_mir_dir == dir) return true;
    std::error_code ec;
    if (fs::exists(fs::u8path(shard_dir(dir)), ec)) {
        g_mir_dir = dir; g_mir_sharded = true; return true;
    }
    std::string legacy = dir + "/.feindex";
    if (!fs::exists(fs::u8path(legacy), ec)) {
        fs::create_directories(fs::u8path(shard_dir(dir)), ec);   // 全新库
        g_mir_dir = dir; g_mir_sharded = true; return true;
    }
    std::string text;
    if (!open_from_path(legacy, meta, password, text, err, false)) return false;
    std::vector<VaultEntry> all;
    if (!parse_index_text(text, all, err)) return false;
    if (!shard_entries(dir, meta, password, all, err)) return false;
    g_mir_dir = dir; g_mir_sharded = true;
    return true;
}

// 强制
bool vault_flush_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, std::string& err) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_mir_dirty.empty()) return true;
    if (g_mir_dir != dir) return true;       // 不是这个库
    bool wrote = false;
    for (const auto& folder : g_mir_dirty) {
        auto it = g_mir.find(folder);
        if (it == g_mir.end()) continue;
        // 写前核对盘面戳
        // 本进程尚未落盘
        // 刚写入
        if (!mirror_load_folder_locked(dir, meta, password, folder, err)) return false;
        it = g_mir.find(folder);
        if (it == g_mir.end()) continue;
        if (!write_folder_index(dir, meta, password, folder, it->second, err)) return false;
        g_mir_pending.erase(folder);
        g_mir_stamp[folder] = folder_stamp_of(dir, folder);
        wrote = true;
    }
    g_mir_dirty.clear();
    g_mir_last_flush_ms = now_ms_mirror();
    if (wrote) bump_index_stamp(dir);
    return true;
}

// 丢弃镜像
// 已在 g_mtx 内调用
static void mirror_drop_locked() {
    for (auto& kv : g_mir) sodium_memzero(kv.second.data(), kv.second.size());
    g_mir.clear();
    g_mir_dirty.clear();
    g_mir_stamp.clear();
    g_mir_pending.clear();
    g_mir_dir.clear();
    g_mir_sharded = false;
}

void vault_drop_index_mirror() {
    std::lock_guard<std::mutex> lk(g_mtx);
    mirror_drop_locked();
}

static bool json_array_append(std::string& arr, const std::string& obj, std::string& err);

// 单个分片文件
static uint64_t folder_stamp_of(const std::string& dir, const std::string& folder) {
    std::error_code ec;
    auto p = fs::u8path(folder_index_path(dir, folder));
    auto t = fs::last_write_time(p, ec);
    if (ec) return 0;                                    // 尚不存
    uint64_t mt = (uint64_t)t.time_since_epoch().count();
    uint64_t sz = (uint64_t)fs::file_size(p, ec);
    if (ec) sz = 0;
    return mt ^ (sz * 0x9E3779B97F4A7C15ULL);
}

// 取某目录
// 关键
// 后续写
static bool mirror_load_folder_locked(const std::string& dir, const VaultMeta& meta,
                                      const SecureBuffer& password, const std::string& folder,
                                      std::string& err) {
    if (g_mir_dir != dir) { mirror_drop_locked(); g_mir_dir = dir; }
    // 本进程已改脏，内存为准
    if (g_mir.count(folder) && g_mir_dirty.count(folder)) return true;
    const uint64_t stamp = folder_stamp_of(dir, folder);
    auto sit = g_mir_stamp.find(folder);
    if (g_mir.count(folder) && sit != g_mir_stamp.end() && sit->second == stamp) return true;

    std::string text;
    if (!read_folder_index(dir, meta, password, folder, text, err)) return false;
    // 盘面版本重放
    auto pit = g_mir_pending.find(folder);
    if (pit != g_mir_pending.end()) {
        for (const auto& obj : pit->second) {
            if (!json_array_append(text, obj, err)) return false;
        }
    }
    g_mir[folder] = std::move(text);
    g_mir_stamp[folder] = stamp;
    return true;
}

// 改动后落盘对应
static bool mirror_touch_locked(const std::string& dir, const VaultMeta& meta,
                                const SecureBuffer& password, const std::string& folder,
                                std::string& err) {
    g_mir_dirty.insert(folder);
    if (now_ms_mirror() - g_mir_last_flush_ms < kMirrorAutoFlushMs) return true;
    auto it = g_mir.find(folder);
    if (it == g_mir.end()) return true;
    if (!write_folder_index(dir, meta, password, folder, it->second, err)) return false;
    g_mir_dirty.erase(folder);
    g_mir_pending.erase(folder);
    g_mir_stamp[folder] = folder_stamp_of(dir, folder);
    bump_index_stamp(dir);                   // 让挂载端/其它实
    g_mir_last_flush_ms = now_ms_mirror();
    return true;
}

// 往 JSON 数组末尾 O
static bool json_array_append(std::string& arr, const std::string& obj, std::string& err) {
    if (arr == "[]" || arr.empty()) { arr = "[" + obj + "]"; return true; }
    size_t last = arr.rfind(']');
    if (last == std::string::npos) { err = "corrupt index text"; return false; }
    arr.resize(last);
    arr += "," + obj + "]";
    return true;
}

bool vault_append_entry(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const VaultEntry& e,
                        std::string& err, bool flush) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_sharded_locked(dir, meta, password, err)) return false;
    std::string folder = folder_rel_of(e.rel_path);
    if (!mirror_load_folder_locked(dir, meta, password, folder, err)) return false;
    const std::string obj = entry_to_json(e);
    if (!json_array_append(g_mir[folder], obj, err)) return false;
    if (!flush) {
        // 批量入盘热循环
        g_mir_pending[folder].push_back(obj);
        g_mir_dirty.insert(folder);
        return true;
    }
    return mirror_touch_locked(dir, meta, password, folder, err);
}

bool vault_write_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& json,
                       std::string& err) {
    // 外部整盘写入
    std::vector<VaultEntry> entries;
    if (!parse_index_text(json, entries, err)) return false;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        mirror_drop_locked();
    }
    return shard_entries(dir, meta, password, entries, err);
}

// 容错读索引
// 重建索引时用它
static void read_index_tolerant(const std::string& dir, const VaultMeta& meta,
                                const SecureBuffer& password, std::vector<VaultEntry>& out) {
    out.clear();
    std::error_code ec;
    std::string sd = shard_dir(dir);
    if (fs::exists(fs::u8path(sd), ec)) {
        for (auto& e : fs::directory_iterator(fs::u8path(sd), ec)) {
            if (ec) break;
            if (!e.is_regular_file()) continue;
            std::string fn = e.path().filename().u8string();
            if (fn.size() < 4 || fn.substr(fn.size() - 4) != ".idx") continue;
            std::string stem = fn.substr(0, fn.size() - 4);
            if (stem != "__root__") {
                bool okhex = (stem.size() % 2 == 0) && !stem.empty();
                for (size_t k = 0; okhex && k < stem.size(); ++k) {
                    char c = stem[k];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                        okhex = false;
                }
                if (!okhex) continue;
            }
            std::string text, ierr;
            if (!open_from_path(e.path().u8string(), meta, password, text, ierr, true)) continue;
            std::vector<VaultEntry> part;
            if (!parse_index_text(text, part, ierr)) continue;
            for (auto& x : part) out.push_back(std::move(x));
        }
        return;
    }
    std::string legacy = dir + "/.feindex";
    if (!fs::exists(fs::u8path(legacy), ec)) return;
    std::string text, ierr;
    if (!open_from_path(legacy, meta, password, text, ierr, true)) return;
    parse_index_text(text, out, ierr);
}

bool vault_reindex(const std::string& dir, const VaultMeta& meta,
                   const SecureBuffer& password, std::string& err,
                   const std::vector<VaultEntry>* old_hint,
                   VDiskProgressFn progress, void* user,
                   VDiskCancelFn cancel, void* cancel_user,
                   bool* cancelled) {
    // 重扫结果必须直
    vault_drop_index_mirror();
    std::vector<VaultEntry> entries;
    std::error_code ec;
    // 名字来源链
    // ① 内存旧索引快照
    // ② 盘面旧索引磁盘
    // ③ 名字信封
    // ④ 随机 store 名
    // 键：随机命名库用 store
    std::map<std::string, std::string> old_name_by_store;
    std::vector<VaultEntry> old_all;   // 旧条目全集
    auto harvest_names = [&](const std::vector<VaultEntry>& src) {
        for (auto& x : src) {
            if (x.is_dir || x.rel_path.empty()) continue;
            size_t slash = x.rel_path.find_last_of('/');
            std::string base = (slash == std::string::npos) ? x.rel_path
                                                            : x.rel_path.substr(slash + 1);
            if (base.empty()) continue;
            if (!x.store.empty()) old_name_by_store.emplace(x.store, base);
            else old_name_by_store.emplace(base, base);   // 旧盘
        }
    };
    // ① 内存快照先登记
    if (old_hint) { harvest_names(*old_hint); old_all.insert(old_all.end(), old_hint->begin(), old_hint->end()); }
    // ② 盘面旧索引
    {
        std::vector<VaultEntry> old;
        read_index_tolerant(dir, meta, password, old);
        harvest_names(old);
        old_all.insert(old_all.end(), old.begin(), old.end());
    }
    // 目录/文件名一律
    fs::path vdir = fs::u8path(dir);
    // 第一遍
    uint64_t total = 0;
    {
        std::error_code ec2;
        auto cnt = fs::recursive_directory_iterator(vdir, ec2);
        if (!ec2) {
            for (; cnt != fs::recursive_directory_iterator(); ++cnt) {
                auto& e = *cnt;
                // 保留子树整体跳
                if (e.is_directory() && path_in_reserved(e.path(), vdir)) {
                    cnt.disable_recursion_pending();
                    continue;
                }
                if (!e.is_regular_file()) continue;
                std::string ffn = e.path().filename().u8string();
                if (ffn == ".feindex" || ffn == "vault.meta" || ffn == ".feindex.tmp") continue;
                if (e.path().extension().u8string() != ".ptd") continue;
                total++;
            }
        }
    }
    uint64_t done = 0;
    if (progress) progress(0, total, user);

    // 第二遍
    // cancel 在每读头前探询
    bool cancelled_flag = false;
    fs::recursive_directory_iterator it(vdir, ec);
    if (!ec) {
        for (; it != fs::recursive_directory_iterator(); ++it) {
            auto& e = *it;
            if (e.is_directory() && path_in_reserved(e.path(), vdir)) {
                it.disable_recursion_pending();   // 回收站子树不重
                continue;
            }
            if (!e.is_regular_file()) continue;
            std::string full = e.path().u8string();              // UTF-8 全路径
            std::string fn   = e.path().filename().u8string();
            if (fn == ".feindex" || fn == "vault.meta" || fn == ".feindex.tmp") continue;
            if (e.path().extension().u8string() != ".ptd") continue;
            if (cancel && cancel(cancel_user)) { cancelled_flag = true; break; }  // 取消
            PtdMeta m;
            if (!read_ptd_metadata(full, m) || !m.valid) {        // 头损坏
                done++; if (progress) progress(done, total, user); continue;
            }
            // 实际存储文件名
            std::string stem = e.path().stem().u8string();
            // 目录结构保留
            std::string reldir;
            try {
                reldir = normsep(fs::relative(e.path(), vdir).parent_path().u8string());
            } catch (...) { reldir.clear(); }
            if (reldir == ".") reldir.clear();
            std::string orig;
            auto oit = old_name_by_store.find(stem);
            if (oit != old_name_by_store.end()) {
                // 旧索引已有该 store
                orig = oit->second;
            } else {
                // 新条目
                if (!read_original_name(full, orig, password) || orig.empty()) orig = stem;
            }
            VaultEntry ve;
            ve.rel_path = reldir.empty() ? orig : (reldir + "/" + orig);
            ve.store    = stem;
            ve.size = m.orig_size;
            ve.algo = vault_mode_str(m.mode);
            ve.kdf = "argon2id";
            if (!rel_path_safe(ve.rel_path)) { done++; if (progress) progress(done, total, user); continue; }
            entries.push_back(std::move(ve));
            done++; if (progress) progress(done, total, user);
        }
    }
    if (cancelled_flag) {
        if (cancelled) *cancelled = true;
        // 取消
        // 盘上 .feindex 分片仍是完
        return true;
    }
    // 保留既有目录条
    // 来源＝盘面旧索引 ∪
    {
        std::set<std::string> seen_dir;
        for (auto& x : old_all) {
            if (!x.is_dir || x.rel_path.empty()) continue;
            if (!seen_dir.insert(x.rel_path).second) continue;
            std::error_code dec;
            if (fs::is_directory(fs::u8path(dir + "/" + x.rel_path), dec))
                entries.push_back(x);
        }
    }
    // 回收站条目
    // 但盘面 .ptd 仍
    // 重建后回收站内
    {
        std::set<std::string> have;
        for (auto& x : entries) have.insert(x.rel_path);
        for (auto& x : old_all) {
            if (x.rel_path.empty() || x.is_dir || !rel_first_reserved(x.rel_path)) continue;
            if (!have.insert(x.rel_path).second) continue;
            std::string p = vault_ptd_path(dir, x.rel_path, x.store);
            if (p.empty()) continue;
            std::error_code dec;
            if (fs::exists(fs::u8path(p), dec)) entries.push_back(x);
        }
    }
    // 按目录分片落盘
    return shard_entries(dir, meta, password, entries, err);
}

std::string vault_entries_to_json(const std::vector<VaultEntry>& entries) {
    std::ostringstream o; o << "[";
    for (size_t i = 0; i < entries.size(); i++) { if (i) o << ","; o << entry_to_json(entries[i]); }
    o << "]";
    return o.str();
}

// M6 写支持
bool vault_upsert_entry(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const VaultEntry& e, std::string& err) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_sharded_locked(dir, meta, password, err)) return false;
    std::string folder = folder_rel_of(e.rel_path);
    if (!mirror_load_folder_locked(dir, meta, password, folder, err)) return false;
    std::vector<VaultEntry> v;
    if (!parse_index_text(g_mir[folder], v, err)) return false;
    bool replaced = false;
    for (auto& x : v) {
        if (x.rel_path == e.rel_path) { x = e; replaced = true; break; }
    }
    if (!replaced) v.push_back(e);
    g_mir[folder] = vault_entries_to_json(v);
    return mirror_touch_locked(dir, meta, password, folder, err);
}

bool vault_remove_entry(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& rel_path, std::string& err) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_sharded_locked(dir, meta, password, err)) return false;
    std::string folder = folder_rel_of(rel_path);
    if (!mirror_load_folder_locked(dir, meta, password, folder, err)) return false;
    std::vector<VaultEntry> v;
    if (!parse_index_text(g_mir[folder], v, err)) return false;
    std::vector<VaultEntry> out;
    out.reserve(v.size());
    for (const auto& x : v) if (x.rel_path != rel_path) out.push_back(x);
    g_mir[folder] = vault_entries_to_json(out);
    return mirror_touch_locked(dir, meta, password, folder, err);
}

// 批量删除
// 「载入 + 解析 + 重加密
bool vault_remove_entries(const std::string& dir, const VaultMeta& meta,
                          const SecureBuffer& password, const std::vector<std::string>& rel_paths,
                          std::string& err) {
    if (rel_paths.empty()) return true;
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_sharded_locked(dir, meta, password, err)) return false;
    std::map<std::string, std::set<std::string>> by_folder;
    for (const auto& r : rel_paths) by_folder[folder_rel_of(r)].insert(r);
    for (auto& kv : by_folder) {
        const std::string& folder = kv.first;
        if (!mirror_load_folder_locked(dir, meta, password, folder, err)) return false;
        std::vector<VaultEntry> v;
        if (!parse_index_text(g_mir[folder], v, err)) return false;
        std::vector<VaultEntry> out;
        out.reserve(v.size());
        for (const auto& x : v) if (!kv.second.count(x.rel_path)) out.push_back(x);
        g_mir[folder] = vault_entries_to_json(out);
        if (!mirror_touch_locked(dir, meta, password, folder, err)) return false;
    }
    return true;
}

// 只写受影响分片
bool vault_write_index_folders(const std::string& dir, const VaultMeta& meta,
                               const SecureBuffer& password,
                               const std::vector<std::string>& folders,
                               const std::vector<VaultEntry>& entries,
                               std::string& err) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!ensure_sharded_locked(dir, meta, password, err)) return false;
    std::vector<std::string> jsons;
    jsons.reserve(folders.size());
    for (const auto& folder : folders) {
        std::vector<VaultEntry> v;
        for (const auto& e : entries)
            if (folder_rel_of(e.rel_path) == folder) v.push_back(e);
        jsons.push_back(vault_entries_to_json(v));
    }
    for (size_t i = 0; i < folders.size(); ++i) {
        g_mir[folders[i]] = jsons[i];
        if (!mirror_touch_locked(dir, meta, password, folders[i], err)) return false;
    }
    return true;
}

// §4.4 恢复密钥
// 保险文件格式
// 密钥 = Argon2id
static const char* kRecoveryMagic = "FEVLT1";
static const size_t kRecoverySaltBytes = crypto_pwhash_SALTBYTES;

// 规范化
static std::string recovery_code_normalize(const std::string& s) {
    std::string o;
    for (char c : s) if (c >= '0' && c <= '9') o += c;
    return o;
}

std::string vault_recovery_gen_code() {
    // 48 位十进制 ≈ 159 bit 熵
    std::string s;
    s.reserve(48);
    for (int i = 0; i < 48; i++) s += (char)('0' + (randombytes_uniform(10)));
    return s;
}

// 恢复文件默认与密文同目录
static std::string recovery_path_legacy(const std::string& dir) {
    return normsep(dir) + "/.fevault";
}

// 首选路径：FE_RECOVERY_HOME 指向独立介质时，恢复文件外置与密文分离
static std::string recovery_path(const std::string& dir) {
    const char* home = std::getenv("FE_RECOVERY_HOME");
    if(home && *home) {
        unsigned char h[HASH_SIZE];
        std::string key = normsep(dir);
        crypto_generichash(h, sizeof(h),
            reinterpret_cast<const unsigned char*>(key.data()), key.size(), nullptr, 0);
        char hex[33]={0};
        sodium_bin2hex(hex, sizeof(hex), h, 16);
        return normsep(home) + "/fevault_" + hex;
    }
    return recovery_path_legacy(dir);
}

bool vault_recovery_exists(const std::string& dir) {
    std::ifstream f(recovery_path(dir), std::ios::binary);
    if(f.good()) return true;
    f.close();
    std::ifstream fl(recovery_path_legacy(dir), std::ios::binary);
    return fl.good();
}

bool vault_recovery_create(const std::string& dir, const SecureBuffer& passphrase,
                           const std::string& code, std::string& err) {
    std::string c = recovery_code_normalize(code);
    if (c.size() != 48) { err = "recovery code must be 48 decimal digits"; return false; }
    if (passphrase.empty()) { err = "empty passphrase"; return false; }

    std::vector<unsigned char> salt(kRecoverySaltBytes);
    randombytes_buf(salt.data(), salt.size());
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(key.data(), key.size(), c.data(), c.size(), salt.data(),
                      crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        err = "Argon2id failed"; return false;
    }
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<unsigned char> cph(crypto_secretbox_MACBYTES + passphrase.size());
    if (crypto_secretbox_easy(cph.data(),
                              (const unsigned char*)passphrase.cdata(), passphrase.size(),
                              nonce.data(), key.data()) != 0) {
        err = "seal failed"; return false;
    }
    std::vector<unsigned char> blob;
    blob.insert(blob.end(), kRecoveryMagic, kRecoveryMagic + 6);
    blob.insert(blob.end(), salt.begin(), salt.end());
    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), cph.begin(), cph.end());

    std::string data(blob.begin(), blob.end());
    std::string werr;
    if (!write_file_atomic(recovery_path(dir), data, werr)) { err = werr; return false; }
    sodium_memzero(key.data(), key.size());
    return true;
}

bool vault_recovery_load(const std::string& dir, const std::string& code,
                         SecureBuffer& out_passphrase, std::string& err) {
    std::string c = recovery_code_normalize(code);
    if (c.size() != 48) { err = "recovery code must be 48 decimal digits"; return false; }
    std::string blob;
    if (!read_file(recovery_path(dir), blob) &&
        !read_file(recovery_path_legacy(dir), blob)) {
        err = "no recovery file (.fevault)"; return false;
    }
    size_t need = 6 + kRecoverySaltBytes + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
    if (blob.size() < need) { err = "corrupt recovery file"; return false; }
    if (memcmp(blob.data(), kRecoveryMagic, 6) != 0) { err = "bad recovery file magic"; return false; }
    const unsigned char* p = (const unsigned char*)blob.data() + 6;
    std::vector<unsigned char> salt(p, p + kRecoverySaltBytes);
    p += kRecoverySaltBytes;
    std::vector<unsigned char> nonce(p, p + crypto_secretbox_NONCEBYTES);
    p += crypto_secretbox_NONCEBYTES;
    size_t cph_len = blob.size() - (6 + kRecoverySaltBytes + crypto_secretbox_NONCEBYTES);

    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(key.data(), key.size(), c.data(), c.size(), salt.data(),
                      crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        err = "Argon2id failed"; return false;
    }
    std::vector<unsigned char> plain(cph_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plain.data(), p, cph_len, nonce.data(), key.data()) != 0) {
        sodium_memzero(key.data(), key.size());
        err = "wrong recovery code";
        return false;
    }
    out_passphrase = SecureBuffer((const char*)plain.data(), plain.size());
    sodium_memzero(plain.data(), plain.size());
    sodium_memzero(key.data(), key.size());
    return true;
}

bool vault_recovery_remove(const std::string& dir, std::string& err) {
    bool removed = false;
    std::string p = recovery_path(dir);
    std::ifstream f(p, std::ios::binary);
    if (f.good()) {
        f.close();
        if (std::remove(p.c_str()) == 0) removed = true;
    } else {
        f.close();
    }
    std::string lp = recovery_path_legacy(dir);
    std::ifstream fl(lp, std::ios::binary);
    if (fl.good()) {
        fl.close();
        if (std::remove(lp.c_str()) == 0) removed = true;
    } else {
        fl.close();
    }
    if (!removed) { err = "no recovery file"; return false; }
    return true;
}
