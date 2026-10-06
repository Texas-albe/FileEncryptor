// 加密盘索引模块实现（M1）。全局命名空间；依赖 libsodium（Argon2id + secretbox）。
#include "vault_index.hpp"
#include "FileEncryptor.hpp"
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
#include <chrono>
#include <filesystem>
#ifdef _WIN32
#  include <windows.h>
#endif

// ---- 索引密钥缓存 hook（H5 批量写优化）----
// holder（vdisk_abi）注册自己的实现：库盐命中即省 0.25s Argon2id。
// 放文件顶层作用域，使内部 write_index/read_index_text 与外部注册函数都能访问。
static bool (*g_index_key_hook)(const SecureBuffer&, const VaultMeta&,
                                std::vector<unsigned char>&, std::string&) = nullptr;
static void (*g_index_key_drop)() = nullptr;

namespace fs = std::filesystem;

namespace {

const char kIdxMagic[6] = {'F','E','I','D','X','1'};

// ---- 小工具 ----
std::string normsep(const std::string& s) {
#ifdef _WIN32
    std::string o = s;
    for (char& c : o) if (c == '\\') c = '/';
    return o;
#else
    return s;
#endif
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

// ---- 极简 JSON（仅覆盖本模块所需子集）----
struct JVal {
    enum T { NUL, BL, NUM, ST, AR, OB } t = NUL;
    bool b = false;
    double n = 0;
    std::string raw;        // 数字原文：避免超大整数经 double 往返失真
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

// 整数取值一律走原文：double 只有 53 位尾数，超大值会饱和成 0x8000000000000000
uint64_t as_u64(const JVal* v, uint64_t def = 0) {
    if (!v || v->t != JVal::NUM) return def;
    if (!v->raw.empty()) {
        if (v->raw[0] == '-' || v->raw[0] == '+') return def;      // 无符号字段不接受符号
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

// ---- 文件 IO ----
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
    // 原子替换：先 remove 再 rename 在两步间崩溃会丢失原文件（.feindex / vault.meta / .fevault
    // 全走这里）。Windows 用 MoveFileExW(MOVEFILE_REPLACE_EXISTING) 单调用完成。
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

// ---- 序列化 ----
std::string meta_to_json(const VaultMeta& m) {
    std::ostringstream o;
    o << "{\"format\":" << m.format
      << ",\"salt\":\"" << to_hex(m.salt) << "\""
      << ",\"root\":" << jstrlit(m.root)
      << ",\"created\":" << m.created
      << ",\"opslimit\":" << m.opslimit
      << ",\"memlimit_kb\":" << m.memlimit_kb;
    if (!m.mount_point.empty()) o << ",\"mount_point\":" << jstrlit(m.mount_point);
    o << "}";
    return o.str();
}

std::string entry_to_json(const VaultEntry& e) {
    std::ostringstream o;
    o << "{\"rel_path\":" << jstrlit(e.rel_path);
    // store 仅在随机命名时写；旧条目无此字段→读取端回退 rel_path 基名
    if (!e.store.empty()) o << ",\"store\":" << jstrlit(e.store);
    o << ",\"orig_abs\":" << jstrlit(e.orig_abs)
      << ",\"size\":" << e.size
      << ",\"mtime\":" << e.mtime
      << ",\"enc_ts\":" << e.enc_ts
      << ",\"algo\":" << jstrlit(e.algo)
      << ",\"kdf\":" << jstrlit(e.kdf) << "}";
    return o.str();
}

bool write_index(const std::string& dir, const VaultMeta& meta,
                 const SecureBuffer& password, const std::string& plaintext, std::string& err) {
    std::vector<unsigned char> key;
    if (!(g_index_key_hook ? g_index_key_hook(password, meta, key, err)
                             : derive_index_key(password, meta, key, err))) return false;
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<unsigned char> cipher(crypto_secretbox_MACBYTES + plaintext.size());
    if (crypto_secretbox_easy(cipher.data(),
                              (const unsigned char*)plaintext.data(), plaintext.size(),
                              nonce.data(), key.data()) != 0) {
        err = "index seal failed";
        return false;
    }
    std::string path = dir + "/.feindex";
    std::string blob;
    blob.append(kIdxMagic, 6);
    blob.append((const char*)nonce.data(), nonce.size());
    blob.append((const char*)cipher.data(), cipher.size());
    return write_file_atomic(path, blob, err);
}

bool read_index_text(const std::string& dir, const VaultMeta& meta,
                     const SecureBuffer& password, std::string& text, std::string& err) {
    std::string path = dir + "/.feindex";
    std::string blob;
    if (!read_file(path, blob)) { text = "[]"; return true; }  // 缺失=空索引
    if (blob.size() < 6 + 24 + crypto_secretbox_MACBYTES) { err = "corrupt index"; return false; }
    if (std::memcmp(blob.data(), kIdxMagic, 6) != 0) { err = "bad index magic"; return false; }
    std::vector<unsigned char> nonce(blob.data() + 6, blob.data() + 6 + 24);
    const unsigned char* cph = (const unsigned char*)blob.data() + 30;
    size_t cph_len = blob.size() - 30;
    std::vector<unsigned char> key;
    if (!(g_index_key_hook ? g_index_key_hook(password, meta, key, err)
                             : derive_index_key(password, meta, key, err))) return false;
    std::vector<unsigned char> plain(cph_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plain.data(), cph, cph_len, nonce.data(), key.data()) != 0) {
        err = "wrong password or corrupt index";
        return false;
    }
    text.assign((const char*)plain.data(), plain.size());
    return true;
}

} // namespace


// ---- 索引密钥缓存注入点 ----
// holder（vdisk_abi）注册缓存实现，库盐命中即省 0.25s Argon2id。
// 用函数指针而非直接调用：跨 TU 符号会被 LTCG 剔除（实测 LNK2001）。

void set_index_key_cache_hook(
    bool (*fn)(const SecureBuffer&, const VaultMeta&, std::vector<unsigned char>&, std::string&),
    void (*drop)()) {
    g_index_key_hook = fn;
    g_index_key_drop = drop;
}
static void call_index_key_drop() { if (g_index_key_drop) g_index_key_drop(); }

void forget_cached_index_keys() { call_index_key_drop(); }

// ---- 索引加解密 ----
// 注：索引密钥的进程内缓存（批量写优化）放在 vdisk_abi.cpp，
// 因为它与句柄的锁定生命周期绑定，且需要在 vdisk 入口统一加锁。
bool derive_index_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key, std::string& err) {
    key.assign(crypto_secretbox_KEYBYTES, 0);
    if (meta.salt.size() != crypto_pwhash_SALTBYTES) { err = "bad salt size"; return false; }
    if (crypto_pwhash(key.data(), key.size(), password.cdata(), password.size(),
                      meta.salt.data(), meta.opslimit,
                      (size_t)meta.memlimit_kb * 1024,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        err = "argon2id derivation failed";
        return false;
    }
    return true;
}

// ===================== 公开 API =====================

std::string vault_random_store_name() {
    unsigned char b[8];
    randombytes_buf(b, sizeof(b));
    static const char* kHex = "0123456789abcdef";
    std::string s; s.reserve(16);
    for (int i = 0; i < 8; ++i) { s.push_back(kHex[b[i] >> 4]); s.push_back(kHex[b[i] & 0xF]); }
    return s;
}

std::string vault_ptd_path(const std::string& dir, const std::string& rel, const std::string& store) {
    std::string subdir, base;
    size_t pos = rel.find_last_of('/');
    if (pos == std::string::npos) { base = rel; }
    else { subdir = rel.substr(0, pos); base = rel.substr(pos + 1); }
    if (!store.empty()) base = store;
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
        case CryptoMode::AES_GCM:   return "AES-GCM(legacy)";
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
    if (!read_file(mp, s)) { err = "vault.meta not found (not a vault?)"; return false; }
    JVal v; size_t i = 0;
    if (!jval(s, v, err, i)) return false;
    if (v.t != JVal::OB) { err = "bad vault.meta"; return false; }
    const JVal* f = v.at("format"); if (!f) { err = "missing format"; return false; }
    const JVal* sl = v.at("salt"); if (!sl) { err = "missing salt"; return false; }
    const JVal* rt = v.at("root"); if (!rt) { err = "missing root"; return false; }
    out.format = (uint32_t)f->n;
    out.salt = from_hex(sl->s);
    out.root = rt->s;
if (auto* p = v.at("created")) out.created = as_u64(p);
if (auto* p = v.at("opslimit")) out.opslimit = (unsigned int)as_u64(p);
if (auto* p = v.at("memlimit_kb")) out.memlimit_kb = (uint32_t)as_u64(p);
    if (auto* p = v.at("mount_point")) out.mount_point = p->s;   // 旧库无此字段→留空
    return true;
}

bool vault_meta_save(const std::string& dir, const VaultMeta& m, std::string& err) {
    return write_file_atomic(dir + "/vault.meta", meta_to_json(m), err);
}

bool vault_derive_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key32, std::string& err) {
    return derive_index_key(password, meta, key32, err);
}

// 解析索引 JSON 文本（供读盘与内存镜像共用）
static bool parse_index_text(const std::string& text, std::vector<VaultEntry>& out, std::string& err) {
    JVal v; size_t i = 0;
    if (!jval(text, v, err, i)) return false;
    if (v.t != JVal::AR) { err = "index is not an array"; return false; }
    for (auto& el : v.a) {
        if (el.t != JVal::OB) continue;
        VaultEntry e;
        if (auto* p = el.at("rel_path")) e.rel_path = p->s;
        if (auto* p = el.at("store")) e.store = p->s;   // 旧索引无此键→留空，按 rel_path 基名解析
        if (auto* p = el.at("orig_abs")) e.orig_abs = p->s;
    // 旧版本曾把 file_size 失败值经 double 往返写成饱和垃圾（2^63），读回时夹回 0
    if (auto* p = el.at("size")) { e.size = as_u64(p); if (e.size >= ((uint64_t)1 << 63)) e.size = 0; }
    if (auto* p = el.at("mtime")) e.mtime = as_i64(p);
    if (auto* p = el.at("enc_ts")) e.enc_ts = as_u64(p);
        if (auto* p = el.at("algo")) e.algo = p->s;
        if (auto* p = el.at("kdf")) e.kdf = p->s;
        out.push_back(std::move(e));
    }
    return true;
}

bool vault_read_index(const std::string& dir, const VaultMeta& meta,
                      const SecureBuffer& password, std::vector<VaultEntry>& out,
                      std::string& err) {
    std::string text;
    if (!read_index_text(dir, meta, password, text, err)) return false;
    return parse_index_text(text, out, err);
}

// ---- 索引内存镜像 ----
// 原本每次 append/upsert/remove 都要「解密全量 → 改 → 加密全量写回」，
// 批量入盘 N 文件即 N 次全量解密 + N 次全量重加密 + N 次落盘。
// 现读一次驻留内存（省重复解密），写操作改内存后立即原子落盘。
namespace {
std::mutex g_mtx;
std::string g_mir_dir;                       // 镜像所属库目录
std::string g_mir_text;                      // 明文 JSON（内存态，非密文）
bool g_mir_dirty = false;
bool g_mir_valid = false;

// 0 = 每次改动都落盘。曾用 200ms 节流省写放大，但未调 flush 的路径会丢整批改动
// （实测 --into-vault 后 .feindex 停在旧内容，recrypt 读到空索引）。
const uint64_t kMirrorAutoFlushMs = 0;
uint64_t g_mir_last_flush_ms = 0;

uint64_t now_ms_mirror() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}  // namespace

// 强制把镜像落盘。锁定/卸载/进程退出前应调用，避免丢改动。
bool vault_flush_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, std::string& err) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_mir_valid || !g_mir_dirty) return true;
    if (g_mir_dir != dir) return true;       // 不是这个库的镜像，交给调用方
    if (!write_index(dir, meta, password, g_mir_text, err)) return false;
    g_mir_dirty = false;
    g_mir_last_flush_ms = now_ms_mirror();
    return true;
}

// 丢弃镜像（换库/锁定时）：下次写重新从盘面读。
// 已在 g_mtx 内调用（内部版）
static void mirror_drop_locked() {
    if (!g_mir_text.empty()) sodium_memzero(g_mir_text.data(), g_mir_text.size());
    g_mir_text.clear();
    g_mir_dir.clear();
    g_mir_dirty = false;
    g_mir_valid = false;
}

void vault_drop_index_mirror() {
    std::lock_guard<std::mutex> lk(g_mtx);
    mirror_drop_locked();
}

// 取镜像文本（必要时从盘面载入并缓存）。caller 持有 g_mtx。
static bool mirror_load_locked(const std::string& dir, const VaultMeta& meta,
                               const SecureBuffer& password, std::string& err) {
    if (g_mir_valid && g_mir_dir == dir) return true;
    mirror_drop_locked();   // 换库：清掉旧镜像（已持 g_mtx）
    if (!read_index_text(dir, meta, password, g_mir_text, err)) return false;
    g_mir_dir = dir;
    g_mir_valid = true;
    g_mir_dirty = false;
    g_mir_last_flush_ms = now_ms_mirror();
    return true;
}

// 改动后落盘（kMirrorAutoFlushMs=0，即每次都写）
static bool mirror_touch_locked(const std::string& dir, const VaultMeta& meta,
                                const SecureBuffer& password, std::string& err) {
    g_mir_dirty = true;
    if (now_ms_mirror() - g_mir_last_flush_ms < kMirrorAutoFlushMs) return true;
    if (!write_index(dir, meta, password, g_mir_text, err)) return false;
    g_mir_dirty = false;
    g_mir_last_flush_ms = now_ms_mirror();
    return true;
}

bool vault_append_entry(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const VaultEntry& e,
                        std::string& err) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!mirror_load_locked(dir, meta, password, err)) return false;
    std::string& existing = g_mir_text;
    std::string obj = entry_to_json(e);
    std::string next;
    if (existing == "[]" || existing.empty()) next = "[" + obj + "]";
    else {
        size_t last = existing.rfind(']');
        if (last == std::string::npos) { err = "corrupt index text"; return false; }
        next = existing.substr(0, last) + "," + obj + "]";
    }
    g_mir_text = next;
    return mirror_touch_locked(dir, meta, password, err);
}

bool vault_write_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& json,
                       std::string& err) {
    // 外部整盘写入：必须丢弃镜像，否则镜像的待落盘改动会覆盖这次写入
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        mirror_drop_locked();
    }
    return write_index(dir, meta, password, json, err);
}

bool vault_reindex(const std::string& dir, const VaultMeta& meta,
                   const SecureBuffer& password, std::string& err) {
    // 重扫结果必须直接落盘并作废内存镜像，否则下一次写会用旧镜像覆盖重扫结果
    vault_drop_index_mirror();
    std::vector<VaultEntry> entries;
    std::error_code ec;
    // 目录/文件名一律走 u8path：fs 的窄串按 ACP(GBK) 解释，中文名会被误解码。
    fs::path vdir = fs::u8path(dir);
    fs::recursive_directory_iterator it(vdir, ec);
    if (!ec) {
        for (auto& e : it) {
            if (!e.is_regular_file()) continue;
            std::string full = e.path().u8string();              // UTF-8 全路径
            std::string fn   = e.path().filename().u8string();
            if (fn == ".feindex" || fn == "vault.meta" || fn == ".feindex.tmp") continue;
            if (e.path().extension().u8string() != ".ptd") continue;
            PtdMeta m;
            if (!read_ptd_metadata(full, m) || !m.valid) continue;
            // 实际存储文件名（随机 hex 或旧盘原始名）→ 索引 store，供挂载按名映射回物理文件
            std::string stem = e.path().stem().u8string();
            // 目录结构保留在磁盘路径里；rel_path 基名从 PTD 头内嵌原始名恢复（随机命名不再能从文件名反推）
            std::string reldir;
            try {
                reldir = normsep(fs::relative(e.path(), vdir).parent_path().u8string());
            } catch (...) { reldir.clear(); }
            if (reldir == ".") reldir.clear();
            std::string orig;
            if (!read_original_name(full, orig, password) || orig.empty()) orig = stem;
            VaultEntry ve;
            ve.rel_path = reldir.empty() ? orig : (reldir + "/" + orig);
            ve.store    = stem;
            ve.size = m.orig_size;
            ve.algo = vault_mode_str(m.mode);
            ve.kdf = "argon2id";
            entries.push_back(std::move(ve));
        }
    }
    std::string js;
    {
        std::ostringstream o; o << "[";
        for (size_t i = 0; i < entries.size(); i++) { if (i) o << ","; o << entry_to_json(entries[i]); }
        o << "]"; js = o.str();
    }
    return write_index(dir, meta, password, js, err);
}

std::string vault_entries_to_json(const std::vector<VaultEntry>& entries) {
    std::ostringstream o; o << "[";
    for (size_t i = 0; i < entries.size(); i++) { if (i) o << ","; o << entry_to_json(entries[i]); }
    o << "]";
    return o.str();
}

// ===================== M6 写支持：索引 upsert/remove =====================
bool vault_upsert_entry(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const VaultEntry& e, std::string& err) {
    std::vector<VaultEntry> v;
    {   // 解析仍走盘面读（需正确处理 JSON 往返），但密钥命中缓存不再重跑 Argon2id
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!mirror_load_locked(dir, meta, password, err)) return false;
    }
    if (!parse_index_text(g_mir_text, v, err)) return false;
    bool replaced = false;
    for (auto& x : v) {
        if (x.rel_path == e.rel_path) { x = e; replaced = true; break; }
    }
    if (!replaced) v.push_back(e);
    std::string next = vault_entries_to_json(v);
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_mir_valid || g_mir_dir != dir) { if (!mirror_load_locked(dir, meta, password, err)) return false; }
    g_mir_text = next;
    return mirror_touch_locked(dir, meta, password, err);
}

bool vault_remove_entry(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& rel_path, std::string& err) {
    std::vector<VaultEntry> v;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!mirror_load_locked(dir, meta, password, err)) return false;
    }
    if (!parse_index_text(g_mir_text, v, err)) return false;
    std::vector<VaultEntry> out;
    out.reserve(v.size());
    for (const auto& x : v) if (x.rel_path != rel_path) out.push_back(x);
    std::string next = vault_entries_to_json(out);
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_mir_valid || g_mir_dir != dir) { if (!mirror_load_locked(dir, meta, password, err)) return false; }
    g_mir_text = next;
    return mirror_touch_locked(dir, meta, password, err);
}

// ===================== §4.4 恢复密钥 =====================
// 保险文件格式： "FEVLT1"(6) + salt(16) + nonce(24) + secretbox(主密码副本)
// 密钥 = Argon2id(恢复密钥串, 该 salt)。不入索引、不随库重扫。
static const char* kRecoveryMagic = "FEVLT1";
static const size_t kRecoverySaltBytes = crypto_pwhash_SALTBYTES;

// 规范化：只保留数字（允许用户输入带空格/连字符的分组形式）
static std::string recovery_code_normalize(const std::string& s) {
    std::string o;
    for (char c : s) if (c >= '0' && c <= '9') o += c;
    return o;
}

std::string vault_recovery_gen_code() {
    // 48 位十进制 ≈ 159 bit 熵（BitLocker 恢复密钥同等语义）
    std::string s;
    s.reserve(48);
    for (int i = 0; i < 48; i++) s += (char)('0' + (randombytes_uniform(10)));
    return s;
}

static std::string recovery_path(const std::string& dir) {
    return normsep(dir) + "/.fevault";
}

bool vault_recovery_exists(const std::string& dir) {
    std::ifstream f(recovery_path(dir), std::ios::binary);
    return f.good();
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
    if (!read_file(recovery_path(dir), blob)) { err = "no recovery file (.fevault)"; return false; }
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
    std::string p = recovery_path(dir);
    std::ifstream f(p, std::ios::binary);
    if (!f.good()) { err = "no recovery file"; return false; }
    f.close();
    if (std::remove(p.c_str()) != 0) { err = "cannot remove recovery file"; return false; }
    return true;
}
