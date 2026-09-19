// 密钥库实现（功能1）。目录与索引格式见 keylib.hpp 注释。
#include "keylib.hpp"
#include "config.hpp"
#include "FileEncryptor.hpp"
#include "asym_crypto.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <set>
#include <cctype>

namespace {

// 文件是否存在（UTF-8 安全；与 main.cpp 的 file_exists_path 同实现）
bool file_exists(const std::string& p) {
    std::ifstream t;
    if (!open_stream(t, p, std::ios::in)) return false;
    t.close();
    return true;
}

// 索引字段名与顺序（save 的唯一写出格式；load 按字段名读取，顺序无关）
const char* kIndexComment =
    "# FileEncryptor key library index.\n"
    "# Key material lives in the individual .key files next to this index;\n"
    "# this file holds metadata only. Names are referenced by -K <name>.\n";

// 单行文本清洗：去掉控制字符与引号/反斜杠，压成单行（备注/别名只在索引中展示）
std::string sanitize_single_line(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7F) continue;          // 控制字符（含换行）
        if (c == '"' || c == '\\') continue;           // 与 YAML 双引号转义冲突
        out.push_back((char)c);
    }
    // 去首尾空白
    size_t a = 0, b = out.size();
    while (a < b && (unsigned char)out[a] <= 0x20) ++a;
    while (b > a && (unsigned char)out[b - 1] <= 0x20) --b;
    return out.substr(a, b - a);
}

// YAML 双引号标量转义（sanitize 已剔除 " 与 \，此处兜底）
std::string yaml_quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back((char)c); }
        else if (c < 0x20) { /* 已被 sanitize 剔除，兜底跳过 */ }
        else out.push_back((char)c);
    }
    out.push_back('"');
    return out;
}

std::string now_string() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

// 读密钥材料（上限 256 KB），修剪首尾空白后按前缀识别类型。
// 返回 false 表示材料为空或既不是 identity 也不是 recipient。
bool read_key_material(const std::string& path, std::string& content, std::string& kind, std::string& err) {
    std::ifstream f;
    if (!open_stream(f, path, std::ios::in | std::ios::binary)) {
        err = "Cannot open key file: " + path;
        return false;
    }
    std::string buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    if (buf.size() > 256 * 1024) {
        err = "Key file too large (>256 KB): " + path;
        return false;
    }
    // 修剪首尾空白（含 CR/LF）
    size_t a = 0, b = buf.size();
    while (a < b && (unsigned char)buf[a] <= 0x20) ++a;
    while (b > a && (unsigned char)buf[b - 1] <= 0x20) --b;
    content = buf.substr(a, b - a);
    // 就地擦除原始缓冲（材料可能含私钥）
    sodium_memzero(buf.data(), buf.size());
    if (content.empty()) {
        err = "Key file is empty: " + path;
        return false;
    }
    if (content.rfind("AGE-SECRET-KEY-", 0) == 0) {
        kind = "identity";
        return true;
    }
    std::string low = content;
    std::transform(low.begin(), low.end(), low.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    if (low.rfind("age1", 0) == 0 || low.rfind("publickey:", 0) == 0) {
        // 统一剥掉可选的 publickey: 前缀
        if (low.rfind("publickey:", 0) == 0) {
            content = content.substr(10);
            a = 0; b = content.size();
            while (a < b && (unsigned char)content[a] <= 0x20) ++a;
            while (b > a && (unsigned char)content[b - 1] <= 0x20) --b;
            content = content.substr(a, b - a);
        }
        kind = "recipient";
        return true;
    }
    err = "Unrecognized key material (expected AGE-SECRET-KEY-... or age1...): " + path;
    return false;
}

} // namespace

std::string keylib_dir() {
    const std::string base = user_config_dir();
    if (base.empty()) return "";
    std::string dir = base;
    if (dir.back() != '/' && dir.back() != '\\') dir += '/';
    return to_native_path(dir + "keys");
}

std::string keylib_index_path() {
    const std::string dir = keylib_dir();
    if (dir.empty()) return "";
    // 索引文件名：library.yaml（v2.3.1 起按用户要求统一回归标准 .yaml 后缀；
    // v2.3.0 曾短暂使用 .yml）。旧名 library.yml 仍可读取，避免升级后旧的
    // 密钥索引"凭空消失"（材料文件仍在，只是索引名变了）。
    const std::string cur = to_native_path(dir + "/library.yaml");
    if (file_exists(cur)) return cur;
    const std::string legacy = to_native_path(dir + "/library.yml");
    if (file_exists(legacy)) return legacy;
    return cur;
}

// 密钥库内文件（<dir>/<file>）：拼接后统一归一化为系统原生分隔符，
// 保证 Windows 下路径不含混用的 '/'。
static std::string keylib_file_path(const std::string& file) {
    const std::string dir = keylib_dir();
    if (dir.empty()) return "";
    return to_native_path(dir + "/" + file);
}

bool keylib_valid_name(const std::string& name) {
    if (name.empty() || name.size() > 64) return false;
    if (name == "." || name == "..") return false;
    for (unsigned char c : name) {
        if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}

bool keylib_load(std::vector<KeyLibEntry>& out, std::string& err) {
    out.clear();
    const std::string path = keylib_index_path();
    if (path.empty()) { err = "No user config directory available."; return false; }
    if (!file_exists(path)) return true;   // 空库

    try {
        YAML::Node root = YAML::LoadFile(path);
        const YAML::Node keys = root["keys"];
        if (!keys || !keys.IsSequence()) return true;
        std::set<std::string> seen;
        for (const auto& n : keys) {
            KeyLibEntry e;
            e.name       = n["name"]    ? n["name"].as<std::string>() : "";
            e.kind       = n["kind"]    ? n["kind"].as<std::string>() : "";
            e.file       = n["file"]    ? n["file"].as<std::string>() : "";
            e.alias      = n["alias"]   ? n["alias"].as<std::string>() : "";
            e.notes      = n["notes"]   ? n["notes"].as<std::string>() : "";
            e.created    = n["created"] ? n["created"].as<std::string>() : "";
            e.public_key = n["public"]  ? n["public"].as<std::string>() : "";
            if (e.name.empty() || e.file.empty() || e.kind.empty()) continue;   // 跳过残缺行
            if (!seen.insert(e.name).second) continue;                          // 重名取首条
            out.push_back(std::move(e));
        }
        return true;
    } catch (const std::exception& ex) {
        err = "Cannot parse key library index: " + std::string(ex.what());
        return false;
    }
}

bool keylib_save(const std::vector<KeyLibEntry>& entries, std::string& err) {
    const std::string dir = keylib_dir();
    const std::string path = keylib_index_path();
    if (dir.empty() || path.empty()) { err = "No user config directory available."; return false; }
    if (!create_directory_recursive(dir)) {
        err = "Cannot create key library directory: " + dir;
        return false;
    }

    std::string text = kIndexComment;
    text += "keys:\n";
    for (const auto& e : entries) {
        text += "  - name: "    + yaml_quote(e.name)       + "\n";
        text += "    kind: "    + yaml_quote(e.kind)       + "\n";
        text += "    file: "    + yaml_quote(e.file)       + "\n";
        text += "    alias: "   + yaml_quote(e.alias)      + "\n";
        text += "    notes: "   + yaml_quote(e.notes)      + "\n";
        text += "    created: " + yaml_quote(e.created)    + "\n";
        text += "    public: "  + yaml_quote(e.public_key) + "\n";
    }

    // 先写临时文件再原子替换，避免写一半的索引被并发读到
    const std::string tmp = path + ".tmp";
    std::ofstream f;
    if (!open_stream(f, tmp, std::ios::out | std::ios::binary | std::ios::trunc)) {
        err = "Cannot write key library index: " + tmp;
        return false;
    }
    f << text;
    f.flush();
    const bool ok = f.good();
    f.close();
    if (!ok) { err = "Write failed: " + tmp; remove_file_utf8(tmp); return false; }
    if (!replace_file_utf8(tmp, path)) {
        err = "Cannot finalize key library index: " + path;
        remove_file_utf8(tmp);
        return false;
    }
    return true;
}

bool keylib_find(const std::vector<KeyLibEntry>& entries,
                 const std::string& name, KeyLibEntry* out) {
    for (const auto& e : entries) {
        if (e.name == name) {
            if (out) *out = e;
            return true;
        }
    }
    return false;
}

bool keylib_add(const std::string& key_path, const std::string& name,
                const std::string& alias, const std::string& notes, std::string& err) {
    if (!keylib_valid_name(name)) {
        err = "Invalid key name: '" + name + "' (use 1..64 chars of A-Z a-z 0-9 . _ -)";
        return false;
    }
    std::vector<KeyLibEntry> entries;
    if (!keylib_load(entries, err)) return false;
    if (keylib_find(entries, name, nullptr)) {
        err = "A key named '" + name + "' already exists (remove it first).";
        return false;
    }

    std::string material, kind;
    if (!read_key_material(key_path, material, kind, err)) return false;

    // identity：导入时即派生公钥并缓存（导出/加密时无需再持有私钥）。
    // 注意：material 必须在写入材料文件之后才能擦除。
    std::string pub;
    if (kind == "identity") {
        AsymOutcome o = fe_identity_to_recipient(material, pub);
        if (!o.ok) {
            sodium_memzero(material.data(), material.size());
            err = "Not a usable age identity: " + o.error;
            return false;
        }
    }

    // 写入材料文件（覆盖前清只读位；写后收紧密钥文件权限）
    const std::string dir = keylib_dir();
    if (!create_directory_recursive(dir)) {
        err = "Cannot create key library directory: " + dir;
        sodium_memzero(material.data(), material.size());
        return false;
    }
    const std::string file_name = name + ".key";
    const std::string dst = keylib_file_path(file_name);
    if (file_exists(dst)) clear_readonly_attribute(dst);
    std::ofstream f;
    if (!open_stream(f, dst, std::ios::out | std::ios::binary | std::ios::trunc)) {
        err = "Cannot write key file: " + dst;
        sodium_memzero(material.data(), material.size());
        return false;
    }
    f << material << "\n";
    f.flush();
    const bool ok = f.good();
    f.close();
    sodium_memzero(material.data(), material.size());
    if (!ok) { err = "Write failed: " + dst; remove_file_utf8(dst); return false; }
    tighten_file_permissions(dst);

    KeyLibEntry e;
    e.name = name;
    e.kind = kind;
    e.file = file_name;
    e.alias = sanitize_single_line(alias);
    e.notes = sanitize_single_line(notes);
    e.created = now_string();
    e.public_key = (kind == "identity") ? pub : "";
    entries.push_back(std::move(e));
    return keylib_save(entries, err);
}

bool keylib_remove(const std::string& name, std::string& err) {
    std::vector<KeyLibEntry> entries;
    if (!keylib_load(entries, err)) return false;
    KeyLibEntry found;
    if (!keylib_find(entries, name, &found)) {
        err = "No such key in library: " + name;
        return false;
    }
    std::vector<KeyLibEntry> remaining;
    remaining.reserve(entries.size() - 1);
    for (auto& e : entries) if (e.name != name) remaining.push_back(std::move(e));
    if (!keylib_save(remaining, err)) return false;

    const std::string dst = keylib_file_path(found.file);
    if (file_exists(dst)) {
        clear_readonly_attribute(dst);
        if (!remove_file_utf8(dst)) {
            // 索引已更新；材料删除失败仅告警，不算失败
            err = "Warning: index updated but the key file could not be deleted: " + dst;
        }
    }
    return true;
}

bool keylib_set_public(const std::string& name, const std::string& pub, std::string& err) {
    std::vector<KeyLibEntry> entries;
    if (!keylib_load(entries, err)) return false;
    bool hit = false;
    for (auto& e : entries) {
        if (e.name == name) { e.public_key = pub; hit = true; break; }
    }
    if (!hit) { err = "No such key in library: " + name; return false; }
    return keylib_save(entries, err);
}

bool keylib_key_path(const std::string& name, std::string& path, std::string& err) {
    std::vector<KeyLibEntry> entries;
    if (!keylib_load(entries, err)) return false;
    KeyLibEntry e;
    if (!keylib_find(entries, name, &e)) {
        err = "No such key in library: " + name;
        return false;
    }
    path = keylib_file_path(e.file);
    if (!file_exists(path)) {
        err = "Key material file is missing: " + path;
        return false;
    }
    return true;
}

bool keylib_recipients(const std::vector<std::string>& names,
                       std::vector<std::string>& pubs, std::string& err) {
    std::vector<KeyLibEntry> entries;
    if (!keylib_load(entries, err)) return false;
    if (entries.empty()) {
        err = "Key library is empty (import with -L add <keyfile> --as <name>).";
        return false;
    }
    for (const auto& name : names) {
        KeyLibEntry e;
        if (!keylib_find(entries, name, &e)) {
            err = "No such key in library: " + name;
            return false;
        }
        if (e.kind == "identity") {
            if (e.public_key.empty()) {
                err = "Key '" + name + "' has no cached public key; run -L pub " + name + " first.";
                return false;
            }
            pubs.push_back(e.public_key);
        } else {
            std::string path, material, kind;
            if (!keylib_key_path(name, path, err)) return false;
            if (!read_key_material(path, material, kind, err)) return false;
            if (kind != "recipient") {
                err = "Key '" + name + "' is an identity, not a recipient public key.";
                return false;
            }
            pubs.push_back(material);
        }
    }
    return true;
}

bool keylib_export(const std::string& name, const std::string& dest_dir, std::string& err) {
    std::vector<KeyLibEntry> entries;
    if (!keylib_load(entries, err)) return false;
    KeyLibEntry e;
    if (!keylib_find(entries, name, &e)) {
        err = "No such key in library: " + name;
        return false;
    }
    std::string dest = dest_dir.empty() ? "." : dest_dir;
    if (dest.back() != '/' && dest.back() != '\\') dest += '/';
    dest += e.file;
    if (file_exists(dest)) {
        err = "Refusing to overwrite existing file: " + dest;
        return false;
    }
    const std::string src = keylib_file_path(e.file);
    std::ifstream in;
    if (!open_stream(in, src, std::ios::in | std::ios::binary)) {
        err = "Key material file is missing: " + src;
        return false;
    }
    std::ofstream out;
    if (!open_stream(out, dest, std::ios::out | std::ios::binary | std::ios::trunc)) {
        err = "Cannot write: " + dest;
        return false;
    }
    out << in.rdbuf();
    const bool ok = out.good();
    in.close(); out.close();
    if (!ok) { err = "Write failed: " + dest; remove_file_utf8(dest); return false; }
    tighten_file_permissions(dest);
    return true;
}
