#define _CRT_SECURE_NO_WARNINGS
#include "config.hpp"
#include "FileEncryptor.hpp"  // 为 create_directory_recur
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <chrono>
#include <memory>
#include <ctime>

#include <yaml-cpp/yaml.h>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

// YAML 配置解析
// (path_whitelist)。未知键静默忽略

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

// 解析布尔标量
static bool parse_bool(const std::string& v, bool& out) {
    std::string s = trim(v);
    // 仅对 ASCII 转小写
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    if (s == "true" || s == "yes" || s == "1" || s == "on") { out = true; return true; }
    if (s == "false" || s == "no" || s == "0" || s == "off") { out = false; return true; }
    return false;
}

static int level_from_string(const std::string& v) {
    std::string s = trim(v);
    // 仅对 ASCII 转小写
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    if (s == "error") return LOG_ERROR;
    if (s == "warn" || s == "warning") return LOG_WARN;
    if (s == "info") return LOG_INFO;
    if (s == "debug") return LOG_DEBUG;
    return -1; // 非字符串 → 当作数
}

bool parse_yaml_config(const std::string& text, Config& cfg, std::string& err, std::string* warn) {
    err.clear();
    YAML::Node root;
    try {
        root = YAML::Load(text);
    } catch (const YAML::Exception& e) {
        err = std::string("YAML parse error: ") + e.what();
        return false;
    }
    if (!root || root.IsNull()) return true; // 空文档 → 默认配置
    if (!root.IsMap()) { err = "Config root must be a mapping (map)"; return false; }

    // 非致命告警累加
    auto note = [&](const char* key, const char* why) {
        if (warn) {
            if (!warn->empty()) *warn += "; ";
            *warn += std::string(key) + ": " + why;
        }
    };

    // 取标量字符串
    auto opt_str = [&](const char* key, std::string& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) { out = n.as<std::string>(); return true; }
        if (n) note(key, "expected a scalar string");
        return false;
    };

    opt_str("log_file", cfg.log_file);

    // log_level
    {
        const YAML::Node& n = root["log_level"];
        if (n && n.IsScalar()) {
            std::string s = n.as<std::string>();
            int lv = level_from_string(s);
            if (lv >= 0) cfg.log_level = lv;
            else {
                try { cfg.log_level = std::stoi(s); }
                catch (...) { note("log_level", "not a valid level or integer"); }
            }
        }
        else if (n) note("log_level", "expected a scalar");
    }

    auto opt_int = [&](const char* key, int& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            try { out = n.as<int>(); }
            catch (...) { note(key, "expected an integer"); }
        }
        else if (n) note(key, "expected a scalar integer");
    };
    opt_int("worker_threads", cfg.worker_threads);

    auto opt_size = [&](const char* key, size_t& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            try { out = n.as<size_t>(); }
            catch (...) { note(key, "expected a non-negative integer"); }
        }
        else if (n) note(key, "expected a scalar integer");
    };
    opt_size("max_open_files", cfg.max_open_files);
    opt_size("max_path_length", cfg.max_path_length);

    // 带单位
    auto opt_size_unit = [&](const char* key, uint64_t& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            std::string s;
            try { s = n.as<std::string>(); }
            catch (...) { note(key, "expected a size string"); return; }
            uint64_t v = 0;
            if (parse_size(s, v)) out = v;
            else note(key, "invalid size (use e.g. 512MB / 1GB)");
        }
        else if (n) note(key, "expected a scalar size");
    };
    opt_size_unit("max_memory_bytes", cfg.max_memory_bytes);
    opt_size_unit("io_buffer_size", cfg.io_buffer_size);
    opt_size_unit("max_speed", cfg.max_speed);

    // 布尔字段
    auto opt_bool = [&](const char* key, bool& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            std::string s;
            try { s = n.as<std::string>(); }
            catch (...) { note(key, "expected a boolean"); return; }
            bool b = out;
            if (!parse_bool(s, b)) note(key, "expected true/false");
            else out = b;
        }
        else if (n) note(key, "expected a scalar boolean");
    };
    opt_bool("path_whitelist_enabled", cfg.path_whitelist_enabled);
    opt_bool("obfuscate_names", cfg.obfuscate_names);
    opt_bool("write_sha256", cfg.write_sha256);

    // 密码强度策略
    auto opt_int2 = [&](const char* key, int& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            try { out = n.as<int>(); }
            catch (...) { note(key, "expected an integer"); }
        }
        else if (n) note(key, "expected a scalar integer");
    };
    opt_int2("min_password_length", cfg.min_password_length);
    opt_int2("min_password_classes", cfg.min_password_classes);

    // 加密强度预设
    {
        const YAML::Node& n = root["kdf_preset"];
        if (n && n.IsScalar()) {
            std::string s;
            try { s = n.as<std::string>(); }
            catch (...) { note("kdf_preset", "expected a scalar"); goto after_preset; }
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c){ return (char)std::tolower(c); });
            if (s == "fast") cfg.kdf_preset = 0;
            else if (s == "standard") cfg.kdf_preset = 1;
            else if (s == "strong") cfg.kdf_preset = 2;
            else {
                try { int v = std::stoi(s); if (v >= 0 && v <= 2) cfg.kdf_preset = v;
                      else note("kdf_preset", "must be 0..2 or fast/standard/strong"); }
                catch (...) { note("kdf_preset", "must be fast/standard/strong or 0..2"); }
            }
        }
        else if (n) note("kdf_preset", "expected a scalar");
    }
    after_preset:;

    // 加密默认算法
    // 空或缺省 = xchacha20
    {
        const YAML::Node& crypto = root["crypto"];
        if (crypto && !crypto.IsNull()) {
            if (!crypto.IsMap()) note("crypto", "expected a mapping");
            else {
                const YAML::Node& n = crypto["default_cipher"];
                if (n && n.IsScalar()) {
                    std::string v = n.as<std::string>();
                    if (v == "xchacha20" || v == "aegis256") cfg.default_cipher = v;
                    else note("crypto.default_cipher", "must be xchacha20 or aegis256");
                }
                else if (n) note("crypto.default_cipher", "expected a scalar string");
            }
        }
    }

    // path_whitelist
    {
        const YAML::Node& n = root["path_whitelist"];
        if (n && n.IsSequence()) {
            for (const auto& item : n) {
                if (item && item.IsScalar()) {
                    std::string s = item.as<std::string>();
                    if (!s.empty()) cfg.path_whitelist.push_back(s);
                }
            }
            if (!cfg.path_whitelist.empty()) cfg.path_whitelist_enabled = true;
        }
        else if (n) note("path_whitelist", "expected a sequence of strings");
    }

    return true;
}

// 单位解析 / 格式化
bool parse_size(const std::string& s, uint64_t& out_bytes) {
    out_bytes = 0;
    std::string t = s;
    // 去首尾空白
    size_t a = 0, b = t.size();
    while (a < b && std::isspace((unsigned char)t[a])) ++a;
    while (b > a && std::isspace((unsigned char)t[b - 1])) --b;
    t = t.substr(a, b - a);
    if (t.empty()) return false;
    // 速率写法可带 "/s"
    if (t.size() >= 2 && t.compare(t.size() - 2, 2, "/s") == 0) t = t.substr(0, t.size() - 2);
    // 拆分数字部分
    size_t i = 0;
    while (i < t.size() && (std::isdigit((unsigned char)t[i]) || t[i] == '.')) ++i;
    std::string num = t.substr(0, i);
    std::string unit = t.substr(i);
    for (char& c : unit) c = (char)std::tolower((unsigned char)c);
    double factor = 1.0;
    if (unit == "kb" || unit == "k") factor = 1024.0;
    else if (unit == "mb" || unit == "m") factor = 1024.0 * 1024.0;
    else if (unit == "gb" || unit == "g") factor = 1024.0 * 1024.0 * 1024.0;
    else if (unit == "b" || unit.empty()) factor = 1.0;
    else return false; // 未知单位
    if (num.empty()) return false;
    double val = 0;
    try { val = std::stod(num); } catch (...) { return false; }
    if (val < 0) return false;
    // stod 接受 "nan"/"inf"
    // 是 UB
    if (!(val >= 0) || !std::isfinite(val)) return false;
    const double prod = val * factor;
    if (!(prod < 18446744073709551616.0)) return false;   // 2^64
    out_bytes = (uint64_t)prod;
    return true;
}

std::string format_size(uint64_t bytes) {
    const uint64_t KB = 1024, MB = 1024 * 1024, GB = 1024ULL * 1024 * 1024;
    char buf[64];
    if (bytes >= GB) std::snprintf(buf, sizeof(buf), "%.2f GB", (double)bytes / GB);
    else if (bytes >= MB) std::snprintf(buf, sizeof(buf), "%.2f MB", (double)bytes / MB);
    else if (bytes >= KB) std::snprintf(buf, sizeof(buf), "%.2f KB", (double)bytes / KB);
    else std::snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return std::string(buf);
}

// 文件读取
static bool file_exists_utf8(const std::string& path) {
#ifdef _WIN32
    int wn = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), NULL, 0);
    if (wn <= 0) return false;
    std::wstring wp(wn, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), &wp[0], wn);
    return _waccess(wp.c_str(), 0) == 0;
#else
    return access(path.c_str(), F_OK) == 0;
#endif
}

static std::string get_cwd() {
#ifdef _WIN32
    DWORD n = GetCurrentDirectoryW(0, NULL);
    if (n == 0) return "";
    std::wstring w(n, L'\0');
    GetCurrentDirectoryW(n, w.data());
    if (!w.empty()) w.pop_back(); // 去掉末尾 '\0'
    std::string dir;
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    dir.resize(len);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &dir[0], len, NULL, NULL);
    return dir;
#else
    char buf[4096] = { 0 };
    if (getcwd(buf, sizeof(buf))) return std::string(buf);
    return "";
#endif
}

static bool write_file_utf8(const std::string& path, const std::string& content) {
#ifdef _WIN32
    int wn = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), NULL, 0);
    if (wn <= 0) return false;
    std::wstring wp(wn, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), &wp[0], wn);
    FILE* f = _wfopen(wp.c_str(), L"wb");
    if (!f) return false;
    size_t written = fwrite(content.data(), 1, content.size(), f);
    fclose(f);
    return written == content.size();
#else
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(content.data(), (std::streamsize)content.size());
    return (bool)f;
#endif
}

// 默认配置模板
static const char* DEFAULT_CONFIG_YAML =
"# 运维参数仅由此文件提供，CLI 不可覆盖；删除即恢复默认。\n"
"log_file: \"\"              # 留空 = 仅控制台进度\n"
"log_level: INFO           # ERROR / WARN / INFO / DEBUG\n"
"worker_threads: 0         # 0 = 自动（CPU 核数）\n"
"max_open_files: 256       # 并发线程上限 = 此值 / 3（防句柄耗尽）\n"
"max_memory_bytes: 0       # 0 = 不限（可写 512MB / 1GB 等）\n"
"io_buffer_size: 1MB       # 内部流式缓冲（可写 512KB / 2MB 等）\n"
"max_speed: 0              # 0 = 不限速；可写 10MB/s、1.5GB/s、512KB/s（进程级总吞吐上限）\n"
"max_path_length: 0        # 0 = 不限\n"
"path_whitelist_enabled: false\n"
"# path_whitelist:\n"
"#   - C:/Data/In\n"
"obfuscate_names: true     # 混淆输出文件名（<16hex>.<3 位小写字母>.ptd）；两条加密路径一致\n"
"crypto:\n"
"  default_cipher: xchacha20   # xchacha20 / aegis256（CLI 未指定 -m 时生效；解密以文件头为准）\n";

// YAML 别名炸弹
// GB 级内存
// read_file_utf8 在流式读取时同
static constexpr int64_t kMaxConfigBytes = 1 << 20;

static bool read_file_utf8(const std::string& path, std::string& out) {
    out.clear();
#ifdef _WIN32
    int wn = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), NULL, 0);
    if (wn <= 0) return false;
    std::wstring wp(wn, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), &wp[0], wn);
    FILE* f = _wfopen(wp.c_str(), L"rb");
    if (!f) return false;
    char buf[1 << 16];
    size_t n;
    int64_t total = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        total += (int64_t)n;
        if (total > kMaxConfigBytes) { fclose(f); return false; }
        out.append(buf, n);
    }
    fclose(f);
    return true;
#else
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    char chunk[1 << 16];
    int64_t total = 0;
    while (f.read(chunk, sizeof(chunk)) || f.gcount() > 0) {
        std::streamsize got = f.gcount();
        if (got > 0) {
            total += (int64_t)got;
            if (total > kMaxConfigBytes) { f.close(); return false; }
            ss.write(chunk, got);
        }
    }
    out = ss.str();
    return true;
#endif
}

// 取文件大小
static int64_t get_file_size_raw(const std::string& path) {
#ifdef _WIN32
    std::wstring wp;
    {
        int wn = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), NULL, 0);
        if (wn <= 0) return -1;
        wp.assign((size_t)wn, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), &wp[0], wn);
    }
    struct _stat64 st;
    if (_wstat64(wp.c_str(), &st) != 0) return -1;
    return st.st_size;
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return -1;
    return (int64_t)st.st_size;
#endif
}

static std::string get_exe_dir() {
#ifdef _WIN32
    wchar_t buf[32768] = { 0 };
    DWORD n = GetModuleFileNameW(NULL, buf, 32768);
    if (n == 0) return "";
    std::wstring w(buf, n);
    size_t pos = w.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return "";
    std::string dir;
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)pos, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    dir.resize(len);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)pos, &dir[0], len, NULL, NULL);
    return dir;
#else
    char buf[4096] = { 0 };
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        std::string p(buf, (size_t)n);
        size_t pos = p.find_last_of('/');
        return pos == std::string::npos ? "" : p.substr(0, pos);
    }
    return "";
#endif
}

static std::string get_user_config_dir() {
#ifdef _WIN32
    // 用 APPDATA 环境变量定位
    // 但无需引入 shlobj.h /
    const char* appdata = std::getenv("APPDATA");
    if (appdata && *appdata) {
        std::string dir(appdata);
        if (!dir.empty() && dir.back() != '/' && dir.back() != '\\') dir += '\\';
        return dir + "FileEncryptor";
    }
    return "";
#elif defined(__ANDROID__)
    // Android 没有可用
    // 不猜目录
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/fileencryptor";
    return "";
#else
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/fileencryptor";
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.config/fileencryptor";
    return "";
#endif
}

std::string user_config_dir() {
    return get_user_config_dir();
}

std::string to_native_path(const std::string& p) {
#ifdef _WIN32
    std::string out = p;
    for (char& c : out) if (c == '/') c = '\\';
    return out;
#else
    return p;
#endif
}

// 配置文件名
// 旧名 .yml
static const char* const kConfigName       = "fileencryptor.yaml";
static const char* const kConfigNameLegacy = "fileencryptor.yml";

// 两个目录是否同
static bool same_dir(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) return false;
    auto norm = [](std::string s) {
        for (char& c : s) if (c == '/') c = '\\';
        while (s.size() > 1 && s.back() == '\\') s.pop_back();
#ifdef _WIN32
        for (char& c : s) c = (char)tolower((unsigned char)c);
#endif
        return s;
    };
    return norm(a) == norm(b);
}

// 在给定目录里挑
static std::string pick_config_in(const std::string& dir) {
    if (dir.empty()) return "";
    std::string p = to_native_path(dir + "/" + kConfigName);
    if (file_exists_utf8(p)) return p;
    std::string legacy = to_native_path(dir + "/" + kConfigNameLegacy);
    if (file_exists_utf8(legacy)) return legacy;
    return "";
}

std::string find_config_file(ConfigSource* src) {
    if (src) *src = ConfigSource::None;
    // 环境变量
    const char* env = std::getenv("FILEENCRYPTOR_CONFIG");
    if (env && *env) {
        if (file_exists_utf8(env)) { if (src) *src = ConfigSource::Env; return env; }
    }
    // 运行目录
    // CWD 与 exe 目录相同
    // 安装包自带
    std::string cwd = get_cwd();
    bool cwd_is_exe = same_dir(cwd, get_exe_dir());
    std::string p = pick_config_in(cwd);
    if (!p.empty()) { if (src) *src = cwd_is_exe ? ConfigSource::ExeDir : ConfigSource::Cwd; return p; }
    // 可执行文件目录
    p = pick_config_in(get_exe_dir());
    if (!p.empty()) { if (src) *src = ConfigSource::ExeDir; return p; }
    // 用户配置目录
    p = pick_config_in(get_user_config_dir());
    if (!p.empty()) { if (src) *src = ConfigSource::UserConfig; return p; }
    return "";
}

Config load_config() {
    Config cfg;
    ConfigSource src = ConfigSource::None;
    std::string path = find_config_file(&src);
    if (path.empty()) {
        // 只在 exe 目录
        // 会在用户任意工
        // 又让下一次运行
        std::string cwd = get_cwd();
        bool wrote = false;
        if (same_dir(cwd, get_exe_dir()) && !cwd.empty()) {
            std::string def = to_native_path(cwd + "/" + kConfigName);
            if (!file_exists_utf8(def)) {
                wrote = write_file_utf8(def, DEFAULT_CONFIG_YAML);
            } else {
                wrote = true; // 已存
            }
        }
        if (!wrote) {
            std::string ucd = get_user_config_dir();
            if (!ucd.empty()) {
                std::string def = to_native_path(ucd + "/" + kConfigName);
                if (!file_exists_utf8(def)) {
                    create_directory_recursive(ucd);
                    write_file_utf8(def, DEFAULT_CONFIG_YAML);
                    std::cerr << "Note: default config written to " << def << "\n";
                }
            }
        }
        return cfg; // 默认配置
    }
    // YAML 别名炸弹防护 配
    if (get_file_size_raw(path) > kMaxConfigBytes) {
        std::cerr << "Warning: config file too large (" << path << "); refusing to load (> "
                  << (kMaxConfigBytes >> 20) << " MB). Using defaults.\n";
        return cfg;
    }
    std::string text;
    if (!read_file_utf8(path, text)) {
        std::cerr << "Warning: cannot read config file: " << path << "\n";
        return cfg;
    }
    // 去除 UTF-8 BOM
    // 首行键名
    if (text.size() >= 3 &&
        (unsigned char)text[0] == 0xEF &&
        (unsigned char)text[1] == 0xBB &&
        (unsigned char)text[2] == 0xBF) {
        text.erase(0, 3);
    }
    std::string err, warn;
    if (!parse_yaml_config(text, cfg, err, &warn)) {
        std::cerr << "Warning: config parse error (" << err << "); using defaults.\n";
        return Config();
    }
    // 非致命
    if (!warn.empty()) {
        std::cerr << "Warning: config at " << path << " has ignored values: " << warn << "\n";
        log_event(LOG_WARN, "config_ignored_values", {{"detail", warn}});
    }
    // v2.1.2
    // 或关闭白名单
    if (src == ConfigSource::Cwd) {
        const Config def;
        bool clamped = false;
        if (cfg.log_file != def.log_file) { cfg.log_file = def.log_file; clamped = true; }
        if (cfg.path_whitelist_enabled != def.path_whitelist_enabled ||
            cfg.path_whitelist != def.path_whitelist) {
            cfg.path_whitelist_enabled = def.path_whitelist_enabled;
            cfg.path_whitelist = def.path_whitelist;
            clamped = true;
        }
        // 加密强度/密码策
        // 长度要求或关闭
        if (cfg.kdf_preset != def.kdf_preset ||
            cfg.min_password_length != def.min_password_length ||
            cfg.min_password_classes != def.min_password_classes ||
            cfg.obfuscate_names != def.obfuscate_names) {
            cfg.kdf_preset = def.kdf_preset;
            cfg.min_password_length = def.min_password_length;
            cfg.min_password_classes = def.min_password_classes;
            cfg.obfuscate_names = def.obfuscate_names;
            clamped = true;
        }
        // M22
        // 全部审计日志
        // default_cipher
        if (cfg.log_level != def.log_level ||
            cfg.io_buffer_size != def.io_buffer_size ||
            cfg.max_memory_bytes != def.max_memory_bytes ||
            cfg.max_speed != def.max_speed ||
            cfg.max_path_length != def.max_path_length ||
            cfg.default_cipher != def.default_cipher ||
            cfg.write_sha256 != def.write_sha256) {
            cfg.log_level = def.log_level;
            cfg.io_buffer_size = def.io_buffer_size;
            cfg.max_memory_bytes = def.max_memory_bytes;
            cfg.max_speed = def.max_speed;
            cfg.max_path_length = def.max_path_length;
            cfg.default_cipher = def.default_cipher;
            cfg.write_sha256 = def.write_sha256;
            clamped = true;
        }
        if (clamped) {
            std::cerr << "Warning: config from the current directory (" << path << ") is not trusted; "
                      << "security-sensitive keys (log_file / path_whitelist / kdf_preset / "
                      << "min_password_* / obfuscate_names / log_level / io_buffer_size / "
                      << "max_memory_bytes / max_speed / max_path_length / default_cipher / "
                      << "write_sha256) from it were ignored. "
                      << "Put them in the exe directory or user config dir instead.\n";
        }
    }
    return cfg;
}

// 结构化 JSON 日志

// v2.1.2
// 统一走 UTF-8 → 宽字符打
#ifdef _WIN32
static std::wstring log_utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(len, L'\0');
    if (len > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}
#endif
static void open_log_stream_utf8(std::ofstream& f, const std::string& path, std::ios::openmode mode) {
#ifdef _WIN32
    f.open(log_utf8_to_wide(path).c_str(), mode);
#else
    f.open(path, mode);
#endif
}

static std::string g_log_file;
static int         g_log_level = LOG_INFO;
static std::mutex  g_log_mutex;
static std::ofstream g_log_stream;

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static const char* level_name(int lv) {
    switch (lv) {
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN";
        case LOG_INFO:  return "INFO";
        case LOG_DEBUG: return "DEBUG";
        default:        return "INFO";
    }
}

void init_logger(const std::string& log_file, int level) {
    g_log_level = level;
    g_log_file = log_file;
    if (!g_log_file.empty()) {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        if (g_log_stream.is_open()) g_log_stream.close();
        open_log_stream_utf8(g_log_stream, g_log_file, std::ios::out | std::ios::app);
        if (!g_log_stream) {
            std::cerr << "Warning: cannot open log file: " << g_log_file << "\n";
        }
    }
}

static bool log_path_key(unsigned char key[32]) {
    static bool loaded = false;
    static unsigned char cached[32] = {0};
    static bool have = false;
    if (!loaded) {
        loaded = true;
        const char* e = std::getenv("FE_LOG_KEY");
        if (e && *e) {
            std::string v(e);
            if (v.size() >= 64) {
                auto val = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return -1;
                };
                bool ok = true;
                for (int i = 0; i < 32; ++i) {
                    int a = val(v[2 * i]), b = val(v[2 * i + 1]);
                    if (a < 0 || b < 0) { ok = false; break; }
                    cached[i] = static_cast<unsigned char>((a << 4) | b);
                }
                have = ok;
            } else if (v.size() >= 32) {
                std::memcpy(cached, v.data(), 32);
                have = true;
            }
        }
    }
    if (have) std::memcpy(key, cached, 32);
    return have;
}

static bool log_is_path_field(const std::string& name) {
    return name == "path" || name == "file" || name == "dir" ||
           name == "out" || name == "outputDir" || name == "intoVault" ||
           name == "keyfile" || name == "identity";
}

static std::string log_basename(const std::string& v) {
    size_t p = v.find_last_of("/\\");
    return p == std::string::npos ? v : v.substr(p + 1);
}

static std::string log_field_value(const std::string& name, const std::string& value) {
    if (!log_is_path_field(name)) return value;
    unsigned char key[32] = {0};
    if (!log_path_key(key)) return log_basename(value);
    unsigned char h[16] = {0};
    crypto_generichash(h, sizeof(h),
        reinterpret_cast<const unsigned char*>(value.data()), value.size(), key, 32);
    std::string out = "h:";
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(h); ++i) {
        out.push_back(hex[h[i] >> 4]);
        out.push_back(hex[h[i] & 15]);
    }
    sodium_memzero(key, 32);
    sodium_memzero(h, sizeof(h));
    return out;
}

static void write_log(int level, const std::string& msg,
                      const std::vector<std::pair<std::string, std::string>>* fields) {
    if (level > g_log_level) return;
    if (g_log_file.empty()) return;
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    // 使用 UTC
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    std::ostringstream line;
    line << "{\"ts\":\"" << ts << "\",\"level\":\"" << level_name(level)
         << "\",\"msg\":\"" << json_escape(msg) << "\"";
    if (fields && !fields->empty()) {
        line << ",\"fields\":{";
        for (size_t i = 0; i < fields->size(); ++i) {
            if (i) line << ",";
            line << "\"" << json_escape((*fields)[i].first) << "\":\""
                 << json_escape(log_field_value((*fields)[i].first,(*fields)[i].second)) << "\"";
        }
        line << "}";
    }
    line << "}\n";

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_stream.is_open()) {
        g_log_stream << line.str();
        g_log_stream.flush();
        // 磁盘满/权限变化/
        // 检测到时复位并
        if (!g_log_stream.good()) {
            g_log_stream.clear();
            open_log_stream_utf8(g_log_stream, g_log_file, std::ios::out | std::ios::app);
            if (!g_log_stream) {
                static bool warned = false;
                if (!warned) {
                    std::cerr << "Warning: cannot write log file (disk full or permission change): "
                              << g_log_file << "\n";
                    warned = true;
                }
            }
        }
    }
}

void log_event(int level, const std::string& msg) {
    write_log(level, msg, nullptr);
}

void log_event(int level, const std::string& msg,
               const std::vector<std::pair<std::string, std::string>>& fields) {
    write_log(level, msg, &fields);
}

// 全局配置访问

static std::shared_ptr<const Config> g_cfg;

void set_global_config(Config cfg) { g_cfg = std::make_shared<const Config>(std::move(cfg)); }

const Config& global_config() {
    static const Config fallback;
    return g_cfg ? *g_cfg : fallback;
}
