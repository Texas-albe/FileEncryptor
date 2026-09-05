#define _CRT_SECURE_NO_WARNINGS
#include "config.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <chrono>
#include <ctime>

#include <yaml-cpp/yaml.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

// =====================================================================
//  YAML 配置解析（依赖 yaml-cpp）
//  支持 fileencryptor.yaml 的全部顶层标量键与单层序列（path_whitelist）。
//  未知键静默忽略；解析失败（含 YAML 语法错误）不致命，由调用方回退默认配置。
// =====================================================================

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

// 去掉行内注释（# 在行首、空白、':' 或 '=' 后开始；忽略引号内 #）
static bool parse_bool(const std::string& v, bool& out) {
    std::string s = trim(v);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s == "true" || s == "yes" || s == "1" || s == "on") { out = true; return true; }
    if (s == "false" || s == "no" || s == "0" || s == "off") { out = false; return true; }
    return false;
}

static int level_from_string(const std::string& v) {
    std::string s = trim(v);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s == "error") return LOG_ERROR;
    if (s == "warn" || s == "warning") return LOG_WARN;
    if (s == "info") return LOG_INFO;
    if (s == "debug") return LOG_DEBUG;
    return -1; // 非字符串 → 当作数字解析
}

bool parse_yaml_config(const std::string& text, Config& cfg, std::string& err) {
    err.clear();
    YAML::Node root;
    try {
        root = YAML::Load(text);
    } catch (const YAML::Exception& e) {
        err = std::string("YAML 解析错误: ") + e.what();
        return false;
    }
    if (!root || root.IsNull()) return true; // 空文档 → 默认配置
    if (!root.IsMap()) { err = "配置顶层必须是映射(map)"; return false; }

    // 取标量字符串（仅当节点为标量）
    auto opt_str = [&](const char* key, std::string& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) { out = n.as<std::string>(); return true; }
        return false;
    };

    opt_str("log_file", cfg.log_file);

    // log_level：优先字符串（ERROR/WARN/INFO/DEBUG），否则按数字
    {
        const YAML::Node& n = root["log_level"];
        if (n && n.IsScalar()) {
            std::string s = n.as<std::string>();
            int lv = level_from_string(s);
            if (lv >= 0) cfg.log_level = lv;
            else { try { cfg.log_level = std::stoi(s); } catch (...) {} }
        }
    }

    auto opt_int = [&](const char* key, int& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) { try { out = n.as<int>(); } catch (...) {} }
    };
    opt_int("worker_threads", cfg.worker_threads);

    auto opt_size = [&](const char* key, size_t& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) { try { out = n.as<size_t>(); } catch (...) {} }
    };
    opt_size("max_open_files", cfg.max_open_files);
    opt_size("max_path_length", cfg.max_path_length);

    // 带单位的大小字段（支持 KB/MB/GB，1024 进制）
    auto opt_size_unit = [&](const char* key, uint64_t& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            std::string s;
            try { s = n.as<std::string>(); } catch (...) { return; }
            uint64_t v = 0;
            if (parse_size(s, v)) out = v;
        }
    };
    opt_size_unit("max_memory_bytes", cfg.max_memory_bytes);
    opt_size_unit("io_buffer_size", cfg.io_buffer_size);
    opt_size_unit("max_speed", cfg.max_speed);

    // 布尔字段
    auto opt_bool = [&](const char* key, bool& out) {
        const YAML::Node& n = root[key];
        if (n && n.IsScalar()) {
            std::string s;
            try { s = n.as<std::string>(); } catch (...) { return; }
            bool b = out;
            if (parse_bool(s, b)) out = b;
        }
    };
    opt_bool("path_whitelist_enabled", cfg.path_whitelist_enabled);
    opt_bool("progress_rotation", cfg.progress_rotation);
    opt_bool("obfuscate_names", cfg.obfuscate_names);

    // path_whitelist：序列；仅显式列出至少一项才启用，空列表不启用
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
    }

    return true;
}

// ---------- 单位解析 / 格式化（统一 1024 进制：KB/MB/GB） ----------
bool parse_size(const std::string& s, uint64_t& out_bytes) {
    out_bytes = 0;
    std::string t = s;
    // 去首尾空白
    size_t a = 0, b = t.size();
    while (a < b && std::isspace((unsigned char)t[a])) ++a;
    while (b > a && std::isspace((unsigned char)t[b - 1])) --b;
    t = t.substr(a, b - a);
    if (t.empty()) return false;
    // 速率写法可带 "/s" 后缀，忽略之
    if (t.size() >= 2 && t.compare(t.size() - 2, 2, "/s") == 0) t = t.substr(0, t.size() - 2);
    // 拆分数字部分与单位部分（单位可选）
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
    out_bytes = (uint64_t)(val * factor);
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

// ---------- 文件读取（UTF-8 安全） ----------
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

// 默认配置模板：CWD 下无 fileencryptor.yaml 时自动生成。与 Config 默认值一致。
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
"progress_rotation: true   # 覆盖 .progress 前先备份 .progress.bak\n"
"obfuscate_names: true     # 混淆输出文件名（<名>.<伪扩展名>.ptd）\n";

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
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    fclose(f);
    return true;
#else
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
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
    // 用 APPDATA 环境变量定位用户配置根（等价于 SHGetFolderPathW(CSIDL_APPDATA)，
    // 但无需引入 shlobj.h / shell32 依赖）。APPDATA 在 Windows 用户会话中始终设置。
    const char* appdata = std::getenv("APPDATA");
    if (appdata && *appdata) {
        std::string dir(appdata);
        if (!dir.empty() && dir.back() != '/' && dir.back() != '\\') dir += '/';
        return dir + "FileEncryptor";
    }
    return "";
#else
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/fileencryptor";
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.config/fileencryptor";
    return "";
#endif
}

std::string find_config_file() {
    // 1) 环境变量（显式，最高优先）
    const char* env = std::getenv("FILEENCRYPTOR_CONFIG");
    if (env && *env) {
        if (file_exists_utf8(env)) return env;
    }
    // 2) 运行目录（CWD）：用户在哪个目录启动程序，配置就在哪里
    std::string cwd = get_cwd();
    if (!cwd.empty()) {
        std::string p = cwd + "/fileencryptor.yaml";
        if (file_exists_utf8(p)) return p;
    }
    // 3) 可执行文件目录
    std::string exe_dir = get_exe_dir();
    if (!exe_dir.empty()) {
        std::string p = exe_dir + "/fileencryptor.yaml";
        if (file_exists_utf8(p)) return p;
    }
    // 4) 用户配置目录
    std::string ucd = get_user_config_dir();
    if (!ucd.empty()) {
        std::string p = ucd + "/fileencryptor.yaml";
        if (file_exists_utf8(p)) return p;
    }
    return "";
}

Config load_config() {
    Config cfg;
    std::string path = find_config_file();
    if (path.empty()) {
        // 运行目录（CWD）下生成默认配置文件，便于用户查看/修改（best-effort，失败则静默回退默认）
        std::string cwd = get_cwd();
        if (!cwd.empty()) {
            std::string def = cwd + "/fileencryptor.yaml";
            if (!file_exists_utf8(def)) {
                write_file_utf8(def, DEFAULT_CONFIG_YAML);
            }
        }
        return cfg; // 默认配置（与生成的模板一致）
    }
    std::string text;
    if (!read_file_utf8(path, text)) {
        std::cerr << "Warning: cannot read config file: " << path << "\n";
        return cfg;
    }
    // 去除 UTF-8 BOM（Windows 记事本 / PowerShell Set-Content 默认会写 EF BB BF），
    // 否则首行键名会带上 BOM 前缀（如 "\uFEFFlog_file"）导致解析失败。
    if (text.size() >= 3 &&
        (unsigned char)text[0] == 0xEF &&
        (unsigned char)text[1] == 0xBB &&
        (unsigned char)text[2] == 0xBF) {
        text.erase(0, 3);
    }
    std::string err;
    if (!parse_yaml_config(text, cfg, err)) {
        std::cerr << "Warning: config parse error (" << err << "); using defaults.\n";
        return Config();
    }
    return cfg;
}

// =====================================================================
//  结构化 JSON 日志
// =====================================================================

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
        g_log_stream.open(g_log_file, std::ios::out | std::ios::app);
        if (!g_log_stream) {
            std::cerr << "Warning: cannot open log file: " << g_log_file << "\n";
        }
    }
}

static void write_log(int level, const std::string& msg,
                      const std::vector<std::pair<std::string, std::string>>* fields) {
    if (level > g_log_level) return;
    if (g_log_file.empty()) return;
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    // 使用 UTC（gmtime）以匹配时间戳末尾的 'Z'，避免把本地时间误标为 UTC 误导日志分析
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
                 << json_escape((*fields)[i].second) << "\"";
        }
        line << "}";
    }
    line << "}\n";

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_stream.is_open()) {
        g_log_stream << line.str();
        g_log_stream.flush();
        // 防御：磁盘满 / 权限变化 / 文件被删会让流进入 badbit/failbit，
        // 若不处理后续所有日志都会静默丢失，运维排障时极具误导性。
        // 检测到异常时复位状态并尝试以 append 重新打开；仍失败则降级为 stderr 告警（仅提示一次，避免刷屏）。
        if (!g_log_stream.good()) {
            g_log_stream.clear();
            g_log_stream.open(g_log_file, std::ios::out | std::ios::app);
            if (!g_log_stream) {
                static bool warned = false;
                if (!warned) {
                    std::cerr << "Warning: cannot write log file (disk full or permission change?): "
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

// =====================================================================
//  全局配置访问
// =====================================================================

static const Config* g_cfg = nullptr;

void set_global_config(const Config& cfg) { g_cfg = &cfg; }

const Config& global_config() {
    static const Config fallback;
    return g_cfg ? *g_cfg : fallback;
}
