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

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

// =====================================================================
//  极简 YAML 读取（零依赖）
//  仅支持本项目需要的语法：
//    - 顶层标量键：   key: value
//    - 单行注释：     # ...
//    - 单层序列：     key:
//                        - item1
//                        - item2
//  足够覆盖 fileencryptor.yaml 的全部可选配置项。
// =====================================================================

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

// 去掉行内注释（# 前为空白或行首；忽略引号内 #）
static std::string strip_comment(const std::string& line) {
    bool in_sq = false, in_dq = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\'' && !in_dq) in_sq = !in_sq;
        else if (c == '"' && !in_sq) in_dq = !in_dq;
        else if (c == '#' && !in_sq && !in_dq) {
            bool preceded_by_space = (i == 0) || std::isspace((unsigned char)line[i - 1]);
            if (preceded_by_space) return line.substr(0, i);
        }
    }
    return line;
}

static std::string unquote(const std::string& v) {
    std::string s = trim(v);
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

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
    std::istringstream in(text);
    std::string raw;
    std::string cur_seq_key; // 当前正在收集序列的键
    int line_no = 0;

    auto set_scalar = [&](const std::string& key, const std::string& val_raw) {
        std::string v = unquote(val_raw);
        if (key == "log_file") {
            cfg.log_file = v;
        } else if (key == "log_level") {
            int lv = level_from_string(v);
            if (lv >= 0) cfg.log_level = lv;
            else { try { cfg.log_level = std::stoi(v); } catch (...) {} }
        } else if (key == "worker_threads") {
            try { cfg.worker_threads = std::stoi(v); } catch (...) {}
        } else if (key == "max_memory_bytes") {
            try { cfg.max_memory_bytes = (uint64_t)std::stoull(v); } catch (...) {}
        } else if (key == "io_buffer_size") {
            try { cfg.io_buffer_size = (size_t)std::stoull(v); } catch (...) {}
        } else if (key == "max_path_length") {
            try { cfg.max_path_length = (size_t)std::stoull(v); } catch (...) {}
        } else if (key == "path_whitelist_enabled") {
            bool b = false; if (parse_bool(v, b)) cfg.path_whitelist_enabled = b;
        } else if (key == "progress_rotation") {
            bool b = false; if (parse_bool(v, b)) cfg.progress_rotation = b;
        }
        // 未知键：静默忽略（前向兼容）
    };

    while (std::getline(in, raw)) {
        ++line_no;
        std::string line = trim(strip_comment(raw));
        if (line.empty()) { cur_seq_key.clear(); continue; }

        // 列表项：属于上一个序列键
        if (line[0] == '-') {
            if (cur_seq_key.empty()) {
                err = "第 " + std::to_string(line_no) + " 行：列表项出现在键之外";
                return false;
            }
            std::string item = trim(line.substr(1));
            item = unquote(item);
            if (!item.empty()) cfg.path_whitelist.push_back(item);
            continue;
        }

        // 顶层键
        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            err = "第 " + std::to_string(line_no) + " 行：缺少 ':'";
            return false;
        }
        std::string key = trim(line.substr(0, colon));
        std::string val = line.substr(colon + 1);
        if (key.empty()) { err = "第 " + std::to_string(line_no) + " 行：空键"; return false; }

        if (val.empty()) {
            // 可能是序列头（后续 - 行）或空标量
            if (key == "path_whitelist") {
                cur_seq_key = key;
                cfg.path_whitelist_enabled = true; // 显式列出即视为启用
            } else {
                cur_seq_key.clear();
                set_scalar(key, "");
            }
        } else {
            cur_seq_key.clear();
            set_scalar(key, val);
        }
    }
    return true;
}

// ---------- 文件读取（UTF-8 安全） ----------
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
        if (std::ifstream(env)) return env;
    }
    // 2) 可执行文件目录
    std::string exe_dir = get_exe_dir();
    if (!exe_dir.empty()) {
        std::string p = exe_dir + "/fileencryptor.yaml";
        if (std::ifstream(p)) return p;
    }
    // 3) 用户配置目录
    std::string ucd = get_user_config_dir();
    if (!ucd.empty()) {
        std::string p = ucd + "/fileencryptor.yaml";
        if (std::ifstream(p)) return p;
    }
    return "";
}

Config load_config() {
    Config cfg;
    std::string path = find_config_file();
    if (path.empty()) return cfg; // 默认配置
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
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
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
