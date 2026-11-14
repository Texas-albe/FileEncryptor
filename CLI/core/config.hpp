#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdint>

// 全局运行配置
// 路径白名单、进度
struct Config {
    std::string log_file;   // 空 = 只走 stdout
    int         log_level = 2; // 0=ERROR 1=WARN 2=INFO 3=DEBUG

    // 并发 / 资源
    int         worker_threads = 0;       // 0 = 自动
    uint64_t    max_memory_bytes = 0;     // 0 = 不限
    size_t      io_buffer_size = 1u << 20; // 内部流式缓冲字
    size_t      max_open_files = 256;     // 并发线程数上限 =
    uint64_t    max_speed = 0;            // 限速

    // 路径安全
    size_t      max_path_length = 0;       // 0 = 不限
    bool        path_whitelist_enabled = false; // 须显式列出至少
    std::vector<std::string> path_whitelist; // 允许

    // 只管可见输出文
    bool        obfuscate_names = true;

    // 密码策略
    int         min_password_length = 0;
    int         min_password_classes = 2;

    // 0=fast 1=standard
    int         kdf_preset = 1;

    // 空 = xchacha20
    std::string default_cipher;

    // 加密成功后生成 <out>.ptd.sha256
    bool        write_sha256 = false;

};

// 配置文件来源
enum class ConfigSource { None = 0, Env, Cwd, ExeDir, UserConfig };

// 优先级
std::string find_config_file(ConfigSource* src = nullptr);

// Win %APPDATA%
std::string user_config_dir();

// Windows 下把 '/' 统一
std::string to_native_path(const std::string& p);

// 出错写 err 后回退默
bool parse_yaml_config(const std::string& text, Config& cfg, std::string& err, std::string* warn = nullptr);

// 1024 进制，可带 "/s"
bool parse_size(const std::string& s, uint64_t& out_bytes);

// 1572864 -> "1.50 MB"，512 -> "512 B"
std::string format_size(uint64_t bytes);

// 加载配置
Config load_config();

// 结构化 JSON 日志
enum LogLevel { LOG_ERROR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DEBUG = 3 };

// log_file 为空
void init_logger(const std::string& log_file, int level);

// 写一条 JSON 行日志
void log_event(int level, const std::string& msg);
void log_event(int level, const std::string& msg,
               const std::vector<std::pair<std::string, std::string>>& fields);

// 启动期设置一次
void    set_global_config(Config cfg);
const Config& global_config();
