#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdint>

// 全局运行配置（仅由 YAML 配置文件提供，CLI 不可覆盖）：日志位置/级别、并发线程、
// 路径白名单、进度文件轮转等运维参数统一走 YAML，避免 CLI 暴露实现细节。
struct Config {
    std::string log_file;   // 空 = 只走 stdout
    int         log_level = 2; // 0=ERROR 1=WARN 2=INFO 3=DEBUG

    // 并发 / 资源
    int         worker_threads = 0;       // 0 = 自动（= 硬件并发数）
    uint64_t    max_memory_bytes = 0;     // 0 = 不限；支持 "512MB" 等带单位写法
    size_t      io_buffer_size = 1u << 20; // 内部流式缓冲字节（不影响磁盘分块格式）
    size_t      max_open_files = 256;     // 并发线程数上限 = 本值/3，防句柄耗尽
    uint64_t    max_speed = 0;            // 限速：每秒最大处理字节数，0 = 不限速（进程级总吞吐上限）

    // 路径安全
    size_t      max_path_length = 0;       // 0 = 不限（按 UTF-8 字节计）
    bool        path_whitelist_enabled = false; // 须显式列出至少一项才启用；空列表全放行
    std::vector<std::string> path_whitelist; // 允许的输入/输出根目录

    // 只管可见输出文件名；原始名始终以加密信封存进密文尾部
    bool        obfuscate_names = true;

    // 口令策略：0=用内置默认(8)；字符类别数 0=不强制；非 ASCII 视为高熵直接放行
    int         min_password_length = 0;
    int         min_password_classes = 2;

    // 0=fast 1=standard(默认) 2=strong；写入文件头，解密端自适应
    int         kdf_preset = 1;

    // 空 = xchacha20；仅在 CLI 未给 -m 时生效，解密永远以文件头 mode 为准
    std::string default_cipher;

    // 加密成功后生成 <out>.ptd.sha256
    bool        write_sha256 = false;

};

// 配置文件来源（v2.1.2：用于判定信任级别）
enum class ConfigSource { None = 0, Env, Cwd, ExeDir, UserConfig };

// 优先级：$FILEENCRYPTOR_CONFIG > CWD（低信任）> 可执行文件目录 > 用户配置目录
std::string find_config_file(ConfigSource* src = nullptr);

// Win %APPDATA%/FileEncryptor；Linux $XDG_CONFIG_HOME/fileencryptor 或 ~/.config/fileencryptor
std::string user_config_dir();

// Windows 下把 '/' 统一为原生分隔符，避免 "AppData/Roaming\keys" 这类混写
std::string to_native_path(const std::string& p);

// 出错写 err 后回退默认；warn 收集非致命的类型/单位告警
bool parse_yaml_config(const std::string& text, Config& cfg, std::string& err, std::string* warn = nullptr);

// 1024 进制，可带 "/s"；"0"/空 = 不限。"1.5GB" 合法
bool parse_size(const std::string& s, uint64_t& out_bytes);

// 1572864 -> "1.50 MB"，512 -> "512 B"
std::string format_size(uint64_t bytes);

// 加载配置：自动定位文件，缺失时返回默认 Config。
Config load_config();

// 结构化 JSON 日志
enum LogLevel { LOG_ERROR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DEBUG = 3 };

// log_file 为空则只写 stdout
void init_logger(const std::string& log_file, int level);

// 写一条 JSON 行日志：{"ts":...,"level":...,"msg":...[, "fields":{...}]}
void log_event(int level, const std::string& msg);
void log_event(int level, const std::string& msg,
               const std::vector<std::pair<std::string, std::string>>& fields);

// 启动期设置一次，之后只读；按值拷贝持有，避免临时 Config 造成悬空指针
void    set_global_config(Config cfg);
const Config& global_config();
