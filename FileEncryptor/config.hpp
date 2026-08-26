#pragma once
#include <string>
#include <vector>
#include <utility>
#include <cstdint>

// ---------- 全局运行配置（仅由 YAML 配置文件提供，CLI 不可覆盖） ----------
// 参见 Issue.md 一.1~一.4、二.3~二.5 的可选建议：日志位置/级别、核心调用数量（并发线程）、
// 路径长度/白名单、进度文件轮转等运维参数统一走 YAML，避免 CLI 暴露实现细节。
struct Config {
    // ---- 结构化日志 ----
    std::string log_file;   // 日志文件；空字符串 = 不写日志文件（仍可有 stdout 进度）
    int         log_level = 2; // 0=ERROR 1=WARN 2=INFO 3=DEBUG

    // ---- 并发 / 资源 ----
    int         worker_threads = 0;       // 0 = 自动（= 硬件并发数）
    uint64_t    max_memory_bytes = 0;     // 0 = 不限（仅作提示/未来限制用）
    size_t      io_buffer_size = 1u << 20; // 内部流式缓冲字节（不影响磁盘分块格式）

    // ---- 路径安全 ----
    size_t      max_path_length = 0;       // 0 = 不限（按 UTF-8 字节计）
    bool        path_whitelist_enabled = false;
    std::vector<std::string> path_whitelist; // 允许的输入/输出根目录（非空且启用时强制校验）

    // ---- 进度文件 ----
    bool        progress_rotation = true;  // 覆盖 .progress 前先备份为 .progress.bak

    // ---- 发布 / 供应链（仅发布脚本使用，运行时忽略） ----
};

// 定位配置文件：env FILEENCRYPTOR_CONFIG → <可执行文件目录>/fileencryptor.yaml
//             → 用户配置目录（Win %APPDATA%/FileEncryptor，Linux $XDG_CONFIG_HOME/fileencryptor 或 ~/.config/fileencryptor）
// 返回首个存在的路径；都不存在则返回空串（调用方使用默认 Config）。
std::string find_config_file();

// 解析极简 YAML（支持顶层标量键与单层序列 `- item`）到 Config。
// 出错时返回 false 并在 err 写入原因（解析错误不致命：回退默认配置并继续）。
bool parse_yaml_config(const std::string& text, Config& cfg, std::string& err);

// 加载配置：自动定位文件，缺失时返回默认 Config。
Config load_config();

// ---------- 结构化 JSON 日志 ----------
// 级别常量
enum LogLevel { LOG_ERROR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DEBUG = 3 };

// 初始化日志（指定日志文件路径与级别；log_file 为空则不写文件）。
void init_logger(const std::string& log_file, int level);

// 写一条 JSON 行日志：{"ts":...,"level":...,"msg":...[, "fields":{...}]}
void log_event(int level, const std::string& msg);
void log_event(int level, const std::string& msg,
               const std::vector<std::pair<std::string, std::string>>& fields);

// ---------- 全局配置（启动期设置一次，之后只读，线程安全） ----------
void    set_global_config(const Config& cfg);
const Config& global_config();
