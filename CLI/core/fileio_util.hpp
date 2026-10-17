// 跨平台文件 I/O 小工具：存在性 / 尺寸 / 截断 / 目录创建。
// UTF-8 路径在 Windows 上统一走宽字符 API（窄字符 API 按 ANSI 代码页解析会打不开中文路径）。
#pragma once
#include <string>
#include <cstdint>

// 文件是否存在（以能否打开为判据，避免 TOCTOU 式的 stat-then-open）
bool fe_file_exists(const std::string& path);

// 文件大小；不存在或 stat 失败返回 -1
int64_t fe_file_size(const std::string& path);

// 截断到指定字节数（续传时丢弃未记账的残片）
bool fe_truncate_file(const std::string& path, uint64_t size);

// 逻辑规范化路径（去 ..），并保留 \\?\ 长路径 / UNC 前缀的语义；
// 走宽字符往返，避免 fs::path 按 ACP 解释使中文/Emoji 路径抛异常。
std::string fe_normalize_path_lexical(const std::string& p);

// 递归创建目录；已存在视为成功
bool create_directory_recursive(const std::string& path);
