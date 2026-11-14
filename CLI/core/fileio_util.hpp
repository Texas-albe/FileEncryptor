// 跨平台文件 I/O 小工
// UTF-8 路径
#pragma once
#include <string>
#include <cstdint>

// 文件是否存
bool fe_file_exists(const std::string& path);

// 文件大小
int64_t fe_file_size(const std::string& path);

// 截断到指定字节
bool fe_truncate_file(const std::string& path, uint64_t size);

// 逻辑规范化路径
// 走宽字符往返，避
std::string fe_normalize_path_lexical(const std::string& p);

// 递归创建目录
bool create_directory_recursive(const std::string& path);
