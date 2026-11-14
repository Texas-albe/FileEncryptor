#pragma once
// 把一棵目录树 / 一
// 单个 .ptd
// 在明文域做
// .ptd 盘面格式
// 明文布局
//   0   magic  "FEPK1\r\n"        8
//   8   version                    4   = 1
//   12  entry_count                4
// 16
//   24  reserved                   8   = 0
//   32  条目 × N
// 末  trailer magic
// 条目
//   path_len  4
// flags 4   bit0 = 目录
// size 8   原始字节数
// mode 4   POSIX 权限位 & 0xFFF
// mtime 8   Unix 秒
// path path_len 字节
// data size 字节

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

extern const char ARCHIVE_MAGIC[8];
inline constexpr uint32_t ARCHIVE_VERSION = 1;
inline constexpr size_t   ARCHIVE_HEADER_SIZE = 32;
inline constexpr uint32_t ARCHIVE_FLAG_DIR = 1u;

// 防御性上限
inline constexpr uint32_t ARCHIVE_MAX_ENTRIES = 1000000;
inline constexpr uint32_t ARCHIVE_MAX_PATH = 4096;

// 归档内
struct ArchiveEntry {
    std::string path;      // 归档内相对路径
    uint64_t    size = 0;  // 原始字节数
    uint32_t    mode = 0;  // POSIX 权限 & 0xFFF
    int64_t     mtime = 0; // Unix 秒
    bool        is_dir = false;
    std::string source;    // 本地源文件路径
};

// 目录递归
// 多根输入避免同
// 用于
bool archive_collect(const std::vector<std::string>& inputs,
                     const std::vector<std::string>& excludes,
                     std::vector<ArchiveEntry>& out, std::string& err);

// O_EXCL 独占创建
bool archive_write(const std::string& out_path,
                   const std::vector<ArchiveEntry>& entries, std::string& err);

// 判断文件是否
bool archive_probe(const std::string& path);

// 路径穿越一律拒
bool archive_extract(const std::string& archive_path, const std::string& out_dir,
                     bool force_overwrite,
                     std::function<void(uint64_t,uint64_t)> progress, std::string& err);

// 取一个当前未
// 实际创建仍
bool archive_make_temp(const std::string& tag, std::string& out_path, std::string& err);

// 同名子项逐个并
// 文件同名时 force_overwrite
bool merge_dir_into(const std::string& src_dir, const std::string& dst_dir,
                    bool force_overwrite, std::string& err);

// 只跟随真实目录
bool remove_tree(const std::string& dir);

// 列目录下一层条
bool list_dir_names(const std::string& dir, std::vector<std::string>& out);
