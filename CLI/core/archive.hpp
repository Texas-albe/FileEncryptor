#pragma once
// 把一棵目录树 / 一批文件打成单个字节流（明文域），再交给 encrypt_file 加密成
// 单个 .ptd；解密侧识别归档头后展开回原目录树。
// 在明文域做而不新开容器版本：压缩、分卷、水印、非对称、密钥轮换全部自动继承，
// .ptd 盘面格式与既有版本保持不变。
//
// 明文布局（定长小端，'/' 分隔的相对路径）：
//   0   magic  "FEPK1\r\n"        8
//   8   version                    4   = 1
//   12  entry_count                4
//   16  total_raw_size             8   各条目原始大小之和（进度与完整性参考）
//   24  reserved                   8   = 0
//   32  条目 × N
//   末  trailer magic "FEPKEND!"   8 + total_raw_size 8
//
// 条目：
//   path_len  4
//   flags     4   bit0 = 目录（size 恒为 0，不带数据）
//   size      8   原始字节数
//   mode      4   POSIX 权限位 & 0xFFF
//   mtime     8   Unix 秒
//   path      path_len 字节（UTF-8）
//   data      size 字节（仅文件）

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

extern const char ARCHIVE_MAGIC[8];
inline constexpr uint32_t ARCHIVE_VERSION = 1;
inline constexpr size_t   ARCHIVE_HEADER_SIZE = 32;
inline constexpr uint32_t ARCHIVE_FLAG_DIR = 1u;

// 防御性上限，避免畸形流把内存吃光
inline constexpr uint32_t ARCHIVE_MAX_ENTRIES = 1000000;
inline constexpr uint32_t ARCHIVE_MAX_PATH = 4096;

// 归档内的一条记录（数据不驻留，size>0 时从 source 指向的文件读）
struct ArchiveEntry {
    std::string path;      // 归档内相对路径，'/' 分隔，无前导 '/'、无 ".."
    uint64_t    size = 0;  // 原始字节数（目录为 0）
    uint32_t    mode = 0;  // POSIX 权限 & 0xFFF
    int64_t     mtime = 0; // Unix 秒
    bool        is_dir = false;
    std::string source;    // 本地源文件路径（打包时读，解包时忽略）
};

// 目录递归（跳过符号链接与重解析点），文件直接收。目录输入保留基名作为顶层目录，
// 多根输入避免同名条目互相覆盖。excludes 连同其子树一起跳过（规范化后比较），
// 用于把输出 .ptd 与临时归档件排除在打包范围外。
bool archive_collect(const std::vector<std::string>& inputs,
                     const std::vector<std::string>& excludes,
                     std::vector<ArchiveEntry>& out, std::string& err);

// O_EXCL 独占创建，目标已存在（含符号链接）时报错，不覆盖不跟随
bool archive_write(const std::string& out_path,
                   const std::vector<ArchiveEntry>& entries, std::string& err);

// 判断文件是否以归档魔数开头（只读头部 8 字节）
bool archive_probe(const std::string& path);

// 路径穿越一律拒绝；已存在的文件按 force_overwrite 决定跳过还是删除重建
bool archive_extract(const std::string& archive_path, const std::string& out_dir,
                     bool force_overwrite,
                     std::function<void(uint64_t,uint64_t)> progress, std::string& err);

// 取一个当前未被占用的路径暂存归档字节流。只保证「返回时不存在」，
// 实际创建仍由 archive_write 的 O_EXCL 把关。
bool archive_make_temp(const std::string& tag, std::string& out_path, std::string& err);

// 同名子项逐个并，不整体替换目录（那会丢掉 dst 里已有的其它内容）。
// 文件同名时 force_overwrite 为真则替换，否则保留 dst 的那份。
bool merge_dir_into(const std::string& src_dir, const std::string& dst_dir,
                    bool force_overwrite, std::string& err);

// 只跟随真实目录项，符号链接本身被删而不跟进去，避免顺着链接删到树外
bool remove_tree(const std::string& dir);

// 列目录下一层条目名（不含 . 与 ..）。读不到返回 false。
bool list_dir_names(const std::string& dir, std::vector<std::string>& out);
