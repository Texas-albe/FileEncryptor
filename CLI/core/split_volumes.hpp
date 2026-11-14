// 分卷
// 走「先出完整 .ptd
// 原样 .ptd
#pragma once

#include <cstdint>
#include <string>
#include <vector>


// <base>.001.ptd / <base>
std::string volume_path(const std::string& ptd_path, uint32_t index);

// "foo.003.ptd" ->
std::string base_ptd_of(const std::string& volume_file);

// 解析 "2GB" / "100M" /
// 。拒绝负数
bool parse_split_size(const std::string& spec, uint64_t& out_bytes, std::string& err);

// 同名卷
bool split_file(const std::string& src, uint64_t volume_bytes,
                uint32_t& out_count, std::string& err);

// 从 1 起连续枚举
// 用来分辨「本来
std::vector<std::string> find_volumes(const std::string& base_ptd,
                                      std::vector<uint32_t>* out_missing = nullptr);

// 序号须
// merged_path 以 O_EXCL 独占创建，已存
// 置 out_conflict=true 让调用方
bool merge_volumes(const std::string& base_ptd, const std::string& merged_path,
                   std::string& err, bool* out_conflict = nullptr);

// 切卷后删掉原件
// 失败只报错
bool finish_encrypt_split(const std::string& ptd_path, uint64_t volume_bytes,
                          bool sha_sidecar, std::string& err);

// 解密输入归一
struct SplitPlan {
    std::string real_input;            // 实际交给解密器
    std::string merged_path;           // 合并产物
    std::vector<std::string> volumes;  // 输入来自分卷
    bool from_volumes = false;
};

// 输入是 foo.003.ptd
// real_input 指向它
bool resolve_decrypt_input(const std::string& in_path, SplitPlan& plan, std::string& err);

// 合并临时件
struct MergedTemp {
    std::string path;
    ~MergedTemp();
};
