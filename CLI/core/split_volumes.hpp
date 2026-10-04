// 分卷：把单个 .ptd 切成定长多卷，或反之合并。
// 走「先出完整 .ptd 再切」：每卷是完整字节的一段，任意卷可独立校验，合并后仍是
// 原样 .ptd。故不改容器格式、不在尾部分卷表，缺卷靠文件存在性判断。
#pragma once

#include <cstdint>
#include <string>
#include <vector>


// <base>.001.ptd / <base>.002.ptd（序号 3 位）
std::string volume_path(const std::string& ptd_path, uint32_t index);

// "foo.003.ptd" -> "foo.ptd"；不是分卷名返回空串。解密时只挑一卷也能用
std::string base_ptd_of(const std::string& volume_file);

// 解析 "2GB" / "100M" / "4096"，允许小数（"1.5G"）。纯数字按字节，1024 进制
// （KB/MB 与 KiB/MiB 等价）。拒绝负数与溢出。
bool parse_split_size(const std::string& spec, uint64_t& out_bytes, std::string& err);

// 同名卷会被覆盖；src 本身保留，由调用方决定何时删
bool split_file(const std::string& src, uint64_t volume_bytes,
                uint32_t& out_count, std::string& err);

// 从 1 起连续枚举，遇第一个缺号即停。out_missing 收集首个缺号之后仍存在的卷号，
// 用来分辨「本来就到这儿」和「中间少了几卷」。
std::vector<std::string> find_volumes(const std::string& base_ptd,
                                      std::vector<uint32_t>* out_missing = nullptr);

// 序号须从 1 起连续，缺号时报错并列出缺哪几卷。
// merged_path 以 O_EXCL 独占创建，已存在（含符号链接）时不覆盖，
// 置 out_conflict=true 让调用方换名重试。
bool merge_volumes(const std::string& base_ptd, const std::string& merged_path,
                   std::string& err, bool* out_conflict = nullptr);

// 切卷后删掉原件。整文件校验单随之失效，故 sha_sidecar 为真时每卷各写一份。
// 失败只报错，完整 .ptd 仍留在原处可用。
bool finish_encrypt_split(const std::string& ptd_path, uint64_t volume_bytes,
                          bool sha_sidecar, std::string& err);

// 解密输入归一的结果。
struct SplitPlan {
    std::string real_input;            // 实际交给解密器的 .ptd
    std::string merged_path;           // 合并产物，非空则需清理
    std::vector<std::string> volumes;  // 输入来自分卷时的全部卷
    bool from_volumes = false;
};

// 输入是 foo.003.ptd（或 foo.ptd 缺失但 foo.001.ptd 在）时合并出完整 .ptd 并把
// real_input 指向它；非分卷输入原样返回。
bool resolve_decrypt_input(const std::string& in_path, SplitPlan& plan, std::string& err);

// 合并临时件的自动清理
struct MergedTemp {
    std::string path;
    ~MergedTemp();
};
