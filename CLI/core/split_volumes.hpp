// 分卷：把单个 .ptd 切成固定大小的多卷，或反之合并。
//
// 走「先出完整 .ptd，再切成多卷」：每卷是完整字节的一段，任意卷都能
// 独立校验，合并后仍是原样 .ptd。所以不改容器格式，也不在文件尾写
// 分卷表；缺卷靠文件存在性判断。
#pragma once

#include <cstdint>
#include <string>
#include <vector>


// 分卷名：<base>.001.ptd / <base>.002.ptd（序号 3 位，不足 999 卷够用）。
std::string volume_path(const std::string& ptd_path, uint32_t index);

// 反推卷名对应的原始 .ptd 路径。"foo.003.ptd" -> "foo.ptd"；
// 不是分卷名则返回空串。解密时用户可以只挑其中一卷。
std::string base_ptd_of(const std::string& volume_file);

// 解析 "2GB" / "512MB" / "100M" / "4096" 这类尺寸，返回字节数。
// 纯数字按字节解析（"4096" = 4096 字节），允许小数（"1.5G"）。
// 1024 进制，KB/MB/GB/TB 与 KiB/MiB/GiB/TiB 等价。拒绝负数与溢出。
bool parse_split_size(const std::string& spec, uint64_t& out_bytes, std::string& err);

// 把 src 切成每卷 volume_bytes 的若干卷，写在 src 同目录。返回卷数。
// 同名卷会被覆盖；src 本身保留，由调用方决定何时删。
bool split_file(const std::string& src, uint64_t volume_bytes,
                uint32_t& out_count, std::string& err);

// 找出 base.ptd 对应的分卷，按序号升序返回完整路径。
// 从 1 起连续枚举，遇到第一个缺号即停；out_missing 收集空洞处的卷号
// （即首个缺号之后仍存在的卷），用来分辨「本来就到这儿」和「中间少了几卷」。
std::vector<std::string> find_volumes(const std::string& base_ptd,
                                      std::vector<uint32_t>* out_missing = nullptr);

// 把 base_ptd 对应的分卷按序号合并成 merged_path。
// 序号必须从 1 开始且连续，缺号时报错并列出缺哪几卷。
bool merge_volumes(const std::string& base_ptd, const std::string& merged_path,
                   std::string& err);

// 加密收尾：把完整 .ptd 切成多卷并删掉原件。原件删掉后整文件校验单
// 就失去意义，故 sha_sidecar 为真时改为每卷各写一份。失败只报错，
// 完整 .ptd 仍留在原处可用。
bool finish_encrypt_split(const std::string& ptd_path, uint64_t volume_bytes,
                          bool sha_sidecar, std::string& err);

// 解密输入归一的结果。
struct SplitPlan {
    std::string real_input;            // 实际交给解密器的 .ptd
    std::string merged_path;           // 合并产物，非空则需清理
    std::vector<std::string> volumes;  // 输入来自分卷时的全部卷
    bool from_volumes = false;
};

// 输入是 foo.003.ptd（或 foo.ptd 缺失但 foo.001.ptd 在）时，合并出完整
// .ptd 并把 real_input 指向它；非分卷输入原样返回。
bool resolve_decrypt_input(const std::string& in_path, SplitPlan& plan, std::string& err);

// 合并临时件的自动清理
struct MergedTemp {
    std::string path;
    ~MergedTemp();
};
