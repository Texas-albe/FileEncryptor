// FileEncryptor 模糊测试 harness：驱动归档路径规范化（fe::util::normalize_rel）。
// 用法同 fuzz_ptd_header.cpp：
//   clang（libFuzzer）: FE_BUILD_FUZZ=ON 时编译为 libFuzzer 二进制，
//   ./FileEncryptorFuzz -runs=100000 corpus/
//   其他编译器（独立驱动）: 读单个文件当输入，手工喂样本回归：
//   ./FileEncryptorFuzz <input-file>
// 目标：任意字节作为归档内相对路径时，".." 穿越、绝对路径、盘符、
// Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，含 con.txt 形式）、
// 控制字符与非法字符一律被拒绝，合法路径的规范化结果稳定——覆盖审计报告
// 低危 D 组指出的「路径规范化/穿越零覆盖」。
#include "util/path_norm.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string in(reinterpret_cast<const char*>(data), size);
    std::string out;
    fe::util::normalize_rel(in, out);
    return 0;
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
// 独立驱动模式：读单个文件喂给 fuzz 函数（MSVC 等无 libFuzzer 编译器使用）
int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 2;
    }
    std::FILE* f = std::fopen(argv[1], "rb");
    if (!f) {
        std::perror("open");
        return 2;
    }
    std::vector<uint8_t> buf;
    uint8_t tmp[4096];
    size_t n;
    while ((n = std::fread(tmp, 1, sizeof tmp, f)) > 0)
        buf.insert(buf.end(), tmp, tmp + n);
    std::fclose(f);
    return LLVMFuzzerTestOneInput(buf.data(), buf.size());
}
#endif
