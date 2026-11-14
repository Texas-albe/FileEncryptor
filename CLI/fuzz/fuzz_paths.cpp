// FileEncryptor 模糊测试 harness：驱动归
// 用法同
// clang
//   ./FileEncryptorFuzz -runs=100000 corpus/
// 其他编译器
//   ./FileEncryptorFuzz <input-file>
// 目标
// Windows 保留设备名
// 控制字符
// 低危 D 组指出
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
// 独立驱动模式
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
