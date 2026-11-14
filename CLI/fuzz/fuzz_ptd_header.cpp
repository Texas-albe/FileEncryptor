// FileEncryptor 模糊测试 harness：驱动 .ptd 头
// 用法
// clang
// ./FileEncryptorFuzz -runs=100000 corpus/
// 其他编译器
// ./FileEncryptorFuzz <input-file>
// 目标
// 不崩溃、不越界
#include "ptd_format.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 版本解析路径
    if (size >= 6) {
        unsigned char ver = data[5];
        header_size_for_version(ver);
        header_hmac_cover(ver);
    }

    // 头部装载
    if (size < HEADER_SIZE_V6) return 0;
    const FileHeaderV6 h = load_header<FileHeaderV6>(data);

    // 容器字段解析
    const uint32_t container_len = get_be32(
        reinterpret_cast<const unsigned char*>(&h.container_len));
    if (container_len > 4096) return 0;   // 防恶意超大值拖
    if (h.reserved[0] == 0x01 && size >= HEADER_SIZE_V6 + 4) {
        // 多收件人扩展区
        const uint32_t n = get_be32(data + HEADER_SIZE_V6);
        if (n <= 255) {
            (void)n;
        }
    }

    // DEK 解裹
    unsigned char dek[32];
    std::memset(dek, 0, sizeof dek);
    unwrap_dek(h.dek_box, data, h.dek_nonce, dek);

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
