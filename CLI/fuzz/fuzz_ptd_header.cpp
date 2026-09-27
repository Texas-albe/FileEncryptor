// FileEncryptor 模糊测试 harness：驱动 .ptd 头部解析与 DEK 解裹路径。
//
// 用法：
//   clang（libFuzzer）: FE_BUILD_FUZZ=ON 时编译为 libFuzzer 二进制，直接
//       ./FileEncryptorFuzz -runs=100000 corpus/
//   其他编译器（独立驱动）: 读单个文件当输入，手工喂样本回归：
//       ./FileEncryptorFuzz <input-file>
//
// 目标：任意字节输入下，版本解析 / 头部装载 / 容器长度 / DEK 解裹路径
// 不崩溃、不越界（libsodium 的 AEAD 解密对任意 box/nonce/密钥安全）。
#include "ptd_format.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 1) 版本解析路径：任意 version 字节都必须安全回落
    if (size >= 6) {
        unsigned char ver = data[5];
        header_size_for_version(ver);
        header_hmac_cover(ver);
    }

    // 2) 头部装载：v6 布局（256 字节）需要足够输入
    if (size < HEADER_SIZE_V6) return 0;
    const FileHeaderV6 h = load_header<FileHeaderV6>(data);

    // 3) 容器字段解析（大端读取 + 扩展标记）
    const uint32_t container_len = get_be32(
        reinterpret_cast<const unsigned char*>(&h.container_len));
    if (container_len > 4096) return 0;   // 防恶意超大值拖慢 fuzz
    if (h.reserved[0] == 0x01 && size >= 4 + 32) {
        // 多收件人扩展区：N 与记录长度关系
        const uint32_t n = get_be32(data + HEADER_SIZE_V6);
        if (n <= 255) {
            (void)n;
        }
    }

    // 4) DEK 解裹：用输入前 32 字节当 KEK，验证 AEAD 解密路径不越界
    unsigned char dek[32];
    std::memset(dek, 0, sizeof dek);
    unwrap_dek(h.dek_box, data, h.dek_nonce, dek);

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
