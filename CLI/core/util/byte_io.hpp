#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

// 字节读写：vector 追加版（write_*）与裸指针版（put_*/get_*），统一项目内手写字节序代码。
namespace fe::util {

// ---- vector 追加 ----
inline void write_u16_le(std::vector<unsigned char>& buf, uint16_t v) {
    buf.push_back(v & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
}
inline void write_u32_le(std::vector<unsigned char>& buf, uint32_t v) {
    buf.push_back(v & 0xFF); buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 16) & 0xFF); buf.push_back((v >> 24) & 0xFF);
}
inline void write_u64_le(std::vector<unsigned char>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back((v >> (i * 8)) & 0xFF);
}

// ---- 裸指针读写（小端） ----
inline void put_le16(unsigned char* p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
}
inline void put_le32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}
inline void put_le64(unsigned char* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (unsigned char)((v >> (i * 8)) & 0xFF);
}
inline uint16_t get_le16(const unsigned char* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
inline uint32_t get_le32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t get_le64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8);
    return v;
}

// ---- 裸指针读写（大端，容器字段用） ----
inline void put_be32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)((v >> 24) & 0xFF);
    p[1] = (unsigned char)((v >> 16) & 0xFF);
    p[2] = (unsigned char)((v >> 8) & 0xFF);
    p[3] = (unsigned char)(v & 0xFF);
}
inline uint32_t get_be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// 把 v 的小端字节从 dst 末尾向前异或（nonce = iv XOR 块索引用），len 为 dst 总长度。
inline void xor_le64_tail(unsigned char* dst, size_t len, uint64_t v) {
    for (size_t j = 0; j < 8 && j < len; ++j)
        dst[len - 1 - j] ^= (unsigned char)((v >> (j * 8)) & 0xFF);
}

} // namespace fe::util
