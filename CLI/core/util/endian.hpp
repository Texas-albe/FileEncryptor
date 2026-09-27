#pragma once
#include <cstdint>

// 字节序转换工具：编译期判断端序，提供 host<->le/be 转换。
namespace fe::util {

constexpr bool is_little_endian() {
    return true; // x86/ARM 均为小端；如需跨平台编译期检测可扩展
}

constexpr uint16_t bswap16(uint16_t v) {
    return (v >> 8) | (v << 8);
}
constexpr uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}
constexpr uint64_t bswap64(uint64_t v) {
    return ((v & 0xFF) << 56) | ((v & 0xFF00) << 40) |
           ((v & 0xFF0000) << 24) | ((v & 0xFF000000) << 8) |
           ((v >> 8) & 0xFF000000) | ((v >> 24) & 0xFF0000) |
           ((v >> 40) & 0xFF00) | ((v >> 56) & 0xFF);
}

constexpr uint16_t htole16(uint16_t v) { return is_little_endian() ? v : bswap16(v); }
constexpr uint16_t le16toh(uint16_t v) { return is_little_endian() ? v : bswap16(v); }
constexpr uint32_t htole32(uint32_t v) { return is_little_endian() ? v : bswap32(v); }
constexpr uint32_t le32toh(uint32_t v) { return is_little_endian() ? v : bswap32(v); }
constexpr uint64_t htole64(uint64_t v) { return is_little_endian() ? v : bswap64(v); }
constexpr uint64_t le64toh(uint64_t v) { return is_little_endian() ? v : bswap64(v); }

} // namespace fe::util
