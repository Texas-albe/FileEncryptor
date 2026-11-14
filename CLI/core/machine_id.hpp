#pragma once
// 机器指纹
// 只产出哈希
#include <cstddef>
#include <cstdint>
#include <string>

inline constexpr size_t WM_ID_LEN = 16;
inline constexpr size_t WM_ID_HEX_LEN = WM_ID_LEN * 2;

// 采集结果
struct MachineId {
    unsigned char id[WM_ID_LEN] = {0};
    uint8_t flags = 0;      
    bool available = false; // 至少一项命

    bool has_mac() const { return (flags & 0x01) != 0; }
    bool has_board() const { return (flags & 0x02) != 0; }
};

// 跨平台采集机器
// Linux
MachineId collect_machine_id();

// 指纹
std::string machine_id_hex(const MachineId& m);

// 指纹
// 展示用完整 32 字符
std::string machine_id_prefix_hex(const MachineId& m, size_t bytes);
