#pragma once
// 机器指纹：MAC 地址与主板序列号各自哈希后合并，再取 SHA-256 前 WM_ID_LEN 字节。
// 只产出哈希，不含任何明文标识，避免把主机信息直接写进用户文件。
#include <cstddef>
#include <cstdint>
#include <string>

inline constexpr size_t WM_ID_LEN = 16;
inline constexpr size_t WM_ID_HEX_LEN = WM_ID_LEN * 2;

// 采集结果。flags 逐位标记来源是否命中，供排障时区分"采集失败"与"机器确实无标识"。
struct MachineId {
    unsigned char id[WM_ID_LEN] = {0};
    uint8_t flags = 0;      // bit0=MAC 命中 bit1=主板序列号命中
    bool available = false; // 至少一项命中

    bool has_mac() const { return (flags & 0x01) != 0; }
    bool has_board() const { return (flags & 0x02) != 0; }
};

// 跨平台采集机器指纹（Windows: GetAdaptersAddresses + WMI Win32_BaseBoard；
// Linux: getifaddrs + /sys/class/dmi）。任一项失败只丢该项，不整体失败。
MachineId collect_machine_id();

// 指纹的十六进制形式（32 字符），用于输出展示。
std::string machine_id_hex(const MachineId& m);

// 指纹的 base32/十六进制短串（WM_ID_LEN 字节，可直接落文本），与 machine_id_hex 区分：
// 展示用完整 32 字符，容器内用前缀版本。
std::string machine_id_prefix_hex(const MachineId& m, size_t bytes);
