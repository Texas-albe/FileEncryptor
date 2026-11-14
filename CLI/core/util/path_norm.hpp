#pragma once
// 归档内相对路径
// 统一分隔符
// 保留设备名 CON/PRN/AUX/NUL
// 如 con.txt / com1.log）
// 保留名判定
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace fe::util {

// 单分量长度上限
inline constexpr size_t kMaxRelComponentBytes = 4096;

// Windows 保留设备名命
// 因此 con.txt / COM1 /
inline bool is_windows_reserved_device(const std::string& name) {
    std::string base = name;
    const size_t bs = base.find_last_of("/\\");
    if (bs != std::string::npos) base = base.substr(bs + 1);
    const size_t dot = base.find('.');
    const std::string stem = (dot != std::string::npos) ? base.substr(0, dot) : base;
    std::string up;
    up.reserve(stem.size());
    for (unsigned char c : stem) up.push_back((char)std::toupper(c));
    if (up == "CON" || up == "PRN" || up == "AUX" || up == "NUL") return true;
    auto is_num = [&](const std::string& pre) {
        if (up.size() <= pre.size()) return false;
        if (up.compare(0, pre.size(), pre) != 0) return false;
        for (size_t i = pre.size(); i < up.size(); ++i)
            if (!std::isdigit((unsigned char)up[i])) return false;
        return true;
    };
    for (int i = 1; i <= 9; ++i) {
        if (is_num("COM" + std::to_string(i))) return true;
        if (is_num("LPT" + std::to_string(i))) return true;
    }
    return false;
}

inline bool normalize_rel(const std::string& in, std::string& out) {
    std::string s;
    s.reserve(in.size());
    for (char c : in) s.push_back((c == '\\') ? '/' : c);
    // 绝对路径
    if (!s.empty() && s[0] == '/') return false;
    if (s.size() >= 2 && s[1] == ':') return false;
    if (s.find('\0') != std::string::npos) return false;

    std::vector<std::string> parts;
    size_t i = 0;
    while (i < s.size()) {
        size_t j = s.find('/', i);
        if (j == std::string::npos) j = s.size();
        std::string seg = s.substr(i, j - i);
        if (seg == "..") return false;             // 穿越
        if (!seg.empty() && seg != ".") parts.push_back(seg);
        i = j + 1;
    }
    if (parts.empty()) return false;
    for (const auto& p : parts) {
        if (p.size() > kMaxRelComponentBytes) return false;
        // Windows 保留名
        for (char c : p) {
            if ((unsigned char)c < 0x20) return false;
            if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') return false;
        }
        if (is_windows_reserved_device(p)) return false;
    }
    out.clear();
    for (size_t k = 0; k < parts.size(); ++k) {
        if (k) out.push_back('/');
        out += parts[k];
    }
    return true;
}

}  // namespace fe::util
