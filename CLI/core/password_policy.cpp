#include "password_policy.hpp"
#include <cctype>

namespace fe::password_policy {

namespace {

// 逐字节分类：调用方可直接传口令缓冲区，避免构造未清零的临时 std::string 副本
int classify(const char* pw, size_t len, bool& lower, bool& upper,
             bool& digit, bool& symbol, bool& non_ascii) {
    lower = upper = digit = symbol = non_ascii = false;
    for(size_t i=0; i<len; ++i) {
        unsigned char c = (unsigned char)pw[i];
        if(c <= 0x7F) {
            if(std::islower(c))      lower = true;
            else if(std::isupper(c)) upper = true;
            else if(std::isdigit(c)) digit = true;
            else if(std::ispunct(c)) symbol = true;
        } else {
            non_ascii = true;  // 多字节字符（UTF-8 中文等）视为一类高熵字符
        }
    }
    return (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
}

// 全同字符（如 8 个「的」、16 个 a）字符类虽达线，熵仍近乎为零。
// 按 UTF-8 字符单元而非单字节比对：汉字是 3 字节序列，逐字节比会漏判。
bool all_same(const char* pw, size_t len) {
    if(len < 2) return false;
    const unsigned char c0 = (unsigned char)pw[0];
    size_t unit = 1;
    if((c0 & 0xE0) == 0xC0)      unit = 2;
    else if((c0 & 0xF0) == 0xE0) unit = 3;
    else if((c0 & 0xF8) == 0xF0) unit = 4;
    if(len % unit != 0) return false;   // 长度不是单元整数倍，必有混排
    for(size_t i = unit; i < len; ++i)
        if(pw[i] != pw[i % unit]) return false;
    return true;
}

} // namespace

bool meets_policy(const char* pw, size_t len, size_t min_len, int min_classes,
                  std::string& reason) {
    if(len < min_len) {
        reason = "Password too short (min " + std::to_string(min_len) +
                 " characters).";
        return false;
    }
    bool lower = false, upper = false, digit = false, symbol = false, non_ascii = false;
    // 非 ASCII 只算一类：此前「含非 ASCII 即放行」会让重复汉字被判为合格
    int kinds = classify(pw, len, lower, upper, digit, symbol, non_ascii)
                + (non_ascii ? 1 : 0);
    if(kinds >= min_classes || len >= 16) {
        if(!all_same(pw, len)) return true;
        reason = "Password too weak: please avoid repeated characters.";
        return false;
    }
    reason = "Password too weak: use at least " + std::to_string(min_classes) +
             " character classes (lower/upper/digit/symbol) or length >= 16.";
    return false;
}

bool meets_policy(const std::string& pw, size_t min_len, int min_classes,
                  std::string& reason) {
    return meets_policy(pw.data(), pw.size(), min_len, min_classes, reason);
}

bool meets_policy(const std::string& pw, std::string& reason) {
    return meets_policy(pw.data(), pw.size(), 8, 2, reason);
}

int strength_score(const std::string& pw) {
    if (pw.empty()) return 0;
    bool lower = false, upper = false, digit = false, symbol = false, non_ascii = false;
    int kinds = classify(pw.data(), pw.size(), lower, upper, digit, symbol, non_ascii);
    size_t len = pw.size();

    int score = 0;
    if (non_ascii) {
        // 多字节字符直接视为高熵：长度 <8 给 2 档，≥8 给 3 档以上
        score = (len < 8) ? 2 : 3;
        if (kinds >= 3 || len >= 16) score = 4;
        return score;
    }
    if (len < 6) return 0;              // 过短，直接拒绝档
    if (len < 8) { score = (kinds >= 3) ? 1 : 0; return score; }
    if (len < 12) {
        score = (kinds >= 3) ? 2 : 1;
    } else if (len < 16) {
        score = (kinds >= 2) ? 3 : 2;
    } else {
        score = (kinds >= 3) ? 4 : 3;
    }
    return score;
}

} // namespace fe::password_policy
