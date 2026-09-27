#include "password_policy.hpp"
#include <cctype>

namespace fe::password_policy {

static int classify(const std::string& pw, bool& lower, bool& upper,
                    bool& digit, bool& symbol, bool& non_ascii) {
    lower = upper = digit = symbol = non_ascii = false;
    for (unsigned char c : pw) {
        if (c <= 0x7F) {
            if (std::islower(c))       lower = true;
            else if (std::isupper(c))  upper = true;
            else if (std::isdigit(c))  digit = true;
            else if (std::ispunct(c))  symbol = true;
        } else {
            non_ascii = true;  // 多字节字符（UTF-8 中文等）熵足够
        }
    }
    int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) +
                (digit ? 1 : 0) + (symbol ? 1 : 0);
    return kinds;
}

bool meets_policy(const std::string& pw, size_t min_len, int min_classes,
                  std::string& reason) {
    if (pw.size() < min_len) {
        reason = "Password too short (min " + std::to_string(min_len) +
                 " characters).";
        return false;
    }
    bool lower, upper, digit, symbol, non_ascii;
    int kinds = classify(pw, lower, upper, digit, symbol, non_ascii);
    if (non_ascii) return true;
    if (kinds >= min_classes || pw.size() >= 16) return true;
    reason = "Password too weak: use at least " + std::to_string(min_classes) +
             " character classes (lower/upper/digit/symbol) or length >= 16.";
    return false;
}

bool meets_policy(const std::string& pw, std::string& reason) {
    return meets_policy(pw, 8, 2, reason);
}

int strength_score(const std::string& pw) {
    if (pw.empty()) return 0;
    bool lower, upper, digit, symbol, non_ascii;
    int kinds = classify(pw, lower, upper, digit, symbol, non_ascii);
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
