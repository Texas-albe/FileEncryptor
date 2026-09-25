// PasswordStrength 实现
#include "PasswordStrength.h"
#include <cmath>

static int charsetSize(const QString& pw, bool& lower, bool& upper, bool& digit, bool& symbol) {
    int size = 0;
    lower = upper = digit = symbol = false;
    for (const QChar& ch : pw) {
        const ushort u = ch.unicode();
        if (u >= 'a' && u <= 'z') { if (!lower) { lower = true; size += 26; } }
        else if (u >= 'A' && u <= 'Z') { if (!upper) { upper = true; size += 26; } }
        else if (u >= '0' && u <= '9') { if (!digit) { digit = true; size += 10; } }
        else { if (!symbol) { symbol = true; size += 33; } }  // ASCII 可见符号约 33 个
    }
    return size;
}

StrengthResult PasswordStrength::evaluate(const QString& pw) {
    StrengthResult r;
    if (pw.isEmpty()) {
        r.level = StrengthLevel::Empty;
        r.label = QStringLiteral("未输入");
        r.colorHex = QStringLiteral("#888888");
        return r;
    }

    bool lower, upper, digit, symbol;
    const int cs = charsetSize(pw, lower, upper, digit, symbol);
    const int len = pw.length();
    const int kinds = (lower?1:0) + (upper?1:0) + (digit?1:0) + (symbol?1:0);

    // 香农熵：entropy = len * log2(charset)
    int entropy = 0;
    if (cs > 0) {
        entropy = static_cast<int>(std::round(len * std::log2(static_cast<double>(cs))));
    }
    r.entropyBits = entropy;

    // 分级（综合熵 + 长度 + 种类）：
    //   弱：长度<6（不满足子进程最低要求）或熵<28
    //   中：长度6-9 且 熵28-47
    //   强：长度>=10 且 熵>=48，或长度>=12
    if (len < 6 || entropy < 28) {
        r.level = StrengthLevel::Weak;
        r.label = QStringLiteral("弱");
        r.colorHex = QStringLiteral("#D32F2F");  // 红
    } else if (len < 10 && entropy < 48) {
        r.level = StrengthLevel::Medium;
        r.label = QStringLiteral("中");
        r.colorHex = QStringLiteral("#F9A825");  // 黄/橙
    } else {
        r.level = StrengthLevel::Strong;
        r.label = QStringLiteral("强");
        r.colorHex = QStringLiteral("#2E7D32");  // 绿
    }

    // 详细说明
    QString kindStr;
    if (lower) kindStr += QStringLiteral("小写 ");
    if (upper) kindStr += QStringLiteral("大写 ");
    if (digit) kindStr += QStringLiteral("数字 ");
    if (symbol) kindStr += QStringLiteral("符号 ");
    if (kindStr.isEmpty()) kindStr = QStringLiteral("无");
    r.detail = QStringLiteral("长度 %1 | 种类 %2 | 熵 ~%3 bits | %4")
                   .arg(len).arg(kinds).arg(entropy).arg(kindStr.trimmed());

    return r;
}

bool PasswordStrength::meetsPolicy(const QString& password, QString& reason) {
    reason.clear();
    const int len = password.length();
    if (len < kMinPasswordLength) {
        reason = QStringLiteral("口令过短（至少 %1 个字符）。").arg(kMinPasswordLength);
        return false;
    }

    bool lower = false, upper = false, digit = false, symbol = false, non_ascii = false;
    for (const QChar& ch : password) {
        const ushort u = ch.unicode();
        if (u <= 0x7F) {
            if (u >= 'a' && u <= 'z') lower = true;
            else if (u >= 'A' && u <= 'Z') upper = true;
            else if (u >= '0' && u <= '9') digit = true;
            else symbol = true;   // ASCII 可见符号
        } else {
            non_ascii = true;     // 多字节字符（如 UTF-8 中文）熵足够
        }
    }
    if (non_ascii) return true;   // 非 ASCII 口令直接放行

    const int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) +
                      (digit ? 1 : 0) + (symbol ? 1 : 0);
    if (kinds >= 2 || len >= 16) return true;

    reason = QStringLiteral("口令过弱：请至少含 2 类字符（小写/大写/数字/符号），或长度 >= 16。");
    return false;
}
