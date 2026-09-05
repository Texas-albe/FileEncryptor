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
