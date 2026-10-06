#include "PasswordStrength.h"
#include <QCoreApplication>
#include <cmath>

// 强度文案面向用户展示，随界面语言翻译
namespace {
QString ps(const char* s) {
    return QCoreApplication::translate("PasswordStrength", s);
}
}

static int charsetSize(const QString& pw, bool& lower, bool& upper, bool& digit, bool& symbol) {
    int size = 0;
    lower = upper = digit = symbol = false;
    for (const QChar& ch : pw) {
        const ushort u = ch.unicode();
        if (u >= 'a' && u <= 'z') { if (!lower) { lower = true; size += 26; } }
        else if (u >= 'A' && u <= 'Z') { if (!upper) { upper = true; size += 26; } }
        else if (u >= '0' && u <= '9') { if (!digit) { digit = true; size += 10; } }
        else { if (!symbol) { symbol = true; size += 33; } }
    }
    return size;
}

StrengthResult PasswordStrength::evaluate(const QString& pw) {
    StrengthResult r;
    if (pw.isEmpty()) {
        r.level = StrengthLevel::Empty;
        r.label = ps("未输入");
        r.colorHex = QStringLiteral("#888888");
        return r;
    }

    bool lower, upper, digit, symbol;
    const int cs = charsetSize(pw, lower, upper, digit, symbol);
    const int len = pw.length();
    const int kinds = (lower?1:0) + (upper?1:0) + (digit?1:0) + (symbol?1:0);

    // 香农熵计算
    int entropy = 0;
    if (cs > 0) {
        entropy = static_cast<int>(std::round(len * std::log2(static_cast<double>(cs))));
    }
    r.entropyBits = entropy;

    // 强度分级
    if (len < 6 || entropy < 28) {
        r.level = StrengthLevel::Weak;
        r.label = ps("弱");
        r.colorHex = QStringLiteral("#D32F2F");
    } else if (len < 10 && entropy < 48) {
        r.level = StrengthLevel::Medium;
        r.label = ps("中");
        r.colorHex = QStringLiteral("#F9A825");
    } else {
        r.level = StrengthLevel::Strong;
        r.label = ps("强");
        r.colorHex = QStringLiteral("#2E7D32");
    }

    // 详细说明
    QString kindStr;
    if (lower)  kindStr += ps("小写 ");
    if (upper)  kindStr += ps("大写 ");
    if (digit)  kindStr += ps("数字 ");
    if (symbol) kindStr += ps("符号 ");
    if (kindStr.isEmpty()) kindStr = ps("无");
    r.detail = ps("长度 %1 | 种类 %2 | 熵 ~%3 bits | %4")
                   .arg(len).arg(kinds).arg(entropy).arg(kindStr.trimmed());

    return r;
}

bool PasswordStrength::meetsPolicy(const QString& password, QString& reason) {
    reason.clear();
    const int len = password.length();
    if (len < kMinPasswordLength) {
        reason = ps("密码过短（至少 %1 个字符）。").arg(kMinPasswordLength);
        return false;
    }

    bool lower = false, upper = false, digit = false, symbol = false, non_ascii = false;
    for (const QChar& ch : password) {
        const ushort u = ch.unicode();
        if (u <= 0x7F) {
            if (u >= 'a' && u <= 'z') lower = true;
            else if (u >= 'A' && u <= 'Z') upper = true;
            else if (u >= '0' && u <= '9') digit = true;
            else symbol = true;
        } else {
            non_ascii = true;
        }
    }
    // 非 ASCII（CJK 等）只算一类字符：此前「含非 ASCII 即放行」会让
    // 「的的的的的的的的」这类重复汉字被判为合格，实际熵近乎为零。
    const int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) +
                      (digit ? 1 : 0) + (symbol ? 1 : 0) + (non_ascii ? 1 : 0);
    if (kinds >= 2 || len >= 16) {
        bool allSame = true;
        for (const QChar& ch : password) {
            if (ch != password.at(0)) { allSame = false; break; }
        }
        if (!allSame) return true;
        reason = ps("密码过弱：请不要使用重复字符。");
        return false;
    }

    reason = ps("密码过弱：请至少含 2 类字符（小写/大写/数字/符号），或长度 >= 16。");
    return false;
}
