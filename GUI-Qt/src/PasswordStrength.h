// 密码强度评估
#pragma once
#include <QString>

enum class StrengthLevel {
    Empty,
    Weak,
    Medium,
    Strong
};

struct StrengthResult {
    StrengthLevel level = StrengthLevel::Empty;
    QString label;
    QString colorHex;
    int entropyBits = 0;
    QString detail;
};

class PasswordStrength {
public:
    static StrengthResult evaluate(const QString& password);

    // 密码策略校验（与 CLI 默认 12/3 对齐）
    static const int kMinPasswordLength = 12;
    static bool meetsPolicy(const QString& password, QString& reason);
};
