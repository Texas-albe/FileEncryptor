// PasswordStrength - 密码强度评估
// 综合：长度 + 字符种类（小写/大写/数字/符号）+ 香农熵 bits 估算
// 分级：弱 / 中 / 强（对应颜色与文案，供右侧密码框实时提示）
// 注意：此为前端即时提示，FileEncryptor 子进程对非交互密钥源仅校验长度>=6
//       （main.cpp L338-341），强度评估仅为 UX，不影响实际加密安全性。
#pragma once
#include <QString>

enum class StrengthLevel {
    Empty,   // 空（无密码）
    Weak,    // 弱
    Medium,  // 中
    Strong   // 强
};

struct StrengthResult {
    StrengthLevel level = StrengthLevel::Empty;
    QString label;       // "弱" / "中" / "强" / ""
    QString colorHex;     // 颜色（#RRGGBB），供样式表
    int entropyBits = 0;   // 熵 bits（供 tooltip）
    QString detail;        // 详细说明（tooltip）
};

class PasswordStrength {
public:
    static StrengthResult evaluate(const QString& password);

    // 口令强策略：GUI 路径在提交前校验，CLI 交互式加密同样套用。
    // 规则：最小长度 8；且至少包含 2 类字符（小写/大写/数字/符号），或长度 >= 16。
    // 非 ASCII（多字节）口令熵足够，直接放行。不合规时 reason 写入中文原因。
    static const int kMinPasswordLength = 8;
    static bool meetsPolicy(const QString& password, QString& reason);
};
