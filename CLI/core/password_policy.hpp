#pragma once
// 口令策略与强度评分，CLI 与两端 GUI 共用同一套判定
#include <cstddef>
#include <string>

namespace fe::password_policy {

// 0=不满足策略（拒绝）1=弱 2=中 3=强 4=极强。
// 依据：长度 + 字符类种类 + 非 ASCII（多字节字符视为高熵）。
int strength_score(const std::string& pw);

// 非 ASCII 直接通过；否则 字符类种类 >= min_classes 或长度 >= 16 即通过。
// 失败时 reason 给出可读原因。
bool meets_policy(const std::string& pw, size_t min_len, int min_classes,
                  std::string& reason);

// 零拷贝重载，避免调用点构造未清零的临时 std::string 副本
bool meets_policy(const char* pw, size_t len, size_t min_len, int min_classes,
                  std::string& reason);

// 便捷重载：min_len=8, min_classes=2
bool meets_policy(const std::string& pw, std::string& reason);

} // namespace fe::password_policy
