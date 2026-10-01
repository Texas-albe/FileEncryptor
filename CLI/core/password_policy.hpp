#pragma once
// 统一口令策略：从 cli/main.cpp 的 static password_meets_policy 抽出，
// 补充强度评分，供 CLI 与 GUI（Qt/WinUI）两侧复用同一套判定与分级约定。
#include <cstddef>
#include <string>

namespace fe::password_policy {

// 强度分级（0-4）：0=不满足策略（拒绝） 1=弱 2=中 3=强 4=极强
// 评分依据：长度 + 字符类种类（小写/大写/数字/符号）+ 非 ASCII（多字节字符视为高熵）。
int strength_score(const std::string& pw);

// 与 CLI 既有判定语义完全一致：非 ASCII 直接通过；否则 字符类种类 >= min_classes 或长度 >= 16 即通过。 通过返回 true；失败时 reason 给出人类可读原因。
bool meets_policy(const std::string& pw, size_t min_len, int min_classes,
                  std::string& reason);

// 零拷贝重载：直接以 (指针, 长度) 判定，避免在调用点构造未清零的临时 std::string 副本
bool meets_policy(const char* pw, size_t len, size_t min_len, int min_classes,
                  std::string& reason);

// 便捷重载：默认策略 min_len=8, min_classes=2。
bool meets_policy(const std::string& pw, std::string& reason);

} // namespace fe::password_policy
