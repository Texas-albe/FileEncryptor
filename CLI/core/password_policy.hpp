#pragma once
// 密码策略
#include <cstddef>
#include <string>

namespace fe::password_policy {

// 0=不满足策略
// 依据
int strength_score(const std::string& pw);

// 非 ASCII 直接通
// 失败时 reason 给出可读
bool meets_policy(const std::string& pw, size_t min_len, int min_classes,
                  std::string& reason);

// 零拷贝重载
bool meets_policy(const char* pw, size_t len, size_t min_len, int min_classes,
                  std::string& reason);

// 便捷重载
bool meets_policy(const std::string& pw, std::string& reason);

} // namespace fe::password_policy
