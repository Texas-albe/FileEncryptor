// FEPK1 私钥全文加密
#pragma once

#include <string>

namespace fe_keyfile {

// 统一用途标识
constexpr const char* PURPOSE_RAGE   = "private-key";
constexpr const char* PURPOSE_WM     = "private-key";
constexpr const char* PURPOSE_KEYLIB = "private-key";

// 写受保护私钥文件
bool write_protected(const std::string& path, const std::string& plaintext,
                     const char* purpose, std::string& err,
                     bool force_argon2 = false);

// 读私钥文件
bool read_protected(const std::string& path, std::string& plaintext,
                    const char* purpose, bool& was_plain, std::string& err);

}
