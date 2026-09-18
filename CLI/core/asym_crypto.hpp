#pragma once
#include <string>
#include <vector>
#include <cstddef>

// 非对称（混合）加密封装层：基于 rage/age 库。
//   - 随机文件密钥由 age 内部生成；
//   - 文件用该密钥以 ChaCha20-Poly1305 加密；
//   - 该文件密钥再以 X25519 公钥包装（非对称部分）。
// 因此“非对称算法加密了文件加密所用的对称密钥”，符合混合加密要求。
//
// 真实实现在定义了 FE_WITH_AGE 时链接 fe_age 静态库；否则所有函数安全降级，
// 返回明确错误（便于在无 rage 静态库的环境下仍编译出 CLI 本体）。
struct AsymOutcome {
    bool ok = false;
    std::string error;
};

// 生成 X25519 密钥对。pub = 收件人公钥("age1...")，priv = 身份私钥("AGE-SECRET-KEY-...")。
// priv 为敏感字符串，调用方取得后应在不再需要时清零。
AsymOutcome fe_generate_keypair(std::string& pub, std::string& priv);

// 用一组收件人公钥加密 in_path -> out_path（输出标准 .age 文件）。
AsymOutcome fe_asym_encrypt(const std::vector<std::string>& recipients,
                            const std::string& in_path,
                            const std::string& out_path);

// 用身份私钥解密 in_path -> out_path。identity 为 AGE-SECRET-KEY-...（敏感）。
AsymOutcome fe_asym_decrypt(const std::string& identity,
                            const std::string& in_path,
                            const std::string& out_path);

// 以下两个函数是纯本地计算（Bech32 编解码 + X25519 基点乘法 + Argon2id），
// **不依赖 fe_age 静态库**，因此无论是否定义 FE_WITH_AGE 都可用。

// 由身份私钥（"AGE-SECRET-KEY-..."）反推对应的收件人公钥（"age1..."）。
// 等价于 rage-keygen -y：私钥还在、公钥丢了时可以重新导出。
AsymOutcome fe_identity_to_recipient(const std::string& identity, std::string& pub);

// 由口令确定性派生 X25519 密钥对（Argon2id → X25519 私钥 → 公钥）。
//   salt：入参为空时函数内部生成 16 字节随机盐并回填；非空时按其值派生
//         （同口令 + 同盐 ⇒ 完全相同的密钥对，可跨机器复现）。
//   pub  = "age1..."，priv = "AGE-SECRET-KEY-..."（敏感，调用方负责清零）。
AsymOutcome fe_derive_keypair(const char* pw, size_t pw_len,
                              std::vector<unsigned char>& salt,
                              std::string& pub, std::string& priv);
