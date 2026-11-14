# 依赖版本锁定

> 最后更新：2026-11-07
> 用途：记录第三方依赖的版本与安全状态，供审计与升级参考。

## 加密库

| 依赖 | 版本 | 来源 | 安全状态 |
|---|---|---|---|
| libsodium | 1.0.22 | `Third Party/libsodium/`（预编译静态库） | 最新稳定版（2024-01）；CVE-2025-69277 无直接调用面 |
| OpenSSL | 4.1.0 | `Third Party/openssl/`（静态 `libcrypto.a`，桌面端与 Android arm64） | SM4-GCM / X25519·X448 / ML-KEM-768 / ML-DSA-65（PQC）经 provider / EVP_PKEY 调用；Android 端 API 26、arm64-v8a 静态接入 |

> 注：Android 端 `libvdisk.so` 静态链接 libsodium / zstd / yaml-cpp / OpenSSL。`WITH_OPENSSL=ON` 时直接使用真实实现；仅当该开关关闭时才回退到降级桩（`asym_crypto_android.cpp`、`watermark_android.cpp`）。Android 版 `libcrypto.a` 由 `python scripts/build_openssl_android.py` 产出到 `out/android/openssl-prefix`，不依赖桌面端产物。

## 其他库

| 依赖 | 版本 | 来源 | 安全状态 |
|---|---|---|---|
| yaml-cpp | 0.9.0 | `Third Party/yaml-cpp/` | 无已知 CVE |
| zstd | 1.5.7 | 系统静态库（`libzstd-dev`，如 `/usr/lib/x86_64-linux-gnu/libzstd.a`）优先，回退 `Third Party/zstd/` 源码编译 | 无已知 CVE |
| .NET / .NET MAUI | net10.0-android | 应用框架与运行时（GUI-Android） | MIT；随框架补丁 |

## 升级策略

- libsodium：跟随上游稳定版，大版本升级需验证 ABI 兼容。
- OpenSSL：已从 **4.1.0-beta1 升到 4.1.0 稳定版**（2026-10-23 发布）。SM4-GCM 必须走 `EVP_CIPHER_fetch`（4.x 已移除 `EVP_sm4_gcm()` 便捷函数）；升级后须重验 **SM4-GCM、X25519/X448、ML-KEM-768、ML-DSA-65** 四条路径（含 PQC 封装/解裹与 RSA/ML-DSA 水印签名）。
- 安全公告监控：定期检查 libsodium / OpenSSL / yaml-cpp / zstd 的 CVE 公告。

## 验证方式

```bash
# libsodium 版本
grep SODIUM_VERSION_STRING "Third Party/libsodium/include/sodium/version.h"

# OpenSSL 版本（opensslv.h 由 Configure 模板生成；源树以 VERSION.dat 为准）
grep -E '^(MAJOR|MINOR|PATCH)=' "Third Party/openssl/VERSION.dat"
```
