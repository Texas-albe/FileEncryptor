# 依赖版本锁定

> 最后更新：2026-09-26
> 用途：记录第三方依赖的版本与安全状态，供审计与升级参考。

## 加密库

| 依赖 | 版本 | 来源 | 安全状态 |
|---|---|---|---|
| libsodium | 1.0.22 | `third_party/libsodium/`（预编译静态库） | 最新稳定版（2024-01）；CVE-2025-69277 无直接调用面 |
| OpenSSL | 4.1.0-beta1 | `third_party/openssl/`（静态链接） | SM4-GCM 与 X25519/X448 经 provider / EVP_PKEY 调用 |

## 其他库

| 依赖 | 版本 | 来源 | 安全状态 |
|---|---|---|---|
| yaml-cpp | 0.9.0 | `third_party/yaml-cpp/` | 无已知 CVE |
| zstd | 1.5.7 | 系统静态库（`libzstd-dev`，如 `/usr/lib/x86_64-linux-gnu/libzstd.a`）优先，回退 `third_party/zstd/` 源码编译 | 无已知 CVE |

## 升级策略

- libsodium：跟随上游稳定版，大版本升级需验证 ABI 兼容。
- OpenSSL：SM4-GCM 必须走 `EVP_CIPHER_fetch`（4.x 已移除 `EVP_sm4_gcm()` 便捷函数）；升级需重验 SM4 与 X25519/X448 两条路径。
- 安全公告监控：定期检查 libsodium / OpenSSL / yaml-cpp / zstd 的 CVE 公告。

## 验证方式

```bash
# libsodium 版本
grep SODIUM_VERSION_STRING third_party/libsodium/include/sodium/version.h

# OpenSSL 版本
grep OPENSSL_VERSION_TEXT third_party/openssl/include/openssl/opensslv.h
```
