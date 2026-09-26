# 依赖版本锁定

> 最后更新：2026-09-26
> 用途：记录第三方依赖的版本与安全状态，供审计与升级参考。

## 加密库

| 依赖 | 版本 | 来源 | 安全状态 |
|---|---|---|---|
| libsodium | 1.0.22 | `third_party/libsodium/`（预编译静态库） | 最新稳定版（2024-01）；CVE-2025-69277 无直接调用面 |
| age crate (fe_age) | 0.12.1 | `E:/rage` workspace（Rust） | ≥0.11.1，CVE-2024-56327 已修复 |

## 其他库

| 依赖 | 版本 | 来源 | 安全状态 |
|---|---|---|---|
| yaml-cpp | 0.9.0 | `third_party/yaml-cpp/` | 无已知 CVE |
| zstd | 1.5.7 | `third_party/zstd/` | 无已知 CVE |

## 升级策略

- libsodium：跟随上游稳定版，大版本升级需验证 ABI 兼容。
- age crate：通过 `E:/rage` workspace 引用，升级时同步更新 Cargo.lock。
- 安全公告监控：定期检查 libsodium / age / yaml-cpp / zstd 的 CVE 公告。

## 验证方式

```bash
# libsodium 版本
grep SODIUM_VERSION_STRING third_party/libsodium/include/sodium/version.h

# age crate 版本
grep '^version' E:/rage/age-ffi/Cargo.toml
```
