# fe_age —— FileEncryptor 非对称加密 C-ABI 静态库

本目录是 [rage/age](https://github.com/str4d/rage) workspace 的一个成员 crate，提供 C-ABI 静态库 `fe_age`，供 FileEncryptor CLI 通过 C++ 调用实现非对称（混合）加密（X25519 公钥包装随机文件密钥，文件体用 ChaCha20-Poly1305）。

## 目录结构

```
age-ffi/
├── Cargo.toml          # fe_age crate（staticlib + cdylib），依赖上级 rage workspace（../，即 third_party/rage）
├── src/lib.rs          # C-ABI 封装：fe_age_encrypt_file / fe_age_decrypt_file / fe_age_generate_keypair ...
├── fe_age.h            # C 头文件（供 CLI 的 core/asym_crypto.cpp 包含）
├── cbindgen.toml       # 可选：用 cbindgen 重新生成 fe_age.h
├── build-win.ps1       # Windows（MSVC x64）构建 → lib/windows/fe_age.lib
├── build-linux.sh      # Linux（x86_64）构建 → lib/linux/libfe_age.a
└── lib/
    ├── windows/fe_age.lib
    └── linux/libfe_age.a
```

## 前置依赖

- Rust 工具链（cargo / rustc）。Windows 需 MSVC 目标 `x86_64-pc-windows-msvc`；Linux 需 `x86_64-unknown-linux-gnu`。
- 本 crate 通过 `Cargo.toml` 的 `age = { workspace = true }` 引用**上级目录的 rage workspace**（`third_party/rage/Cargo.toml` 已把 `age-ffi` 注册为 workspace 成员），故 `age` 及其 `age-core` 等依赖的 workspace 解析可正常解析。重编前请确认 `third_party/rage/` 下 rage 仓库源码完整。

## 构建

### Windows（MSVC x64）

```powershell
cd third_party/rage            # rage 仓库根（本 crate 是其 workspace 成员）
cd third_party/rage/age-ffi   # 或直接在此目录运行脚本
./build-win.ps1
# 产物：age-ffi/lib/windows/fe_age.lib
```

### Linux（x86_64）

```bash
cd third_party/rage
./build-linux.sh
# 产物：age-ffi/lib/linux/libfe_age.a
```

## 与 CLI 的集成

CLI 的 `CMakeLists.txt` 通过 `WITH_AGE`（默认 ON）查找本目录（默认根：`third_party/rage/age-ffi`）：

- `find_path(FE_AGE_INCLUDE_DIR NAMES fe_age.h HINTS ../age-ffi)` 定位头文件；
- `find_library(FE_AGE_LIBRARY ... HINTS ../age-ffi/lib/windows|linux)` 定位静态库；
- 二者均找到后定义 `FE_WITH_AGE` 并链接，同时补上 Rust staticlib 所需的系统库（Windows：bcrypt advapi32 userenv kernel32 ws2_32 ncrypt crypt32；Linux：pthread dl m）。

> 未找到 `fe_age` 静态库时 CMake 仅 WARNING，回退为不含非对称加密的版本（CLI 相关调用返回明确错误），不中断构建。
> 可用 `-DFE_AGE_DIR=<age-ffi 目录>` 显式指定位置。

## 对外 C 接口（fe_age.h）

- `fe_age_get_version()` —— 库版本字符串。
- `fe_age_generate_keypair(char** pub, char** priv)` —— 生成 X25519 身份（公钥 `age1...` / 私钥 `AGE-SECRET-KEY-1...`）。
- `fe_age_encrypt_file(const char* const* recipients, size_t n, const char* in, const char* out, char** err)` —— 多收件人加密。
- `fe_age_decrypt_file(const char* const* identities, size_t n, const char* in, const char* out, char** err)` —— 身份私钥解密。
- 所有函数均 `panic` 安全（`catch_unwind`），错误经 `err` 返回，调用方用 `fe_age_free_string` 释放。
