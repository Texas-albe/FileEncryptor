# FileEncryptor

一个基于 [libsodium](https://libsodium.gitbook.io/) 的命令行文件加密 / 解密工具，支持分块加密、断点续传、批量并行处理与跨平台 UTF-8 路径。当前版本 **v1.2.0**（磁盘文件格式版本 **v2**，向后兼容 v1）。

---

## 特性

- **强加密**：`AES-256-GCM` 或 `XChaCha20-Poly1305` 两种 AEAD 算法，每块独立认证（MAC）。
- **强健的密钥派生**：`Argon2id`（内存硬哈希）从口令派生密钥，参数（迭代次数 / 内存）持久化在文件头、可按需增强。
- **分块处理**：以 1 MiB 为块流式加解密，内存占用恒定，支持超大文件（> 4 GiB）。
- **断点续传**：中断后可复用 `.progress` 进度文件续传；进度损坏时自动放弃并安全从头重写。
- **批量 & 并行**：`-be` / `-bd` 递归处理目录，可指定线程数 `-j`。
- **跨平台路径**：Windows / POSIX 统一走 UTF-8（含非 ASCII 文件名）。
- **安全加固**：跨进程输出锁、路径穿越防御、符号链接 / 重解析点防护、解密原子落盘（先写 `.part` 再重命名）。

---

## 安全模型

| 维度 | 措施 |
| --- | --- |
| 机密性 | AES-256-GCM / XChaCha20-Poly1305，密钥由 Argon2id（≥ 4 轮 / 128 MiB）派生 |
| 完整性 / 认证 | 每块 AEAD-MAC；`mode`、`version`、文件大小等元数据纳入 AAD，防篡改 |
| 抗降级 | 仅两种强算法、无弱算法分支，`mode`/`version` 在 AAD 内认证，无法被降级 |
| 抗重放 | 每文件随机 `salt` + `iv`，`nonce = iv XOR 块索引` 唯一；伪造 / 损坏的 `.progress` 无法跳过 MAC |
| 密钥内存 | 派生后 `sodium_mlock` 锁定；输入 / 结束时 `sodium_memzero` 清零 |
| 写入安全 | 跨进程锁（`<out>.lock`）、符号链接 / 重解析点拒绝、`.part` 半成品 `chmod 0600`（POSIX）后原子重命名 |
| 路径安全 | 对所有写出路径做组件级 `..` 穿越检查 |

> **安全提示**：本工具保护静态存储中的文件机密性，但不提供机密性以外的来源认证。请使用强口令，并妥善保存口令——口令丢失即无法恢复数据。

---

## 命令行用法

```
FileEncryptor [-e|-d|-be|-bd] <输入路径> [-o <输出目录>] [-de] [-m aes|xchacha20] [-y] [-j <线程数>]
```

### 模式

| 选项 | 说明 |
| --- | --- |
| `-e` | 加密单个文件 |
| `-d` | 解密单个文件（输入须为 `.ptd`） |
| `-be` | 批量加密（目录 / 文件，递归） |
| `-bd` | 批量解密（目录 / 文件，递归） |
| `-h` / `--help` / `-?` | 显示帮助 |

### 选项

| 选项 | 说明 |
| --- | --- |
| `-o <dir>` | 输出目录（默认：源文件所在目录） |
| `-de` | 加密成功后删除源文件（仅加密模式有效） |
| `-m <mode>` | 加密算法：`aes`（默认）或 `xchacha20` |
| `-y` / `--force` | 不询问，直接覆盖已存在的输出文件 |
| `-j <num>` | 并行线程数（默认：CPU 核心数） |

### 示例

```bat
REM 加密单个文件（口令交互输入两次）
FileEncryptor.exe -e secret.docx

REM 加密并指定输出目录、加密后删除源文件
FileEncryptor.exe -e secret.docx -o D:\vault -de

REM 使用 XChaCha20 算法加密
FileEncryptor.exe -e big.iso -m xchacha20

REM 解密单个文件
FileEncryptor.exe -d secret.docx.ptd

REM 批量加密整个目录，4 线程并行
FileEncryptor.exe -be D:\Photos -o D:\Photos.enc -j 4

REM 批量解密，强制覆盖不询问
FileEncryptor.exe -bd D:\Photos.enc -o D:\Photos.restored -y
```

---

## 文件格式与产物

- **加密输出**：`<原名>.ptd`（解密输入须为 `.ptd`）。
- **续传进度**：`<输出>.progress`（24 字节：magic + version + chunks + bytes），正常完成后自动删除。
- **解密中间文件**：`<输出>.part`（全部校验通过后才原子重命名为最终输出，避免残留明文）。
- **跨进程锁**：`<输出>.lock`（原子创建 + PID，失效锁自动回收）。
- **格式版本**：文件头 `VERSION` 字段。`v2`（当前）新增 `opslimit` / `memlimit_kb` 字段；`v1` 文件可正常解密（向后兼容）。

---

## 构建

依赖：**C++20** 编译器 + **libsodium**（静态或动态均可）。

### 使用 MSVC（已含 `.vcxproj`）

用 Visual Studio 打开 `FileEncryptor.vcxproj`，配置好 libsodium 的 include / lib 路径后直接生成；或命令行：

```bat
cl /std:c++20 /O2 /MT /DSODIUM_STATIC /utf-8 ^
   main.cpp FileEncryptor.cpp ^
   /I <libsodium>\include ^
   /link /LIBPATH:<libsodium>\lib libsodium.lib
```

### 使用 MinGW-w64（g++）

```bat
g++ -std=c++20 -O2 -municode ^
    main.cpp FileEncryptor.cpp ^
    -I <libsodium>/include -L <libsodium>/lib -lsodium ^
    -o FileEncryptor.exe
```

> 运行时需将 `libsodium`（及 MinGW 运行时 `libstdc++-6`、`libgcc_s_seh-1`、`libwinpthread-1`）放在 exe 同目录或位于 `PATH`。

### POSIX（Linux / macOS）

```sh
g++ -std=c++20 -O2 main.cpp FileEncryptor.cpp -lsodium -o FileEncryptor
```

---

## 已知限制

- 解密输入必须是 `.ptd` 文件（单文件模式下强制校验）。
- `-j` 异常值会被忽略并回退到默认线程数（不会崩溃）。
- 跨进程锁为「按输出文件」粒度，批量并行各线程处理不同文件，设计上无进程内争用；跨进程仅存在「非原子失效锁回收」的极低危 TOCTOU（不损坏数据）。
- 口令丢失无法恢复数据；工具不托管口令。

---

## 许可证

本工具使用GPL v3进行许可。详见 `LICENSE` 文件。

---

# FileEncryptor

A command-line file encryption / decryption tool built on [libsodium](https://libsodium.gitbook.io/). It features chunked encryption, resumable transfers, batch parallel processing, and cross-platform UTF-8 paths. Current version **v1.2.0** (on-disk file format version **v2**, backward compatible with v1).

---

## Features

- **Strong encryption**: `AES-256-GCM` or `XChaCha20-Poly1305` AEAD algorithms, each chunk independently authenticated (MAC).
- **Robust key derivation**: `Argon2id` (memory-hard) derives the key from the passphrase; parameters (iterations / memory) are persisted in the file header and can be strengthened over time.
- **Chunked processing**: streams at 1 MiB per chunk with constant memory footprint; supports very large files (> 4 GiB).
- **Resumable transfers**: interrupted jobs resume via the `.progress` file; a corrupt progress file is detected and safely restarted from scratch.
- **Batch & parallel**: `-be` / `-bd` recursively process directories with configurable thread count (`-j`).
- **Cross-platform paths**: unified UTF-8 on Windows / POSIX (including non-ASCII filenames).
- **Security hardening**: cross-process output lock, path-traversal defense, symlink / reparse-point protection, atomic decrypt landing (write `.part` first, then rename).

---

## Security Model

| Dimension | Measure |
| --- | --- |
| Confidentiality | AES-256-GCM / XChaCha20-Poly1305; key derived by Argon2id (≥ 4 passes / 128 MiB) |
| Integrity / authenticity | Per-chunk AEAD-MAC; `mode`, `version`, file size, etc. included in AAD to prevent tampering |
| Anti-downgrade | Only two strong algorithms, no weak branches; `mode`/`version` authenticated inside AAD, cannot be downgraded |
| Anti-replay | Per-file random `salt` + `iv`; `nonce = iv XOR chunk index` is unique; forged / corrupt `.progress` cannot skip MAC |
| Key memory | `sodium_mlock` after derivation; `sodium_memzero` on input / teardown |
| Write safety | Cross-process lock (`<out>.lock`), symlink / reparse-point rejection, `.part` intermediate `chmod 0600` (POSIX) then atomic rename |
| Path safety | Component-level `..` traversal check on all output paths |

> **Security note**: this tool protects the confidentiality of data at rest. It does not provide provenance authentication beyond that. Use a strong passphrase and keep it safe — losing the passphrase means the data is unrecoverable.

---

## Command-Line Usage

```
FileEncryptor [-e|-d|-be|-bd] <input path> [-o <output dir>] [-de] [-m aes|xchacha20] [-y] [-j <threads>]
```

### Modes

| Option | Description |
| --- | --- |
| `-e` | Encrypt a single file |
| `-d` | Decrypt a single file (input must be `.ptd`) |
| `-be` | Batch encrypt (directory / file, recursive) |
| `-bd` | Batch decrypt (directory / file, recursive) |
| `-h` / `--help` / `-?` | Show help |

### Options

| Option | Description |
| --- | --- |
| `-o <dir>` | Output directory (default: the source file's directory) |
| `-de` | Delete the source file after successful encryption (encryption only) |
| `-m <mode>` | Encryption algorithm: `aes` (default) or `xchacha20` |
| `-y` / `--force` | Overwrite existing output files without prompting |
| `-j <num>` | Number of parallel threads (default: CPU core count) |

### Examples

```bat
REM Encrypt a single file (passphrase entered twice interactively)
FileEncryptor.exe -e secret.docx

REM Encrypt to a target directory and delete the source afterwards
FileEncryptor.exe -e secret.docx -o D:\vault -de

REM Encrypt with XChaCha20
FileEncryptor.exe -e big.iso -m xchacha20

REM Decrypt a single file
FileEncryptor.exe -d secret.docx.ptd

REM Batch encrypt a whole directory, 4 threads
FileEncryptor.exe -be D:\Photos -o D:\Photos.enc -j 4

REM Batch decrypt, force overwrite without prompting
FileEncryptor.exe -bd D:\Photos.enc -o D:\Photos.restored -y
```

---

## File Format & Artifacts

- **Encrypted output**: `<original name>.ptd` (decryption input must be `.ptd`).
- **Resume progress**: `<output>.progress` (24 bytes: magic + version + chunks + bytes), removed automatically on success.
- **Decrypt intermediate**: `<output>.part` (renamed to the final output only after all chunks pass MAC — avoids leftover plaintext).
- **Cross-process lock**: `<output>.lock` (atomic create + PID; stale locks auto-reclaimed).
- **Format version**: the header `VERSION` field. `v2` (current) adds `opslimit` / `memlimit_kb`; `v1` files decrypt normally (backward compatible).

---

## Building

Requirements: **C++20** compiler + **libsodium** (static or shared).

### MSVC (a `.vcxproj` is included)

Open `FileEncryptor.vcxproj` in Visual Studio, configure the libsodium include / lib paths, then build. Or from the command line:

```bat
cl /std:c++20 /O2 /MT /DSODIUM_STATIC /utf-8 ^
   main.cpp FileEncryptor.cpp ^
   /I <libsodium>\include ^
   /link /LIBPATH:<libsodium>\lib libsodium.lib
```

### MinGW-w64 (g++)

```bat
g++ -std=c++20 -O2 -municode ^
    main.cpp FileEncryptor.cpp ^
    -I <libsodium>/include -L <libsodium>/lib -lsodium ^
    -o FileEncryptor.exe
```

> At runtime, place `libsodium` (and, for MinGW, the runtimes `libstdc++-6`, `libgcc_s_seh-1`, `libwinpthread-1`) next to the exe or on `PATH`.

### POSIX (Linux / macOS)

```sh
g++ -std=c++20 -O2 main.cpp FileEncryptor.cpp -lsodium -o FileEncryptor
```

---

## Known Limitations

- Decryption input must be a `.ptd` file (enforced in single-file mode).
- An invalid `-j` value is ignored and falls back to the default thread count (no crash).
- The cross-process lock is per-output-file; batch parallelism processes different files per thread, so there is no intra-process contention. Cross-process only has a very-low-risk non-atomic stale-lock reclamation TOCTOU (does not corrupt data).
- Losing the passphrase makes data unrecoverable; the tool does not escrow passphrases.

---

## License

This tool is licensed under GPL v3.See the `LICENSE` file for details.
