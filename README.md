# FileEncryptor

一个基于 [libsodium](https://libsodium.gitbook.io/) 的命令行文件加密 / 解密工具，支持分块加密、断点续传、批量并行处理与跨平台 UTF-8 路径。当前版本 **v1.3.0**（磁盘文件格式版本 **v3**，向后兼容 v1 / v2）。

---

## 特性

- **强加密（双算法，XChaCha20 为默认）**：
  - `XChaCha20-Poly1305`（IETF，默认模式）—— 25 字节 nonce，无硬件依赖，全平台可用。
  - `AEGIS-256` —— 32 字节密钥 / 32 字节 nonce / 32 字节 tag 的 AEAD，软件与硬件路径均可用，且在支持 AES-NI 的 x86 CPU 上性能极高（需 AES-NI，详见「已知限制」）。
  - 每块独立认证（MAC）。旧版 `AES-256-GCM` 不再用于**新加密**，仅保留用于**解密旧版 v1/v2 文件**。
- **强健的密钥派生**：`Argon2id`（内存硬哈希）从口令派生密钥，参数（迭代次数 / 内存）持久化在文件头、可按需增强。
- **分块处理**：以 1 MiB 为块流式加解密，内存占用恒定，支持超大文件（> 4 GiB）。
- **断点续传 + 进度防篡改**：中断后可复用 `.progress` 进度文件续传；进度文件现在带 **HMAC** 认证，伪造 / 损坏的 `.progress` 会被检测并安全从头重写，无法劫持续传、跳过 MAC 或注入数据。
- **块 nonce 防碰撞**：每块 nonce 由 `sodium_increment` 在文件级随机 `iv` 上逐块自增生成，彻底消除旧 `iv XOR 块索引` 方案的理论碰撞风险。
- **明文完整性校验**：加密前对明文计算 **Blake2b** 哈希并写入 v3 文件头，解密后重新计算并比对，可验证整个明文的完整性与来源真实性。
- **加密后自检**：`encrypt_file` 成功后立即用同一口令解密验证（尺寸 + Blake2b 哈希），确保产物可恢复；自检失败则删除产物并报错。
- **批量 & 并行**：`-be` / `-bd` 递归处理目录，可指定线程数 `-j`。
- **跨平台路径**：Windows / POSIX 统一走 UTF-8（含非 ASCII 文件名）。
- **安全加固**：跨进程输出锁、路径穿越防御、符号链接 / 重解析点防护、解密原子落盘（先写 `.part` 再重命名）。

---

## 安全模型

| 维度 | 措施 |
| --- | --- |
| 机密性 | `XChaCha20-Poly1305`（默认）或 `AEGIS-256`；密钥由 Argon2id（≥ 4 轮 / 128 MiB）派生；旧 `AES-256-GCM` 仅用于解密 v1/v2 遗产文件 |
| 完整性 / 认证（块级） | 每块 AEAD-MAC；`mode`、`version`、文件大小等元数据纳入 AAD，防篡改 |
| 完整性 / 认证（文件级） | 明文 **Blake2b** 哈希写入 v3 头 `plaintext_hash`，解密后重算比对，端到端验证整个明文 |
| 抗降级 | `mode` 与 `version` 均在 AAD 内认证；新加密仅 XChaCha20 / AEGIS-256 两种强算法，无弱算法分支，无法被降级 |
| 抗重放 / nonce 复用 | 每文件随机 `salt` + 32 字节 `iv`；每块 `nonce = sodium_increment(iv)` 唯一自增，无 XOR、无碰撞可能 |
| 续传防劫持 | `.progress` 进度文件携带 **HMAC**（HMAC-SHA512/256）；伪造 / 损坏的进度无法通过认证，必然触发安全重写，无法跳过 MAC 或注入块 |
| 加密即可恢复 | 加密成功后立即解密自检（尺寸 + Blake2b），自检不过则删除产物，保证落地产物一定可解密 |
| 密钥内存 | 派生后 `sodium_mlock` 锁定；输入 / 结束时 `sodium_memzero` 清零 |
| 写入安全 | 跨进程锁（`<out>.lock`）、符号链接 / 重解析点拒绝、`.part` 半成品 `chmod 0600`（POSIX）后原子重命名 |
| 路径安全 | 对所有写出路径做组件级 `..` 穿越检查 |

> **安全提示**：本工具保护静态存储中的文件机密性与完整性，但不提供机密性以外的来源认证（除 Blake2b 明文完整性外）。请使用强口令，并妥善保存口令——口令丢失即无法恢复数据。

---

## 命令行用法

```
FileEncryptor [-e|-d|-be|-bd] <输入路径> [-o <输出目录>] [-de] [-m xchacha20|aegis256] [-y] [-j <线程数>]
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
| `-m <mode>` | 加密算法：`xchacha20`（默认）或 `aegis256` |
| `-y` / `--force` | 不询问，直接覆盖已存在的输出文件 |
| `-j <num>` | 并行线程数（默认：CPU 核心数） |

### 示例

```bat
REM 加密单个文件（口令交互输入两次，默认 XChaCha20）
FileEncryptor.exe -e secret.docx

REM 加密并指定输出目录、加密后删除源文件
FileEncryptor.exe -e secret.docx -o D:\vault -de

REM 使用 AEGIS-256 算法加密（需 AES-NI；不支持时自动回退 / 提示）
FileEncryptor.exe -e big.iso -m aegis256

REM 显式使用默认 XChaCha20
FileEncryptor.exe -e big.iso -m xchacha20

REM 解密单个文件（自动识别 v1/v2/v3 格式）
FileEncryptor.exe -d secret.docx.ptd

REM 批量加密整个目录，4 线程并行
FileEncryptor.exe -be D:\Photos -o D:\Photos.enc -j 4

REM 批量解密，强制覆盖不询问
FileEncryptor.exe -bd D:\Photos.enc -o D:\Photos.restored -y
```

---

## 文件格式与产物

- **加密输出**：`<原名>.ptd`（解密输入须为 `.ptd`）。
- **格式版本**：文件头 `VERSION` 字段。`v3`（当前）在 v2 基础上将 `iv` 缓冲扩到 32 字节（容纳 AEGIS-256 的 32 字节 nonce）并新增 32 字节 `plaintext_hash`，固定头区共 **109 字节**（93 字节 `FileHeaderV3` 结构 + 16 字节分块元数据）；`v1` / `v2` 文件可正常解密（向后兼容，旧文件使用 `AES-256-GCM` 解密路径）。
- **续传进度**：`<输出>.progress`，正常完成后自动删除。现在携带 **HMAC 认证**（magic + version + 已处理块数 + 已处理字节数 + 32 字节 HMAC，共 56 字节），伪造 / 损坏的进度无法绕过认证。
- **解密中间文件**：`<输出>.part`（全部校验通过后才原子重命名为最终输出，避免残留明文）。
- **跨进程锁**：`<输出>.lock`（原子创建 + PID，失效锁自动回收）。
- **v3 文件头结构（93 字节）**：`magic[4]` + `version` + `mode` + `opslimit(uint16)` + `memlimit_kb(uint32)` + `salt[16]` + `iv_len` + `iv[32]` + `plaintext_hash[32]`。其后再紧跟 16 字节分块元数据：`chunk_size(uint32)` + `total_chunks(uint32)` + `orig_size(uint64)`，故文件固定头区共 **109 字节**。

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
- **AEGIS-256 需要 CPU 支持 AES-NI（x86）**：在不支持的平台上 `aegis256_supported()` 返回 false，单文件模式会提示并回退到 XChaCha20，批量模式自动回退，不会用不支持的算法加密。`XChaCha20` 无硬件依赖，始终可用。
- `-j` 异常值会被忽略并回退到默认线程数（不会崩溃）。
- 跨进程锁为「按输出文件」粒度，批量并行各线程处理不同文件，设计上无进程内争用；跨进程仅存在「非原子失效锁回收」的极低危 TOCTOU（不损坏数据）。
- 口令丢失无法恢复数据；工具不托管口令。
- v3 为破坏性格式升级，但**向后兼容 v1/v2**（旧文件仍可直接解密，无需重加密）。

---

## 许可证

本工具使用 GPL v3 进行许可。详见 `LICENSE` 文件。

---

# FileEncryptor

A command-line file encryption / decryption tool built on [libsodium](https://libsodium.gitbook.io/). It features chunked encryption, resumable transfers, batch parallel processing, and cross-platform UTF-8 paths. Current version **v1.3.0** (on-disk file format version **v3**, backward compatible with v1 / v2).

---

## Features

- **Strong encryption (two algorithms, XChaCha20 default)**:
  - `XChaCha20-Poly1305` (IETF, default mode) — 24-byte nonce, no hardware dependency, available everywhere.
  - `AEGIS-256` — AEAD with 32-byte key / 32-byte nonce / 32-byte tag; very fast on AES-NI-capable x86 CPUs (requires AES-NI, see Known Limitations).
  - Each chunk independently authenticated (MAC). The legacy `AES-256-GCM` is **no longer used for new encryption**; it is retained only to **decrypt legacy v1/v2 files**.
- **Robust key derivation**: `Argon2id` (memory-hard) derives the key from the passphrase; parameters (iterations / memory) are persisted in the file header and can be strengthened over time.
- **Chunked processing**: streams at 1 MiB per chunk with constant memory footprint; supports very large files (> 4 GiB).
- **Resumable + tamper-proof progress**: interrupted jobs resume via the `.progress` file, which is now **HMAC-authenticated**; a forged or corrupt `.progress` is detected and safely restarted from scratch — resume hijacking, MAC-skipping, and chunk injection are prevented.
- **Collision-free chunk nonces**: each chunk nonce is produced by `sodium_increment` over a per-file random `iv`, eliminating the theoretical reuse risk of the old `iv XOR chunk index` scheme.
- **Plaintext integrity**: a **Blake2b** hash of the plaintext is computed before encryption and stored in the v3 header; after decryption it is recomputed and compared, end-to-end verifying the whole plaintext.
- **Encrypt-then-verify**: after `encrypt_file` succeeds, the output is immediately decrypted with the same passphrase (size + Blake2b check); on mismatch the output is deleted and encryption reports failure, guaranteeing the artifact is recoverable.
- **Batch & parallel**: `-be` / `-bd` recursively process directories with configurable thread count (`-j`).
- **Cross-platform paths**: unified UTF-8 on Windows / POSIX (including non-ASCII filenames).
- **Security hardening**: cross-process output lock, path-traversal defense, symlink / reparse-point protection, atomic decrypt landing (write `.part` first, then rename).

---

## Security Model

| Dimension | Measure |
| --- | --- |
| Confidentiality | `XChaCha20-Poly1305` (default) or `AEGIS-256`; key derived by Argon2id (≥ 4 passes / 128 MiB); legacy `AES-256-GCM` only for decrypting v1/v2 files |
| Integrity / authenticity (chunk) | Per-chunk AEAD-MAC; `mode`, `version`, file size, etc. included in AAD to prevent tampering |
| Integrity / authenticity (file) | Plaintext **Blake2b** hash stored in the v3 `plaintext_hash` field; recomputed and compared after decryption, end-to-end |
| Anti-downgrade | `mode`/`version` authenticated inside AAD; new encryption uses only XChaCha20 / AEGIS-256 strong algorithms, no weak branch, cannot be downgraded |
| Anti-replay / nonce reuse | Per-file random `salt` + 32-byte `iv`; `nonce = sodium_increment(iv)` per chunk, unique, no XOR, no collision |
| Resume hijacking | `.progress` carries an **HMAC** (HMAC-SHA512/256); forged / corrupt progress fails authentication and triggers a safe rewrite — cannot skip MAC or inject chunks |
| Encrypt = recoverable | After encryption, immediate decrypt self-check (size + Blake2b); failure deletes the artifact, ensuring the output is always decryptable |
| Key memory | `sodium_mlock` after derivation; `sodium_memzero` on input / teardown |
| Write safety | Cross-process lock (`<out>.lock`), symlink / reparse-point rejection, `.part` intermediate `chmod 0600` (POSIX) then atomic rename |
| Path safety | Component-level `..` traversal check on all output paths |

> **Security note**: this tool protects the confidentiality and integrity of data at rest (including whole-plaintext integrity via Blake2b), but does not provide provenance authentication beyond that. Use a strong passphrase and keep it safe — losing the passphrase means the data is unrecoverable.

---

## Command-Line Usage

```
FileEncryptor [-e|-d|-be|-bd] <input path> [-o <output dir>] [-de] [-m xchacha20|aegis256] [-y] [-j <threads>]
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
| `-m <mode>` | Encryption algorithm: `xchacha20` (default) or `aegis256` |
| `-y` / `--force` | Overwrite existing output files without prompting |
| `-j <num>` | Number of parallel threads (default: CPU core count) |

### Examples

```bat
REM Encrypt a single file (passphrase entered twice interactively, XChaCha20 by default)
FileEncryptor.exe -e secret.docx

REM Encrypt to a target directory and delete the source afterwards
FileEncryptor.exe -e secret.docx -o D:\vault -de

REM Encrypt with AEGIS-256 (requires AES-NI; auto-fallback / prompt if unavailable)
FileEncryptor.exe -e big.iso -m aegis256

REM Explicitly use the default XChaCha20
FileEncryptor.exe -e big.iso -m xchacha20

REM Decrypt a single file (auto-detects v1/v2/v3)
FileEncryptor.exe -d secret.docx.ptd

REM Batch encrypt a whole directory, 4 threads
FileEncryptor.exe -be D:\Photos -o D:\Photos.enc -j 4

REM Batch decrypt, force overwrite without prompting
FileEncryptor.exe -bd D:\Photos.enc -o D:\Photos.restored -y
```

---

## File Format & Artifacts

- **Encrypted output**: `<original name>.ptd` (decryption input must be `.ptd`).
- **Format version**: the header `VERSION` field. `v3` (current) expands the `iv` buffer to 32 bytes (to hold AEGIS-256's 32-byte nonce) and adds a 32-byte `plaintext_hash` over the v2 layout; the fixed header region totals **109 bytes** (93-byte `FileHeaderV3` struct + 16-byte chunk metadata); `v1` / `v2` files decrypt normally (backward compatible; legacy files use the `AES-256-GCM` decrypt path).
- **Resume progress**: `<output>.progress`, removed automatically on success. Now carries **HMAC authentication** (magic + version + processed-chunks + processed-bytes + 32-byte HMAC, 56 bytes total); forged / corrupt progress cannot bypass authentication.
- **Decrypt intermediate**: `<output>.part` (renamed to the final output only after all chunks pass MAC — avoids leftover plaintext).
- **Cross-process lock**: `<output>.lock` (atomic create + PID; stale locks auto-reclaimed).
- **v3 header struct (93 bytes)**: `magic[4]` + `version` + `mode` + `opslimit(uint16)` + `memlimit_kb(uint32)` + `salt[16]` + `iv_len` + `iv[32]` + `plaintext_hash[32]`. It is immediately followed by a 16-byte chunk-metadata record: `chunk_size(uint32)` + `total_chunks(uint32)` + `orig_size(uint64)`, so the fixed on-disk header region is **109 bytes**.

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
- **AEGIS-256 requires CPU AES-NI (x86)**: on unsupported platforms `aegis256_supported()` returns false; single-file mode prompts and falls back to XChaCha20, batch mode auto-falls back, so it never encrypts with an unsupported algorithm. `XChaCha20` has no hardware dependency and is always available.
- An invalid `-j` value is ignored and falls back to the default thread count (no crash).
- The cross-process lock is per-output-file; batch parallelism processes different files per thread, so there is no intra-process contention. Cross-process only has a very-low-risk non-atomic stale-lock reclamation TOCTOU (does not corrupt data).
- Losing the passphrase makes data unrecoverable; the tool does not escrow passphrases.
- v3 is a breaking format bump but is **backward compatible with v1/v2** (old files decrypt directly, no re-encryption needed).

---

## License

This tool is licensed under GPL v3. See the `LICENSE` file for details.
