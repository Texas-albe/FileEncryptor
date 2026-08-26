# FileEncryptor

跨平台（Windows / Linux / macOS）文件加密工具，基于 [libsodium](https://doc.libsodium.org/) 实现高强度、抗篡改、可续传的分块加密。

- 磁盘文件格式版本 **v3**（向后兼容 v1 / v2，旧文件可直接解密，无需重加密）。
- 程序版本 **1.5.0**。

---

## 功能特性

- **算法**
  - `XChaCha20-Poly1305`（默认，IETF 变体）—— 无需硬件加速，移动端 / 服务器通用。
  - `AEGIS-256` —— 在支持 **AES-NI** 的 CPU 上性能极高（32 字节 nonce / 32 字节 tag 的 AEAD）。
  - `AES-256-GCM` 仅用于**解密旧版 v1/v2 文件**，新加密不再使用。
- **密钥派生**：Argon2id（默认 `opslimit=4` / `memlimit=128 MiB`），参数随文件头持久化，未来可无损增强。
- **完整性保护**
  - 每文件 `salt` + `iv` 随机生成；每块 `nonce = sodium_increment(iv)` 逐块自增，杜绝 nonce 复用。
  - 明文 **Blake2b** 哈希写入文件头，解密后重新计算并比对，端到端验证完整性。
  - 进度文件 `.progress` 带 **HMAC-SHA512/256** 认证，防止续传劫持。
- **可续传加密 / 解密**：中断后重跑可从中断点继续（含算法模式一致性校验，断点损坏或模式不匹配则安全从头重写）。
  - *v1.4.1 修复*：此前 Windows 下进度文件（`.progress`）因 `std::rename` 在目标已存在时失败，导致仅第 1 块能记录进度、续传退化为从头重做；现改用 `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` 覆盖写，每个数据块都能正确更新进度。Linux 不受影响。
- **批量处理**：支持目录递归、多线程并行（并发数由 YAML `worker_threads` 配置）、源文件删除（`-de`）、强制覆盖（`-y`）、断点续传（重跑自动从 `.progress` 继续）。
- **断点续传（单文件 + 批量）**：单文件（`-e`/`-d`）与批量（`-be`/`-bd`）模式均默认自动续传。中断后重跑同一命令，若存在同名 `.progress` 即从中断点继续，无需额外开关；大文件（>25 MB）尤其受益。续传前先做模式/元数据一致性校验，损坏或模式不匹配则安全从头重写。
- **安全细节**：解密原子落盘（先写 `.part` 再重命名）、输出锁防并发写、路径穿越防御、符号链接 / 重解析点拒绝、密钥 `sodium_mlock` 锁定、POSIX 下半成品 `chmod 0600`。

---

## v1.5.0 运维与安全增强

> 设计原则（混合架构）：**所有运维类参数**（日志位置/级别、并发线程数、资源上限、路径安全策略、进度轮转）统一由 **YAML 配置文件** 提供，**CLI 不可覆盖**；CLI 仅保留动作与输入接口（密钥、密码、路径、模式等）。详见下文「YAML 配置」。

- **一.1 密钥文件 / 环境变量输入（非交互）**：除交互式口令外，新增 `-k <keyfile>` 从文件读取密钥材料，或用环境变量 `ENCRYPTOR_KEY` 传入。优先级：`-k` > `ENCRYPTOR_KEY` > 交互式输入（适用无人值守 / CI 场景）。
- **一.2 结构化 JSON 日志**：运行时可输出结构化日志（`{"ts","level","msg",["fields"]}`），日志文件路径与级别由 YAML `log_file` / `log_level` 控制；控制台进度条不受影响。
- **一.4（部分）资源与并发配置（YAML）**：`worker_threads`（并发线程数，0=自动）、`max_memory_bytes`（预留上限，暂未强制）、`io_buffer_size`（内部流式缓冲）。*注：超大文件分块 `--chunk-size` 因会改变磁盘格式版本（v3 头结构），本期未实现，分块大小仍固定 1 MiB。*
- **二.3（部分）进度文件轮转**：覆盖 `.progress` 前先备份为 `.progress.bak`（`progress_rotation`，默认开），降低写坏丢失断点的风险。
- **二.4 路径长度 / 白名单**：YAML `max_path_length`（UTF-8 字节上限）、`path_whitelist_enabled` + `path_whitelist`（启用后输入/输出必须位于白名单根目录之下），校验失败时拒绝处理并保留默认安全行为。
- **二.5 供应链签名（发布脚本）**：`scripts/sign-release.sh` 对发布产物生成 SHA256SUMS 并可用 GPG 签名；日志默认命名格式 `{YY-MM-DD_HHMMSS}.log`。
- **一.5 容器化与静态发布（发布脚本）**：`Dockerfile` 提供基于 Debian 的构建/运行镜像；`scripts/build-release.sh` 产出各平台静态二进制与零依赖 DEB/RPM。
- **CLI 调整**：`-j <线程数>` 已废弃（被忽略并打印警告），并发数改由 YAML `worker_threads` 配置；强制覆盖标志由 `-f` 改为 `-y` / `--force`。

---

## 依赖

- **C++17** 编译器（MSVC / g++ / Clang）。
- **libsodium >= 1.0.19**（AEGIS-256 需要；1.0.22 及以上推荐）。CMake 会在配置阶段校验版本，过低会给出明确报错。

---

## 构建

### Linux（生成自包含的 DEB / RPM）

默认**静态链接** libsodium，产出的安装包**无需在安装时再下载任何第三方库**。

```bash
# 1) 安装构建与打包工具（一次性）
sudo apt install cmake ninja-build pkg-config fakeroot rpm
#    libsodium 需 >= 1.0.19；推荐从源码安装到 /usr/local（会被 CMake 优先选中）：
sudo apt remove libsodium-dev            # 若系统存在旧的 apt 版，建议先移除
curl -sSL https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz | tar xz
cd libsodium-1.0.22 && ./configure && make -j && sudo make install
sudo ldconfig

# 2) 配置 + 构建（建议先清掉旧构建目录，避开历史同名目录残留）
rm -rf out/build/linux-release
cmake --preset linux-release
cmake --build --preset linux-release

# 3) 打包（同时产出 .deb 和 .rpm）
cd out/build/linux-release && cpack
# 产物：file-encryptor_1.4.7-1_amd64.deb 与 file-encryptor-1.4.7-1.x86_64.rpm
```

> 若系统中同时存在多个 libsodium（如 apt 旧版 + `/usr/local` 新版），可显式指定：
> `cmake -S . -B build -DSODIUM_ROOT=/usr/local ...`

最终用户安装：
```bash
sudo dpkg -i file-encryptor_1.5.0-1_amd64.deb
# 或
sudo rpm -ivh file-encryptor-1.5.0-1.x86_64.rpm
```

### Windows（预编译 libsodium + MSVC）

把官方预编译包（含 `static` 子目录的 MSVC 版）安装到 **`C:\Program Files\libsodium`**，
CMake 会自动按 `x64/Release/v143/static/` 找到静态库并完成静态链接（无需 DLL）：

```powershell
# 方式一：Visual Studio「打开文件夹」直接加载本工程的 CMakePresets，选 windows-release / windows-debug
# 方式二：命令行（需处于 VS 的 x64 开发者命令提示符 / Developer PowerShell 中）
cmake --preset windows-release
cmake --build --preset windows-release
# 产物：out\build\windows-release\bin\FileEncryptor.exe（已内嵌 libsodium，单文件可分发）
```

- 静态链接时 CMake 会自动把运行时库切换为 `/MT`（静态 CRT），并与 libsodium 的静态库保持一致，
  避免 `LNK2038` CRT 不匹配；同时定义 `SODIUM_STATIC`，避免 `__imp_` 符号找不到（`LNK2019`）。
- 也可用 vcpkg：`vcpkg install libsodium` 后启用 vcpkg toolchain，CMake 配置包会自动定位。

### 手动指定 libsodium（任意平台）

解压预编译 / 源码安装的 libsodium 后，设置环境变量或 CMake 变量：

```bash
export SODIUM_ROOT=/path/to/libsodium   # Linux / macOS
set   SODIUM_ROOT=C:\path\to\libsodium  # Windows
cmake -S . -B build -DSODIUM_ROOT=$SODIUM_ROOT ...
```

### 动态 / 静态链接切换

- 默认 `SODIUM_STATIC=ON`（静态链接，便于打包自包含）。
- 需要动态链接时：`cmake -S . -B build -DSODIUM_STATIC=OFF`。

---

## 发布与供应链签名

- **`Dockerfile`**：基于 Debian 的多阶段镜像，可在容器内完成构建与运行，便于 CI 复现。
- **`scripts/build-release.sh`**：一键产出各平台**静态二进制**与零依赖 `DEB`/`RPM`（沿用 CMakePresets + CPack）。
- **`scripts/sign-release.sh`**：对发布产物生成 `SHA256SUMS` 并可用 GPG 签名，便于下游校验完整性（Issue.md 二.5）。

---

## 用法（CLI）

```
FileEncryptor <动作> <输入路径...> [选项]

动作（单文件）：
  -e                加密单个文件（默认动作，也可省略）
  -d                解密单个文件（输入须为 .ptd）
  -be               批量加密目录/文件
  -bd               批量解密目录/文件
  -h / --help / -?  显示帮助

选项：
  <输入路径>         单文件：一个位置参数；批量：用 -i <目录> 指定（可多次）
  -o <dir>          输出目录（默认：输入同级目录）
  -i <dir>          批量输入目录（可多次，仅 -be/-bd 使用）
  -m <mode>         加密模式：xchacha20（默认）| aegis256
  -de               加密成功后删除源文件（仅加密）
  -y / --force      覆盖已存在的输出（不再询问）
  -k <keyfile>      从文件读取密钥材料（非交互；替代：ENCRYPTOR_KEY 环境变量）
  -j <n>            【已废弃，被忽略】并发线程数，改由 fileencryptor.yaml 的 worker_threads 配置

密钥来源优先级：-k 密钥文件 > ENCRYPTOR_KEY 环境变量 > 交互式输入（省略则交互式输入，不回显，须 ≥6 字符）。

续传：单文件（`-e`/`-d`）与批量（`-be`/`-bd`）模式均默认自动；中断后重跑同一命令，若存在同名 `.progress` 即从中断点继续，无需额外开关。
```

示例：

```bash
# 交互式输入口令，加密单个文件（默认 XChaCha20）
FileEncryptor secret.docx

# 用 AEGIS-256 批量加密目录（并发数写进 fileencryptor.yaml 的 worker_threads），成功后删除源
FileEncryptor -be ./docs -m aegis256 -de

# 用密钥文件非交互加密
FileEncryptor -e secret.docx -k ./key.bin -o ./out

# 用环境变量解密（与上方加密使用同一密钥材料）
set ENCRYPTOR_KEY=@raw-key-material
FileEncryptor -d secret.docx.ptd -o ./out

# 中断后续传解密（重跑即可，自动续传）
FileEncryptor -bd ./encrypted_dir -o ./decrypted
```

---

## YAML 配置（运维参数）

所有运维类参数**仅**由配置文件提供，CLI 不可覆盖（见上文设计原则）。复制 `fileencryptor.yaml.example` 为 `fileencryptor.yaml` 放到以下任一位置即生效（优先级从高到低）：

1. 环境变量 `FILEENCRYPTOR_CONFIG` 指向的路径；
2. 可执行文件所在目录；
3. 用户配置目录：Windows `%APPDATA%\FileEncryptor`；Linux `$XDG_CONFIG_HOME/fileencryptor` 或 `~/.config/fileencryptor`。

配置文件缺失时自动回退到默认 `Config`，不影响正常运行；解析错误不致命（回退默认并继续）。

完整参数（`fileencryptor.yaml.example` 含逐项注释）：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `log_file` | `""`（不写文件） | 结构化 JSON 日志文件路径；控制台进度条不受影响 |
| `log_level` | `2` | 0=ERROR 1=WARN 2=INFO 3=DEBUG |
| `worker_threads` | `0`（自动） | 批量处理并发线程数（0 = 取硬件并发数） |
| `max_memory_bytes` | `0`（不限） | 预留上限，暂未强制限制 |
| `io_buffer_size` | `1048576` | 内部流式缓冲字节（不影响磁盘分块格式） |
| `max_path_length` | `0`（不限） | 输入/输出路径 UTF-8 字节长度上限 |
| `path_whitelist_enabled` | `false` | 是否启用路径白名单 |
| `path_whitelist` | `[]` | 允许的输入/输出根目录（启用后必须位于其中之一之下） |
| `progress_rotation` | `true` | 覆盖 `.progress` 前先备份为 `.progress.bak` |

> 注：解析器为极简 YAML（顶层标量键 + 单层 `- item` 序列），请勿使用嵌套结构或复杂语法。

---

## 文件格式

- 加密产物扩展名 `.ptd`，固定文件头 **109 字节**（v3）：magic(`FENC`) + version + mode + Argon2 参数 + salt + iv + plaintext_hash + 分块元数据。
- 续传元数据写入同名 `.progress`（HMAC 认证）。
- 跨版本兼容：`decrypt_file` 按文件头 `version` 字段区分 v1 / v2 / v3 并相应解析。

---

## 许可证

本项目以 **GPLv3** 许可证发布，详见仓库 `LICENSE` 文件。
