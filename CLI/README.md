# FileEncryptor CLI

跨平台（Windows / Linux / macOS）文件加密命令行工具，基于 [libsodium](https://doc.libsodium.org/) 实现高强度、抗篡改、可续传的分块加密。

- 磁盘文件格式版本 **v4**（向后兼容 v1 / v2 / v3，旧文件可直接解密，无需重加密）。
- 程序版本 **2.1.1**。

---

## 项目定位

本项目是 **FileEncryptor CLI 独立子项目**：编译产出 `FileEncryptorCLI(.exe)`，所有加密 / 解密 / 续传 / 路径安全 / YAML 配置逻辑全部静态链接进此可执行文件，**零外部运行时依赖**（libsodium、yaml-cpp 均静态打进二进制）。

配套的图形界面项目位于 `../GUI/` —— GUI 通过 `QProcess` 启动本 CLI 程序执行实际加解密，本身不链接任何加密代码。

| 项目 | 产物 | 依赖 | 关系 |
|---|---|---|---|
| **本项目**（CLI） | `FileEncryptorCLI(.exe)` | libsodium（静态）+ yaml-cpp（静态） | 完全独立，可单独发布 |
| `../GUI/`（GUI） | `FileEncryptorGUI(.exe)` | Qt6（静态） + 本 CLI 作为运行时子进程 | GUI 依赖 CLI；CLI 不依赖 GUI |

> 为什么 GUI 不直接链接本项目的 `core/` 代码：Qt6 官方只提供 `/MD`（动态 CRT）构建，libsodium 静态库是 `/MT`，两者 CRT 冲突（LNK2038）。正确架构是**进程级隔离**：GUI 用 `QProcess` 启动本 CLI exe。

---

## 功能特性

- **算法**
  - `XChaCha20-Poly1305`（默认，IETF 变体）—— 无需硬件加速，移动端 / 服务器通用。
  - `AEGIS-256` —— 在支持 **AES-NI** 的 CPU 上性能极高（32 字节 nonce / 32 字节 tag 的 AEAD）。
  - `AES-256-GCM` 仅用于**解密旧版 v1/v2 文件**，新加密不再使用。
  - `age`（非对称混合加密，`-m age`）—— 基于 [rage/age](https://github.com/str4d/rage) 的 X25519 + ChaCha20-Poly1305：每个文件用随机对称文件密钥加密，再用收件人 X25519 公钥包装该密钥，支持多收件人、无需共享口令。
- **密钥派生**：Argon2id（默认 `opslimit=4` / `memlimit=128 MB`），参数随文件头持久化，未来可无损增强。
- **完整性保护**
  - 每文件 `salt` + `iv` 随机生成；每块 `nonce = sodium_increment(iv)` 逐块自增，杜绝 nonce 复用。
  - 明文 **Blake2b** 哈希写入文件头，解密后重新计算并比对，端到端验证完整性。
  - 进度文件 `.progress` 带 **HMAC-SHA512/256** 认证，防止续传劫持。
- **可续传加密 / 解密**：中断后重跑可从中断点继续（含算法模式一致性校验，断点损坏或模式不匹配则安全从头重写）。
- **批量处理**：支持目录递归、多线程并行（并发数由 YAML `worker_threads` 配置）、源文件删除（`-de`）、强制覆盖（`-y`）、断点续传（重跑自动从 `.progress` 继续）。
- **防御文件头篡改（v4 头 HMAC 安全信封）**：v4 在 v3 头部基础上追加 32 字节 `header_hmac`，由"元数据认证密钥"（与主密钥域分离派生，标签 `FE_header_auth_v4`）对文件头前 77 字节（magic / version / mode / Argon2 参数 / salt / iv）做独立 HMAC-SHA512/256 认证；替换 salt / iv / mode 等头字段的篡改会在解密端被拒绝（仅通用错误，不泄露细节），文件头成为"安全信封"。
- **密钥内存安全（RAII SecureBuffer）**：所有口令 / 密钥 / 派生中间密钥统一由 `SecureBuffer` 持有（构造 `sodium_mlock` 锁页，析构自动 `sodium_memzero` + `sodium_munlock`）；禁止拷贝、允许移动（所有权转移避免双清零），任何正常返回或异常展开路径都不遗留明文密钥在堆内存。
- **续传进度文件双重保护（防重放）**：`.progress` 的 HMAC 额外绑定"源文件标识" `compute_progress_binding`（规范化路径 + 大小 + mtime），旧的有效 `.progress` 无法被重放到不同文件（路径 / mtime / size 任一变化即 HMAC 失配），合法中断续传则可正常恢复。
- **精确错误处理与信息泄露防护（`-v`）**：默认（非 `-v` 且非 DEBUG 日志）所有认证失败（密码错误 / 文件头被改 / 明文哈希不符 / 进度损坏）只返回通用错误；仅 `-v` 才在 stderr 暴露具体原因。
- **路径处理与资源耗尽防御**：`validate_io_paths` 先 `path_has_traversal` 拒绝任何 `..` 组件，再 `normalize_path_lexical`（解析 `.` / `..`、统一分隔符）做白名单前缀与长度比较；新增 YAML `max_open_files`（默认 256），批量 / 高并发时并发线程数上限 = `max_open_files / 3`。
- **输出文件名混淆（v1.7.0+ 默认开启）**：加密产出形如 `<16位十六进制>.<伪扩展名>.ptd`，原始文件名加密追加到密文末尾（`FENX` 信封），多语言文件名可正确还原；可通过 YAML `obfuscate_names: false` 关闭。

---

## 依赖

- **C++17** 编译器（MSVC / g++ / Clang）。
- **CMake ≥ 3.15**。
- **libsodium ≥ 1.0.19**（AEGIS-256 需要；1.0.22 及以上推荐）。CMake 会在配置阶段校验版本，过低会给出明确报错。
- **yaml-cpp**（YAML 配置解析，v1.7.2 起依赖）。Linux 安装 `libyaml-cpp-dev`；Windows 把 yaml-cpp 安装到 `C:\Program Files\yaml-cpp`（标准布局：头文件 `include/`、静态库 `lib/`、CMake 配置 `lib/cmake/`），或设置 `YAMLCPP_ROOT` 指向其根目录。

---

## 构建

### Linux（生成自包含的 DEB / RPM）

默认**静态链接** libsodium，产出的安装包**无需在安装时再下载任何第三方库**。

```bash
# 1) 安装构建与打包工具（一次性）
sudo apt install cmake ninja-build pkg-config fakeroot rpm libyaml-cpp-dev
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
# 产物：file-encryptor-cli_2.1.1-1_amd64.deb 与 file-encryptor-cli-2.1.1-1.x86_64.rpm
```

> 若系统中同时存在多个 libsodium（如 apt 旧版 + `/usr/local` 新版），可显式指定：
> `cmake -S . -B build -DSODIUM_ROOT=/usr/local ...`

最终用户安装：

```bash
sudo dpkg -i file-encryptor-cli_2.1.1-1_amd64.deb
# 或
sudo rpm -ivh file-encryptor-cli-2.1.1-1.x86_64.rpm
```

### Windows（预编译 libsodium + MSVC）

把官方预编译包（含 `static` 子目录的 MSVC 版）安装到 **`C:\Program Files\libsodium`**，
CMake 会自动按 `x64/Release/v143/static/` 找到静态库并完成静态链接（无需 DLL）：

```powershell
# 方式一：Visual Studio「打开文件夹」直接加载本工程的 CMakePresets，选 windows-vs2026-release / windows-vs2026-debug
# 方式二：命令行（需处于 VS 的 x64 开发者命令提示符 / Developer PowerShell 中）
cmake --preset windows-vs2026-release
cmake --build --preset windows-vs2026-release --config Release
# 产物：out\build\windows-vs2026-release\bin\Release\FileEncryptorCLI.exe
#     （已内嵌 libsodium + yaml-cpp，单文件可分发）
```

- 静态链接时 CMake 会自动把运行时库切换为 `/MT`（静态 CRT），并与 libsodium 的静态库保持一致，
  避免 `LNK2038` CRT 不匹配；同时定义 `SODIUM_STATIC`，避免 `__imp_` 符号找不到（`LNK2019`）。
- 也可用 vcpkg：`vcpkg install libsodium` 后启用 vcpkg toolchain，CMake 配置包会自动定位。

### macOS

```bash
brew install libsodium yaml-cpp cmake ninja
cmake --preset macos-release
cmake --build --preset macos-release
# 产物：out/build/macos-release/bin/FileEncryptorCLI
```

---

## 用法

```
FileEncryptorCLI <动作> <输入路径...> [选项]

动作：
  文件加解密：
    -e                加密单个文件（默认动作，也可省略）
    -d                解密单个文件（输入须为 .ptd）
    -be               批量加密目录/文件
    -bd               批量解密目录/文件
    -h / --help / -?  显示帮助
  密钥管理（rage/age）：
    -g                随机生成 X25519（rage）密钥对（公钥→stdout，私钥→<dir>/rage_private.txt）
    -G                由口令确定性派生 X25519 密钥对（Argon2id），输出同 -g，另写 <dir>/rage_derive_salt.txt
    -Y                由私钥文件（-k）反推并打印对应公钥（等价 rage-keygen -y）
    --salt <hex|file> -G 使用的盐（16 字节；省略则随机）

选项：
  <输入路径>         单文件：一个位置参数；批量：用 -i <目录> 指定（可多次）
  -o <dir>          输出目录（默认：输入同级目录）
  -i <dir>          批量输入目录（可多次，仅 -be/-bd 使用）
  -m <mode>         加密模式：xchacha20（默认）| aegis256 | rage（非对称混合；age 为兼容别名）
  -r <pub|file>     非对称加密（rage）的收件人公钥：可直接给 age1... 公钥字符串，
                    或给公钥文件（每行一个，支持 # 注释 / 空行 / publickey: 前缀）
  --key-stdin       从 stdin 读取密码直到 EOF（二进制安全，仅对称模式）；GUI 对称模式默认走此通道
  -de               加密成功后删除源文件（仅加密）
  -y / --force      覆盖已存在的输出（不再询问）
  -k <keyfile>      从文件读取密钥材料（非交互；替代：ENCRYPTOR_KEY 环境变量）；
                    -m rage 解密时该文件必须是身份私钥文件（AGE-SECRET-KEY-...）
  -v / --verbose    显示认证失败的详细原因（默认仅返回通用错误，防信息泄露）

密钥来源优先级（对称模式）：-k 密钥文件 > --key-stdin（stdin 管道） > ENCRYPTOR_KEY 环境变量 > 交互式输入（须 ≥6 字符）。
非对称模式（rage）：加密用 -r 收件人公钥（公钥字符串或公钥文件）；解密用 -k <私钥文件> 传入身份私钥，**绝不走环境变量 / stdin**。

# 生成 X25519 密钥对：公钥打到 stdout（可重定向），私钥落到文件
FileEncryptorCLI -g -o ./keys > pubkey.txt

# 由口令派生密钥对（口令经 stdin 传入；同口令 + 同盐永远得到同一对密钥）
FileEncryptorCLI -G -o ./keys --key-stdin > pubkey.txt
# 用已有的盐 + 同一个口令重新派生出同一对密钥（私钥文件丢了也能找回）
FileEncryptorCLI -G -o ./keys --key-stdin --salt ./keys/rage_derive_salt.txt

# 由私钥反推公钥
FileEncryptorCLI -Y -k ./keys/rage_private.txt

# 非对称（rage）混合加密：直接用公钥字符串，或给公钥文件
FileEncryptorCLI -e secret.docx -m rage -r age1... -o ./out
FileEncryptorCLI -e secret.docx -m rage -r ./recipients.txt -o ./out

# 解密：私钥以文件形式经 -k 传入（不走 stdin / 环境变量）
FileEncryptorCLI -d secret.docx.age -m rage -k ./keys/rage_private.txt -o ./out

续传：单文件（`-e`/`-d`）与批量（`-be`/`-bd`）模式均默认自动；中断后重跑同一命令，若存在同名 `.progress` 即从中断点继续，无需额外开关。
```

示例：

```bash
# 交互式输入口令，加密单个文件（默认 XChaCha20）
FileEncryptorCLI secret.docx

# 用 AEGIS-256 批量加密目录（并发数写进 fileencryptor.yaml 的 worker_threads），成功后删除源
FileEncryptorCLI -be ./docs -m aegis256 -de

# 用密钥文件非交互加密
FileEncryptorCLI -e secret.docx -k ./key.bin -o ./out

# 用环境变量解密（与上方加密使用同一密钥材料）
ENCRYPTOR_KEY=@raw-key-material FileEncryptorCLI -d secret.docx.ptd -o ./out

# 中断后续传解密（重跑即可，自动续传）
FileEncryptorCLI -bd ./encrypted_dir -o ./decrypted
```

---

## YAML 配置（运维参数）

所有运维类参数**仅**由配置文件提供，CLI 不可覆盖（见上文设计原则）。复制 `fileencryptor.yaml.example` 为 `fileencryptor.yaml` 放到以下任一位置即生效（优先级从高到低）：

1. 环境变量 `FILEENCRYPTOR_CONFIG` 指向的路径；
2. 运行目录（CWD，即启动程序时所在的目录）；
3. 可执行文件所在目录；
4. 用户配置目录（Windows `%APPDATA%\FileEncryptor\` / Linux `~/.config/FileEncryptor/`）。

常用项（详见配置文件内联注释）：

| 项 | 默认 | 说明 |
|---|---|---|
| `log_file` | `""` | 留空 = 仅控制台进度；非空 = 写入指定文件 |
| `log_level` | `INFO` | `ERROR` / `WARN` / `INFO` / `DEBUG` |
| `worker_threads` | `0` | `0` = 自动（CPU 核数） |
| `max_open_files` | `256` | 批量并发线程数上限 = `max_open_files / 3`（防句柄耗尽） |
| `io_buffer_size` | `1MB` | 内部流式缓冲（1024 进制，可写 `512KB` / `2MB` 等） |
| `max_speed` | `0` | 进程级总吞吐上限；`0` = 不限；如 `10MB/s`、`1.5GB/s` |
| `max_path_length` | `0` | UTF-8 字节上限；`0` = 不限 |
| `path_whitelist_enabled` | `false` | 是否启用路径白名单 |
| `progress_rotation` | `true` | 覆盖 `.progress` 前先备份 `.progress.bak` |
| `obfuscate_names` | `true` | 输出文件名混淆（v1.7.0+） |

---

## 发布与供应链

- **`Dockerfile`**：基于 Debian 的多阶段镜像，可在容器内完成构建与运行，便于 CI 复现。
- **`scripts/build-release.sh`**：一键产出各平台**静态二进制**与零依赖 `DEB`/`RPM`。
- **`scripts/sign-release.sh`**：对发布产物生成 `SHA256SUMS` 并可用 GPG 签名。

---

## 非对称（混合）加密：集成 rage/age（X25519 + ChaCha20-Poly1305）

非对称模式（`-m rage`，兼容别名 `age`）采用**混合加密**：每个文件用随机生成的对称文件密钥（ChaCha20-Poly1305）加密，再用收件人的 **X25519** 公钥包装该文件密钥。无需与对方共享口令，只需交换公钥；可指定多个收件人（每人都能独立解密）。底层复用 [rage/age](https://github.com/str4d/rage) 的 C-ABI 静态库 `fe_age`（封装 `age` crate v0.12.1）。

- **密钥对生成**：`-g` 直接生成——**公钥打印到 stdout**（便于重定向 / 管道给 `-r`），**私钥写入 `-o <dir>/rage_private.txt`**；提示信息一律走 stderr，保证 stdout 是干净的一行公钥。
- **加密**：`-r <pub|file>` 给收件人公钥——可直接是 `age1...` 字符串，也可以是公钥文件（每行一个，可空行 / `#` 注释 / `publickey:` 前缀），输出 `<名>.age`。
- **解密**：**必须**用私钥文件：`-k <私钥文件>`（内容为 `AGE-SECRET-KEY-...`，自动去除首尾空白 / 换行）。身份私钥不再经 stdin 传入，**绝不走环境变量**。

### 密钥派生（`-G`）与公钥导出（`-Y`）

这两个动作是纯本地计算（Argon2id + X25519 + Bech32），**不依赖 `fe_age` 静态库**，因此在未集成为非对称加密的构建里同样可用。

- **`-G` 口令派生**：`Argon2id(口令, 盐) → 32 字节 → X25519 钳位 → 密钥对`。
  输出与 `-g` 一致（公钥到 stdout、私钥到 `<dir>/rage_private.txt`），额外写出 **`<dir>/rage_derive_salt.txt`**（16 字节随机盐的 hex）。
  **同一口令 + 同一盐永远得到同一对密钥**，所以记住口令即可代替保存私钥文件；但**盐必须一并保存**，否则无法再次派生。
  用 `--salt <hex|file>` 传入已保存的盐即可复现；口令可来自 `--key-stdin`（推荐，GUI 走此通道）、`-k <文件>`、`ENCRYPTOR_KEY` 或交互输入（≥6 字符）。
  已存在同名密钥文件时拒绝覆盖，除非带 `-y`。
- **`-Y` 公钥导出**：读取 `-k <私钥文件>` 中的 `AGE-SECRET-KEY-...`，做一次 X25519 基点乘法反推出 `age1...` 公钥并打印到 stdout。用于私钥还在、公钥丢失的场景（等价 `rage-keygen -y`）。
- **Bech32 实现注意事项**：age 的身份私钥串是 `bech32_encode(HRP="AGE-SECRET-KEY-")` 之后整体大写，其**校验和按小写 HRP 展开计算**。若按大写 HRP 展开，age 会拒绝该串（`invalid Bech32 encoding`）。

### 构建 fe_age 静态库（Windows / Linux）

`fe_age` 源码位于仓库 `../age-ffi/`，是 `rage` workspace 的一个成员 crate（C-ABI `staticlib`）。需先分别编译出两平台静态库，再交给 CLI 的 CMake 集成：

```powershell
# Windows（MSVC，x64）：在 E:/rage 仓库根执行
cd ../age-ffi
./build-win.ps1          # 产出 age-ffi/lib/windows/fe_age.lib
```

```bash
# Linux（x86_64）：在 E:/rage 仓库根执行
cd ../age-ffi
./build-linux.sh         # 产出 age-ffi/lib/linux/libfe_age.a
```

也可显式指定 age-ffi 目录：`cmake -S . -B build -DFE_AGE_DIR=/path/to/age-ffi ...`。

> CMake 集成：`WITH_AGE`（默认 ON）。找到 `fe_age.h` + `fe_age.lib`/`libfe_age.a` 后定义 `FE_WITH_AGE` 并链接；**未找到时仅给出 WARNING，回退为不含非对称加密的版本**（相关调用返回明确错误，不中断构建）。详见 `../age-ffi/README.md`。

---

## 与 GUI 项目的协作

GUI 项目位于仓库同级目录 `../GUI/`，编译产出 `FileEncryptorGUI(.exe)`。要让 GUI 能正常调用本 CLI：

- **开发期**：把本项目 build 出的 `FileEncryptorCLI.exe` 复制到 GUI 项目的 build 输出目录（或设置 `FILEENCRYPTOR_EXE` 环境变量指向 CLI exe 的绝对路径）。
- **打包发布**：把 `FileEncryptorGUI(.exe)` 与 `FileEncryptorCLI(.exe)` 放到同一目录，GUI 启动时会自动在同目录、env、PATH 中依次查找。

详见 `../GUI/README.md`。
