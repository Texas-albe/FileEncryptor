# FileEncryptor

跨平台（Windows / Linux / macOS）文件加密工具，基于 [libsodium](https://doc.libsodium.org/) 实现高强度、抗篡改、可续传的分块加密。

- 磁盘文件格式版本 **v3**（向后兼容 v1 / v2，旧文件可直接解密，无需重加密）。
- 程序版本 **1.4.0**。

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
- **可续传加密 / 解密**：中断后重跑可从中断点继续（含一致性校验，断点损坏则安全从头重写）。
- **批量处理**：支持目录递归、多线程并行（`-j`）、源文件删除（`-de`）、强制覆盖（`-f`）。
- **安全细节**：解密原子落盘（先写 `.part` 再重命名）、输出锁防并发写、路径穿越防御、符号链接 / 重解析点拒绝、密钥 `sodium_mlock` 锁定、POSIX 下半成品 `chmod 0600`。

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
# 产物：file-encryptor_1.4.0-1_amd64.deb 与 file-encryptor-1.4.0-1.x86_64.rpm
```

> 若系统中同时存在多个 libsodium（如 apt 旧版 + `/usr/local` 新版），可显式指定：
> `cmake -S . -B build -DSODIUM_ROOT=/usr/local ...`

最终用户安装：
```bash
sudo dpkg -i file-encryptor_1.4.0-1_amd64.deb
# 或
sudo rpm -ivh file-encryptor-1.4.0-1.x86_64.rpm
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

## 用法（CLI）

```
FileEncryptor <输入路径> [-m <模式>] [-o <输出目录>] [-p <口令>] [-e|-d]
              [-r] [-j <线程数>] [-de] [-f] [-h]

  <输入路径>            文件或目录（目录会递归批量处理）
  -e / --encrypt       加密（默认）
  -d / --decrypt       解密
  -m <mode>            加密模式：xchacha20（默认）| aegis256
  -o <dir>             输出目录（默认：输入同级加密 / 解密目录）
  -p <password>        口令（省略则交互式输入，不回显）
  -r / --resume        续传模式（从中断点继续）
  -j <n>               并行线程数（批量模式，0 = 自动）
  -de                  处理成功后删除源文件
  -f / --force         覆盖已存在的输出
  -h / --help          显示帮助
```

示例：

```bash
# 交互式输入口令，加密单个文件（默认 XChaCha20）
FileEncryptor secret.docx

# 用 AEGIS-256 加密目录，4 线程并行，成功后删除源
FileEncryptor ./docs -m aegis256 -j 4 -de

# 续传解密
FileEncryptor secret.docx.ptd -d -r

# 直接给出口令（脚本场景）
FileEncryptor data.bin -p "my passphrase" -o ./out
```

---

## 文件格式

- 加密产物扩展名 `.ptd`，固定文件头 **109 字节**（v3）：magic(`FENC`) + version + mode + Argon2 参数 + salt + iv + plaintext_hash + 分块元数据。
- 续传元数据写入同名 `.progress`（HMAC 认证）。
- 跨版本兼容：`decrypt_file` 按文件头 `version` 字段区分 v1 / v2 / v3 并相应解析。

---

## 许可证

见 [CHANGELOG.md](CHANGELOG.md) 与仓库 LICENSE 文件。
