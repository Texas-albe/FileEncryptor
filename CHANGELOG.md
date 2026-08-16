# ChangeLog

本文件记录 FileEncryptor 的所有重要变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.4.1] - 2026-08-16（断点续传进度写入修复 + 多项健壮性修复）

> 程序版本号 1.4.0 → 1.4.1。磁盘文件格式版本仍为 **v3**（完全兼容，无需重加密旧产物）。

### Fixed

- **[主缺陷] Windows 下断点续传进度文件写入失败（`save_progress`）**：`save_progress()` 之前直接调用 `std::rename` 落盘进度文件，而 **MSVC 的 `std::rename` 在目标 `.progress` 已存在时返回 `EEXIST` 失败**（POSIX 语义是原子覆盖，故 Linux 不受影响）。结果仅第 1 个块能写入进度，从第 2 块起全部 `Failed to save progress`，中断后重跑永远从第 1 块开始、断点续传退化为从头重做。现改用已有的 `replace_file_utf8()`（Windows 走 `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`、Linux 走 `std::remove`+`std::rename`），保证每次块处理后都能覆盖更新进度文件；`save_progress()`/`remove_progress()` 内清理临时/旧文件也统一改用 `remove_file_utf8()`（规避 Windows ANSI 路径对非 ASCII 字符的处理问题）。
- **[P2] 续传不校验加密算法模式一致性**：`encrypt_file()` 续传分支此前只校验 `chunk_size`/`total_chunks`/`orig_size`，不校验已存在输出的 `mode` 与本次 `-m` 是否一致。若上次用 `-m aegis256` 中途中断、重跑时漏加 `-m`（默认 xchacha20），会复用旧 v3 头部却用不同算法续写，最终自解密失败并删除产物。现续传前显式比较 `existing_v3.mode` 与本次模式，不一致则清晰报错（"Output file was created with a different encryption mode … cannot resume"）并中止，而非静默混写。
- **[P3] 续传截断失败被忽略**：加密续传 `truncate_file(out_path, …)` 与解密续传 `truncate_file(part_path, …)` 的返回值此前被忽略；磁盘异常/文件占用导致截断失败时，残留超长密文会在后续尺寸校验失败并触发产物整体删除。现检查两个 `truncate_file` 调用点返回值，失败时立即中止并报错。
- **[P4] 输出锁错误信息误导**：`acquire_output_lock()` 此前对所有失败原因统一返回 `false`，调用点一律报 "Output file is locked by another process"。现改为返回原因码 `LockResult{OK, LOCKED, CANNOT_CREATE}`，调用方区分"真被其它进程锁定"（锁文件存在且持有进程存活）与"无法创建锁文件"（权限/路径过长或非法，Windows 未用 `\\?\` 长路径前缀）并给出不同提示，便于排障。
- **[P6] Linux 密码输入未检查 `tcgetattr` 返回值**：`get_password_posix()` 此前直接调用 `tcgetattr(STDIN_FILENO, &oldt)` 未检查返回值；当 stdin 非 TTY（管道喂密码、CI 环境）时 `oldt` 为未初始化内存，随后 `tcsetattr` 写入未定义状态。现先检查 `tcgetattr` 返回值，失败（非 TTY）时跳过终端回显设置、仅正常读取密码行。

### Added

- **[P5] 批量加密失败文件汇总**：`process_files()` 此前仅在批量**解密**失败时打印失败清单，批量**加密**失败时只散落各线程 stderr 无汇总。现与解密分支对称，批量加密结束也打印 `--- Encryption errors (N files) ---` 清单及失败总数。



## [1.4.0] - 2026-08-15（跨平台构建修复：libsodium 版本校验与查找顺序、打包文档）

> 磁盘文件格式版本仍为 **v3**（与 v1.2.0+ 完全兼容，无需重加密旧产物）。程序版本号 1.3.0 → 1.4.0。

### Fixed

- **链接期 `undefined reference to crypto_aead_aegis256_*`**：根因是系统同时存在多个 libsodium 时，CMake 经 **pkg-config 优先**选中了较旧版本（如 apt 的 `libsodium-dev` 1.0.18），其不提供 AEGIS-256 符号。现改为**手动查找（`/usr/local` 优先）> pkg-config 回退**，自动选中较新的 `libsodium`（如 `/usr/local` 1.0.22）。
- **静态库查找遗漏 `/usr/local` + 构建目录缓存污染**：静态链接分支的 `find_library` 原先未在 `HINTS` 中纳入 `/usr/local`，且构建目录缓存了在 `/usr/local` 安装 libsodium **之前**探测得到的 `NOTFOUND`/apt 旧值，导致即便源码已安装到 `/usr/local`，仍链接到 apt 的 `libsodium.a`（无 AEGIS-256）。现已在 `HINTS` 显式优先搜索 `/usr/local`，并在配置期 `unset(... CACHE)` 强制重新探测；同时新增 **`nm` 符号级校验**：用 `nm` 直接确认选中的库包含 `crypto_aead_aegis256_encrypt`，否则在配置期即 FATAL_ERROR，避免再次出现“头文件来自 `/usr/local`、链接库却来自 apt 旧版”的头库不一致问题。
- **版本能力校验**：配置阶段新增 AEGIS-256 版本能力检查（需 libsodium **>= 1.0.19**），版本过低时在配置期即给出清晰报错与解决办法，而非链接期诡异的 undefined reference。

### Added

- **README.md**：新增跨平台构建 / 打包 / 用法文档（含 Linux 自包含 DEB/RPM、Windows vcpkg、手动指定 `SODIUM_ROOT` 等场景）。
- 多 libsodium 共存时的规避指引：`cmake -DSODIUM_ROOT=/usr/local ...` 或 `sudo apt remove libsodium-dev`。
- **DEB/RPM 打包脚本 `package-linux.sh`**：在 Linux 上一键 `configure → build → cpack`（生成器自动选 Ninja / Unix Makefiles），产出自包含包；缺少 `rpmbuild` 时自动退化为仅打 DEB 并提示 `sudo apt install rpm`。CPack 另新增 `CPACK_STRIP_FILES ON`（打包时剥离调试符号）与 `CPACK_PACKAGE_RELEASE "1"`（RPM 发布号）。
- **零声明依赖 + 静态链接硬校验**：CPack 显式 `CPACK_DEBIAN_PACKAGE_DEPENDS ""`（DEB 的 Depends 留空）+ `CPACK_RPM_PACKAGE_AUTOREQPROV OFF`（连同自动 Provides 一起关闭），确保 DEB/RPM 元数据不含任何 `libsodium` 依赖。新增 `cmake/CheckStaticSodium.cmake`（构建期 `POST_BUILD` 调用）：用 `objdump -p` 检查可执行文件的 `NEEDED` 段，若仍动态依赖 `libsodium.so` 则**构建直接失败**，从根上杜绝“看起来自包含、实际却动态链接”的包。

### Changed

- 程序版本号升至 **1.4.0**（`FileEncryptor.hpp` 中 `FE_VERSION_*` 与 `CMakeLists.txt` 的 `project(... VERSION 1.4.0)` 同步；DEB/RPM 包名与版本随之更新）。

### Fixed（持续修复）

- **Windows 静态链接 libsodium**：此前 Windows 默认走动态链接（导入库 + DLL）。现 `SODIUM_STATIC`（默认 ON）在 Windows 上也优先选用预编译包里的静态库（如 `C:\Program Files\libsodium\x64\Release\v143\static\libsodium.lib`），并自动：
  - 定义 `SODIUM_STATIC` 编译宏，避免 `sodium.h` 把符号声明为 `__declspec(dllimport)` 而引发 `LNK2019`（__imp_ 符号找不到）；
  - 将运行时库切换为静态 CRT `/MT`（`MSVC_RUNTIME_LIBRARY = MultiThreaded`），与 libsodium 静态库的 `LIBCMT` 保持一致，避免 `LNK2038`（CRT 不匹配）。
  - 最终 `FileEncryptor.exe` **单文件自包含、无 `libsodium.dll` 依赖**。
- 重建缺失的 **CMakePresets.json**（含 `linux-release` / `windows-release` 等预设），恢复 `cmake --preset` 跨平台构建流程。

---

## [1.3.0] - 2026-08-14（安全加固：进度 HMAC、AEGIS-256、nonce 自增、Blake2b、加密自检）

> 磁盘文件格式版本 **v2 → v3**（向后兼容 v1 / v2，旧文件仍可直接解密，无需重加密）。

### Added

- **进度文件 HMAC 认证（防续传劫持）**：`.progress` 现在携带 **HMAC-SHA512/256**（32 字节派生 key + 32 字节 tag），覆盖 `magic + version + 已处理块数 + 已处理字节数`。伪造 / 损坏的进度无法通过认证，必然触发安全从头重写——无法跳过 MAC、无法注入块、无法劫持续传。
- **AEGIS-256 加密模式**：新增 `CryptoMode::AEGIS256`（32 字节密钥 / 32 字节 nonce / 32 字节 tag 的 AEAD），作为 AES-GCM 的替代；引入运行时探测 `aegis256_supported()`（缺 AES-NI 的 CPU 上返回 false）。
- **块 nonce 改用 `sodium_increment`**：每块 `nonce = sodium_increment(iv)` 在文件级随机 `iv` 上逐块自增，彻底消除旧 `iv XOR 块索引` 方案的理论碰撞风险（v1/v2 解密仍用旧 nonce 派生）。
- **明文 Blake2b 完整性校验**：加密前对明文计算 **Blake2b** 哈希写入 v3 头 `plaintext_hash[32]`；解密后重新计算并比对，端到端验证整个明文完整性与来源真实性。
- **加密后自检**：`encrypt_file` 成功后立即用同一口令解密验证（尺寸 + Blake2b），自检失败则删除产物并报错，保证落地产物一定可解密恢复。
- 回归测试 `Temp/rt_test.cpp` 扩充至 **24/24 PASS**：覆盖 XChaCha20 / AEGIS-256 的小 / 大（>5 MiB 多块）/ 空文件字节级往返（含加密自检）、错误口令拒绝、密文篡改拒绝、篡改 `.progress` 安全重启。

### Changed

- **默认算法改为 XChaCha20-Poly1305**：`CryptoMode` 默认值由 `AES_GCM` 改为 `XCHACHA20`；CLI `-m` 取值变为 `xchacha20`（默认）/ `aegis256`，移除 `aes`。
- **移除新加密中的 AES-GCM**：`AES-256-GCM`（`crypto_aead_aes256gcm`）仅保留用于**解密旧版 v1/v2 文件**；新文件使用 XChaCha20 或 AEGIS-256。
- **文件格式升级 v3**：v3 在 v2 基础上将 `iv` 缓冲扩到 32 字节（容纳 AEGIS-256 的 32 字节 nonce）并新增 32 字节 `plaintext_hash`，固定头区共 **109 字节**（93 字节 `FileHeaderV3` 结构 + 16 字节分块元数据：chunk_size / total_chunks / orig_size）；`decrypt_file` 改为版本感知解析（v1 / v2 / v3）。
- **批量续传回退判定**：批量模式在 AEGIS-256 不可用时改为基于 `aegis256_supported()` 的探测回退（原为 AES 探测）。

### Security

- 续传防劫持（HMAC）、nonce 防碰撞（`sodium_increment`）、文件级 Blake2b 完整性、加密自检四者共同构成「可恢复且防篡改」的静态存储保护；`mode` / `version` 仍纳入 AAD 抗降级。

---

## [1.2.1] - 2026-08-14（批量续传与解密路径回归修复）

> 本轮聚焦批量模式的两条回归，并补全回归测试。磁盘文件格式版本仍为 **v2**（与 v1.2.0 完全兼容，无需重加密旧产物）。

### Fixed

- **批量解密输出路径多嵌套一层（F10 / P04 / S01）**：`build_batch_out_path` 增加 `encrypt` 方向判断，解密时**不再**附加输入根目录名，还原结构恢复为 `<解密目录>/<源目录>/...`，与 v1.1.1 一致；加密时仍附加以保留源目录名。
- **批量续传恢复字节不一致（S08）**：修复 prescan 把"仅有头部、无 `.progress` 的半截 `.ptd`"（强杀于首个 `save_progress` 前）误判为已完成而跳过的问题。新增 `is_complete_output()` 按预期尺寸比对，仅当"头部有效 + 无 `.progress` + 尺寸完整"才跳过，否则重新加密，确保重跑后解密字节一致。

### Added

- 回归测试 `_verify/verify.cpp` 扩充至 **39/39 PASS**：新增 S08 批量续传字节一致性、S08-b（仅头部无 `.progress` 重加密）、V1 兼容实测（合成 v1 样本解密）、>4TiB 伪造头部拒绝、>4GiB 稀疏往返、`-j 64` 并行压力、符号链接穿透拒绝等。

---

## [1.2.0] - 2026-08-12（安全性强化与缺陷修复累积版本）

> 基线为 v1.1.1（回归报告 64 用例 46 PASS / 18 FAIL）。本轮起经过多轮审查与真实编译验证，累计修复严重 / 中等 / 代码质量 / 跨平台 / 安全类问题共 20+ 项，回归套件 `_verify/verify.cpp` 达 **32/32 PASS**（含原功能 + S1/S2/S4 安全专项 + V1 兼容）。
>
> **磁盘文件格式版本：v1 → v2（向后兼容，旧 v1 `.ptd` 仍可解密）。**

### 文件格式变更（破坏性但向后兼容）

- 文件头 `VERSION` 由 1 升到 2。v2 头部在原有 47 字节基础上新增 `opslimit(uint16)` 与 `memlimit_kb(uint32)` 两个字段（共 53 字节），用于**持久化 Argon2id 密钥派生参数**。
- `decrypt_file` 改为**版本感知解析**：v1 文件按旧参数（3 迭代 / 64MiB）解密，v2 文件按文件头内存储的参数解密；头部偏移、PREFIX、AAD 均按每文件 `hdr_size` 计算。
- `is_file_valid` 同时接受 v1 / v2，批处理模式可正确识别旧版输出。

### Added

- **跨进程输出锁（N-2）**：加密 / 解密前在 `<输出>.lock` 处原子 `CREATE_NEW` 并写入持有者 PID，防止并发进程写同一输出导致损坏；检测到失效锁（持有者已退出）时自动回收。
- **路径穿越统一防御（S4）**：新增 `path_has_traversal()`，按分隔符拆分成路径组件，任何 `..` 分量即拒绝；在 `encrypt_file` / `decrypt_file` 入口对所有最终写出路径（out_path、part_path）统一检查。
- **符号链接 / 重解析点防护（S2）**：新增 `path_is_symlink()`（Windows 检测 `FILE_ATTRIBUTE_REPARSE_POINT`，POSIX 用 `lstat` / `S_ISLNK`）；在创建 / 打开 `.part`、最终输出、原子重命名落盘**前**拒绝已存在的符号链接 / 重解析点，避免攻击者用 symlink 劫持写入导致任意文件截断。
- **解密原子落盘**：解密先写入 `<输出>.part` 半成品，全部数据块 MAC 校验通过后再原子重命名（`MoveFileExW` / `rename`）为最终输出，避免中途残留可被读取的明文文件。
- **KDF 强度提升**：新文件默认 Argon2id 提升到 moderate 档 `opslimit=4 / memlimit=128MiB`（原为交互档 `3 / 64MiB`），因参数已入库，未来可无损增强而不破坏旧文件。

### Changed

- **密钥派生参数入库**：Argon2id 参数从硬编码改为从文件头读取（v2）；解密时按版本回退到旧参数（v1 = 3 / 64MiB）。
- **续传（resume）重写**：
  - 改用 `std::fstream(in|out)` + `truncate_file()` 截到断点；
  - 严格保证「先 `fout.flush()` 再 `save_progress()`」，消除「磁盘已写、进度未记」的窗口（P1-2 / N-16）。
  - 续传前校验 `processed_chunks > total_chunks` 或 `processed_bytes > total_size`，损坏（如断电导致的半截进度）则放弃续传、从头重写，而非静默截断（X10）。
- **目录遍历（P1-3）**：`create_directory_recursive` / `is_directory` / `collect_files_from_dir` 改用 `_wstat64` / `_wmkdir` / `_wfindfirst`（Windows）与 `lstat` + `S_ISLNK` 跳过符号链接（POSIX），修复非 UTF-8 路径失败与符号链接死循环。
- **nonce 块索引**显式小端序列化，兼容旧 `.ptd` 文件（N-18）。
- **大文件支持**：`total_size` / `start_bytes` / `processed_bytes` 改为 `uint64_t`，支持 > 4GiB 文件（N-19）。
- **批处理输出路径**：`build_batch_out_path` 复用统一的 `path_has_traversal()` 组件法，消除两处 28 行重复拼接及前缀 `..` 漏检（S4 批处理遗漏）。
- **统一 UTF-8 删除**：源文件删除（`-de`）与解密成品删除改用 `remove_file_utf8`（`_wremove`）（UTF-8 删除）。
- **anti_debug 误判修复**：仅当 `errno == EBUSY` 才退出，避免其他错误被误判为调试器而终止进程。
- **POSIX 密码清零**：读取密码后 `line.clear()` 清零内存中的明文密码副本。

### Fixed

- **P1-1 续传大小计算**：`expected_size` 改用 `last_chunk_len = orig_size - (total_chunks - 1) * chunk_size` 精确计算，修复续传结尾多 / 少字节导致的校验失败或文件损坏。
- **P1-2 续传截断竞态**：见 Changed 续传条目。
- **P1-3 目录遍历符号链接**：见 Changed。
- **P2-1 覆盖提示路径不一致**：先算出最终 `out_path`（加密加 `.ptd`、解密剥 `.ptd`）再提示覆盖，避免提示路径与实际写出路径不符。
- **P2-2 线程数崩溃**：`-j` 包 `try/catch`，异常时回退默认线程数而非崩溃。
- **P2-3（中等）**：已在本轮修复并纳入 `test_p2_3()` 回归（详见 `_verify/verify.cpp`）。
- **N-15 删除死代码**。
- **N-16 续传 flush 顺序**：见 Changed 续传条目。
- **N-18 nonce 小端序列化**：见 Changed。
- **N-19 uint64_t 类型**：见 Changed。
- **S1 解密头部越界读（严重）**：原校验 `if((mode==AES_GCM&&…)||(mode==XCHACHA20&&…))` 在 `mode` 为未知值（如 99）时整体为 false，从而**跳过 iv_len 检查**，随后 `memcpy(nonce, header.iv, iv_len)` 在 `iv_len` 被恶意设大时会越界读取 `header.iv[24]` 之外的内存（崩溃 / 信息泄露）。现强制先校验 `mode ∈ {AES_GCM, XCHACHA20}`，再校验 `iv_len` 等于该模式期望值且 `≤ sizeof(header.iv)`。
- **S2 符号链接 TOCTOU（严重）**：见 Added。
- **S4 路径穿越（中等）**：见 Added + 修复批处理遗漏。
- **worker 回退绕过**：`build_batch_out_path` 返回空（穿越被拒）时不再回退 `out_path = in_path`（解密会覆盖源文件并绕过 `out_dir` 限制），改为跳过该文件并记录错误。
- **UTF-8 删除失败**：见 Changed 统一 UTF-8 删除。
- **anti_debug 误杀**：见 Changed。
- **POSIX 密码未清零**：见 Changed。

### Security

- **抗降级**：`mode` 与 `version` 均包含在 AEAD 的 AAD 中认证，且只有 AES-GCM / XChaCha20 两种强算法、无弱算法分支，无法被降级篡改。
- **抗重放**：每文件 `salt` + `iv` 随机（`randombytes`），`nonce = iv XOR 块索引` 唯一；每块 MAC 校验，伪造 / 损坏的 `.progress` 无法跳过 MAC，无重放面。
- **解密成品权限（POSIX）**：新建 `.part` 后 `chmod 0600`，防止半截明文被其他用户读取。
- **密钥内存**：派生后用 `sodium_mlock` 锁定，失败仅告警。
- **跨进程锁竞争**：锁按每个输出文件独立（`<out>.lock`），批量并行各线程处理不同文件，设计上无进程内争用；仅跨进程存在「非原子失效锁回收」的 TOCTOU（安全假阴性，不损坏数据，低危）。
- **回归套件**：`_verify/verify.cpp` 提供 32/32 字节级测试（含 S1 畸形头、S2 真实重解析点、S4 穿越、V1 兼容）。该套件**保留在仓库作为固定验收**，但**不编入发布版 `FileEncryptor.exe`**（与 `main.cpp` 的 `wmain` 冲突、依赖 `<windows.h>`），仅作独立测试目标 `_verify/verify.exe`。

---

## [1.1.1] - 基线版本

- 初版分块加密（`CHUNK_SIZE = 1MiB`）、AES-GCM / XChaCha20 双算法、Argon2id 密钥派生、续传、批处理、多线程。
- 已知问题（P1-1~P1-3、P2-1~P2-3、N-15~N-19、S1、S2、S4、X10 等）均已在上方 `[1.2.0]` 中全部修复并通过真实编译验证。
