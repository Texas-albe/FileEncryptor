# ChangeLog

本文件记录 FileEncryptor 的所有重要变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.2.1] - 2026-08-14（批量续传与解密路径回归修复）

> 本轮聚焦批量模式的两条回归，并补全回归测试。磁盘文件格式版本仍为 **v2**（与 v1.2.0 完全兼容，无需重加密旧产物）。

### Fixed

- **批量解密输出路径多嵌套一层（F10 / P04 / S01）**：`build_batch_out_path` 增加 `encrypt` 方向判断，解密时**不再**附加输入根目录名，还原结构恢复为 `<解密目录>/<源目录>/...`，与 v1.1.1 一致；加密时仍附加以保留源目录名。
- **批量续传恢复字节不一致（S08）**：修复 prescan 把"仅有头部、无 `.progress` 的半截 `.ptd`"（强杀于首个 `save_progress` 前）误判为已完成而跳过的问题。新增 `is_complete_output()` 按预期尺寸比对，仅当"头部有效 + 无 `.progress` + 尺寸完整"才跳过，否则重新加密，确保重跑后解密字节一致。

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

---

## [1.1.1] - 基线版本

- 初版分块加密（`CHUNK_SIZE = 1MiB`）、AES-GCM / XChaCha20 双算法、Argon2id 密钥派生、续传、批处理、多线程。
- 已知问题（P1-1~P1-3、P2-1~P2-3、N-15~N-19、S1、S2、S4、X10 等）均已在上方 `[1.2.0]` 中全部修复并通过真实编译验证。
