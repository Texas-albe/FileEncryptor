# FileEncryptor 源代码安全审计报告（汇总）

- 审计日期：2026-09-27
- 审计范围：CLI 核心加密、CLI 入口与配置、GUI-Qt、GUI-WinUI 四大模块全部源码
- 审计方式：静态人工白盒审查，未修改任何源码
- 版本基线：2.4.4（已知修复项已去重，不重复报告）

## 一、总体结论

| 严重程度 | 数量 |
|----------|------|
| 高       | 0    |
| 中       | 11   |
| 低       | 25   |
| **合计** | **36** |

**核心加密路径实现规范**：Argon2id 密钥派生、XChaCha20-Poly1305 / AEGIS-256 / AES-GCM 加密、随机数全部来自 libsodium，未发现硬编码密钥/IV、ECB 模式、nonce 复用、可远程触发的缓冲区溢出。命令注入面控制良好（Qt 用 QStringList、WinUI 用 ArgumentList，密钥均经 stdin 注入不进 argv）。

**主要风险集中在三个方向**：
1. **密钥/口令内存清零不彻底**——派生中间值、托管堆字节数组、Qt 临时 QByteArray 未用安全擦除
2. **Windows 下半成品明文文件权限未收紧**——.prt 文件继承默认 DACL
3. **自动下载 CLI 二进制无完整性校验**——Qt 和 WinUI 两个 GUI 均存在供应链风险

---

## 二、中危问题（11 项）

### 【中-1】主密钥派生子密钥时拷入普通 vector，析构未擦除
- **文件**：`CLI/core/kdf.cpp:92-98, 100-106`；同类 `CLI/core/FileEncryptor.cpp:1038-1045`
- **描述**：派生函数把 master_key 拼进普通 `std::vector<unsigned char> in`，未 mlock，离开作用域析构不做 `sodium_memzero`，残留 32 字节主密钥副本于堆。
- **修复建议**：用 SecureBuffer 承接，或在 `crypto_generichash` 后显式 `sodium_memzero(in.data(), in.size())`。

### 【中-2】Windows 下半成品明文 .prt 与输出文件未收紧 DACL
- **文件**：`CLI/core/FileEncryptor.cpp:543-547`（restrict_permissions 空 Windows 分支）、`2419/2494`（解密 .prt）、`1763`（加密输出）
- **描述**：`restrict_permissions` 仅 POSIX chmod 0600，Windows 为空。解密逐块还原的明文先写 `<out>.prt`，在 Windows 上继承父目录默认 DACL，多用户环境下同机其他主体可在原子改名前读到明文。
- **修复建议**：Windows 分支复用 `tighten_file_permissions(path)` 到 .prt/输出文件。

### 【中-3】解密失败时半成品明文 .prt 直接 unlink，未覆写
- **文件**：`CLI/core/FileEncryptor.cpp:2771`
- **描述**：失败清理仅 `remove_file_utf8(part_path)`，.prt 中已落盘的明文片段不做任何覆写即删除，可被取证恢复。
- **修复建议**：失败清理 .prt 前先用 Wipe（至少一次随机/0x00 覆写）再删除。

### 【中-4】run_recover 还原文件名直接拼接导致路径遍历
- **文件**：`CLI/cli/main.cpp:702-714`（核心拼接在 705 行）
- **描述**：`newpath=base+orig+".ptd"` 中 orig 来自解密出的密文尾部文件名信封，属数据可控值，未做 basename 净化就直接拼到目录前缀并用于原地重命名。若信封文件名含 `..\..\..\Windows\Temp\evil` 或绝对路径，会把 .ptd 移出原目录。
- **修复建议**：拼接前对 orig 取 basename，拒绝 `/ \ ..`，复用统一路径净化函数。

### 【中-5】rewrap 新口令明文写入可预测临时文件，未限制权限
- **文件**：`GUI-Qt/src/MainWindow.cpp:1483-1501`（写入）、`1695-1698`（完成后删）
- **描述**：密钥轮换时新口令直接写入 `QDir::tempPath()/fileencryptor_rewrap_<pid>.key`，以 `--new-key-file` 传给子进程。QSaveFile 默认权限 Unix 下通常 0644，同机其他用户可读明文新口令；文件名仅用 PID，有符号链接抢占窗口；进程被强杀时明文残留。
- **修复建议**：`setPermissions(ReadOwner|WriteOwner)`（0600）；文件名追加 QUuid 随机后缀；任务结束（含取消/异常）立即 unlink。

### 【中-6】Qt 自动下载 CLI 二进制无完整性校验（供应链风险）
- **文件**：`GUI-Qt/src/CliNotFoundDialog.cpp:76-169`
- **描述**：从 GitHub releases 挑选第一个 `FileEncryptorCLI-*.exe` asset 下载到外壳同目录，随后被直接执行。全程不校验 SHA256、不校验代码签名。若仓库/CDN 被攻陷，可下发任意二进制以用户权限执行。
- **修复建议**：Release 附带 SHA256 清单，下载后强制比对；先写临时文件校验通过再原子移动；后续可加 Release 公钥签名校验。

### 【中-7】PasswordDialog 对临时口令 QByteArray 用普通 memset（可被优化消除）
- **文件**：`GUI-Qt/src/PasswordDialog.cpp:165-167`
- **描述**：`memset(b.data(), 0, b.size())` 为裸 memset，项目自建 secure_zero 的目的正是规避"memset 后对象出作用域被优化为 dead store"。开启优化后该清零可能被消除，口令 UTF-8 字节残留堆上。
- **修复建议**：改为 `secure_zero(b.data(), size_t(b.size()))`。

### 【中-8】WinUI 口令明文驻留托管堆，写入 stdin 的字节数组事后未清零
- **文件**：`GUI-WinUI/ViewModels/MainViewModel.cs:168`；`GUI-WinUI/Services/CliProcessService.cs:53-55`
- **描述**：口令以明文 managed string 存在于 GC 堆；`Encoding.UTF8.GetBytes(password + "\n")` 生成 byte[] 写入子进程 stdin 后从未 `Array.Clear`，该字节数组在 GC 回收前一直明文驻留内存，且会因 GC 压缩被复制到不同地址。
- **修复建议**：写入 stdin 后立即在 finally 中 `Array.Clear(request.StdinData, 0, request.StdinData.Length)`；避免 `password + "\n"` 拼接；长期用固定 char[]/byte[] 接收口令并用完即清零。

### 【中-9】WinUI 自动下载 CLI 无完整性校验，且保存文件名未净化（路径穿越/供应链）
- **文件**：`GUI-WinUI/MainWindow.xaml.cs:161-193`
- **描述**：从 GitHub release 取 browser_download_url 直接下载，以 API 返回的 asset name 作为文件名落盘，仅做 StartsWith/EndsWith 过滤，未用 `Path.GetFileName` 净化。asset 名含 `..\` 时可跳出应用目录造成任意位置写入可执行文件；下载二进制无签名/哈希校验。
- **修复建议**：落盘前 `fileName = Path.GetFileName(fileName.Trim())`；内置 CLI SHA256 指纹或签名公钥校验；下载域白名单。

### 【中-10】WinUI 子进程 Process 对象退出后未 Dispose（句柄泄漏）
- **文件**：`GUI-WinUI/Services/CliProcessService.cs:45, 73-100`
- **描述**：`_process` 创建后订阅 Exited，读完 ExitCode 后直接 EmitFinished，全程未 `_process.Dispose()`。Process 实现 IDisposable，未释放会泄漏底层等待句柄/STDIN 句柄，批量任务下句柄累积。
- **修复建议**：OnProcessExited 末尾（或 finally）补 `_process.Dispose()`；Cancel() 路径也补。

### 【中-11】WinUI 临时统计文件名用 Guid.NewGuid 且存在 TOCTOU
- **文件**：`GUI-WinUI/Services/CliProcessService.cs:31, 79-83`
- **描述**：统计文件名 `fe_stats_{Guid.NewGuid():N}.json`，Guid.NewGuid 不是 CSPRNG 保证；temp 目录对同机其他进程可写时存在预判/预创建窗口。File.Exists 与 ReadAllText 之间是 TOCTOU，期间文件可被替换为伪造 JSON。
- **修复建议**：用 `RandomNumberGenerator.GetBytes` 生成随机名；以 FileShare.None 独占打开；把统计文件放到用户专属目录。

---

## 三、低危问题（25 项）

### CLI 核心加密（6 项）

| # | 文件 | 行号 | 问题 | 修复建议 |
|---|------|------|------|----------|
| L1 | `FileEncryptor.cpp` | 1067-1075 | 混淆基名派生时栈上 key[32]/seed[32] 未清零 | 用毕 sodium_memzero |
| L2 | `FileEncryptor.cpp` | 1587/1613/1838/2005/2363 | 多处栈上 hdr_auth[32] 子密钥未擦除 | 作用域末 sodium_memzero |
| L3 | `FileEncryptor.cpp` | 1759→1763, 2415→2419, 2490→2494 | 输出先默认 0644 创建再 chmod 0600，存在短暂可读窗口 | open 时直接 O_CREAT,0600 或先 umask(0077) |
| L4 | `FileEncryptor.cpp` | 1712 vs 1752/1759, 2374 vs 2490 | 符号链接检查与实际打开输出之间 TOCTOU | 以 O_NOFOLLOW 一次打开完成检查+打开 |
| L5 | `mapped_file.cpp` | 62, 75 | 32 位构建下文件大小强转 size_t 静默截断 | 32 位下 >SIZE_MAX 直接报错 |
| L6 | `FileEncryptor.cpp` | 584-596, 613-622 | 跨进程锁"失效锁回收"存在极小竞争，可能误报 CANNOT_CREATE | 回收重建失败时按 LOCKED 重试一次 |

### CLI 入口与配置（7 项）

| # | 文件 | 行号 | 问题 | 修复建议 |
|---|------|------|------|----------|
| L7 | `keylib.cpp` | 83-88 | read_key_material 先全量读入再判 256KB 上限，上限形同虚设 | 流式分块读取，超 256KB 即中断 |
| L8 | `main.cpp` | 819, 1252-1253, 1267-1268 | 多处密钥/输入读取无大小上限，与 keylib 不一致 | 统一加流式上限（密钥≤256KB、stdin≤1MB） |
| L9 | `keylib.cpp` | 174-185 | keylib_load 反序列化索引时未再校验 name/file 字段，被篡改的 library.yaml 可越库目录读写 | 加载时重跑 keylib_valid_name，校验 file 不含路径分隔符/..、以 .key 结尾 |
| L10 | `config.cpp` | 525-540 | CWD 低信任配置仅回退 log_file/path_whitelist，kdf_preset/min_password_length/obfuscate_names 仍可被植入生效 | 把加密强度/口令/混淆键也纳入 CWD 来源默认值回退 |
| L11 | `config.cpp` | 495 vs 331-334 | 配置文件大小预检与实际流式读取之间 TOCTOU，可绕过 1MB 防护 | read_file_utf8 循环内累计字节数，超限即停 |
| L12 | `keylib.cpp` | 170 | keylib YAML 解析无大小/别名展开上限，与 config.cpp 防护不一致 | 复用配置侧 1MB 预检 |
| L13 | `main.cpp` | 1279-1284 | ENCRYPTOR_KEY 环境变量副本读入 SecureBuffer 后，进程环境块中原串未擦除 | 读完即 unsetenv/_putenv 缩短窗口；文档建议优先 --key-stdin |

### GUI-Qt（4 项）

| # | 文件 | 行号 | 问题 | 修复建议 |
|---|------|------|------|----------|
| L14 | `TaskHistory.cpp` | 30-48, 145-159 | 任务历史把 inputPaths/keyfile/identity(私钥路径) 明文写入 tasks.log，未显式设 0600 权限 | 创建后 setPermissions(ReadOwner|WriteOwner)，history 目录 0700 |
| L15 | `PasswordDialog.cpp` | 143, 165 | QString 口令副本未擦除（Qt 容器固有限制） | 可接受；文档化风险 |
| L16 | `MainWindow.cpp` | 1263-1264, 1483-1484, 1381 | 临时文件名用 <名>_<pid> 固定模板，可预测 | 统一改用 QTemporaryFile |
| L17 | `TaskHistory.cpp` | 233 | prune 保留最旧而非最新 N 条，刚 append 的最新记录反被裁掉（功能性缺陷） | 写回应为 for(int i=keepLatest-1; i>=0; --i) |

### GUI-WinUI（8 项）

| # | 文件 | 行号 | 问题 | 修复建议 |
|---|------|------|------|----------|
| L18 | `CliArgBuilder.cs` | 95-99 | 位置参数未以 -- 分隔，文件名以 - 开头可被当作开关 | 位置路径前加 --，或以 .\ 前缀 |
| L19 | `PasswordDialog.xaml.cs` | 77 | GUI 侧口令策略仅校验长度≥6，未调用已定义的 MeetsPolicy（要求 2 类字符或长度≥16） | 确认时调用 MeetsPolicy，不满足禁用确定按钮 |
| L20 | `App.xaml.cs` | 18-26, 31-39 | 崩溃日志把异常对象 ToString() 写入 crash.log，将来口令路径异常可能携带缓冲区内容 | 日志仅记异常类型+消息，不整对象 ToString() |
| L21 | `MainViewModel.cs` | 286-296 | 完成后在 UI 线程递归扫描输出目录统计 .ptd 大小，大目录/网络盘时 UI 卡死 | 移到后台线程，完成后封送回 UI |
| L22 | `TaskNotificationWindow.xaml.cs` | 34-36 | DisplayArea.GetFromWindowId 返回值未判空，异常显示配置下可能 NRE | 判空并回退默认工作区 |
| L23 | `MainViewModel.cs` | 305-314 | 死代码 ParseProgress 中 int.Parse 未防护，未来接 stdout 时异常输出可触发 FormatException | 改 int.TryParse 或删除 |
| L24 | `MainWindow.xaml.cs` | 554-567 | 自定义背景图路径自由文本，填 http(s):// 会让应用出网请求 | 限制为本地文件路径（Uri.IsFile），拒绝远程 scheme |
| L25 | `PasswordDialog.xaml.cs` | 69-72 | 颜色解析硬假设 7 位 #RRGGBB，健壮性不足 | 解析前校验长度/格式，用 int.TryParse |

---

## 四、各模块审计结论

| 模块 | 高危 | 中危 | 低危 | 关键正面发现 |
|------|------|------|------|-------------|
| CLI 核心加密 | 0 | 3 | 6 | 随机数全 libsodium；nonce 递增无复用；路径双重校验；续传 HMAC 防重放；v6 DEK 包裹 |
| CLI 入口与配置 | 0 | 1 | 7 | 密钥/口令各返回路径均正确 sodium_memzero+SecureBuffer；无命令注入/格式化串；JSON 日志已转义 |
| GUI-Qt | 0 | 3 | 4 | 参数逐 QStringList 传递无 shell 拼接；密钥经 stdin 注入不进 argv；主口令路径已用 secure_zero |
| GUI-WinUI | 0 | 4 | 8 | 参数用 ArgumentList 正确转义；密钥经 stdin 注入；命令预览/任务历史/settings.json 均不含口令 |

---

## 五、修复优先级建议

### 第一优先级（直接影响机密性）
1. **中-2**：Windows .prt 明文文件 DACL 收紧 — 运行中明文可被同机其他用户读取
2. **中-1**：KDF 派生 vector 主密钥擦除 — 主密钥副本残留堆
3. **中-8**：WinUI StdinData 字节数组清零 — 口令明文驻留托管堆
4. **中-5**：Qt rewrap 新口令临时文件 0600 — 新口令明文落盘可读

### 第二优先级（供应链与数据完整性）
5. **中-6 / 中-9**：Qt/WinUI 下载 CLI 二进制 SHA256 校验 + 文件名净化
6. **中-3**：解密失败 .prt 覆写后再删除
7. **中-4**：run_recover 还原文件名 basename 净化

### 第三优先级（内存与资源一致性）
8. **中-7**：Qt PasswordDialog memset → secure_zero（一行修复）
9. **中-10**：WinUI Process.Dispose
10. **中-11**：WinUI 统计文件 CSPRNG 命名 + 独占打开

### 第四优先级（防御纵深，25 项低危按需排期）

---

## 六、已知基线（已修复，本次不重复报告）

- secure_zero.hpp 已在 2.4.4 补齐
- BufferPool release 不清零已在 2.4.4 修复
- force-decrypt 明文清零已改用 secure_zero
- 悬垂指针（salt_ptr）已在 2.4.2 修复
- v6 文件恒判 corrupted 已在 2.4.2 修复
- 白名单相对路径已在 2.4.3 修复
- rage 模式路径白名单绕过已在 2.1.2 修复

---

*本报告为纯静态审计结果，未修改任何源码。各 shard 详细报告见 security_audit_shard1.md ~ security_audit_shard4.md。*
