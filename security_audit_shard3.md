# FileEncryptor GUI-Qt 模块源代码安全审计报告（shard3）

- 审计范围：`E:\FileEncryptor\GUI-Qt\src\` 下全部 `.cpp/.h`（共 33 个文件）
- 审计日期：2026-09-27
- 审计方式：逐文件人工走读 + 危险 API 模式扫描（memcpy/strcpy/system/popen/rand/memset 等）
- 已排除的已知基线问题：secure_zero.hpp 补齐、BufferPool 清零、force-decrypt 清零、salt_ptr 悬垂、v6 corrupted 误判、白名单相对路径、rage 白名单绕过（均不重复报告）

---

## 一、总体结论

GUI-Qt 是一层 Qt 外壳，真正的加解密由同目录 `FileEncryptorCLI` 子进程完成，密钥经 stdin 管道注入、不进 argv/环境变量，命令行参数逐 `QStringList` 传递（无 shell 拼接）。整体安全设计意识较好：

- 未发现缓冲区溢出、数组越界、格式化字符串、空指针解引用、整数溢出类内存安全问题；
- 未发现硬编码密钥/口令/IV，未发现 `rand()` 类不安全随机数；
- 未发现 shell 命令拼接（`QProcess::setArguments` + 无 shell 启动）；
- 主口令路径在 `onRunClicked` / `onRewrapClicked` 中已用 `secure_zero` 正确擦除 `std::vector` 与 `QByteArray` 副本。

共发现 **3 个中危、4 个低危/信息性** 问题，无高危。按严重程度排序如下。

---

## 二、中危问题（Medium）

### M1. rewrap 新口令以明文写入可预测临时文件，未限制文件权限

- **文件**：`MainWindow.cpp`
- **行号**：1483–1501（写入），1695–1698（完成后删除），210–213（关闭兜底）
- **问题描述**：
  密钥轮换（rewrap）时，新口令 `newPw` 被直接写入临时文件
  `QDir::tempPath()/fileencryptor_rewrap_<pid>.key`（`QSaveFile` 默认权限），再以 `--new-key-file` 传给子进程。该文件存在三个问题：
  1. **权限未收紧**：`QSaveFile`/`QFile` 未显式设置权限位，类 Unix 平台下受 umask 影响通常为 `0644`，同机其他用户可读到此新口令明文；
  2. **文件名可预测**：仅以 PID 命名，位于共享临时目录，存在被预创建/符号链接占用（symlink race）的窗口；
  3. **崩溃残留**：正常路径下 `onCommandFinished`（1696）与 `closeEvent`（211）会删除该文件，但若进程被强杀/断电，明文新口令会永久残留在临时目录。
  这是本模块内唯一一处把口令明文落盘的位置。
- **修复建议**：
  - 写盘前用 `QSaveFile::setPermissions(QFile::ReadUserWriteUser)`（Unix 下等价 `0600`）；
  - 文件名追加随机后缀（如 `QUuid::createUuid().toString(WithoutBraces)`）而非仅 PID；
  - 写入后 `fsync`，任务结束（无论成功/失败/取消）立即 `unlink`，并在 `closeEvent`/析构中兜底（已部分做到，需确认异常路径）；
  - 若 CLI 支持 `--new-key-stdin` 之类通道，优先改为第二路 stdin 管道或 memfd，避免口令落盘。

### M2. 自动下载 CLI 二进制无完整性校验（供应链风险）

- **文件**：`CliNotFoundDialog.cpp`
- **行号**：76–169（下载流程），132–145（`pickCliAsset`），157–169（落盘）
- **问题描述**：
  当本机未找到 CLI 时，用户点击"下载 CLI"，GUI 从 `https://api.github.com/.../releases/tags/<tag>` 拉取 asset 列表，挑选第一个前缀为 `FileEncryptorCLI-*`、后缀为 `.exe` 的 asset，将其 `browser_download_url` 内容直接下载到外壳同目录（`selfDir()`），之后由 `FileEncryptorLocator` 定位并**直接执行**。
  全程：
  - 不校验 Release 附带的 SHA256/校验和文件；
  - 不校验代码签名；
  - 不做证书/公钥 pinning（仅依赖系统默认 TLS）。
  若 GitHub 账号/仓库或 CDN 被攻陷，攻击者可下发任意二进制，被用户以当前权限执行。对一款"加密工具"而言，自动拉取并执行未签名二进制会削弱用户对工具链根信任的假设。
- **修复建议**：
  - 发布流程中为每个 CLI 产物生成 SHA256 清单并随 Release 分发；GUI 下载后强制比对清单哈希，不匹配即拒绝落盘/执行；
  - 校验通过前先写到临时文件，校验通过再原子移动到 `selfDir()`；
  - 下载到 `selfDir()` 前提示用户该文件将被执行，并显示版本/大小；
  - 后续可考虑在 GUI 中内置 Release 公钥指纹做签名校验。

### M3. PasswordDialog 对临时口令 QByteArray 使用普通 `memset`（可被优化消除）

- **文件**：`PasswordDialog.cpp`
- **行号**：165–167
- **问题描述**：
  ```cpp
  QByteArray b = m_pw->text().toUtf8();
  m_secret.assign(b.begin(), b.end());
  memset(b.data(), 0, b.size());   // ← 普通 memset
  ```
  `b` 是仅持有本次口令 UTF-8 字节的局部 `QByteArray`。项目自建 `secure_zero()`（`secure_zero.h`，volatile 逐字节写）的目的，正是规避"`std::memset` 后对象即离开作用域、编译器将其判定为 dead store 而优化掉"这一类问题——本文件第 121 行注释也明确写了这一点。此处却对 `b` 使用裸 `memset`，与 `MainWindow.cpp:1404/1432/1524` 的修法不一致。开启优化后该次清零可能被消除，口令 UTF-8 字节残留在堆上直到被下次分配覆盖。
- **修复建议**：把第 167 行改为 `secure_zero(b.data(), size_t(b.size()));`，与全工程擦除策略统一。

---

## 三、低危 / 信息性问题（Low / Info）

### L1. 任务历史把敏感路径（含私钥文件路径）明文写入，且未收紧 Unix 文件权限

- **文件**：`TaskHistory.cpp`
- **行号**：30–48（`toJson` 写入字段），145–159（`append` 打开 `tasks.log`）；`TaskHistory.h:33–35`（`keyfile/recipient/identity` 字段）
- **问题描述**：
  历史文件 `%APPDATA%/FileEncryptor/history/tasks.log` 以 JSONL 明文记录 `inputPaths`、`outputDir`、`keyfile`、`identity`（私钥文件路径）、`recipient`。口令本身未入库（这是对的），但：
  1. 未显式设置文件权限。类 Unix 下受 umask 影响通常为 `0644`，同机其他用户可读，获知用户私钥文件位置与处理过的敏感文件路径；
  2. `identity` 字段是 AGE 私钥文件的绝对路径，属于定位敏感材料的元数据。
  Windows 上 ACL 一般继承用户目录权限，风险较低；Linux/macOS 上建议收紧。
- **修复建议**：
  - `append`/`save` 创建文件后调用 `QFile::setPermissions(ReadOwner|WriteOwner)`（Unix 等价 `0600`）；目录 `history/` 设为 `0700`；
  - 可选：`identity`/`keyfile` 仅存文件名而非绝对路径，或加开关让用户选择是否记录路径。

### L2. QString 口令副本未被擦除（Qt 容器限制）

- **文件**：`PasswordDialog.cpp`
- **行号**：143（`const QString pw = m_pw->text();` in `validate`），165（`m_pw->text().toUtf8()`）
- **问题描述**：口令在进入 `std::vector<unsigned char> m_secret` 之前，先以 `QString` 形式存在（`validate()` 的局部 `pw`、`onAccept()` 中 `m_pw->text()` 的临时返回值）。Qt 的 `QString` 不提供安全擦除 API，这些堆副本在析构后不会被清零。这是 Qt GUI 层的固有限制，影响范围仅限于口令在堆上的短暂驻留；主流程已在 `onAccept` 后清空输入框并把字节拷贝进 `m_secret` 再由调用方 `secure_zero`。
- **修复建议**：可接受现状；如要进一步降低残留，可在 `PasswordDialog` 关闭后对 `m_secret` 之外不再保留任何 `QString` 口令副本（现状已接近），并在文档中说明 Qt 字符串无法彻底擦除的限制。

### L3. 临时文件名可预测（PID 命名）

- **文件**：`MainWindow.cpp`
- **行号**：1263–1264（收件人临时公钥文件 `fileencryptor_recipients_<pid>.txt`），1483–1484（rewrap 新口令文件），1381（统计文件 `fe_stats_<pid>.json`）
- **问题描述**：三处临时文件均以 `<程序名>_<pid>.<ext>` 固定模板命名。收件人文件仅含公钥（非机密）、统计文件无敏感数据，风险低；rewrap 文件的问题已在 M1 单列。类 Unix 共享 `/tmp` 下固定命名存在符号链接抢占窗口（当前用户自己的 PID 目录下竞争难度较高，但仍属于不规范实践）。
- **修复建议**：统一改用 `QTemporaryFile`（随机名、关闭即删）或追加 `QUuid` 后缀。

### L4.（功能性缺陷，顺带报告）TaskHistory::prune 保留的是"最旧"而非"最新" N 条

- **文件**：`TaskHistory.cpp`
- **行号**：219–236（尤其 233 行循环）
- **问题描述**：
  `load()` 第 180 行 `std::reverse` 后 `out[0]` 为最新一条。`prune(1000)` 在记录数超阈值时按
  `for(int i=all.size()-1; i>=all.size()-keepLatest; --i)` 写回，写入的是 `all[size-keepLatest .. size-1]`，即**最旧的 1000 条**，丢弃了刚 append 的最新记录。功能上表现为历史超过 1000 条后新记录被立即裁掉。此为正确性 bug，不直接构成安全漏洞，但会影响审计取证/排障时看到的历史是否完整。
- **修复建议**：写回应为 `for(int i=keepLatest-1; i>=0; --i)`（最新在前的数组中取前 `keepLatest` 条、按时间正序写出）。

---

## 四、经核查未发现问题的文件

| 文件 | 结论 |
|---|---|
| `secure_zero.h` | volatile 逐字节写零实现正确，空指针/长度为 0 已保护。未发现问题。 |
| `CliArgBuilder.cpp/.h` | 参数逐 `QStringList` 传递，无 shell 拼接；口令走 stdin 不进 argv；预览仅展示且不参与执行。路径遍历校验委托子进程（基线已覆盖）。未发现问题。 |
| `ProcessCommandExecutor.cpp/.h`、`ICommandExecutor.h` | `QProcess` 逐参数启动、SeparateChannels、`write` 后 `closeWriteChannel`；`m_process` parented + `deleteLater`，资源释放正确；`emitFinished` 幂等。未发现问题。 |
| `FileEncryptorLocator.cpp/.h` | 仅按名探测可执行文件，无危险操作；版本号/URL 硬编码非密钥。未发现问题。 |
| `PasswordStrength.cpp/.h` | 纯长度/字符集统计，无内存操作；非 ASCII 放行属产品策略。未发现问题。 |
| `MainWindow.cpp/.h`（除 M1/L2/L3 外） | 口令 `pw`/`oldPw`/`newPw` 在 `onRunClicked`/`onRewrapClicked` 中均经 `secure_zero` 擦除；扫描线程用 `shared_ptr<const>` 不可变快照 + `atomic<bool>` 取消标志，无竞态；QSettings 仅存主题/几何/背景图路径，不存口令；输出区不打印口令明文。 |
| `TaskHistoryDialog.cpp`、`TaskSummaryDialog.cpp` | 表格展示与删除逻辑，无敏感数据新增泄露。未发现问题。 |
| `EtaEstimator.cpp` | 纯统计/格式化，除零已判断。未发现问题。 |
| `FontBootstrap.cpp` | 字体加载；`fc-cache` 经 `startDetached` 逐参数启动，无拼接。未发现问题。 |
| `MsgBox.cpp`、`ThemeManager.cpp`、`ViewSettingsDialog.cpp`、`AboutDialogs.cpp`、`BatchProgressPanel.cpp/.h`、`CliNotFoundDialog.h`、`EtaEstimator.h`、`FontBootstrap.h`、`MsgBox.h`、`TaskHistoryDialog.h`、`TaskSummaryDialog.h`、`ThemeManager.h`、`ViewSettingsDialog.h`、`AboutDialogs.h`、`BatchProgressPanel.h` | UI/主题/展示逻辑，无内存或凭据处理风险；`QString::asprintf` 均使用字面量格式串，无格式化字符串漏洞。未发现问题。 |
| `main.cpp` | 仅初始化与窗口显示。未发现问题。 |

---

## 五、15 项审计要点逐条对照

1. 缓冲区溢出/数组越界：未发现（全模块无 `memcpy/strcpy/sprintf` 类调用，Qt 容器自动管理边界）。
2. 密码/密钥内存清零：主路径已用 `secure_zero` 正确擦除（MainWindow 1404/1432/1524、PasswordDialog 析构 122）；**遗留 M3**（PasswordDialog 167 行裸 memset）。
3. 路径遍历：GUI 不自行解析输出写入，路径校验委托子进程（基线 2.4.3 已修复白名单）。
4. 命令注入：未发现；`QProcess` 逐参数、无 shell。
5. 整数溢出：未发现（计数均为 `qint64`/`int`，UI 小数值域）。
6. 未初始化变量：头文件成员均有类内初始化（`= nullptr`/`=0`/`=false`），`ShellOptions`/`TaskRecord` 字段全部初始化。
7. 竞态条件：扫描线程使用不可变快照 + 原子取消标志，`QFutureWatcher` 回主线程；未发现共享数据竞争。TOCTOU：临时文件符号链接问题见 M1/L3。
8. 硬编码密钥/密码/IV：未发现。
9. 不安全随机数：未使用 `rand()`；记录 ID 用 `QUuid`（OS RNG）。
10. 加密算法误用：GUI 不做加密，仅选择 `-m xchacha20/aegis256/rage` 开关，算法实现与 KDF 在子进程。
11. 空指针解引用：UI 指针均有判空（`if(m_xxx)`），未发现解引用风险。
12. 资源泄漏：`QProcess`/`QNetworkReply`/`QLabel` 均 parented 或 `deleteLater`；临时文件有删除路径（除 M1 崩溃残留窗口）。
13. 格式化字符串：未发现；`asprintf` 全为字面量。
14. 不安全文件权限：**见 M1（rewrap 临时口令文件）、L1（tasks.log）**。
15. 密码明文写入日志/配置/历史：口令本身未入历史/日志/配置；**M1 是唯一一处口令落盘（临时 key 文件）**；历史仅记录路径元数据（L1）。

---

## 六、修复优先级建议

1. **M3**（一行改动，立即修）：`PasswordDialog.cpp:167` 改用 `secure_zero`。
2. **M1**：rewrap 临时 key 文件权限 `0600` + 随机名 + 尽快 unlink。
3. **L1**：`tasks.log` 与 history 目录设为 `0600`/`0700`。
4. **M2**：CLI 自动下载增加 SHA256 校验（需要发布流程配套）。
5. L2/L3/L4 视后续版本安排。
