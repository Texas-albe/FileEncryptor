# ChangeLog - FileEncryptor GUI

本文件记录 **FileEncryptor GUI** 子项目的所有重要变更（图形界面 `FileEncryptorGUI(.exe)`）。
命令行子项目的变更记录请见 `../CLI/CHANGELOG.md`。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **GUI 与 CLI 拆分子项目的边界（自 2.1.0 起）**：
> - GUI 仅描述本项目自身的实现变更（界面、主题、图标、构建、依赖查找等）。
> - 加密核心 / 算法 / 磁盘格式 v4 / 续传 / YAML 配置 等行为变更请见 `../CLI/CHANGELOG.md`（CLI 是行为实现的承担者）。

## [1.4.1] - 2026-09-25

GUI 本体性能与代码质量优化（配套 CLI 期望版本仍为 2.4.1）。

### Performance
- **输出区无限增长限制**：拟 cmd 输出文档设 `setMaximumBlockCount(5000)`，长批量任务下不再无限累积文本拖慢渲染。
- **CLI 能力探测异步化**：`probeZstdSupport` 由主线程同步 `waitForFinished` 改为 QProcess `finished` 信号 + 单发 1s 超时定时器，避免界面卡顿（原超时 3s+kill 等待，现 1s）。
- **目录扫描缓存改为共享快照**：`scanInputs` 入参由值传递 `QHash` 改为 `shared_ptr<const QHash>`，每轮只增引用计数、不再整表拷贝（快照不可变，无竞态）。
- **进程清理等待降至 200ms**：`ProcessCommandExecutor::cleanup` 的 `waitForFinished(1000)` 降为 200ms，限制取消/析构路径阻塞。

### Fixed
- **进度帧锚点抗裁剪**：`renderFrameLine` 改用 `QTextBlock` 句柄锚定帧首块（随文档裁剪自动前移，块被裁掉则回退追加），修复 `setMaximumBlockCount` 裁剪后字符偏移锚点失效导致的残影/重复帧。
- **收件人临时文件仅运行时写入**：`resolveRecipients` 由 `collectOptions`（含 pending 扫描调用）移至 `onRunClicked` 运行时调用，避免非运行时残留临时公钥文件；预览在多收件人时显示「N 个收件人」而非临时文件路径。

### Refactored
- **`secure_zero` 抽到公共头**（新增 `src/secure_zero.h`），`MainWindow` 与 `PasswordDialog` 共用，消除两处重复实现。
- **`applyPanelTransparency` 抽公共字段 QSS 模板** `fieldCss`，输入框/输出框/数值框复用同一基础样式。
- **`AboutDialogs` 改用命名参数**（`%{bodyFg}` 等）替代位置占位符 `%1..%7`，提升可维护性。
- **`TaskHistory::append` 后自动 `prune(1000)`** 控制历史体积；删除 `filePath()` 冗余的 `d.isEmpty()` 检查。
- **`closeEvent` 兜底清理 `m_rewrapTempKey`**（轮换被中途关闭时不再残留临时密钥文件）。

## [1.4.0] - 2026-09-24

配套 CLI 2.4.0：新增密钥轮换界面、源文件安全处理选项，以及 AEGIS-256 非交互场景的弹窗警告。

### Added
- **「密钥轮换 (Rewrap)」动作**：运行按钮行新增「 密钥轮换」按钮，依次弹出旧口令与新口令输入框，
  经临时密钥文件把两者交予 CLI `--rewrap`（payload 不动，仅重裹 DEK）；运行结束后删除该临时文件。
- **源文件处理选项组**：加密动作下新增「加密后处理源文件」——可选项为「保留」「删除到回收站」
  「安全擦除」。对应 CLI `--recycle-source` / `--wipe-source`（保留 `-de` 直接删除）。
- **AEGIS-256 非交互弹窗警告**：选中 AEGIS-256 但本机 `--features` 探测到 `aegis=0` 时，
  启动前弹出 `QMessageBox::warning` 明确告知「当前 CPU 不支持 AES-NI，AEGIS-256 会极慢且抗侧信道能力弱，
  请改用 XChaCha20」，并中止任务；与 CLI 非交互「明确拒绝、不自动降级」行为保持一致。
- **zstd 压缩开关与级别解耦**：「压缩 (zstd)」勾选后下发布尔开关 `-zstd`（**不带任何参数值**，
  对应 CLI 新增的布尔别名），仅在级别非默认时追加 `--compression-level <N>`。此前只下发取值型
  `--compression-level`，不存在布尔开关，导致"开关型压缩参数"在 GUI 侧无从表达。

### Fixed
- **命令预览不刷新 / 停止刷新**：`refreshCommandPreview()` 原先用「输出区文本是否以 `>>>` 开头」
  作文本嗅探判据，一旦输出区先落盘了非预览内容（如任务历史写入失败警告），预览会永久停止刷新。
  改为运行态之外一律整块重绘预览。
- **`updateAsymVisibility()` 不再漏刷新**：该函数会改变压缩行显隐、模式、动作等影响 argv 的状态，
  但自身不触发预览重绘，各调用点需各自补一次——「手动重试 CLI 检测」就漏了，导致重定位 CLI 后
  预览仍显示旧路径。现改为在函数末尾统一触发一次 `refreshCommandPreview()`。

### Changed
- **版本号提升至 1.4.0**（配套 CLI 期望版本同步为 2.4.0）。

解密流程修复、界面异步解耦与实时进度（GUI 侧，配套 CLI 2.4.0 帧末行 `FILES ...`）。

### Added
- **状态栏实时计数条（常驻右侧）**：运行中以「当前: `<文件>` | 完成 `<x>/<y>` | 跳过 `<n>` | 失败 `<n>`」
  实时刷新；解析 CLI 批量进度帧末行 `FILES done/total SKIP n FAIL n` 与每线程槽位行（当前文件）、
  以及单文件模式的 `Encrypting:/Decrypting:`、`Skipped:`、`Failed: ... (skipped, continuing ...)`、
  `Skipped N non-.ptd file(s)` 行；空闲时展示「待处理: N 个文件 / 体积」（复用 `EtaEstimator::formatBytes`）。
- **目录规模统计异步化**：`recomputePending()` 改为"防抖登记 + `QtConcurrent` 工作线程递归扫描"，
  新增 `QFutureWatcher<ScanResult>`、`std::shared_ptr<std::atomic<bool>>` 跨线程取消标志、
  按输入路径的目录扫描结果缓存 `m_dirCache`；勾选/取消条目等高频输入变化经 180ms 防抖合并为一次扫描，
  命中缓存的输入直接复用，不再重复递归遍历整个目录（此前上万文件目录同步扫描会卡住界面数百毫秒以上）。
- **批量进度帧节流渲染**：CLI 每 40ms 一帧，GUI 合并到 ~120ms 渲染一次（`m_frameTimer` 单发 120ms），
  避免高频整帧替换 + 滚动把界面拖慢（表现为"程序在跑但界面半天无响应"）。

### Fixed
- **解密失败不中断整批任务 + 实时可见**：密码错误文件经 CLI 打印红色 `Failed: ... (skipped,
  continuing with remaining files)` 并继续后续文件，GUI 实时累加「失败」计数，不再让界面看似卡死。
- **任务结束终态汇总**：`onCommandFinished` 在收尾前刷出节流中最后一帧，并在摘要行追加
  `（完成 x / 跳过 y / 失败 z）`；源文件集合变化（部分被删/移回收站）后作废扫描缓存并重新统计待处理规模。
- **任务历史落盘计数为准**：`filesDone` 优先采用帧/逐文件精确计数（`m_doneFiles`），无帧场景回退到文件开始标记数。

### Changed
- 链接新增 `Qt6::Concurrent`（静态库，随 `third_party/smelibs` 分发）；`find_package` 补 `Concurrent` 组件。
- `MainWindow` 析构中先置扫描取消标志再 `waitForFinished()`，避免工作线程在窗口析构后访问已释放对象。

---
## [1.3.0] - 2026-09-19

本次版本重构批量进度的呈现方式，并下线密钥库 GUI（功能改由 CLI 密钥库 `-L` 承担），配套 CLI 2.3.0。

### Added
- **【批量进度面板】拟命令行上部固定展示**：新增 `BatchProgressPanel`（独立文件，与 CLI `core/progress_frame.cpp` 格式化 / 列宽算法一一对应），仅在批量模式（`-be` / `-bd`）可见，固定在输出区上部。其汇总行 + 每线程行结构与 CLI 终端帧完全一致：字段顺序、分隔符（` | `）、自适应单位（B / KB / MB / GB / TB）与空闲行占位均对齐，GUI 直接整帧渲染 CLI 输出的进度帧（不进输出区，避免刷屏）。
- **扩展名收敛（与 CLI 一致）**：任务历史 `tasks.jsonl` → `tasks.log`、密钥库索引 `library.yml`；配置文件按 CLI 行为搜索 `fileencryptor.yml`（旧 `fileencryptor.yaml` 读取时回退）。
- **YAML 文件后缀回归 `.yaml`（与 CLI 同步）**：配置编辑入口优先查找 `fileencryptor.yaml`，新写默认配置同样生成 `.yaml`（旧 `.yml` 名读取时仍兼容）。
- **「生成校验单 (--sha256)」选项**：加密动作向 CLI 下发 `--sha256`，成功后生成 `<输出名>.ptd.sha256` 校验单（CLI 侧后缀同步恢复）；解密动作不下发。
- **目录输入自动转批量**：单文件动作（`-e` / `-d`）下加入目录（拖放或选择）时，自动切换为对应批量动作（`-be` / `-bd`）并提示，避免 CLI 以目录输入拒绝整次任务。
- **任务历史回放恢复输入路径**：历史记录保存输入文件 / 文件夹的原路径，回放（双击回填）时将它们恢复到输入列表原位，命令补全即用；旧记录无路径字段，行为不变。
- **压缩行显示逻辑与级别框可用性修复**：行首标题「压缩 (zstd)」此前未纳入显隐逻辑，解密 / 批量解密 / 密钥动作下残留显示，现整行（标题 + 勾选框 + 级别框）仅随「加密 / 批量加密」（对称模式）显示；级别框不再随勾选态或 zstd 探测结果禁用，行可见即可直接键入修改（CLI 无 zstd 时仅以 tooltip 提示，参数不下发由 `CliArgBuilder` 兜底）；数值框移除上下按钮，保留键入与键盘 ↑/↓ 微调，样式与输入框一致。
- **【zstd 压缩适配】压缩开关 + 级别选择**：中部新增「压缩 (zstd)」行（`-z` 勾选框 + 级别 SpinBox，范围 `-5..22`、默认 3，级别范围与 CLI `--compression-level` 一致：1..22 常规 / -1..-5 快速档）。仅对称加密动作显示，解密 / 非对称 / 密钥动作自动隐藏（含行首标题）；启动与手动重试 CLI 检测时经 `FileEncryptorCLI --features` 探测 zstd 能力（解析 `zstd=1/0`），CLI 无 zstd 时以 tooltip 提示更换 CLI（控件保持可用，压缩参数不下发）。勾选后 `CliArgBuilder` 仅在「对称 + 加密」场景向 CLI 下发 `--compression-level <N>`（命令预览同步展示，纯整数值不加引号），与 CLI 校验规则双重兜底。

### Changed
- **【工具菜单】精简为「任务历史」**：移除「密钥库管理」与「批量 ETA」两项。批量 ETA 不再作为任务列表的一部分，改由批量进度面板在上部区域实时呈现；任务历史面板不再内嵌 ETA 预估区。
- **批量进度帧内嵌到拟 cmd 输出区（独立面板下线）**：帧式进度（汇总行 + 每线程一行）直接写入拟 cmd 输出流，随执行过程逐帧覆盖刷新，不再渲染在输出区上方的独立 `BatchProgressPanel`；空闲态不再显示「TOTAL 0 B / ETA --:--」占位行，进度只在执行过程中出现。帧定位采用文档字符区间（替换前自校验帧首字符，失效时自动回退为追加），避免光标锚点随文本编辑漂移导致进度行越刷越多；帧块与后续普通输出以换行隔离，COLUMNS 帧宽按输出区等宽字符宽度注入。
- **拟 cmd 滚动条样式**：输出框的部分样式表会让 `QAbstractScrollArea` 的原生滚动条退化为样式表基元绘制（Windows 上表现为滑块与箭头按钮重叠），现显式接管滚动条样式：移除箭头按钮，仅保留圆角滑块，配色随主题联动。
- **拟 cmd 显示优化**：输出区禁止自动折行（超宽行横向滚动兜底），最小高度提升至 360px、垂直分割默认比例调整为 520:380，容纳「1 汇总行 + N 线程行」整帧；路径缩写由 CLI 侧配合（只缩目录、完整保留文件名，极端情况才缩短文件名并保留扩展名）。
- 批量 ETA 口径随之调整：运行中的 ETA 由 CLI 进度帧直接给出（内嵌于输出区帧内）；空闲态预估不再展示。

### Removed
- **下线 GUI 密钥库（`KeyLibrary` / `KeyLibraryDialog`）**：密钥库管理入口整体移除（中部「密钥库...」按钮、工具菜单项、路由与全部源文件），相关死代码一并清除。密钥库管理改由 CLI `-L` 子命令承担；GUI 任务历史配置目录改用与 CLI 同源的用户配置根（不再依赖 `KeyLibrary::dir()`）。

## [1.2.2] - 2026-09-18

本次为功能与交互增强版本（GUI 自身版本序列保持 1.2.2，配套 CLI 2.2.0，见 `../CLI/CHANGELOG.md`）。

### Added
- **【功能1·GUI】密钥库 / 身份管理**：新增密钥库管理（「密钥管理」行「密钥库...」按钮常显 + 工具菜单「密钥库管理...」入口，不再藏于默认隐藏的非对称组内），集中管理本机 age 身份与收件人：列出名称 / 类型 / 别名 / 创建时间 / 备注 / 缓存公钥，支持导入（自动识别身份与收件人，身份导入时经 CLI `-Y` 自动派生并缓存公钥）、移除、导出与一键复制公钥；选中条目可直接「应用为收件人」（公钥串并入收件人框，配合多收件人通道）或「应用为身份」（私钥文件路径填入身份框）。存储与 CLI 共用 `<用户配置目录>/keys/`（索引 `library.yaml` + 每密钥一个材料文件），两端任一端导入的密钥对另一端立即可见；材料文件权限收紧为仅拥有者可读。
- **【功能4·GUI】文件 / 目录拖放加入输入列表**：把文件或目录从资源管理器拖进主窗口即加入左侧文件列表（自动去重、默认勾选、刷新命令预览），目录同样支持（配合批量动作 `-be` / `-bd`）。
- **【功能8·GUI】多收件人输入**：非对称加密的收件人框支持逗号 / 分号分隔的多个 `age1...` 公钥串，GUI 自动写出临时公钥文件走 CLI 的 `-r` 文件通道（文件内容仅公钥，非机密，退出时清理）；单条目行为不变（公钥串或公钥文件路径二选一）。
- **【功能11·GUI】取消保留已完成输出并汇总**：点击「取消」后不再只显示退出码——按 CLI 的文件开始标记统计，明确提示"已保留 N 个已完成文件的输出，重跑同一任务将从 `.progress` 续传未完成部分"，避免用户误以为已完成的文件也被丢弃。
- **【功能5·GUI】任务历史面板**：新增 `TaskHistory`（持久化层）与 `TaskHistoryDialog`（界面），记录每次运行的任务 id、起止时间、耗时、动作（`-e/-d/-be/-bd/-g/-G/-Y`）、加密模式、输入路径数、输入字节总量（目录递归统计）、已完成文件数、输出目录、退出码、是否取消、错误信息与结果（成功 / 失败 / 已取消）。存储为 `<用户配置目录>/history/tasks.jsonl`（JSONL 追加写，每行一条独立 JSON，单条损坏不影响其余条目；路径与密钥库同根并统一为系统原生分隔符）。面板按时间倒序列出全部记录并显示吞吐与统计（成功 / 失败 / 取消计数），支持刷新、清空（二次确认）与**双击回放**（把该次任务的动作、加密模式、输出目录回填主窗口，输入路径仍需用户自行选择）。入口：工具菜单「任务历史与批量 ETA...」+ 输出区标题行「任务历史...」按钮。
- **【功能6·GUI】批量 ETA 面板**：新增 `EtaEstimator`——取历史中「完整成功」记录的吞吐**中位数**（抗单次异常值），按 `动作+模式 → 动作 → 全体` 三级分层取样（最多最近 10 条）预估当前输入的处理时间；运行中再按「已完成文件数 / 总数」实时外推，并与历史预估按进度加权融合，每秒刷新。样本不足时明示「暂无历史样本」而非给出臆测数字。界面两处呈现：输出区标题行右侧 ETA 指示条（空闲=历史预估，运行中=已用时间 / 完成数 / 剩余），以及任务历史面板顶部的 ETA 预估区（数据量、预估耗时、参考吞吐、样本数）。

### Fixed
- **【路径·GUI】密钥库路径分隔符统一为系统原生格式**：`KeyLibrary::dir()` / `indexPath()` 及全部密钥材料路径拼接结果统一经 `QDir::toNativeSeparators()` 归一化；消除 `%APPDATA%`（原生反斜杠）与代码拼接 `/` 混用产生的混合分隔符路径（与 CLI 侧 `to_native_path()` 修复配套，两端共用同一密钥库目录）。
- **【主题·GUI】「密钥库...」按钮纳入主题化按钮样式**：该按钮此前未被纳入 `applyPanelTransparency()` 的按钮样式循环，浅色主题下回落默认深色渲染，与整体主题不符；现已与浏览/设置等按钮一致随浅色 / 深色主题正确着色（初始化与主题切换时均会刷新）。
- **【缺陷3·GUI】命令预览引号策略重写**：原先靠"参数字符串与 ShellOptions 成员逐一比对"决定是否加引号，既会在等值撞车时重复判定，也无法覆盖未来新增的取值 flag；改为按位置判断（上一项是 `-o` / `-i` / `-k` / `-r` / `--salt` 则当前项为路径值）并统一对含空格、制表符或内嵌双引号的参数加引号与转义。实际执行仍走 `buildArguments()` 由 `QProcess` 逐参数传递，不经过引号层。
- **【缺陷8/9·GUI】口令输入框回归标准 QLineEdit**：删除自绘的 `EyeLineEdit`（完全接管 `paintEvent` 会绕开输入法预编辑、选区高亮、长文本滚动与 RTL，深色主题还需自配文字色）；「小眼睛」改用 `QLineEdit::addAction(TrailingPosition)` 尾部动作，由控件自行排布并处理文本避让，替换原先把 QHBoxLayout 塞进 QLineEdit 加手工 `setTextMargins` 的写法。掩码字符随系统主题（圆点），点击眼睛在显示 / 隐藏间切换。
- **【缺陷10·GUI】`finished` 信号防重复发射**：崩溃等场景下 `errorOccurred` 与 `finished` 可能先后到达、`errorOccurred` 亦可能多次触发，此前每条路径都会走 `emitFinished`，上层把一次任务当成两次结束（进度条提前归零、取消按钮状态错乱）。现以 `m_finishedEmitted` 保证每次 `execute()` 至多发一次。
- **【缺陷17·GUI】HTML 调色板从 QPalette 派生**：正文 / 背景 / 代码块 / 弱化文字色此前在 `buildXxxPalette()`（QColor）与 `htmlPalette()`（十六进制串）各维护一份，已出现 `mutedFg` 与 `PlaceholderText` 漂移；现统一从 QPalette 生成，仅深色下刻意更亮的强调色（标题绿 / 蓝、链接）保留独立定义。
- **【缺陷18·GUI】版本号单一来源**：`main.cpp`（1.2.1）、`MainWindow` 标题（1.2.1）、`AboutDialogs`（1.0.1）三处兜底版本互不一致；新增 `FileEncryptorLocator::guiVersion()` 作为唯一来源，三处统一读取；CLI 期望版本与候选文件名同样收敛到 `getExpectedNames()`（由 `version()` 派生），`locate()` 不再维护第二份硬编码列表。

### Changed
- **【中·GUI】密钥库入口改为常显**：原「密钥库...」按钮放在非对称加密组内，而该组默认隐藏，只有切到非对称模式才能看到。现移至「密钥管理」行常显，并在「工具」菜单增加「密钥库管理...」入口。
- **【中·构建】静态 Qt 随仓库分发**：smelibs 静态 Qt 分发放入仓库根 `third_party/smelibs/`，Windows 构建的 `CMAKE_PREFIX_PATH` 优先使用该目录，回退 `C:/Program Files/smelibs`。
- **【中·版本】GUI 版本号保持 1.2.2（沿用自身版本序列，不与 CLI 对齐）**：`project(FileEncryptorGUI VERSION 1.2.2)`、`FileEncryptorLocator::guiVersion()`；CLI 探测期望版本维持 2.2.0（`version()`）。

## [1.2.1] - 2026-09-12

### Changed
- **【高·GUI】统一弹窗模块 `MsgBox`**：封装警告 / 提示 / 错误 / 确认四类弹窗，提供 `title + content + 可选回调` 的可复用调用（`warn/info/error/confirm/show/showAsync`），风格与 ThemeManager 一致，项目内复用、调用方式统一（替换散落的 `QMessageBox::*`）。
- **【高·GUI】口令改为运行时安全弹窗输入（PIN 风格）**：移除主页面常驻密码框；点击「运行」后经 `PasswordDialog` 输入——密码框右侧（框内）放置「小眼睛」按钮（透明背景与文本框一致），**按住显示明文、松开恢复掩码**，掩码以 `*` 表示（`EyeLineEdit` 自绘：QLineEdit 无 `setPasswordCharacter` 接口），图标在睁眼 / 闭眼间切换；加密 / 派生要求二次确认并校验口令策略，口令不经 QString 常驻、用完即擦除，经 stdin 注入子进程不落盘。
- **【中·GUI】移除主页面独立口令提示区**：删除右栏「口令」提示面板，中央选项面板自然占满横向空间，布局更连贯；密钥文件占位文案同步更新为「运行弹窗输入」。
- **【低·GUI】清理无用代码**：删除 `CliArgBuilder` 中不可达的 `KeyGen`/`Derive`/`PubKey` switch 分支（上方已提前 return）；移除从未赋值的 `ShellOptions::password` 字段及其预览占位逻辑。
- **【低·GUI】命令预览路径统一加双引号**：`buildPreview` 对程序路径与全部路径类参数（`-o`/`-i`/`-k`/`-r` 值）无条件用双引号包裹，不再仅对含空格路径加引号，规范且防路径注入/歧义。

### Fixed
- **【中·GUI】补齐口令策略并对 GUI 路径生效**：`PasswordStrength::meetsPolicy` 与 CLI 策略对齐（最小长度 8、至少 2 类字符或 ≥16；非 ASCII 放行），GUI 提交前校验，拒绝弱口令与两次不一致。
- **【中·GUI】修复模拟 CMD 进度条显示异常**：`ProcessCommandExecutor` 按 `\r` 切分进度帧、`OutputLine` 新增 `isProgress`，GUI 原地刷新上一行而非重复追加，消除末尾进度行重复堆积 / 清屏异常。
- **【中·GUI】收紧口令内存处理**：口令存于 `std::vector<unsigned char>`（非锁页 QString），`accept` 后清空输入框明文、`takePassword` 移动出缓冲，运行后擦除 stdin 副本，降低被 dump 风险。
- **【低·安全·GUI】口令擦除改为抗优化写入**：`std::memset` 紧跟 `clear()` 会被编译器判定为 dead store 而整段优化掉（审计问题 9）；改用 `secure_zero()`（volatile 逐字节写零）擦除 `PasswordDialog` 内部缓冲与 `MainWindow` 的口令向量。`QByteArray::clear()` 只减引用不清零，`stdinData` 释放前先逐字节写零。
- **【低·GUI】CLI 版本探测同步至 2.1.2**：`FileEncryptorLocator::version()` 与候选文件名更新，避免旧探测名优先命中已被隔离的旧版 CLI。

## [1.2.0] - 2026-09-12

### Added
- **【中·GUI】新增「口令派生密钥对 (-G)」动作**：用右侧口令经 Argon2id 确定性派生 X25519 密钥对；口令经子进程 stdin 管道注入（不经 argv / 环境变量），需要 ≥6 字符。输出公钥打印到输出面板，私钥与随机盐分别写入 `rage_private.txt` / `rage_derive_salt.txt`。
- **【中·GUI】新增「导出公钥 (-Y)」动作**：选择已有私钥文件，反推并打印对应 `age1...` 公钥（等价 `rage-keygen -y`）。
- **【中·GUI】非对称（age / X25519 混合）加密模式**：模式下拉新增「非对称加密 (age / X25519)」，加密填收件人公钥文件、解密填身份私钥文件。
- **【中·GUI】新增「Generate keypair (-g)」动作**：选中后无需输入文件 / 密码，只需输出目录；公钥打印在输出面板，私钥写入该目录的 `rage_private.txt`。

### Changed
- **【中·版本】版本号同步至 1.2.0**：`project(FileEncryptorGUI VERSION 1.2.0)`、`setApplicationVersion("1.2.0")`。
- **【中·GUI】移除主题切换中的"跟随系统"选项**：主题下拉框仅保留「浅色 / 深色」两态；默认主题改为浅色，旧"跟随系统"持久化值（0）自动迁移为浅色；`ThemeManager` 移除 `System` 枚举值与 `detectSystemDark()` 系统暗色探测逻辑。
- **【中·GUI】非对称加密界面浏览按钮中文化并适配主题**：收件人公钥 / 身份私钥的浏览按钮文案由 `Browse...` 改为中文 `浏览...`，并将这两个按钮纳入主题样式循环，确保随浅色 / 深色主题正确着色。
- **【中·GUI】rage 相关文案改回中文**：模式项改为「非对称 rage（X25519 + ChaCha20-Poly1305）」，非对称分组、公钥/私钥行标签与占位提示、文件选择框、缺密钥等校验提示全部中文化；原理说明改为中文（随机文件密钥用 X25519 公钥封装，加密只要公钥、解密才要私钥）。
- **【中·GUI】三个 rage 密钥动作共用同一说明区**：`-g` / `-G` / `-Y` 的说明分组标题与正文随选中动作动态切换，并按动作只显示需要的输入行（`-Y` 只留私钥行），同时禁用与动作无关的「加密模式」下拉。：模式名显示为 `Asymmetric - rage`；公钥框（`-r`）可直接粘贴 `age1...` 公钥字符串或选公钥文件，私钥框标注为 `-k` 私钥文件。
- **【中·GUI】非对称解密改用 `-k` 传私钥**：不再把身份私钥内容读入后写入子进程 stdin，改为把私钥文件路径作为 `-k` 传给 CLI；非对称模式下不再向子进程注入任何 stdin 数据。

### Security
- **【高·密钥通道】GUI 不再经环境变量注入密钥**：对称密码与非对称身份私钥一律经子进程 **stdin 管道** 注入（CLI 侧 `--key-stdin` 读取），避免被 `/proc` 或环境窥探；`CliArgBuilder::buildEnvironment` 仅返回系统环境，不再写入 `ENCRYPTOR_KEY`。

## [1.0.1] - 2026-09-06

### Added
- **【中·GUI】菜单栏新增"编辑"菜单**：顶层菜单（与"关于"同处一行），"编辑 YAML 配置..."按 CLI 的搜索顺序（`FILEENCRYPTOR_CONFIG` 环境变量 → CWD → CLI exe 目录 → 用户配置目录）定位 `fileencryptor.yaml`，未找到时在 CWD 生成与 CLI 一致的默认模板，再经 `QDesktopServices::openUrl` 调用系统默认编辑器打开。
- **【低·项目】根目录新增项目概览 README**（`../README.md`）：项目用途、CLI/GUI 目录结构、快速构建与跨平台要点。

### Changed
- **【中·GUI】主题切换与视图设置移入菜单栏**：原独立顶部工具栏（导航栏）取消，"主题"下拉框（跟随系统/浅色/深色）与"视图设置"按钮经 `QMenuBar::setCornerWidget` 置于菜单栏右上角，与"关于"同一行显示。
- **【低·版本】版本号同步至 1.0.1**：`project(FileEncryptorGUI VERSION 1.0.1)`、`setApplicationVersion`、窗口标题、鸣谢/README 摘要对话框兜底值、README 程序版本声明。

## [1.0.0] - 2026-09-05（GUI 独立子项目首版）

> **版本号重置说明**：GUI 拆分为独立子项目后版本序列重新开始（2.0.0 → 1.0.0），1.0.0 为 `GUI/` 独立子项目的首个正式版本，与 `../CLI/` 版本号解耦、不再跟随 CLI 同步升级。

### Changed
- **【高·架构】项目独立化为 GUI 单一子项目**：本仓库原为「CLI + GUI 统一项目」（共享 `core/`），现拆分为两个独立构建单元：CLI 在 `../CLI/` 独立编译产出 `FileEncryptorCLI(.exe)`；GUI 在本目录独立编译产出 `FileEncryptorGUI(.exe)`，运行时通过 `QProcess` 调用 CLI。本 GUI 不再包含 `add_subdirectory(gui)` / 顶层 libsodium / yaml-cpp 查找逻辑，CMakeLists/CMakePresets/README/LICENSE 各自维护。
- **【高·依赖】Qt6 改为完全静态链接**：原项目依赖系统 Qt6（动态 `.dll` / `.so`）；现改为链接静态 Qt6（`C:/Program Files/smelibs` 这种预编译静态 Qt 分发，`Qt6::Core` 等为 `STATIC IMPORTED`）。Qt6Core / Qt6Gui / Qt6Widgets 主库及 Qt6Bundled* 捆绑依赖（Qt6BundledFreetype / Qt6BundledHarfbuzz / Qt6BundledLibjpeg / Qt6BundledLibpng / Qt6BundledPcre2）全部静态链接进 exe。
- **【高·构建】Qt 平台插件与图像格式插件静态导入**：`src/main.cpp` 通过 `#include <QtPlugin>` + `Q_IMPORT_PLUGIN` 静态导入 `QWindowsIntegrationPlugin`（Windows 平台抽象）、`QJpegPlugin` / `QGifPlugin` / `QICOPlugin`（图标 / 资源加载所需图像格式）。运行时无需 `platforms/qwindows.dll` / `imageformats/qjpeg.dll` 等任何 Qt 插件 DLL。
- **【中·运行时】CLI 查找路径简化**：`FileEncryptorLocator` 不再向上多级查找 `../bin/`、`../../bin/`、`../build_test/` 等统一项目布局路径，改为三段查找：`FILEENCRYPTOR_EXE` 环境变量 → GUI exe 同目录 → `PATH`。适配 CLI/GUI 独立项目结构。
- **【中·构建】CMakePresets 简化**：移除无关的 Linux / macOS Ninja 预设的 cacheVariables，VS2026 预设默认 `CMAKE_PREFIX_PATH="C:/Program Files/smelibs"`（用户提供的静态 Qt 分发）。
- **【低·版本】版本号同步至 1.0.0**：`project(FileEncryptorGUI VERSION 1.0.0)`、`setApplicationVersion("1.0.0")`、窗口标题 `FileEncryptorGUI 1.0.0`、鸣谢 / README 摘要对话框的版本号兜底值、README 程序版本声明。
- **【低·GUI】鸣谢名单角色调整**：Twilight飞友 由「测试」改为「宣传」；「测试」项下保留 就不错了我。
- **【高·跨平台】Qt 插件静态导入加 `QT_STATIC` 守卫**：`src/main.cpp` 的 `Q_IMPORT_PLUGIN(...)` 原只按 `Q_OS_WIN` / `Q_OS_LINUX` / `Q_OS_MACOS` 区分，在 **共享 Qt**（Linux 发行版默认）下会因找不到插件类而编译失败。现统一用 `#ifdef QT_STATIC` 包裹：静态 Qt（如 smelibs）下照旧编译期链入平台 / 图像插件，共享 Qt 下由 Qt 运行时加载插件，同一份源码两端都能构建。
- **【中·跨平台】子进程输出按 UTF-8 解码**：`ProcessCommandExecutor` 原用 `QString::fromLocal8Bit` 解析 CLI 输出，Windows 下按系统代码页（GBK）、Linux 下按 locale 解码，会把 CLI 的 UTF-8 中文提示解成乱码。改为 `QString::fromUtf8`（CLI 已 `SetConsoleOutputCP(CP_UTF8)` 且全程 UTF-8 输出）。
- **【低·构建】`CMAKE_PREFIX_PATH` 不再无条件追加 Windows 静态 Qt 路径**：`CMakeLists.txt` 仅在 `WIN32 AND EXISTS "C:/Program Files/smelibs"` 时加入该前缀，Linux 下用系统 / 发行版 Qt（`CMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake` 等）。
- **【低·GUI】对话框 HTML 字体族补充 Linux 中文字体**：`"Microsoft YaHei"` 之后追加 `"Noto Sans CJK SC"`，避免 Linux 下中文回退到无 CJK 字形的字体。

### Fixed
- **【高·GUI】Linux 下界面中文显示为方块（豆腐块）**：Linux 最小化 / 无中文字体环境里，Qt 默认字体（DejaVu Sans 等）不含 CJK 字形，中文全渲染成 □。新增 `src/FontBootstrap.{h,cpp}`：启动期依次尝试「环境变量 `FILEENCRYPTOR_UI_FONT` 显式指定 → 系统默认字体已含中文（Windows/macOS 走此分支）→ 系统候选清单挑含中文字体 → 构建期嵌入的 Noto Sans SC（`GUI/fonts.qrc` 仅非 Windows 嵌入 exe）」，命令输出窗口经 `FontBootstrap::monoFont()` 取含中文的等宽字体（无则退回界面字体，宁可不等宽也不出方块）。嵌入字体文件 `GUI/fonts/NotoSansSC-Regular.otf`（Noto Sans SC，SIL OFL 许可）仅 Linux/macOS 构建打进 exe，Windows 由系统 YaHei 覆盖故不嵌入以控制体积。

### Added
- **【中·构建】CPack 打包 DEB / RPM**：`CMakeLists.txt` 在 `if(UNIX)` 下加入 CPack 配置（与 CLI 对齐）：包名 `file-encryptor-gui`、安装前缀 `/usr`、生成器 `DEB;RPM`；DEB 关闭 `CPACK_DEBIAN_PACKAGE_SHLIBDEPS` 且 `Depends` 清空，RPM 关闭 `AUTOREQ`/`AUTOREQPROV`，确保静态 Qt6 + 嵌入字体下包零运行时依赖声明（自包含）。DEB/RPM 为 Unix 专属，配置用 `if(UNIX)` 守护，Windows 构建不受影响。生成命令：`cmake --build --preset linux-release` 后于构建目录 `cpack`。

### Changed
- **【中·GUI】导航栏主题切换（原“视图”菜单移除）**：顶部新增导航栏（QToolBar），以 `QComboBox` 提供「跟随系统 / 浅色 / 深色」三模式切换，替代原“视图(&V)”菜单中的主题选项（已删除）。`ThemeManager` 改为单例（`instance()`），`setTheme` 时发射 `themeChanged(bool)` 信号，导航栏下拉框与面板半透明底色随之同步。
- **【中·GUI】自定义背景图（视图设置）**：新增 `ViewSettingsDialog`，用户可选图片作主窗口背景（预览 + 清除）。主窗口以铺满底图（QLabel，`KeepAspectRatioByExpanding`）+ 面板半透明（`rgba` 约 0.82，随主题变底色）呈现；选定图片后窗口按图片比例拉伸/缩小（约束在屏幕 90% 内、高 480–900）。背景图路径（键 `backgroundImage`）与窗口几何（`saveGeometry`/`restoreGeometry`，键 `geometry`）经 QSettings 持久化，重启后保持生效。

### Fixed
- **【中·GUI】CLI 重命名后 GUI 识别不到**：`FileEncryptorLocator::locate()` 原仅按固定名 `FileEncryptorCLI(.exe)` 查找，重命名 CLI（如改为 `FileEncryptor.exe`/`fe.exe`）即失效。现按候选名列表 `FileEncryptorCLI` / `FileEncryptor` / `file-encryptor-cli` / `fe`（Windows 加 `.exe`）在“同目录 + PATH”两段依次探测，任一命中即返回。

## [2.0.0] - 2026-09-05（标题栏图标 / 版本号同步 / 主题切换）

> GUI 主版本号升级（1.7.2 → 2.0.0）。GUI 行为零变更（仅是项目结构 / 图标 / 主题 / 版本号层面的里程碑）。

### Added
- **【中·GUI】颜色主题切换**：新增 `ThemeManager`，支持「跟随系统 / 浅色 / 深色」三态切换，经 QSettings 持久化用户偏好，启动期在主窗口构造前应用。深色调色板文字对比度满足 WCAG AA（stdout #E6E6E6 对 #1E1E1E 底 ≈ 13:1，stderr #FF8A80 ≈ 5.4:1），修复此前深色模式下文字与背景过近不可读的问题。
- **【中·GUI】应用图标**：`logogui.ico` 嵌入 GUI exe（Windows .rc 资源）；GUI 经 Qt 资源（`:/icons/app.ico`）`setWindowIcon` 设置窗口标题栏图标，三端统一渲染。

### Changed
- **【中·版本】全量版本号同步至 2.0.0**：`FE_VERSION_*` 宏、`project(FileEncryptorGUI VERSION 2.0.0)`、`setApplicationVersion`、`FileEncryptorGUI 2.0.0` 窗口标题、关于对话框（鸣谢 / README 摘要标题均含版本号，取自 `qApp->applicationVersion()` 单一真相源）、README 程序版本声明。
- **【低·GUI】命令输出窗口高度优化**：下部命令浏览窗口高度缩减为原来的一半，给主功能区更多空间。

## [1.7.2] - 2026-09-05（GUI 行为无变更）

> GUI 项目版本号随 CLI 同步升级（1.7.1 → 1.7.2）。本期无 GUI 行为变更，仅跟随 CLI 版本号。

## [1.7.0] - 2026-09-04（GUI 行为无变更）

> GUI 项目版本号随 CLI 同步升级（1.6.0 → 1.7.0）。本期无 GUI 行为变更。

## [1.6.0] - 2026-08-27（GUI 行为无变更）

> GUI 项目版本号随 CLI 同步升级。本期无 GUI 行为变更。

## [1.0.0-rc1] - 2026-08-20（首版 GUI 引入 / 整合为统一项目）

> GUI 子项目首版。架构设计：CLI + GUI 整合为统一项目，共享 `core/` 加密核心；GUI 通过 `QProcess` 调用 `FileEncryptorCLI.exe` 执行实际加解密。

### Added
- **【高·架构】CLI + GUI 整合为统一项目**：项目重构为 `core/`（共享加密核心：FileEncryptor.cpp / config.cpp / secure_buffer.hpp）+ `cli/`（命令行入口 main.cpp）+ `gui/`（Qt6 图形界面）三子目录。`FileEncryptorCLI.exe` 链接 core 全部加密逻辑（libsodium + yaml-cpp 静态，完全独立自包含）；`FileEncryptorGUI.exe` 通过 QProcess 调用 CLI 执行实际加解密。加密核心零重复（只在 core/），CLI 完全独立不依赖 Qt，GUI 运行时依赖 FileEncryptorCLI.exe。此架构由 Qt6 /MD 与 libsodium /MT 的 CRT 冲突（LNK2038）决定。
- **【高·GUI】Qt6 跨平台图形界面**：五区域布局（顶栏「关于/视图」菜单 + 左侧文件选择 + 中部功能区 + 右侧密码框 + 下部只读命令输出）。`ICommandExecutor` 抽象 + `ProcessCommandExecutor`（QProcess 异步按行捕获 stdout/stderr，支持 CancellationToken 取消 kill）；`CliArgBuilder` 将 GUI 参数 1:1 映射为与 main.cpp 参数解析一致的 argv；密钥经 `ENCRYPTOR_KEY` 环境变量注入子进程（不入 argv、不留盘）。窗口大小自适应（QSplitter 可拖动调比例）。
- **【低·构建】VS2026 一键编译**：`CMakePresets.json` 新增 `windows-vs2026-release` / `windows-vs2026-debug` 预设（generator="Visual Studio 18 2026"），VS2026 Community 打开文件夹即识别一键编译调试。

### Notes
- GUI 运行时依赖 `FileEncryptorCLI.exe`：CLI 须位于 GUI exe 同目录，或通过 `FILEENCRYPTOR_EXE` 环境变量指向，或在 PATH 中可找到。
- GUI 不链接任何加密代码：所有加解密逻辑均在 CLI 中实现。

> 早期版本（v0.x、1.0.x）的 GUI 行为变更记录不在此文件维护，详见 Git 提交记录。
