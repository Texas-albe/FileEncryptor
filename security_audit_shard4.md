# FileEncryptor GUI-WinUI 模块源代码安全审计报告

- 审计范围：`E:\FileEncryptor\GUI-WinUI\` 下全部 `.cs` / `.xaml`（已排除 bin/obj/build）
- 审计日期：2026-09-27
- 审计模式：仅审计，未修改任何源码
- 已按已知基线（secure_zero / BufferPool / force-decrypt 清零 / salt_ptr / v6 判 corrupted / 白名单相对路径 / rage 路径白名单绕过）去重，不重复报告

## 概览

| 严重程度 | 数量 |
|---|---|
| 高 | 0 |
| 中 | 4 |
| 低 | 8 |

整体结论：参数传递走 `ProcessStartInfo.ArgumentList`（非拼接命令行字符串），密钥经 stdin 注入、不进 argv/环境变量/历史记录/命令预览，命令注入面控制良好；未发现硬编码密钥、未发现加密算法误用、未发现缓冲区溢出。主要风险集中在“口令在托管堆中未清零”“下载的 CLI 无完整性校验且文件名未净化”“Process 句柄未释放”三点。

---

## 中危

### M-1 口令明文驻留托管堆，写入 stdin 的字节数组事后未清零
- 文件：`ViewModels\MainViewModel.cs:168`；`Services\CliProcessService.cs:53-55`；`PasswordDialog.xaml.cs:11`
- 描述：
  - `PasswordDialog.Password` 直接暴露 `PasswordBox.Password`（不可变 `string`），口令以明文 managed string 存在于 GC 堆。
  - `RunWithPassword` 执行 `Encoding.UTF8.GetBytes(password + "\n")` 生成 `byte[] StdinData`（MainViewModel.cs:168），其中 `password + "\n"` 还额外复制了一份字符串。
  - `CliProcessService.Execute` 把该 `byte[]` 写入子进程 stdin 后即 Close（CliProcessService.cs:53-55），**从未对 `StdinData` 做 `Array.Clear`/零覆盖**。该字节数组在 GC 回收前一直以明文驻留内存，且会因 GC 压缩而被复制到不同地址，无法保证擦除。
  - 对一个加密工具而言，口令/派生材料在内存中残留到进程结束，是与“密钥材料应最小化生命周期”相悖的。
- 修复建议：
  1. 写入 stdin 后立即 `Array.Clear(request.StdinData, 0, request.StdinData.Length);`（在 `finally` 中）。
  2. 尽量避免 `password + "\n"` 拼接；可在构造字节时直接在尾部加 `\n`。
  3. 长期方案：用固定 `char[]`/`byte[]` 接收口令（`PasswordBox` 可通过 `PasswordChanged` 读取字符并自行缓冲），用完即 `Array.Clear`；不要把口令交给不可变 `string` 长期持有。
  4. 进程结束前可主动 `GC.Collect()` 不解决根本问题，需从缓冲区生命周期入手。

### M-2 自动下载的 CLI 可执行文件无完整性校验，且保存文件名未净化（路径穿越 / 供应链）
- 文件：`MainWindow.xaml.cs:161-193`
- 描述：
  - `DownloadCliFromGithub` 从 GitHub API 拉取 release assets，取 `browser_download_url` 直接 `GetByteArrayAsync`，再以 API 返回的 asset `name` 作为文件名 `Path.Combine(AppContext.BaseDirectory, fileName)` 落盘（191-192 行），之后 `FileEncryptorLocator` 会在同目录发现并执行它。
  - 仅做了 `StartsWith("FileEncryptorCLI-")` 与 `EndsWith(".exe")` 过滤，**未用 `Path.GetFileName(fileName)` 净化**。若 asset 名形如 `FileEncryptorCLI-x\..\..\..\..\Windows\System32\bad.exe`，`Path.Combine` 后规范化会跳出应用目录，造成任意位置写入可执行文件。
  - 下载的二进制**没有任何签名校验或哈希比对**（无 SHA256/签名固定）。HTTPS 只能防网络窃听/篡改，不能防仓库账号被盗、release 被替换或 CDN 投毒；一旦官方 release 被换成恶意包，GUI 会自动下载并在下次运行时执行，构成远程代码执行。
- 修复建议：
  1. 落盘前 `fileName = Path.GetFileName(fileName.Trim());`，拒绝含路径分隔符/`..` 的名字。
  2. 内置期望的 CLI SHA256 指纹（或签名公钥），下载后校验不通过则拒绝写入并提示。
  3. 下载链接限定在 `https://github.com/Texas-albe/FileEncryptor/releases/...` 或 `objects.githubusercontent.com` 白名单域。
  4. 不要静默自动执行；下载完成后提示用户、由用户确认重启后再加载。

### M-3 子进程 Process 对象退出后未 Dispose（句柄/事件泄漏）
- 文件：`Services\CliProcessService.cs:45,73-100`
- 描述：`_process = new Process { ..., EnableRaisingEvents = true }` 创建后订阅了 `Exited`，在 `OnProcessExited` 中读取 `ExitCode` 与统计文件后直接 `EmitFinished`，**全程未调用 `_process.Dispose()`**。`Process` 实现了 `IDisposable`，未释放会泄漏底层等待句柄/STDIN 句柄；批量重复任务下句柄累积。
- 修复建议：在 `OnProcessExited` 末尾（或 `finally`）`try { _process.Dispose(); } catch { }`，并在 `Cancel()` 路径也补 Dispose；注意 Dispose 前先读完 `ExitCode`。

### M-4 临时统计文件名用 `Guid.NewGuid()` 且存在 TOCTOU
- 文件：`Services\CliProcessService.cs:31,79-83`
- 描述：
  - 统计文件路径 `Path.Combine(Path.GetTempPath(), $"fe_stats_{Guid.NewGuid():N}.json")`。`Guid.NewGuid()` 在 .NET 默认实现虽使用随机数，但**不是 CSPRNG 保证**；临时目录对同机其他用户/进程可写时，存在被预判/预创建的窗口。
  - 79 行 `if (File.Exists(_statsFile))` 与 83 行 `File.ReadAllText(_statsFile)` 之间是典型 TOCTOU：检查后读取，期间文件可被替换为伪造 JSON（注入 `files_done`/`total_bytes` 等仅影响 GUI 显示，不影响加密结果，但属于可被本地低权限进程污染的数据通道）。
- 修复建议：
  1. 用 `RandomNumberGenerator.GetBytes` 生成随机名（如 16 字节 hex）替代 `Guid.NewGuid()`。
  2. 以 `FileShare.None` 独占方式打开统计文件，或读取后立即校验内容结构，不依赖 `File.Exists` 判断。
  3. 把统计文件放到用户专属目录（如 `%LocalAppData%\FileEncryptor\GUI\`）而非全局 temp。

---

## 低危

### L-1 位置参数未以 `--` 分隔，文件名以 `-` 开头可被当作开关
- 文件：`Services\CliArgBuilder.cs:95-99`
- 描述：批量模式把每个输入路径作为独立 `-i <path>` 的值，单文件模式直接 `args.Add(options.InputPaths[0])` 作为位置参数。若用户/拖拽加入的文件恰好命名为 `-o`、`-y`、`-de` 之类（以 `-` 开头），CLI 解析器可能把它误判为开关而非路径，造成参数错位/非预期行为。`ArgumentList` 只保证不经 shell 转义，不能阻止“值长得像开关”。
- 修复建议：在所有位置路径参数前加 `--` 终止选项解析（确认 CLI 支持 GNU `--`），或对以 `-` 开头的路径做 `.\` 前缀处理。

### L-2 GUI 侧口令策略过弱（仅要求长度 ≥6）
- 文件：`PasswordDialog.xaml.cs:77`；`Services\PasswordStrengthService.cs:16`
- 描述：`ValidateMatch` 仅校验 `PwdBox.Password.Length >= 6` 即放行（77 行），并未调用 `PasswordStrengthService.MeetsPolicy`（81-110 行定义了更严策略但未在弹窗流程中强制）。用户可输入 `123456` 这类弱口令直接走加密。最终强度由 CLI 决定，但 GUI 提前放行弱口令会误导用户。
- 修复建议：在 `OnPrimaryButton` 确认时调用 `MeetsPolicy`，不满足则禁用确定按钮并提示原因。

### L-3 崩溃日志可能落盘异常对象文本
- 文件：`App.xaml.cs:18-26,31-39`
- 描述：`WriteCrashLog` 把 `e.ExceptionObject` / `e.Exception.ToString()` / `e.Message` 写入 `%LocalAppData%\FileEncryptor\GUI\crash.log`。.NET 异常 `ToString()` 不含局部变量，因此口令一般不会被记录；但若将来在口令处理路径上抛出携带缓冲区内容的自定义异常，可能把敏感材料写进明文日志。日志文件采用 `WriteAllText` 覆盖写，权限继承自用户目录。
- 修复建议：崩溃日志仅记录异常类型+消息，不要整对象 `ToString()`；定期截断；确认不记录任何来自 stdin/口令缓冲区的对象。

### L-4 完成后在 UI 线程递归扫描输出目录统计 `.ptd` 大小
- 文件：`ViewModels\MainViewModel.cs:286-296`
- 描述：`OnFinished` 经 `DispatcherQueue.TryEnqueue` 在 UI 线程对 `OutputDir` 做 `EnumerateFiles("*.ptd", AllDirectories)` 并 `Sum(new FileInfo(f).Length)`。若输出目录巨大/网络盘/含大量文件，UI 线程会长时间阻塞，表现为界面卡死（DoS 体验）。该扫描与加解密正确性无关，仅用于汇总展示。
- 修复建议：放到后台线程，完成后再封送回 UI；或用进度条/异步方式，避免阻塞 UI 线程。

### L-5 `DisplayArea.GetFromWindowId` 返回值未判空
- 文件：`TaskNotificationWindow.xaml.cs:34-36`
- 描述：34 行取 `displayArea` 后 35 行直接 `displayArea.WorkArea`。多显示器/远程会话等异常配置下 `GetFromWindowId` 可能返回 null，导致 NRE 崩溃（被 App 崩溃兜底捕获，但通知窗起不来）。
- 修复建议：判空并回退到主显示器工作区或屏幕默认值。

### L-6 死代码 `ParseProgress` 中 `int.Parse` 未防护
- 文件：`ViewModels\MainViewModel.cs:305-314`
- 描述：`ParseProgress` 用正则 `skipped\s+(\d+)` 匹配后直接 `int.Parse(m.Groups[1].Value)`（311 行）。当前 `CliProcessService` 未重定向 stdout，该方法无调用方（死代码），但若未来接上 stdout 解析，恶意/异常输出可触发 `FormatException`。
- 修复建议：改为 `int.TryParse`；在真正接 stdout 前删除该死代码。

### L-7 自定义背景图路径可指向任意本地/远程 URI
- 文件：`MainWindow.xaml.cs:554-567`；`ViewSettingsDialog.xaml.cs:73-99`
- 描述：`CustomBackgroundPath` 由用户自由文本设置，随后 `new BitmapImage { UriSource = new Uri(path) }` 加载。若填写 `http(s)://` 地址，应用会向远程发起请求（可被用于探测内网/出网）；填写本地路径则仅作背景显示。该值持久化在 `settings.json`。影响有限（仅本机显示、不回传），但属于未限制的 URI 加载面。
- 修复建议：限制 `UriSource` 为本地文件路径（`Uri.IsFile`），拒绝 http/其他 scheme；或在设置时校验扩展名。

### L-8 `PasswordDialog` 颜色解析硬假设 7 位 hex
- 文件：`PasswordDialog.xaml.cs:69-72`
- 描述：`result.ColorHex.Substring(1,2)/(3,2)/(5,2)` 假定颜色串为 `#RRGGBB` 7 字符。当前 `PasswordStrengthService` 中 ColorHex 均为硬编码合法值，不会触发；但若未来某处把空串/短串/非法格式赋给 `ColorHex`，会抛 `ArgumentOutOfRangeException`。属健壮性问题，非直接安全漏洞。
- 修复建议：用 `ColorHelper`/`Color.FromArgb` 前先校验长度与格式，或 `int.TryParse(NumberStyles.HexNumber)`。

---

## 已核对但未发现安全问题的文件

- `Models\CommandTypes.cs`：纯 DTO（CommandRequest/CommandResult/OutputLine），无逻辑。`StdinData` 默认 `Array.Empty<byte>()`，无空指针。
- `Models\SelectablePath.cs`：INotifyPropertyChanged 包装，无逻辑。
- `Models\ShellOptions.cs`：选项枚举与容器，无逻辑。
- `Models\TaskRecord.cs`：任务记录 DTO。**已确认不含口令字段**（仅记录路径/模式/计数，不记录口令或密钥材料），历史记录不泄密。
- `ViewModels\ObservableObject.cs`：MVVM 基类，无逻辑。
- `Services\CliArgBuilder.cs`：以 `List<string>` 构建参数并由 `ArgumentList` 逐项添加（非命令行字符串拼接），开关与值分离正确；密钥不进入 argv（仅追加 `--key-stdin` 注释）。仅见 L-1 的 `--` 分隔问题。
- `Services\FileEncryptorLocator.cs`：按环境变量→同目录→ProgramFiles→PATH 顺序探测可执行名；`IsExecutable` 仅 `File.Exists`。信任 `FILEENCRYPTOR_EXE` 环境变量与 PATH 是设计使然（等价于用户已控制 PATH），不构成额外漏洞。
- `Services\SettingsService.cs`：`settings.json` 仅存主题/窗口尺寸/背景路径/上次目录/CLI 路径，**不含口令或密钥**；读写带 try/catch，损坏回退默认。
- `Services\TaskHistoryService.cs`：JSON 行式追加/读取/删除；逐条 try/catch 跳过损坏行；记录中无口令。文件位于用户 Roaming AppData，ACL 默认用户私有。
- `Services\PasswordStrengthService.cs`：纯字符集/熵计算，不使用 `Random`/加密原语，无安全问题。
- `Services\EtaEstimatorService.cs`：中位数/速率/格式化数学，除零已防护（`bytes<=0`、`fraction<=0`、`median` 前判空），无安全问题。
- `Services\ThemeService.cs`：读注册表 `AppsUseLightTheme` 仅作判断，无写操作；无安全问题。
- `App.xaml` / `MainWindow.xaml` / `TaskNotificationWindow.xaml`：绑定均为 `{x:Bind OneWay}` / `{Binding}` 到 string 属性，WinUI TextBlock 不解析 XAML/HTML；`NavigateUri` 均为硬编码 https 链接；无 XAML 注入、无数据绑定执行风险。
- `MainWindow.xaml.cs`：除 M-2 下载逻辑外，文件/目录均通过 `FileOpenPicker`/`FolderPicker`/拖拽获得；`OnEditConfig` 用 `UseShellExecute=true` 打开的是固定拼出的 `%AppData%\FileEncryptor\config.yaml`，无注入。
- `CliProcessService.cs`：除 M-3/M-4 外，`UseShellExecute=false`、`RedirectStandardInput=true`、不把口令写入环境变量（仅写统计文件路径），进程取消走 `Kill(entireProcessTree)`。
- `MainViewModel.cs`：除 M-1、L-4、L-6 外，`OnFinished` 经 `DispatcherQueue` 封送 UI，命令预览不含口令，任务记录不含口令。
- `PasswordDialog.xaml.cs`：除 M-1、L-2、L-8 外，无逻辑问题。
- `TaskHistoryDialog.xaml.cs` / `TaskSummaryDialog.xaml.cs` / `TaskNotificationWindow.xaml.cs` / `ViewSettingsDialog.xaml.cs`：纯 UI 展示/编辑，无命令执行或敏感数据落盘（ViewSettingsDialog 见 L-7）。

---

## 重点检查项结论速览

| # | 检查项 | 结论 |
|---|---|---|
| 1 | 缓冲区溢出/数组越界 | 未发现（C# 托管边界；仅 L-8 字符串 Substring 健壮性） |
| 2 | 口令/密钥内存清零 | **M-1**：StdinData 字节数组未清零，口令 string 驻留堆 |
| 3 | 路径遍历 | **M-2**：下载 asset 文件名未 `GetFileName` 净化；GUI 自身不做 `..\` 校验（由 CLI 白名单负责，基线已覆盖） |
| 4 | 命令注入 | 未发现：统一 `ArgumentList` 逐项添加、`UseShellExecute=false`；仅 L-1 缺 `--` 分隔 |
| 5 | 整数溢出 | 未发现（大小/速率均用 long/double） |
| 6 | 未初始化变量 | 未发现（`null!` 均在构造函数赋值或判空） |
| 7 | 竞态条件 | **M-4** 统计文件 TOCTOU；其余经 DispatcherQueue 封送，风险低 |
| 8 | 硬编码密钥/密码/IV | 未发现 |
| 9 | 不安全随机数 | **M-4**：统计文件名用 `Guid.NewGuid()`（非 CSPRNG） |
| 10 | 加密算法误用 | 未发现（GUI 不做加密，委托 CLI；选项映射正确） |
| 11 | 空指针解引用 | L-5：`DisplayArea` 未判空；其余有判空 |
| 12 | 资源泄漏 | **M-3**：`Process` 未 Dispose |
| 13 | 格式化字符串 | 未发现（插值/拼接均为展示用途，无用户可控格式串） |
| 14 | 不安全文件权限 | 未发现（配置/历史/崩溃日志均落用户 profile 目录，继承 ACL） |
| 15 | 口令明文写日志/配置/历史 | 未发现落盘泄露（历史/预览/配置均不含口令）；L-3 提示崩溃日志需谨慎 |
| 16 | XAML 注入/绑定安全 | 未发现 |
