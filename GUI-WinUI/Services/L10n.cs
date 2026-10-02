using System.Collections.Generic;
using System.Globalization;

namespace FileEncryptorGUI.Services;

// 轻量多语言字典
public static class L10n
{
    public const string Zh = "zh";
    public const string En = "en";
    public const string Ru = "ru";

    private static readonly Dictionary<string, string> EnMap = new()
    {
        // 菜单栏（Title 经代码应用）
        ["编辑"] = "Edit",
        ["视图"] = "View",
        ["工具"] = "Tools",
        ["关于"] = "About",
        ["编辑 CLI 配置"] = "Edit CLI configuration",
        ["重新检测 CLI 程序"] = "Re-detect the CLI program",
        ["背景设置..."] = "Background settings...",
        ["检查更新..."] = "Check for updates...",
        ["鸣谢..."] = "Credits...",
        ["README 摘要..."] = "README summary...",
        // XAML 静态文本（视觉树遍历应用）
        ["文件选择"] = "File selection",
        ["添加文件..."] = "Add files...",
        ["添加目录..."] = "Add folder...",
        ["清空"] = "Clear",
        ["操作"] = "Actions",
        ["加密"] = "Encrypt",
        ["解密"] = "Decrypt",
        ["批量加密"] = "Batch encrypt",
        ["批量解密"] = "Batch decrypt",
        ["密钥管理"] = "Key management",
        ["生成密钥对"] = "Generate keypair",
        ["口令派生密钥对"] = "Derive keypair from passphrase",
        ["导出公钥"] = "Export public key",
        ["加密模式"] = "Encryption mode",
        ["XChaCha20-Poly1305"] = "XChaCha20-Poly1305",
        ["AEGIS-256"] = "AEGIS-256",
        ["SM4-GCM"] = "SM4-GCM",
        ["X25519 非对称"] = "X25519 asymmetric",
        ["文件算法："] = "File cipher:",
        ["XChaCha20-Poly1305（默认）"] = "XChaCha20-Poly1305 (default)",
        ["非对称模式下的文件载荷加密算法；非对称部分只加密此处所选算法生成的密钥"] =
            "Symmetric cipher used for the file payload; the asymmetric part only wraps the key it generates",
        ["X25519 非对称模式下只负责包裹文件密钥，载荷密文算法由右侧「文件算法」指定"] =
            "In X25519 asymmetric mode the app only wraps the file key; the payload cipher comes from \"File cipher\"",
        ["勾选后非对称封装走 X448 曲线，不勾选为 X25519；生成密钥对同样改走 X448"] =
            "Checked: asymmetric wrapping uses the X448 curve; unchecked uses X25519 (also applies to keypair generation)",
        ["压缩 (zstd)"] = "Compression (zstd)",
        ["压缩数据"] = "Compress data",
        ["压缩级别:"] = "Compression level:",
        ["压缩级别（0-22）:"] = "Compression level (0-22):",
        ["输出目录"] = "Output directory",
        ["留空 = 输出到源文件目录"] = "Leave empty = output next to the source files",
        ["浏览..."] = "Browse...",
        ["密钥文件"] = "Key file",
        ["留空 = 运行弹窗输入"] = "Leave empty = enter in the run dialog",
        ["选项"] = "Options",
        ["保留源文件"] = "Keep source files",
        ["删除源文件"] = "Delete source files",
        ["安全擦除"] = "Secure wipe",
        ["移至回收站"] = "Move to Recycle Bin",
        ["覆盖已存在文件"] = "Overwrite existing files",
        ["生成校验单"] = "Generate checksum file",
        ["密钥轮换"] = "Key rotation",
        ["▶ 运行"] = "▶ Run",
        ["■ 取消"] = "■ Cancel",
        ["收件人:"] = "Recipients:",
        ["公钥或公钥文件路径"] = "Public key or a public-key file path",
        ["身份文件:"] = "Identity file:",
        ["私钥文件路径"] = "Private key file path",
        ["还原完整原始文件名（批量解密，较慢）"] = "Restore full original file names (batch decrypt, slower)",
        ["命令预览"] = "Command preview",
        ["任务历史..."] = "Task history...",
        // MainWindow：浏览器错误提示
        ["[添加文件] 错误: {0}"] = "[Add files] error: {0}",
        ["[添加目录] 错误: {0}"] = "[Add folder] error: {0}",
        ["[输出目录] 错误: {0}"] = "[Output directory] error: {0}",
        ["[密钥文件] 错误: {0}"] = "[Key file] error: {0}",
        ["[收件人] 错误: {0}"] = "[Recipient] error: {0}",
        ["[身份文件] 错误: {0}"] = "[Identity file] error: {0}",
        // MainWindow：CLI 检测与下载
        ["FileEncryptor CLI 未找到"] = "FileEncryptor CLI not found",
        ["无法找到 FileEncryptor CLI 可执行文件\n\n程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。\n\n预期文件名：\n{0}\n\n当前程序目录：{1}"] =
            "The FileEncryptor CLI executable could not be found\n\nThis program needs the FileEncryptorCLI command-line tool to encrypt and decrypt.\n\nExpected file names:\n{0}\n\nCurrent program directory: {1}",
        ["重试"] = "Retry",
        ["下载 CLI"] = "Download CLI",
        ["关闭"] = "Close",
        ["准备下载…"] = "Preparing to download…",
        ["正在从 GitHub 检索可用版本…"] = "Retrieving available releases from GitHub…",
        ["未找到预期的 CLI {0}（要求 tag GUI{1}_CLI{0}），已中止下载"] =
            "Expected CLI {0} not found (requires tag GUI{1}_CLI{0}); download aborted",
        ["找到 {0}，正在获取下载链接…"] = "Found {0}, fetching the download link…",
        ["未找到当前平台的 CLI 包"] = "No CLI package found for this platform",
        ["下载链接域名不在白名单内，已中止"] = "Download URL domain is not allowlisted; aborted",
        ["下载文件名非法，已中止"] = "Invalid download file name; aborted",
        ["下载中：{0}"] = "Downloading: {0}",
        ["SHA256 校验失败，下载内容已被丢弃"] = "SHA256 verification failed; the downloaded content was discarded",
        ["CLI release 未提供 .sha256 清单，跳过完整性校验"] = "The CLI release provides no .sha256 manifest; integrity check skipped",
        ["下载完成：{0}"] = "Download complete: {0}",
        ["下载失败：{0}"] = "Download failed: {0}",
        ["[添加文件] 错误: "] = "[Add files] error: ",
        ["[添加目录] 错误: "] = "[Add folder] error: ",
        ["[输出目录] 错误: "] = "[Output directory] error: ",
        ["[密钥文件] 错误: "] = "[Key file] error: ",
        ["[收件人] 错误: "] = "[Recipients] error: ",
        ["[身份文件] 错误: "] = "[Identity file] error: ",
        // MainWindow：密钥轮换 / 配置
        ["密钥轮换（v6 容器）"] = "Key rotation (v6 container)",
        ["选择一个已加密的 .ptd 文件，用旧口令解密后用新口令重新包裹 DEK。\n文件内容不变，仅更换口令。"] =
            "Choose an encrypted .ptd file to decrypt with the old passphrase and re-wrap its DEK with a new one.\nFile content unchanged; only the passphrase is replaced.",
        ["选择文件"] = "Select file",
        ["取消"] = "Cancel",
        ["密钥轮换功能实现中"] = "Key rotation is being implemented",
        ["配置文件不存在（首次运行 CLI 后生成）"] = "Configuration file does not exist (generated on first CLI run)",
        // MainWindow：检查更新 / 更新
        ["检查更新"] = "Check for updates",
        ["未找到更新器 (Updater.exe)。请确认程序安装完整，或前往 GitHub 手动获取新版本。"] =
            "Updater (Updater.exe) not found. Please verify the installation is complete, or get the new version from GitHub manually.",
        ["检查失败：{0}"] = "Check failed: {0}",
        ["发现新版本"] = "New version available",
        ["发现新版本 {0}。\n\n{1}\n\n是否现在下载并安装？"] = "New version {0} available.\n\n{1}\n\nDownload and install now?",
        ["下载并安装"] = "Download and install",
        ["已是最新版本（{0}）。"] = "You are up to date ({0}).",
        ["检查更新时出错：{0}"] = "Error while checking for updates: {0}",
        ["更新"] = "Update",
        ["未找到适用于本平台的安装包，请前往 GitHub 手动下载。"] = "No package available for this platform. Please download it from GitHub manually.",
        ["正在下载并校验…"] = "Downloading and verifying…",
        ["无法启动更新器。"] = "Could not launch the updater.",
        ["正在下载…"] = "Downloading…",
        ["正在校验完整性…"] = "Verifying integrity…",
        ["更新包已下载并校验完成。"] = "Update package downloaded and verified.",
        ["更新失败："] = "Update failed: ",
        ["未知错误"] = "Unknown error",
        ["更新包已就绪，存放于：\n{0}\n请关闭程序后以该文件替换当前程序并重新启动。"] =
            "Update package ready, saved at:\n{0}\nPlease close the app, replace it with that file and restart.",
        ["更新失败（退出码 "] = "Update failed (exit code ",
        ["）。可前往 GitHub 手动下载。"] = "). You can also download it from GitHub manually.",
        ["更新出错："] = "Update error: ",
        // 鸣谢 / README 摘要
        ["感谢以下贡献者的付出："] = "Thanks to these contributors:",
        ["个人主页"] = "Homepage",
        ["代码开发"] = "Development",
        ["赞助支持"] = "Sponsor",
        ["测试"] = "Testing",
        ["宣传"] = "Promotion",
        ["\n本项目基于 libsodium 实现文件加密（XChaCha20-Poly1305 / AEGIS-256），采用 C++17 编写，跨平台运行于 Windows / Linux / macOS。"] =
            "\nFile encryption is built on libsodium (XChaCha20-Poly1305 / AEGIS-256), written in C++17, running cross-platform on Windows / Linux / macOS.",
        ["鸣谢"] = "Credits",
        ["— 项目摘要"] = "— Project summary",
        ["简介：跨平台（Windows / Linux / macOS）文件加密工具，基于 libsodium 实现 XChaCha20-Poly1305 与 AEGIS-256 加密。"] =
            "Summary: a cross-platform (Windows / Linux / macOS) file encryption tool built on libsodium with XChaCha20-Poly1305 and AEGIS-256.",
        ["核心特性"] = "Key features",
        ["• 加密算法：XChaCha20-Poly1305（默认）/ AEGIS-256，密钥经 Argon2id 派生"] =
            "• Ciphers: XChaCha20-Poly1305 (default) / AEGIS-256, keys derived via Argon2id",
        ["• 单文件与批量：支持单文件加/解密，及目录批量加/解密（递归）"] =
            "• Single & batch: single-file encrypt/decrypt plus recursive folder batch encrypt/decrypt",
        ["• 断点续传：加密中断后可从上次进度继续，防静默数据丢失"] =
            "• Resumable: interrupted encryption resumes from the last checkpoint, preventing silent data loss",
        ["• 路径安全：拒绝目录穿越（..），白名单前缀校验"] = "• Path safety: rejects directory traversal (..), allowlist prefix checks",
        ["• 限速：进程级令牌桶限速（YAML max_speed 配置）"] = "• Rate limiting: process-level token bucket (YAML max_speed)",
        ["• 配置化：日志/并发/路径策略等运维参数经 YAML 配置"] = "• Configurable: logging/concurrency/path policy via YAML",
        ["命令行用法"] = "Command-line usage",
        ["密钥来源优先级"] = "Key source priority",
        ["-k <keyfile>（密钥文件） > --key-stdin（stdin 管道） > ENCRYPTOR_KEY（环境变量） > 交互式输入；非对称模式用 X25519 身份私钥 > 交互式输入"] =
            "-k <keyfile> (key file) > --key-stdin (stdin pipe) > ENCRYPTOR_KEY (environment variable) > interactive input; asymmetric mode uses an X25519 identity private key > interactive input",
        ["许可证：GPLv3"] = "License: GPLv3",
        ["本窗口为 README 摘要，完整文档请见项目根目录 README.md"] = "This is a README summary; see README.md in the project root for full documentation",
        ["README 摘要"] = "README summary",
        // 任务回填 / CLI 检测状态
        ["已恢复任务: {0}"] = "Task restored: {0}",
        ["已检测到 CLI: {0}"] = "CLI detected: {0}",
        ["未检测到 FileEncryptor CLI"] = "FileEncryptor CLI not detected",
        // 运行时状态（切换语言即时刷新）
        ["就绪"] = "Ready",
        ["运行中..."] = "Running...",
        ["已取消"] = "Cancelled",
        ["失败 (exit {0})"] = "Failed (exit {0})",
        ["任务已取消"] = "Task cancelled",
        ["任务结束 (exit {0})"] = "Task finished (exit {0})",
        ["当前: {0} | 完成 {1} | 跳过 {2} | 失败 {3} / 共 {4}"] =
            "Current: {0} | done {1} | skipped {2} | failed {3} / {4} in total",
        // PasswordDialog
        ["口令"] = "Passphrase",
        ["确认口令"] = "Confirm passphrase",
        ["输入口令"] = "Enter passphrase",
        ["确定"] = "OK",
        ["强度：{0}"] = "Strength: {0}",
        ["两次输入的口令不一致"] = "The two passphrases do not match",
        // TaskSummaryDialog
        ["用时"] = "Elapsed",
        ["平均速度"] = "Average speed",
        ["加密后大小"] = "Encrypted size",
        ["完成"] = "Done",
        ["跳过"] = "Skipped",
        ["失败"] = "Failed",
        ["任务完成"] = "Task complete",
        // TaskHistoryDialog
        ["任务历史（双击恢复，右键删除）"] = "Task history (double-click to restore, right-click to delete)",
        ["共 {0} 条记录"] = "{0} record(s) in total",
        ["共 0 条记录"] = "0 records in total",
        ["清空全部"] = "Clear all",
        ["暂无历史记录"] = "No history records yet",
        ["输入 {0} 个, {1}, 耗时 {2}"] = "{0} input(s), {1}, took {2}",
        ["删除此条"] = "Delete this entry",
        // ViewSettingsDialog
        ["视图设置"] = "View settings",
        ["保存"] = "Save",
        ["自定义背景图"] = "Custom background image",
        ["图片路径"] = "Image path",
        ["清除背景"] = "Clear background",
        ["支持 PNG / JPG / BMP / WebP 格式。"] = "PNG / JPG / BMP / WebP formats are supported.",
        // TaskHistoryService 动作标签
        ["口令派生密钥对"] = "Derive keypair from passphrase",
        // NationalDayTheme
        ["祝祖国{0}岁生日快乐！永远繁荣昌盛！"] = "Happy {0}th Birthday to the People's Republic of China! May it always prosper!",
        // PasswordStrengthService
        ["未输入"] = "Not entered",
        ["弱"] = "Weak",
        ["中"] = "Medium",
        ["强"] = "Strong",
        ["小写 "] = "lowercase ",
        ["大写 "] = "uppercase ",
        ["数字 "] = "digits ",
        ["符号 "] = "symbols ",
        ["无"] = "none",
        ["长度 {0} | 种类 {1} | 熵 ~{2} bits | {3}"] = "Length {0} | Classes {1} | Entropy ~{2} bits | {3}",
        ["口令过短（至少 {0} 个字符）。"] = "Passphrase too short (at least {0} characters).",
        ["口令过弱：请至少含 2 类字符（小写/大写/数字/符号），或长度 >= 16。"] =
            "Passphrase too weak: include at least 2 character classes (lower/upper/digits/symbols), or length >= 16.",
        // CliArgBuilder
        ["  # 密钥经 stdin 管道注入"] = "  # key injected via stdin pipe",
        // 语言切换提示（双语合成串，按语言分别给出）
        ["语言 / Language"] = "Language",
        ["语言已切换，界面已立即刷新。\nLanguage switched; the UI has been refreshed."] = "Language switched; the UI has been refreshed.",
        ["确定 / OK"] = "OK",
        // 更新检查（Updater 返回的错误码）
        ["网络连接不可用，请检查网络后重试。"] = "Network unreachable; check your connection and retry.",
        ["无法解析服务器地址，请检查网络后重试。"] = "Could not resolve the server; check your connection and retry.",
        ["检查更新超时，请稍后再试。"] = "The update check timed out. Please try again later.",
        ["安全证书校验失败，可能是网络环境拦截了更新服务。"] = "Security certificate verification failed; the update service may be blocked.",
        ["检查过于频繁，请稍后再试。"] = "Too many check requests. Please try again later.",
        ["服务端未找到可更新的版本。"] = "No updatable release found on the server.",
        ["更新服务地址不可达。"] = "The update service host is not allowed or unreachable.",
        ["检查更新未返回结果（可能已超时）。请稍后再试。"] = "The update check returned nothing (possibly timed out). Please try again later.",
        ["更新器未返回任何结果（可能已超时）。"] = "The updater returned nothing (possibly timed out).",
        ["无法启动更新器，请确认程序安装完整。"] = "Could not launch the updater; make sure the installation is complete.",
        ["下载超时，请稍后再试。"] = "The download timed out. Please try again later.",
    };

    // 俄文译文（zh -> ru）
    private static readonly Dictionary<string, string> RuMap = new()
    {
        ["编辑"] = "Правка",
        ["视图"] = "Вид",
        ["工具"] = "Сервис",
        ["关于"] = "О программе",
        ["编辑 CLI 配置"] = "Редактировать конфигурацию CLI",
        ["重新检测 CLI 程序"] = "Заново обнаружить программу CLI",
        ["背景设置..."] = "Настройки фона…",
        ["检查更新..."] = "Проверить обновления…",
        ["鸣谢..."] = "Благодарности…",
        ["README 摘要..."] = "Краткое описание README…",
        ["文件选择"] = "Выбор файлов",
        ["添加文件..."] = "Добавить файлы…",
        ["添加目录..."] = "Добавить каталог…",
        ["清空"] = "Очистить",
        ["操作"] = "Действия",
        ["加密"] = "Зашифровать",
        ["解密"] = "Расшифровать",
        ["批量加密"] = "Пакетное шифрование",
        ["批量解密"] = "Пакетная расшифровка",
        ["密钥管理"] = "Управление ключами",
        ["生成密钥对"] = "Создать пару ключей",
        ["口令派生密钥对"] = "Производная пара ключей от пароля",
        ["导出公钥"] = "Экспортировать открытый ключ",
        ["加密模式"] = "Режим шифрования",
        ["XChaCha20-Poly1305"] = "XChaCha20-Poly1305",
        ["AEGIS-256"] = "AEGIS-256",
        ["SM4-GCM"] = "SM4-GCM",
        ["X25519 非对称"] = "X25519 асимметричное",
        ["文件算法："] = "Алгоритм файла:",
        ["XChaCha20-Poly1305（默认）"] = "XChaCha20-Poly1305 (по умолчанию)",
        ["非对称模式下的文件载荷加密算法；非对称部分只加密此处所选算法生成的密钥"] =
            "Симметричный шифр полезной нагрузки файла; асимметричная часть только оборачивает его ключ",
        ["X25519 非对称模式下只负责包裹文件密钥，载荷密文算法由右侧「文件算法」指定"] =
            "В асимметричном режиме X25519 оборачивается только ключ файла; шифр полезной нагрузки задан справа",
        ["勾选后非对称封装走 X448 曲线，不勾选为 X25519；生成密钥对同样改走 X448"] =
            "С флажком — обёртка ключа по кривой X448, без флажка — X25519 (в том числе при генерации пары ключей)",
        ["压缩 (zstd)"] = "Сжатие (zstd)",
        ["压缩数据"] = "Сжимать данные",
        ["压缩级别:"] = "Уровень сжатия:",
        ["压缩级别（0-22）:"] = "Уровень сжатия (0-22):",
        ["输出目录"] = "Каталог вывода",
        ["留空 = 输出到源文件目录"] = "Пусто = вывод рядом с исходными файлами",
        ["浏览..."] = "Обзор…",
        ["密钥文件"] = "Файл ключа",
        ["留空 = 运行弹窗输入"] = "Пусто = ввод в диалоге запуска",
        ["选项"] = "Параметры",
        ["保留源文件"] = "Сохранять исходные файлы",
        ["删除源文件"] = "Удалить исходные файлы",
        ["安全擦除"] = "Безопасное стирание",
        ["移至回收站"] = "Переместить в корзину",
        ["覆盖已存在文件"] = "Перезаписывать существующие файлы",
        ["生成校验单"] = "Создавать файл контрольной суммы",
        ["密钥轮换"] = "Ротация ключей",
        ["▶ 运行"] = "▶ Запустить",
        ["■ 取消"] = "■ Отмена",
        ["收件人:"] = "Получатели:",
        ["公钥或公钥文件路径"] = "Публичный ключ или путь к файлу публичного ключа",
        ["身份文件:"] = "Файл удостоверения:",
        ["私钥文件路径"] = "Путь к файлу закрытого ключа",
        ["还原完整原始文件名（批量解密，较慢）"] = "Восстановить полные исходные имена файлов (пакетная расшифровка, медленнее)",
        ["命令预览"] = "Предпросмотр команды",
        ["任务历史..."] = "История задач…",
        ["[添加文件] 错误: {0}"] = "[Добавление файлов] ошибка: {0}",
        ["[添加目录] 错误: {0}"] = "[Добавление каталога] ошибка: {0}",
        ["[输出目录] 错误: {0}"] = "[Каталог вывода] ошибка: {0}",
        ["[密钥文件] 错误: {0}"] = "[Файл ключа] ошибка: {0}",
        ["[收件人] 错误: {0}"] = "[Получатели] ошибка: {0}",
        ["[身份文件] 错误: {0}"] = "[Файл удостоверения] ошибка: {0}",
        ["FileEncryptor CLI 未找到"] = "FileEncryptor CLI не найден",
        ["无法找到 FileEncryptor CLI 可执行文件\n\n程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。\n\n预期文件名：\n{0}\n\n当前程序目录：{1}"] = "Не удалось найти исполняемый файл FileEncryptor CLI\n\nПрограмме требуется инструмент командной строки FileEncryptorCLI для шифрования и расшифровки.\n\nОжидаемые имена файлов:\n{0}\n\nТекущий каталог программы: {1}",
        ["重试"] = "Повторить",
        ["下载 CLI"] = "Загрузить CLI",
        ["关闭"] = "Закрыть",
        ["准备下载…"] = "Подготовка к загрузке…",
        ["正在从 GitHub 检索可用版本…"] = "Поиск доступных версий на GitHub…",
        ["未找到预期的 CLI {0}（要求 tag GUI{1}_CLI{0}），已中止下载"] = "Ожидаемый CLI {0} не найден (требуется тег GUI{1}_CLI{0}); загрузка прервана",
        ["找到 {0}，正在获取下载链接…"] = "Найден {0}, получение ссылки для загрузки…",
        ["未找到当前平台的 CLI 包"] = "Пакет CLI для текущей платформы не найден",
        ["下载链接域名不在白名单内，已中止"] = "Домен ссылки загрузки не в разрешённом списке; прервано",
        ["下载文件名非法，已中止"] = "Недопустимое имя файла загрузки; прервано",
        ["下载中：{0}"] = "Загрузка: {0}",
        ["SHA256 校验失败，下载内容已被丢弃"] = "Проверка SHA256 не пройдена; загруженные данные отброшены",
        ["CLI release 未提供 .sha256 清单，跳过完整性校验"] = "Релиз CLI не содержит манифест .sha256; проверка целостности пропущена",
        ["下载完成：{0}"] = "Загрузка завершена: {0}",
        ["下载失败：{0}"] = "Ошибка загрузки: {0}",
        ["[添加文件] 错误: "] = "[Добавление файлов] ошибка: ",
        ["[添加目录] 错误: "] = "[Добавление каталога] ошибка: ",
        ["[输出目录] 错误: "] = "[Каталог вывода] ошибка: ",
        ["[密钥文件] 错误: "] = "[Файл ключа] ошибка: ",
        ["[收件人] 错误: "] = "[Получатели] ошибка: ",
        ["[身份文件] 错误: "] = "[Файл удостоверения] ошибка: ",
        ["密钥轮换（v6 容器）"] = "Ротация ключей (контейнер v6)",
        ["选择一个已加密的 .ptd 文件，用旧口令解密后用新口令重新包裹 DEK。\n文件内容不变，仅更换口令。"] = "Выберите зашифрованный .ptd файл: расшифруйте старым паролем и заново упакуйте его DEK новым.\nСодержимое файла не меняется, меняется только пароль.",
        ["选择文件"] = "Выбрать файл",
        ["取消"] = "Отмена",
        ["密钥轮换功能实现中"] = "Функция ротации ключей в разработке",
        ["配置文件不存在（首次运行 CLI 后生成）"] = "Файл конфигурации не существует (создаётся после первого запуска CLI)",
        ["检查更新"] = "Проверить обновления",
        ["未找到更新器 (Updater.exe)。请确认程序安装完整，或前往 GitHub 手动获取新版本。"] = "Установщик (Updater.exe) не найден. Убедитесь, что программа установлена полностью, или получите новую версию с GitHub вручную.",
        ["检查失败：{0}"] = "Ошибка проверки: {0}",
        ["发现新版本"] = "Доступна новая версия",
        ["发现新版本 {0}。\n\n{1}\n\n是否现在下载并安装？"] = "Доступна новая версия {0}.\n\n{1}\n\nЗагрузить и установить сейчас?",
        ["下载并安装"] = "Загрузить и установить",
        ["已是最新版本（{0}）。"] = "Установлена последняя версия ({0}).",
        ["检查更新时出错：{0}"] = "Ошибка при проверке обновлений: {0}",
        ["更新"] = "Обновление",
        ["未找到适用于本平台的安装包，请前往 GitHub 手动下载。"] = "Пакет для этой платформы не найден; загрузите его с GitHub вручную.",
        ["正在下载并校验…"] = "Загрузка и проверка…",
        ["无法启动更新器。"] = "Не удалось запустить установщик.",
        ["正在下载…"] = "Загрузка…",
        ["正在校验完整性…"] = "Проверка целостности…",
        ["更新包已下载并校验完成。"] = "Пакет обновления загружен и проверен.",
        ["更新失败："] = "Ошибка обновления: ",
        ["未知错误"] = "Неизвестная ошибка",
        ["更新包已就绪，存放于：\n{0}\n请关闭程序后以该文件替换当前程序并重新启动。"] = "Пакет обновления готов, сохранён по адресу:\n{0}\nЗакройте программу, замените ею текущую и перезапустите.",
        ["更新失败（退出码 "] = "Ошибка обновления (код выхода ",
        ["）。可前往 GitHub 手动下载。"] = "). Можно также загрузить с GitHub вручную.",
        ["更新出错："] = "Ошибка обновления: ",
        ["感谢以下贡献者的付出："] = "Благодарим этих участников:",
        ["个人主页"] = "Домашняя страница",
        ["代码开发"] = "Разработка",
        ["赞助支持"] = "Спонсор",
        ["测试"] = "Тестирование",
        ["宣传"] = "Продвижение",
        ["\n本项目基于 libsodium 实现文件加密（XChaCha20-Poly1305 / AEGIS-256），采用 C++17 编写，跨平台运行于 Windows / Linux / macOS。"] = "\nШифрование файлов построено на libsodium (XChaCha20-Poly1305 / AEGIS-256), написано на C++17, работает кроссплатформенно в Windows / Linux / macOS.",
        ["鸣谢"] = "Благодарности",
        ["— 项目摘要"] = "— Краткое описание проекта",
        ["简介：跨平台（Windows / Linux / macOS）文件加密工具，基于 libsodium 实现 XChaCha20-Poly1305 与 AEGIS-256 加密。"] = "Кратко: кроссплатформенное средство шифрования файлов (Windows / Linux / macOS) на базе libsodium с XChaCha20-Poly1305 и AEGIS-256.",
        ["核心特性"] = "Ключевые особенности",
        ["• 加密算法：XChaCha20-Poly1305（默认）/ AEGIS-256，密钥经 Argon2id 派生"] = "• Шифры: XChaCha20-Poly1305 (по умолчанию) / AEGIS-256, ключи производятся через Argon2id",
        ["• 单文件与批量：支持单文件加/解密，及目录批量加/解密（递归）"] = "• Одиночные и пакетные: шифрование/расшифровка одного файла и рекурсивная пакетная для каталогов",
        ["• 断点续传：加密中断后可从上次进度继续，防静默数据丢失"] = "• Возобновление: прерванное шифрование продолжается с контрольной точки, предотвращая тихую потерю данных",
        ["• 路径安全：拒绝目录穿越（..），白名单前缀校验"] = "• Безопасность путей: запрещает выход из каталога (..), проверка префиксов по разрешённому списку",
        ["• 限速：进程级令牌桶限速（YAML max_speed 配置）"] = "• Ограничение скорости: токен-ведро на уровне процесса (параметр YAML max_speed)",
        ["• 配置化：日志/并发/路径策略等运维参数经 YAML 配置"] = "• Настраивается: журналирование/параллелизм/политики путей через YAML",
        ["命令行用法"] = "Использование в командной строке",
        ["密钥来源优先级"] = "Приоритет источников ключа",
        ["-k <keyfile>（密钥文件） > --key-stdin（stdin 管道） > ENCRYPTOR_KEY（环境变量） > 交互式输入；非对称模式用 X25519 身份私钥 > 交互式输入"] = "-k <keyfile> (файл ключа) > --key-stdin (канал stdin) > ENCRYPTOR_KEY (переменная среды) > интерактивный ввод; в асимметричном режиме используется закрытый ключ X25519 > интерактивный ввод",
        ["许可证：GPLv3"] = "Лицензия: GPLv3",
        ["本窗口为 README 摘要，完整文档请见项目根目录 README.md"] = "Это краткое описание README; полную документацию см. в README.md в корне проекта",
        ["README 摘要"] = "Краткое описание README",
        ["已恢复任务: {0}"] = "Задача восстановлена: {0}",
        ["已检测到 CLI: {0}"] = "CLI обнаружен: {0}",
        ["未检测到 FileEncryptor CLI"] = "FileEncryptor CLI не обнаружен",
        ["就绪"] = "Готово",
        ["运行中..."] = "Выполняется…",
        ["已取消"] = "Отменено",
        ["失败 (exit {0})"] = "Ошибка (выход {0})",
        ["任务已取消"] = "Задача отменена",
        ["任务结束 (exit {0})"] = "Задача завершена (выход {0})",
        ["当前: {0} | 完成 {1} | 跳过 {2} | 失败 {3} / 共 {4}"] = "Текущий: {0} | Готово {1} | Пропущено {2} | Ошибок {3} / всего {4}",
        ["口令"] = "Пароль",
        ["确认口令"] = "Подтвердите пароль",
        ["输入口令"] = "Введите пароль",
        ["确定"] = "ОК",
        ["强度：{0}"] = "Надёжность: {0}",
        ["两次输入的口令不一致"] = "Введённые пароли не совпадают",
        ["用时"] = "Затрачено",
        ["平均速度"] = "Средняя скорость",
        ["加密后大小"] = "Размер после шифрования",
        ["完成"] = "Готово",
        ["跳过"] = "Пропущено",
        ["失败"] = "Ошибка",
        ["任务完成"] = "Задача выполнена",
        ["任务历史（双击恢复，右键删除）"] = "История задач (двойной щелчок — восстановить, правый — удалить)",
        ["共 {0} 条记录"] = "Всего записей: {0}",
        ["共 0 条记录"] = "Всего записей: 0",
        ["清空全部"] = "Очистить всё",
        ["暂无历史记录"] = "История пока пуста",
        ["输入 {0} 个, {1}, 耗时 {2}"] = "Ввод: {0}, {1}, затрачено {2}",
        ["删除此条"] = "Удалить эту запись",
        ["视图设置"] = "Настройки вида",
        ["保存"] = "Сохранить",
        ["自定义背景图"] = "Своя фоновая картинка",
        ["图片路径"] = "Путь к изображению",
        ["清除背景"] = "Очистить фон",
        ["支持 PNG / JPG / BMP / WebP 格式。"] = "Поддерживаются форматы PNG / JPG / BMP / WebP.",
        ["口令派生密钥对"] = "Производная пара ключей от пароля",
        ["祝祖国{0}岁生日快乐！永远繁荣昌盛！"] = "С днём рождения {0} Китайской Народной Республики! Пусть она всегда процветает!",
        ["未输入"] = "Не введён",
        ["弱"] = "Слабый",
        ["中"] = "Средний",
        ["强"] = "Надёжный",
        ["小写 "] = "строчные ",
        ["大写 "] = "прописные ",
        ["数字 "] = "цифры ",
        ["符号 "] = "символы ",
        ["无"] = "нет",
        ["长度 {0} | 种类 {1} | 熵 ~{2} bits | {3}"] = "Длина {0} | Классы {1} | Энтропия ~{2} бит | {3}",
        ["口令过短（至少 {0} 个字符）。"] = "Пароль слишком короткий (минимум {0} символов).",
        ["口令过弱：请至少含 2 类字符（小写/大写/数字/符号），或长度 >= 16。"] = "Пароль слишком слабый: используйте минимум 2 класса символов (строчные/прописные/цифры/символы) или длину >= 16.",
        ["  # 密钥经 stdin 管道注入"] = "  # ключ введён через канал stdin",
        ["语言 / Language"] = "Язык",
        ["语言已切换，界面已立即刷新。\nLanguage switched; the UI has been refreshed."] = "Язык переключён; интерфейс обновлён.",
        ["确定 / OK"] = "OK",
        // 更新检查（Updater 返回的错误码）
        ["网络连接不可用，请检查网络后重试。"] = "Сеть недоступна; проверьте подключение и повторите.",
        ["无法解析服务器地址，请检查网络后重试。"] = "Не удалось разрешить адрес сервера; проверьте подключение и повторите.",
        ["检查更新超时，请稍后再试。"] = "Проверка обновлений превысила таймаут. Попробуйте позже.",
        ["安全证书校验失败，可能是网络环境拦截了更新服务。"] = "Проверка сертификата не удалась; сервис обновлений, возможно, заблокирован.",
        ["检查过于频繁，请稍后再试。"] = "Слишком много запросов. Попробуйте позже.",
        ["服务端未找到可更新的版本。"] = "На сервере не найдено доступной версии.",
        ["更新服务地址不可达。"] = "Адрес сервиса обновлений недоступен.",
        ["检查更新未返回结果（可能已超时）。请稍后再试。"] = "Проверка обновлений не вернула результат (возможно, таймаут). Попробуйте позже.",
        ["更新器未返回任何结果（可能已超时）。"] = "Обновлятор не вернул результат (возможно, таймаут).",
        ["无法启动更新器，请确认程序安装完整。"] = "Не удалось запустить обновлятор; проверьте целостность установки.",
        ["下载超时，请稍后再试。"] = "Загрузка прервана по таймауту. Попробуйте позже.",
    };

    // 外文→中文反向表
    private static readonly Dictionary<string, string> ZhFromEnMap = BuildReverseMap(EnMap);
    private static readonly Dictionary<string, string> ZhFromRuMap = BuildReverseMap(RuMap);

    public static string Current { get; private set; } = Zh;

    // 启动期初始化语言
    public static void Init()
    {
        var saved = App.Settings.Current.Language;
        Current = string.IsNullOrEmpty(saved)
            ? (CultureInfo.CurrentUICulture.TwoLetterISOLanguageName switch
                {
                    "zh" => Zh,
                    "ru" => Ru,
                    _ => En,
                })
            : saved;
    }

    // 规范回中文再翻译
    public static string T(string text)
    {
        string baseZh = text;
        if (ZhFromEnMap.TryGetValue(text, out var z1)) baseZh = z1;
        else if (ZhFromRuMap.TryGetValue(text, out var z2)) baseZh = z2;

        if (Current == En) return EnMap.TryGetValue(baseZh, out var en) ? en : baseZh;
        if (Current == Ru) return RuMap.TryGetValue(baseZh, out var ru) ? ru : baseZh;
        return baseZh;
    }

    // 带参翻译
    public static string F(string zh, params object?[] args) => string.Format(T(zh), args);

    private static Dictionary<string, string> BuildReverseMap(Dictionary<string, string> src)
    {
        var map = new Dictionary<string, string>();
        foreach (var kv in src)
            if (!map.ContainsKey(kv.Value)) map[kv.Value] = kv.Key;
        return map;
    }

    // 保存语言选择
    public static void Set(string lang)
    {
        Current = lang;
        App.Settings.Current.Language = lang;
        App.Settings.Save();
    }
}
