# ChangeLog - FileEncryptor GUI

本文件记录 **FileEncryptor GUI** 子项目的所有重要变更（图形界面 `FileEncryptorGUI(.exe)`）。
命令行子项目的变更记录请见 `../CLI/CHANGELOG.md`。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **GUI 与 CLI 拆分子项目的边界（自 2.1.0 起）**：
> - GUI 仅描述本项目自身的实现变更（界面、主题、图标、构建、依赖查找等）。
> - 加密核心 / 算法 / 磁盘格式 v4 / 续传 / YAML 配置 等行为变更请见 `../CLI/CHANGELOG.md`（CLI 是行为实现的承担者）。

---

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

---

## [1.0.1] - 2026-09-06

### Added
- **【中·GUI】菜单栏新增"编辑"菜单**：顶层菜单（与"关于"同处一行），"编辑 YAML 配置..."按 CLI 的搜索顺序（`FILEENCRYPTOR_CONFIG` 环境变量 → CWD → CLI exe 目录 → 用户配置目录）定位 `fileencryptor.yaml`，未找到时在 CWD 生成与 CLI 一致的默认模板，再经 `QDesktopServices::openUrl` 调用系统默认编辑器打开。
- **【低·项目】根目录新增项目概览 README**（`../README.md`）：项目用途、CLI/GUI 目录结构、快速构建与跨平台要点。

### Changed
- **【中·GUI】主题切换与视图设置移入菜单栏**：原独立顶部工具栏（导航栏）取消，"主题"下拉框（跟随系统/浅色/深色）与"视图设置"按钮经 `QMenuBar::setCornerWidget` 置于菜单栏右上角，与"关于"同一行显示。
- **【低·版本】版本号同步至 1.0.1**：`project(FileEncryptorGUI VERSION 1.0.1)`、`setApplicationVersion`、窗口标题、鸣谢/README 摘要对话框兜底值、README 程序版本声明。

---

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

---

## [2.0.0] - 2026-09-05（标题栏图标 / 版本号同步 / 主题切换）

> GUI 主版本号升级（1.7.2 → 2.0.0）。GUI 行为零变更（仅是项目结构 / 图标 / 主题 / 版本号层面的里程碑）。

### Added
- **【中·GUI】颜色主题切换**：新增 `ThemeManager`，支持「跟随系统 / 浅色 / 深色」三态切换，经 QSettings 持久化用户偏好，启动期在主窗口构造前应用。深色调色板文字对比度满足 WCAG AA（stdout #E6E6E6 对 #1E1E1E 底 ≈ 13:1，stderr #FF8A80 ≈ 5.4:1），修复此前深色模式下文字与背景过近不可读的问题。
- **【中·GUI】应用图标**：`logogui.ico` 嵌入 GUI exe（Windows .rc 资源）；GUI 经 Qt 资源（`:/icons/app.ico`）`setWindowIcon` 设置窗口标题栏图标，三端统一渲染。

### Changed
- **【中·版本】全量版本号同步至 2.0.0**：`FE_VERSION_*` 宏、`project(FileEncryptorGUI VERSION 2.0.0)`、`setApplicationVersion`、`FileEncryptorGUI 2.0.0` 窗口标题、关于对话框（鸣谢 / README 摘要标题均含版本号，取自 `qApp->applicationVersion()` 单一真相源）、README 程序版本声明。
- **【低·GUI】命令输出窗口高度优化**：下部命令浏览窗口高度缩减为原来的一半，给主功能区更多空间。

---

## [1.7.2] - 2026-09-05（GUI 行为无变更）

> GUI 项目版本号随 CLI 同步升级（1.7.1 → 1.7.2）。本期无 GUI 行为变更，仅跟随 CLI 版本号。

---

## [1.7.0] - 2026-09-04（GUI 行为无变更）

> GUI 项目版本号随 CLI 同步升级（1.6.0 → 1.7.0）。本期无 GUI 行为变更。

---

## [1.6.0] - 2026-08-27（GUI 行为无变更）

> GUI 项目版本号随 CLI 同步升级。本期无 GUI 行为变更。

---

## [1.0.0-rc1] - 2026-08-20（首版 GUI 引入 / 整合为统一项目）

> GUI 子项目首版。架构设计：CLI + GUI 整合为统一项目，共享 `core/` 加密核心；GUI 通过 `QProcess` 调用 `FileEncryptorCLI.exe` 执行实际加解密。

### Added
- **【高·架构】CLI + GUI 整合为统一项目**：项目重构为 `core/`（共享加密核心：FileEncryptor.cpp / config.cpp / secure_buffer.hpp）+ `cli/`（命令行入口 main.cpp）+ `gui/`（Qt6 图形界面）三子目录。`FileEncryptorCLI.exe` 链接 core 全部加密逻辑（libsodium + yaml-cpp 静态，完全独立自包含）；`FileEncryptorGUI.exe` 通过 QProcess 调用 CLI 执行实际加解密。加密核心零重复（只在 core/），CLI 完全独立不依赖 Qt，GUI 运行时依赖 FileEncryptorCLI.exe。此架构由 Qt6 /MD 与 libsodium /MT 的 CRT 冲突（LNK2038）决定。
- **【高·GUI】Qt6 跨平台图形界面**：五区域布局（顶栏「关于/视图」菜单 + 左侧文件选择 + 中部功能区 + 右侧密码框 + 下部只读命令输出）。`ICommandExecutor` 抽象 + `ProcessCommandExecutor`（QProcess 异步按行捕获 stdout/stderr，支持 CancellationToken 取消 kill）；`CliArgBuilder` 将 GUI 参数 1:1 映射为与 main.cpp 参数解析一致的 argv；密钥经 `ENCRYPTOR_KEY` 环境变量注入子进程（不入 argv、不留盘）。窗口大小自适应（QSplitter 可拖动调比例）。
- **【低·构建】VS2026 一键编译**：`CMakePresets.json` 新增 `windows-vs2026-release` / `windows-vs2026-debug` 预设（generator="Visual Studio 18 2026"），VS2026 Community 打开文件夹即识别一键编译调试。

### Notes
- GUI 运行时依赖 `FileEncryptorCLI.exe`：CLI 须位于 GUI exe 同目录，或通过 `FILEENCRYPTOR_EXE` 环境变量指向，或在 PATH 中可找到。
- GUI 不链接任何加密代码：所有加解密逻辑均在 CLI 中实现。

---

> 早期版本（v0.x、1.0.x）的 GUI 行为变更记录不在此文件维护，详见 Git 提交记录。
