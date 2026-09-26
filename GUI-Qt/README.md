# FileEncryptor GUI (Qt6 / Linux)

> **Windows 版本已迁移至 WinUI 3**，见 [../GUI-WinUI/](../GUI-WinUI/)。本项目仅用于 Linux/macOS 的 Qt6 构建。

FileEncryptor **图形界面**。Windows 侧使用 **WinUI 3**（Windows App SDK，C#），Linux 侧使用 **Qt 6**（Widgets，C++，静态链接）。两个平台共享同一份 CLI 后端，界面各自独立实现。

- 程序版本 **2.0.0**（配套 CLI 2.4.2）。

---

## 项目定位

本项目是 **FileEncryptor GUI 独立子项目**：编译产出 `FileEncryptorGUI(.exe)`，是 FileEncryptor 命令行工具的图形界面外壳。

| 项目 | 产物 | 依赖 | 关系 |
|---|---|---|---|
| `../CLI/`（CLI） | `FileEncryptorCLI(.exe)` | libsodium（静态）+ yaml-cpp（静态） | 完全独立，可单独发布 |
| **本项目**（GUI） | `FileEncryptorGUI(.exe)` | Qt6（**静态**）+ 运行时依赖本 CLI 子进程 | GUI 依赖 CLI；CLI 不依赖 GUI |

> **架构说明**：GUI **不直接链接加密核心代码**（`core/`）。Qt6 官方只提供 `/MD`（动态 CRT）构建，libsodium 静态库是 `/MT`，两者 CRT 冲突（LNK2038）决定了 GUI 不能直接链接含 libsodium 的 core。正确架构是**进程级隔离**：GUI 用进程调用（Windows: `System.Diagnostics.Process`；Linux: `QProcess`）启动 FileEncryptorCLI，异步捕获 stdout/stderr 实时回显，取消即 kill 进程。所有加密核心逻辑只在 CLI 项目。

---

## 依赖

- **C++17** 编译器（MSVC / g++ / Clang）。
- **CMake ≥ 3.16**。
- **Qt 6.2+ Widgets**。静态 / 动态 Qt 均可构建（源码已用 `QT_STATIC` 宏自动区分）：
  - **Windows**：仓库自带 `../third_party/smelibs/` 静态 Qt，CMake 自动选用，无需额外安装。
  - **Linux/WSL**：优先 `/opt/smelibs`（静态 Qt），没有则回退系统 `qt6-base-dev`（动态，运行时依赖 Qt6 *.so）。
  - **macOS**：`brew install qt`。
- **运行时依赖**：`FileEncryptorCLI(.exe)` 须位于 GUI exe 同目录，或通过 `FILEENCRYPTOR_EXE` 环境变量指向，或在 PATH 中可找到。

---

## 构建

### Windows（VS2026 + 静态 Qt，smelibs）

```powershell
# 方式一：VS2026「打开文件夹」直接加载 GUI 项目，选 windows-vs2026-release / windows-vs2026-debug
# 方式二：命令行（需 VS2026 x64 Developer Command Prompt / Developer PowerShell）
cmake --preset windows-vs2026-release
cmake --build --preset windows-vs2026-release --config Release
# 产物：out\build\windows-vs2026-release\Release\FileEncryptorGUI.exe
#     （完全自包含：无 Qt6Core.dll / Qt6Gui.dll / Qt6Widgets.dll / platforms/qwindows.dll 依赖）
```

静态 Qt 分发已随仓库放于 `../third_party/smelibs/`，CMake 只使用这一条仓库相对路径（不再引用任何本机绝对路径）。如使用其他位置的静态 Qt，在命令行覆盖：
```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
      -DCMAKE_PREFIX_PATH="<静态 Qt 根目录>"   # 例: ../third_party/smelibs
```

> **关键前提（Windows）**：`Qt6::Core` / `Qt6::Gui` / `Qt6::Widgets` 必须是 **STATIC IMPORTED** 目标（`add_library(Qt6::Core STATIC IMPORTED)`，见 `lib/cmake/Qt6Core/Qt6CoreTargets.cmake`）才能得到零 DLL 的自包含 exe。动态构建的 Qt（官方 msvc2022_64 默认）也能构建成功，但会链接到 `Qt6Core.dll`，运行时需把 Qt DLL 放在 exe 同目录（与本项目"不依赖 Qt DLL"目标不符）。Linux / macOS 使用系统动态 Qt 时同理（运行时依赖 Qt6 *.so / framework）。

> **平台插件 / 图像格式插件**：`src/main.cpp` 中的 `Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)` / `QJpegPlugin` / `QGifPlugin` / `QICOPlugin` 等声明用 `#ifdef QT_STATIC` 包裹——仅**静态 Qt** 下才编译期链入插件（链接器把插件代码静态打入 exe，运行时无需 `platforms/qwindows.dll` 或 `imageformats/qjpeg.dll`）；动态 Qt 下自动跳过，由 Qt 运行时加载插件。因此同一份源码在 Windows 静态 Qt 与 Linux / macOS 共享 Qt 下都能构建。

### Linux

```bash
# 静态 Qt 已放 /opt/smelibs（CMake 自动识别）；用系统动态 Qt 则：
sudo apt install qt6-base-dev
cmake --preset linux-release
cmake --build --preset linux-release
# 构建完成后自动：
#   - 拷到 out/Ubuntu-26.04/build/linux-release/bin/FileEncryptorGUI-2.0.0-Qt-Linux
#   - cpack 生成 out/packages/file-encryptor-gui-qt-2.0.0-Linux.deb 和 .rpm
```

> **Linux 中文字体（豆腐块修复）**：最小化 / 服务器环境常无 CJK 字体，界面中文会渲染成方块（□）。
> 本项目在 Linux/macOS 构建期把 `fonts/NotoSansSC-Regular.otf`（Noto Sans SC，SIL OFL）经
> `fonts.qrc` 嵌入 exe，启动期由 `FontBootstrap` 自动加载为兜底界面字体，无需系统预装中文字体。
> 若你已安装中文字体（如 `fonts-noto-cjk`），则自动沿用系统字体、不加载嵌入字体。
> 系统缺 CJK 字体而回退到嵌入字体时，`FontBootstrap` 会同时把该字体导出到
> `~/.local/share/fonts/FileEncryptor/` 并刷新 fontconfig 缓存——窗口标题栏由窗口管理器
> 经 fontconfig 绘制，应用内字体兜底覆盖不到；不导出的话标题栏中文会显示为码点方块，
> 导出后（通常重启应用生效）即恢复正常。
> 也可用环境变量 `FILEENCRYPTOR_UI_FONT=<字体族名>` 强制指定。

> 本项目「无 DLL / 无 SO」目标在 Linux 下需使用静态构建的 Qt6（即 `-static` Qt 编译选项或
> 三方静态包）。系统默认的动态 Qt 包构建会成功但运行时依赖 Qt6Core.so 等。

### macOS

```bash
brew install qt
cmake --preset macos-release
cmake --build --preset macos-release
# 产物：out/build/macos-release/FileEncryptorGUI.app
```

---

## 运行时：定位 FileEncryptorCLI

GUI 通过 `FileEncryptorLocator` 按以下顺序查找 `FileEncryptorCLI(.exe)`：

1. 环境变量 `FILEENCRYPTOR_EXE`（绝对路径）—— 显式覆盖
2. GUI exe 同目录 —— 打包发布的常见布局
3. `PATH` 环境变量中的可执行文件 —— Linux/macOS 安装到 `/usr/bin` 后

> 早期版本曾向上多级查找 `../bin/`、`../../bin/`、`../build_test/` 等统一项目布局路径，
> 已移除以适配独立项目结构。

找不到 CLI 时 GUI 仍能启动，但任何加解密动作会立即报错并提示用户配置 CLI 路径。

### 开发期典型布局

```
FileEncryptor/
├── CLI/
│   └── out/build/windows-vs2026-release/Release/FileEncryptorCLI.exe
└── GUI/
    └── out/build/windows-vs2026-release/Release/FileEncryptorGUI.exe
```

把 `FileEncryptorCLI.exe` 复制到 GUI 的 `Release/` 目录即可（或者设置 `FILEENCRYPTOR_EXE` 指向 CLI 的绝对路径）。

---

## 使用

直接运行 `FileEncryptorGUI(.exe)`：

- **顶栏（菜单栏）**：关于菜单（鸣谢 + README 摘要 + 关于 Qt）、编辑菜单（“编辑 YAML 配置...”用系统默认编辑器打开 CLI 的 fileencryptor.yaml）；右上角为主题下拉框（浅色 / 深色）与 `视图设置` 按钮（自定义背景图），与“关于”同一行
- **左侧**：文件选择面板（添加文件 / 添加目录 / 清空；支持从资源管理器拖放文件 / 目录）
- **中部**：动作按钮（加密 / 解密 / 批量加密 / 批量解密）+ 模式选择（XChaCha20-Poly1305 / AEGIS-256）。密钥库管理已整体下线 GUI——改由 CLI 的 `-L` 子命令（list/add/remove/show/pub/export）与 `-K` 按名解析收件人 / 身份承担，两端共用 `<用户配置目录>/keys/`。
- **右侧**：密码输入框（星号遮挡 + 强度提示）
- **下部**：只读命令输出窗口（实时显示 CLI 子进程 stdout/stderr，按主题着色）；其标题行右侧为「任务历史...」入口（功能5）。输出区**上部固定**一块「批量进度面板」（功能6，仅批量模式 `-be` / `-bd` 可见）：由 CLI 的进度帧驱动，渲染「汇总行（总大小 | 已处理大小 | 总速率 | ETA）+ 每线程一行（文件路径 | 进度条 | 速率 | ETA）」，字段顺序、分隔符与自适应单位（B/KB/MB/GB/TB）与 CLI 终端帧完全一致；空闲时按历史吞吐预估总耗时。任务历史面板列出每次运行的开始时间、动作、模式、规模、耗时、吞吐与结果，支持清空、双击回填参数重跑（功能5）。

### 任务历史（功能5）

- **存储**：`<用户配置目录>/history/tasks.log`（JSONL，每行一条记录，追加写；单条损坏不影响其余条目；扩展名统一为 3 字符）。路径与密钥库同根，统一经 `QDir::toNativeSeparators()` 归一化，不含混用分隔符。
- **记录内容**：任务 id、起止时间、耗时、动作（`-e/-d/-be/-bd/-g/-G/-Y`）、加密模式、输入路径数、输入字节总量（目录递归统计）、已完成文件数、输出目录、退出码、是否取消、错误、结果（成功 / 失败 / 已取消）。
- **ETA 算法（仅用于批量面板空闲预估）**：取历史中「完整成功」记录的吞吐中位数（抗单次异常值），按 `动作+模式 → 动作 → 全体` 三级分层取样，最多取最近 10 条；运行中改用 CLI 实时进度帧外推。样本不足时批量面板明示「暂无历史样本」而不给出臆测数字。
- **入口**：输出区标题行右侧「任务历史...」按钮（工具菜单仅保留「任务历史」一项）。

详细交互说明见源文件注释与 `src/MainWindow.cpp`。

---

## 主题

支持双态主题切换（**浅色 / 深色**），用户偏好经 `QSettings` 持久化到注册表 / 配置文件：

- **Windows**：`HKEY_CURRENT_USER\Software\FileEncryptor\FileEncryptorGUI\theme`
- **Linux**：`~/.config/FileEncryptor/FileEncryptorGUI.conf`
- **macOS**：`~/Library/Preferences/com.FileEncryptor.FileEncryptorGUI.plist`

主题切换经 `ThemeManager::initialize(&app)` 在主窗口构造前应用，避免闪烁。

深色调色板满足 WCAG AA 对比度：
- 背景 `#1E1E1E`，stdout 文字 `#E6E6E6`（≈ 13:1）
- stderr 文字 `#FF8A80`（≈ 5.4:1）

---

## 图标

- **exe 图标**（Windows 任务栏 / 资源管理器）：经 `FileEncryptorGUI.rc` 嵌入 `logogui.ico`
- **窗口标题栏图标**（三端统一）：经 Qt 资源 `icons.qrc`（`/icons/app.ico`）在 `main.cpp` 中 `setWindowIcon(QIcon(":/icons/app.ico"))` 设置

---

## CMakePresets 速查

| 预设名 | 平台 | 生成器 | 构建类型 | 适用场景 |
|---|---|---|---|---|
| `linux-release` | Linux | Ninja | Release | 生产构建 |
| `linux-debug` | Linux | Ninja | Debug | 调试 |
| `macos-release` | macOS | Ninja | Release | 生产构建 |
| `windows-vs2026-release` | Windows | Visual Studio 18 2026 | Release | **VS2026 一键编译** |
| `windows-vs2026-debug` | Windows | Visual Studio 18 2026 | Debug | **VS2026 一键调试** |

预设不写入任何本机绝对路径，Qt 一律取自仓库相对路径 `../third_party/smelibs/`；如静态 Qt 放在别处，请在命令行用 `-DCMAKE_PREFIX_PATH=...` 覆盖。

---

## 常见问题

### 启动时找不到 CLI

GUI 启动后状态栏提示"未找到 FileEncryptorCLI"。解决：

1. 把 CLI 的 `FileEncryptorCLI.exe` 复制到 GUI exe 同目录
2. 或设置环境变量 `FILEENCRYPTOR_EXE=<CLI exe 绝对路径>`
3. 或把 CLI exe 目录加入 `PATH`

### 构建报 Qt 找不到

确认 `CMAKE_PREFIX_PATH` 指向的 Qt 安装包含 `lib/cmake/Qt6Core/Qt6CoreConfig.cmake`。`smelibs` 路径下应有 `lib/cmake/Qt6/`、`lib/cmake/Qt6Core/`、`lib/cmake/Qt6Widgets/` 等目录。

### 链接报 LNK2019 / undefined reference

通常是用了动态 Qt（`add_library(Qt6::Core SHARED IMPORTED)`），本项目需要静态 Qt。检查 `lib/cmake/Qt6Core/Qt6CoreTargets.cmake` 头部是否为 `add_library(Qt6::Core STATIC IMPORTED)`。

### GUI 启动后白屏 / 无控件

通常是插件未正确静态导入。检查 `src/main.cpp` 是否包含 `#include <QtPlugin>` 和 `Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)` 等声明。

---

## 与 CLI 项目的关系

CLI 项目位于仓库同级目录 `../CLI/`。详见 `../CLI/README.md`。
