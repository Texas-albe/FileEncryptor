# FileEncryptor GUI

跨平台（Windows / Linux / macOS）FileEncryptor **图形界面**。基于 Qt 6（Widgets）实现，**静态链接** Qt 主库与所有依赖（Qt6Core / Qt6Gui / Qt6Widgets 及 Qt6Bundled*），运行时**不依赖任何 Qt DLL 或插件 DLL**。

- 程序版本 **1.2.0**。

---

## 项目定位

本项目是 **FileEncryptor GUI 独立子项目**：编译产出 `FileEncryptorGUI(.exe)`，是 FileEncryptor 命令行工具的图形界面外壳。

| 项目 | 产物 | 依赖 | 关系 |
|---|---|---|---|
| `../CLI/`（CLI） | `FileEncryptorCLI(.exe)` | libsodium（静态）+ yaml-cpp（静态） | 完全独立，可单独发布 |
| **本项目**（GUI） | `FileEncryptorGUI(.exe)` | Qt6（**静态**）+ 运行时依赖本 CLI 子进程 | GUI 依赖 CLI；CLI 不依赖 GUI |

> **架构说明**：GUI **不直接链接加密核心代码**（`core/`）。Qt6 官方只提供 `/MD`（动态 CRT）构建，libsodium 静态库是 `/MT`，两者 CRT 冲突（LNK2038）决定了 GUI 不能直接链接含 libsodium 的 core。正确架构是**进程级隔离**：GUI 用 `QProcess` 启动 FileEncryptorCLI.exe，异步捕获 stdout/stderr 实时回显，取消即 kill 进程。所有加密核心逻辑只在 CLI 项目。

---

## 依赖

- **C++17** 编译器（MSVC / g++ / Clang）。
- **CMake ≥ 3.16**。
- **Qt 6.2+ Widgets**。静态 / 动态 Qt 均可构建（源码已用 `QT_STATIC` 宏自动区分）：
  - **静态 Qt**（Windows 默认，如 `C:\Program Files\smelibs` 这种已编译为 `.lib` 的分发）：得到零 Qt DLL/SO 依赖的自包含 exe。
  - **动态 Qt**（Linux 发行版默认 `qt6-base-dev`、macOS `brew install qt`）：构建同样通过，插件由 Qt 运行时加载。
  - 官方 Qt 在线安装器可选「Static Qt Builds」组件。
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

CMakePresets 默认 `CMAKE_PREFIX_PATH="C:/Program Files/smelibs"`（用户安装的静态 Qt 分发）。如使用其他路径的静态 Qt，可在命令行覆盖：
```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
      -DCMAKE_PREFIX_PATH="D:/Qt/6.11.2/static_msvc2022_64"
```

> **关键前提（Windows）**：`Qt6::Core` / `Qt6::Gui` / `Qt6::Widgets` 必须是 **STATIC IMPORTED** 目标（`add_library(Qt6::Core STATIC IMPORTED)`，见 `lib/cmake/Qt6Core/Qt6CoreTargets.cmake`）才能得到零 DLL 的自包含 exe。动态构建的 Qt（官方 msvc2022_64 默认）也能构建成功，但会链接到 `Qt6Core.dll`，运行时需把 Qt DLL 放在 exe 同目录（与本项目"不依赖 Qt DLL"目标不符）。Linux / macOS 使用系统动态 Qt 时同理（运行时依赖 Qt6 *.so / framework）。

> **平台插件 / 图像格式插件**：`src/main.cpp` 中的 `Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)` / `QJpegPlugin` / `QGifPlugin` / `QICOPlugin` 等声明用 `#ifdef QT_STATIC` 包裹——仅**静态 Qt** 下才编译期链入插件（链接器把插件代码静态打入 exe，运行时无需 `platforms/qwindows.dll` 或 `imageformats/qjpeg.dll`）；动态 Qt 下自动跳过，由 Qt 运行时加载插件。因此同一份源码在 Windows 静态 Qt 与 Linux / macOS 共享 Qt 下都能构建。

### Linux

```bash
# Ubuntu/Debian 安装 Qt6 静态构建（apt 通常只提供动态 .so，需手动构建静态 Qt 或使用
# 三方静态包如 aqt 的 static 版本；最稳妥是从源码按 -static 选项编译 Qt6）
# 此处以系统动态 Qt 演示（注意：动态 Qt 模式下构建产物会依赖 Qt6 *.so，违背"无 DLL"目标）：
sudo apt install qt6-base-dev
cmake --preset linux-release
cmake --build --preset linux-release
# 产物：out/build/linux-release/FileEncryptorGUI
```

> **打包为 DEB / RPM**：Linux 构建后可生成发行包（需 `dpkg` / `rpmbuild`）：
> ```bash
> cmake --build --preset linux-release        # 产出 out/build/linux-release/FileEncryptorGUI
> cd out/build/linux-release && cpack          # 同目录生成 .deb 与 .rpm（安装前缀 /usr，零运行时依赖声明）
> ```
> 包名 `file-encryptor-gui`，自动依赖探测已关闭（静态 Qt6 + 嵌入字体 = 自包含）。

> **Linux 中文字体（豆腐块修复）**：最小化 / 服务器环境常无 CJK 字体，界面中文会渲染成方块（□）。
> 本项目在 Linux/macOS 构建期把 `fonts/NotoSansSC-Regular.otf`（Noto Sans SC，SIL OFL）经
> `fonts.qrc` 嵌入 exe，启动期由 `FontBootstrap` 自动加载为兜底界面字体，无需系统预装中文字体。
> 若你已安装中文字体（如 `fonts-noto-cjk`），则自动沿用系统字体、不加载嵌入字体。
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
- **左侧**：文件选择面板（添加文件 / 添加目录 / 清空）
- **中部**：动作按钮（加密 / 解密 / 批量加密 / 批量解密）+ 模式选择（XChaCha20-Poly1305 / AEGIS-256）
- **右侧**：密码输入框（星号遮挡 + 强度提示）
- **下部**：只读命令输出窗口（实时显示 CLI 子进程 stdout/stderr，按主题着色）

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

Windows 预设的默认 `CMAKE_PREFIX_PATH="C:/Program Files/smelibs"`（用户提供的静态 Qt），如路径不同请在命令行覆盖。

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
