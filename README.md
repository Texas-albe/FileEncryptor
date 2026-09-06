# FileEncryptor-UI

**FileEncryptor 的图形界面包装器 · v3.0.0**（含 CLI 命令行引擎源码）

这是一个完整的开源项目，包含两部分：
- **`src/`**：用 C# WinForms 写的原生 Windows **图形界面**（GUI），把命令行用法变成可视化操作——选文件/文件夹、输入口令、点按钮即可加解密。
- **`cli/`**：由 **瑶璎珞** 编写的 **命令行引擎**（C++ / CMake），也就是真正的加解密核心 `FileEncryptor`。GUI 在底层调用它来完成加密。

> 本项目由 **TwilightFY801（Twilight飞友）** 与 **瑶璎珞** 共同维护，统一按 **GPL-3.0** 开源（详见下方"许可证"）。

---

## ✨ 功能特性（图形界面）

- 原生 Windows 图形界面（C# WinForms / .NET），自包含单文件发布，**无需安装 .NET 运行库**即可运行
- 四种工作模式：加密单个文件、解密单个文件、批量加密目录、批量解密目录（递归处理）
- 点按钮选择文件/文件夹，可指定输出目录
- 口令输入：加密需 ≥6 位且两次一致，解密一次即可，可显示/隐藏
- 选项：加密后删除源文件、强制覆盖已存在文件、显示详细错误；算法可选 XChaCha20（默认）或 AEGIS-256
- 实时进度条（仿 Windows 文件资源管理器样式）+ 详细日志
- 浅色 / 深色主题，跟随系统或手动切换，可加载自定义背景图片
- 圆角、磨砂/半透明卡片等现代化外观
- 启动时显示"关于"弹窗，左下角"制作人员"可查看全部制作人及各自的 Bilibili / GitHub 链接

## 📦 目录结构

```
FileEncryptor-UI/
├── src/                        # 图形界面源码（C# WinForms）
│   ├── FileEncryptorGUI.csproj
│   ├── Program.cs
│   ├── MainForm.cs
│   ├── AboutDialog.cs
│   ├── CreditsForm.cs          # “制作人员”浏览器窗口
│   ├── Backdrop.cs
│   ├── BgLoader.cs
│   ├── GlassPanel.cs
│   ├── ModernProgressBar.cs
│   ├── Theme.cs
│   ├── TransControls.cs
│   ├── Ui.cs
│   └── app.manifest
├── cli/                        # 命令行引擎源码（C++ / CMake，由瑶璎珞编写）
│   ├── CMakeLists.txt
│   ├── cmake/                  # CMake 辅助脚本
│   ├── cli/                    # CLI 入口（main.cpp 等）
│   ├── core/                   # 加解密核心（FileEncryptor.cpp/.hpp、config 等）
│   ├── fileencryptor.yaml
│   ├── README.md / CHANGELOG.md
│   └── LICENSE                 # 引擎自身的 GPL-3.0 声明
├── FileEncryptorGUI.ico        # 程序图标（多尺寸）
├── tb.png                      # 图标源图
├── qs/                         # 浅色主题背景图（运行时从 exe 同目录加载）
├── ss/                         # 深色主题背景图（运行时从 exe 同目录加载）
├── LICENSE                     # GPL-3.0
└── README.md
```

## 🚀 使用方法

1. 编译 GUI 得到 `FileEncryptorGUI.exe`（见下方"如何编译"）。
2. 编release 或准备 `FileEncryptor.exe`（命令行引擎，可用 `cli/` 的 CMake 构建，或直接使用引擎发布版）。
3. 把 `FileEncryptor.exe` 放到与该 GUI exe **同级或上一级** 目录（程序会自动查找）。
4. 双击 `FileEncryptorGUI.exe` 即可使用。

> `qs/`、`ss/` 背景图需放在 exe 同目录下才会被加载（否则使用纯色背景）。

## 🔧 如何编译

### 图形界面（GUI）
需要 .NET SDK（目标框架 `net10.0-windows`，在 Windows 上编译）。

```powershell
dotnet publish src/FileEncryptorGUI.csproj -c Release -r win-x64 --self-contained true -o publish
```

### 命令行引擎（CLI）
需要 CMake + 支持 C++20 的编译器（如 MSVC / MinGW）以及 [libsodium](https://download.libsodium.org/)。

```bash
cd cli
cmake -S . -B build
cmake --build build --config Release
```

## 🔗 来源与署名

| 项目 | 说明 | 来源 |
| --- | --- | --- |
| `FileEncryptor` CLI（引擎） | 命令行加解密核心，C++，**由瑶璎珞编写** | [https://github.com/Texas-albe/FileEncryptor](https://github.com/Texas-albe/FileEncryptor) |
| `FileEncryptor-UI`（本项目） | 图形界面（GUI）+ CLI 源码整合仓库 | 本仓库 |

**制作人员：**
- 软件制作 / 引擎：瑶璎珞
- UI 制作：Twilight飞友（TwilightFY801）
- 测试人员：瑶璎珞、就不错了我、Twilight飞友

## 📄 许可证

本项目统一使用 [GNU General Public License v3.0](LICENSE)（GPL-3.0）开源。
- `src/`（图形界面源码）与 `cli/`（命令行引擎源码）均遵循 GPL-3.0。
- GPL-3.0 为强 copyleft 协议：**任何使用、修改或分发本项目（或其衍生作品）的人，都必须以 GPL-3.0 开源**，并附带本许可证全文与对应源码。

> 若你不希望你的代码被 GPL 条款约束，请勿在本仓库基础上修改后闭源分发（详见 [GPL-3.0 说明](https://www.gnu.org/licenses/gpl-3.0.html)）。
