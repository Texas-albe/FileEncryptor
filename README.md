# FileEncryptor

跨平台 C++17 文件加密工具，基于 libsodium（XChaCha20-Poly1305 / AEGIS-256），GPLv3 许可。
支持 Windows / Linux（macOS 未充分测试）。磁盘格式默认 v6（可扩展加密容器，含 header_hmac 安全信封；
按需可写 v4/v5 头，v1–v6 全部可直接解密，向后兼容）。

## 项目用途

- 对任意文件/目录进行单文件或批量加解密（`.ptd` 格式），支持断点续传、进度备份、文件名加密与输出名混淆。
- 密钥来源（对称）：`-k` 密钥文件 > `--key-stdin`（stdin 管道） > `ENCRYPTOR_KEY` 环境变量 > 交互输入。非对称（age）模式用 X25519 公钥加密文件密钥，私钥经 stdin / 密钥文件传入，不经环境变量。
- 运维参数（日志/并发/限速/白名单）统一由 `fileencryptor.yaml` 提供，CLI 不可覆盖。

## 目录结构

```
FileEncryptor/
├── CLI/                # 命令行程序（CMake，产出 FileEncryptorCLI）
│   ├── core/           # 加密核心
│   ├── cli/            # main.cpp 参数解析
│   └── cmake/          # 校验脚本
├── GUI-Qt/             # Linux 图形界面（Qt6 Widgets，C++，CMake）
│   ├── src/            # MainWindow、QProcess 调 CLI
│   └── fonts/          # 嵌入中文字体
├── GUI-WinUI/          # Windows 图形界面（WinUI 3 / .NET 8，C#）— 独立项目
│   ├── FileEncryptorGUI.WinUI3.csproj
│   ├── MainWindow.xaml / .cs
│   ├── Services/       # CLI 调用、主题、历史、定位等
│   ├── ViewModels/
│   ├── installer/      # WiX v4 MSI 安装包
│   └── build.cmd
├── FileEncryptor.slnx  # VS 解决方案（GUI-WinUI + installer）
└── README.md
```

CLI 与 GUI 相互独立构建。GUI 不链接加密代码，通过子进程调用 CLI（Windows: `System.Diagnostics.Process`；Linux: `QProcess`），二者置于同一目录即可协同运行。

## 快速上手

### Windows（Visual Studio 2026）

1. 双击 `FileEncryptor.slnx` 打开解决方案（含 GUI-WinUI + MSI 安装包两个项目）
2. 顶部配置选 **Release x64**
3. F5 运行 GUI，或右键 installer 项目 → 生成，自动产出 MSI
4. CLI 为 CMake 项目：VS「打开文件夹」选择 `CLI/` 目录，选 `windows-vs2026-release` 配置

命令行等价方式：
```powershell
# GUI + MSI 一键构建（installer 会自动 publish GUI）
& "E:\Microsoft Visual Studio\MSBuild\Current\Bin\MSBuild.exe" FileEncryptor.slnx /p:Configuration=Release /p:Platform=x64

# 仅 CLI
cd CLI && cmake --preset windows-vs2026-release && cmake --build --preset windows-vs2026-release
```

```bash
# Linux (WSL):
cd CLI && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
cd ../GUI-Qt && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
```

详细用法见各子项目 README（`CLI/README.md`、`GUI-WinUI/README.md`、`GUI-Qt/README.md`）。

## 跨平台要点

- Windows：CLI 静态链接 libsodium + yaml-cpp（/MT）；GUI-WinUI 使用 WinUI 3（Windows App SDK，自包含部署），MSI 安装到 `%ProgramFiles%\FileEncryptor\`。
- Linux：CLI 系统 libsodium；GUI-Qt 使用 Qt6（静态或动态），内嵌 Noto Sans SC 兜底中文字体。
- 源码 UTF-8，平台分支一律 `#ifdef _WIN32` / `#else` 成对出现。

## 许可

GPLv3（见 `CLI/LICENSE`、`GUI-Qt/LICENSE`、`GUI-WinUI/LICENSE`）。Noto Sans SC 字体为 SIL OFL。
