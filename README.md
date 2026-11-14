# FileEncryptor

跨平台 C++17 文件加密工具，基于 libsodium（XChaCha20-Poly1305 / AEGIS-256），AGPLv3 许可。
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
│   │   └── saf/        # SAF 存储抽象框架（本地/归档/加密盘/云/挂载 后端 + 管道原语）
│   ├── cli/            # main.cpp 参数解析
│   ├── include/        # vdisk.h 等对外 C ABI 头
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
├── CERT/               # 自签名代码签名证书（root.cer/.pvk/.spc，本机私有，不入库）
├── FileEncryptor.slnx  # VS 解决方案（GUI-WinUI + installer）
└── README.md
```

CLI 与 GUI 相互独立构建。GUI 不链接加密代码，通过子进程调用 CLI（Windows: `System.Diagnostics.Process`；Linux: `QProcess`），二者置于同一目录即可协同运行。

### SAF 存储抽象框架

`CLI/core/saf/` 提供统一存储抽象（`Stream` + `StorageBackend`），已并入 CLI 一同构建，
覆盖本地文件系统、归档（zip/7z/tar）、加密盘（经 `vdisk.dll` 运行时加载）、
云端（可插拔）与挂载盘五类后端。核心能力：

- `saf_pump` 通用分块搬运：任意 `Stream` → 任意 `Stream`，不落临时文件；
- `saf_open_stdio` / `saf_open_memory_read|write`：stdio 与内存流；
- `saf_transfer_file` / `saf_transfer_tree`：后端间搬运与断点续传、幂等去重。

CLI 的管道传输即建立在这些原语之上（见下）。

### 管道传输（stdin / stdout）

```bash
cat secret.txt | fe -e - -k pw -o out/          # 明文从 stdin，密文落盘
fe -e - -k pw --stdout < secret.txt > s.ptd     # 明文从 stdin，密文直出 stdout
fe -d s.ptd -k pw --stdout | tar x              # 明文直出 stdout，明文零落盘
```

`-`（stdin 数据）与 `--key-stdin`（stdin 口令）互斥：管道传数据时口令走 `-k <file>`
或 `ENCRYPTOR_KEY` 环境变量。解密到 stdout 完全不落盘明文。

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

GNU Affero General Public License v3.0（AGPLv3，全文见根目录 `LICENSE`；CLI、GUI-Qt、GUI-WinUI、Updater 目录另有副本）。
官方许可地址：<https://www.gnu.org/licenses/agpl-3.0.html>
Copyright (C) 2024-2026 FileEncryptor Contributors

本项目源码随发布仓库完整提供；分发修改版或通过网络向用户提供修改后的程序时，
请按 AGPLv3 第 13 条提供对应的完整源码。Noto Sans SC 字体为 SIL OFL，第三方依赖仍遵循各自许可。

### Corresponding Source（AGPLv3 第 13 条）

- 完整对应源码：<https://github.com/Texas-albe/FileEncryptor>，取与所运行程序**同一版本号**的 tag 或 commit；版本号见各端「关于」页。
- 构建与打包脚本在仓库 `scripts/`，native 依赖在 `Third Party/`；第三方组件及许可见 `CLI/DEPENDENCIES.md` 与应用内「鸣谢」页。
- 网络服务端正在运行的版本，其对应源码以该版本 tag 的仓库快照为准；若仓库不可访问或需要离线归档，
  可通过发布渠道向作者索取与二进制版本一一对应的源码归档。
