# FileEncryptor

跨平台 C++17 文件加密工具，基于 libsodium（XChaCha20-Poly1305 / AEGIS-256），GPLv3 许可。
支持 Windows / Linux（macOS 未充分测试）。磁盘格式 v4（141B 头 + header_hmac 安全信封，向后兼容 v1–v3）。

## 项目用途

- 对任意文件/目录进行单文件或批量加解密（`.ptd` 格式），支持断点续传、进度备份、文件名加密与输出名混淆。
- 密钥来源：`-k` 密钥文件 > `ENCRYPTOR_KEY` 环境变量 > 交互输入。
- 运维参数（日志/并发/限速/白名单）统一由 `fileencryptor.yaml` 提供，CLI 不可覆盖。

## 目录结构

```
FileEncryptor/
├── CLI/    # 命令行程序（独立子项目，产出 FileEncryptorCLI）
│   ├── core/    # 加密核心：FileEncryptor、config(yaml-cpp)、SecureBuffer
│   ├── cli/     # main.cpp 参数解析与 FileEncryptorCLI.rc 图标
│   ├── cmake/   # CheckStaticSodium 等校验脚本
│   └── scripts/ # 发布构建/签名脚本
├── GUI/    # Qt6 图形界面（独立子项目，产出 FileEncryptorGUI）
│   ├── src/     # MainWindow、QProcess 调 CLI、主题/字体引导、视图设置
│   └── fonts/   # 嵌入的中文字体（仅非 Windows 构建打入 exe）
└── README.md
```

两个子项目相互独立构建：CLI 不依赖 GUI；GUI 不链接加密代码，通过 QProcess 子进程调用 CLI，
二者置于同一目录（或设 `FILEENCRYPTOR_EXE` 环境变量）即可协同运行。

## 快速上手

```bash
# CLI
cd CLI && cmake --preset windows-vs2026-release && cmake --build --preset windows-vs2026-release
# Linux: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# GUI
cd GUI && cmake --preset windows-vs2026-release && cmake --build --preset windows-vs2026-release
```

详细用法见各子项目 README（`CLI/README.md`、`GUI/README.md`）。

## 跨平台要点

- Windows：静态链接 libsodium + yaml-cpp（/MT）；GUI 用 smelibs 静态 Qt，零 Qt DLL 依赖。
- Linux：系统 Qt + 发行版 libsodium；GUI 内嵌 Noto Sans SC 兜底中文字体（防方块）。
- 源码 UTF-8，平台分支一律 `#ifdef _WIN32` / `#else` 成对出现。

## 许可

GPLv3（见 `CLI/LICENSE`、`GUI/LICENSE`）。Noto Sans SC 字体为 SIL OFL。
