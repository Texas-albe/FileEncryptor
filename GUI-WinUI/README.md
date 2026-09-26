# FileEncryptor GUI (WinUI 3)

Windows 平台的 FileEncryptor 图形界面，基于 **WinUI 3 (Windows App SDK 1.5)** 和 **.NET 8**（C#）。

Linux 平台的 Qt6 版本见 [`../GUI-Qt/`](../GUI-Qt/)。

- 程序版本 **2.0.0**（配套 CLI 2.4.2）。

## 项目定位

本项目是 FileEncryptor 的 Windows 图形界面外壳，通过子进程调用 `FileEncryptorCLI.exe` 执行实际加解密。GUI 不链接加密核心代码，所有加密逻辑在 CLI 项目中。

| 项目 | 产物 | 技术栈 |
|---|---|---|
| `../CLI/` | `FileEncryptorCLI.exe` | C++17 / CMake / libsodium |
| **本项目** | `FileEncryptorGUI-2.0.0-WinUI-Windows.exe` | C# / .NET 8 / WinUI 3 |
| `../GUI-Qt/` | `FileEncryptorGUI-2.0.0-Qt-Linux` | C++ / Qt6 |

## 功能

- 对称加解密（XChaCha20-Poly1305 / AEGIS-256），口令经 stdin 安全管道注入
- 非对称加密（X25519 + ChaCha20-Poly1305），多收件人
- 批量加解密（目录递归，自动跳过已存在的有效输出）
- 密钥生成 / 口令派生密钥对 / 公钥导出
- v6 容器密钥轮换（rewrap）
- zstd 压缩
- 磨砂玻璃背景（Acrylic），支持自定义背景图
- 默认深色主题
- 文件列表勾选：仅勾选的条目参与执行
- 命令预览实时显示当前参数，运行时输出首行为完整命令
- 任务历史：清空全部、右键删除、双击回放全部参数
- 任务完成汇总弹窗（用时、平均速度、加密后大小、完成/跳过/失败）
- 密码强度评估、确认密码、内置显示密码按钮
- 进度实时回显（直接控制台执行）
- 拖放文件、SHA256 校验单

## 构建

需要 **.NET 8 SDK** + Visual Studio 2026（勾选「使用 .NET 的桌面开发」）。

```powershell
# 方式一：VS2026 打开 ../FileEncryptor.slnx（默认 Release x64）
# 方式二：命令行（用 VS 的 MSBuild，需指定 x64 平台）
& "E:\Microsoft Visual Studio\MSBuild\Current\Bin\MSBuild.exe" FileEncryptorGUI.WinUI3.csproj /p:Configuration=Release /p:Platform=x64 /t:Build

# 发布自包含部署 + MSI 安装包
.\build.cmd publish
```

## 打包

MSI 安装包由 WiX v4 构建（`installer/`），安装到 `%ProgramFiles%\FileEncryptor\`，含开始菜单和桌面快捷方式。

启动时会自动探测 CLI，未找到时弹窗提示预期文件名并提供重试与下载入口。

## 共享资源

图标引用自 `../GUI-Qt/logogui.ico`，不重复存放。
