# FileEncryptor GUI (WinUI 3)

Windows 平台的 FileEncryptor 图形界面，基于 **WinUI 3 (Windows App SDK 1.5)** 和 **.NET 8**（C#）。

Linux 平台的 Qt6 版本见 [`../GUI-Qt/`](../GUI-Qt/)。

- 程序版本 **2.1.1**（配套 CLI 2.7.1）。

## 项目定位

本项目是 FileEncryptor 的 Windows 图形界面外壳，通过子进程调用 `FileEncryptorCLI.exe` 执行实际加解密。GUI 不链接加密核心代码，所有加密逻辑在 CLI 项目中。

| 项目 | 产物 | 技术栈 |
|---|---|---|
| `../CLI/` | `FileEncryptorCLI.exe` | C++17 / CMake / libsodium |
| **本项目** | `FileEncryptorGUI-2.1.1-WinUI-Windows.msi` | C# / .NET 8 / WinUI 3 |
| `../GUI-Qt/` | `FileEncryptorGUI-2.1.1-Qt-Linux` | C++ / Qt6 |

## 功能

- 对称加解密（XChaCha20-Poly1305 / AEGIS-256），密码经 stdin 安全管道注入
- 非对称加密（X25519 + ChaCha20-Poly1305），多收件人
- 批量加解密（目录递归，自动跳过已存在的有效输出）
- 密钥生成 / 密码派生密钥对 / 公钥导出
- v6 容器密钥轮换（rewrap）
- zstd 压缩
- 磨砂玻璃背景（Acrylic），支持自定义背景图
- 主题切换：「视图」菜单里可选浅色 / 深色 / 跟随系统，选择即生效并记住
- 文件列表勾选：仅勾选的条目参与执行
- 命令预览实时显示当前参数
- 在系统控制台窗口中运行 CLI：进度、结果与提示实时可见，任务结束后窗口保留 3 秒再关闭
- 界面语言 简体中文 / English / Русский，切换即时生效，无需重启
- 任务历史：清空全部、右键删除、双击回放全部参数
- 任务完成汇总弹窗（用时、平均速度、加密后大小、完成/跳过/失败）
- 密码强度评估、确认密码、内置显示密码按钮
- 拖放文件、SHA256 校验单
- 预览解密：新开窗口显示密文里的内容，不写出解密文件

## 密码内存残留（已知限制）

.NET 托管 `string` 不可变且受 GC 管理，密码在界面与参数组装中的中间副本无法可靠清零（`SecureString` 在 .NET Core 上已不推荐用于新开发）。项目已做的：写入子进程 stdin 的字节数组在 `finally` 中 `Array.Clear`、崩溃日志只记异常类型与消息不记录对象内容、历史记录不存密码。残留窗口限于本进程托管堆，不落盘、不进 argv / 环境变量。需要更强保证时应改用 `PasswordBox`（`SecurePassword` 走非托管内存）。

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
