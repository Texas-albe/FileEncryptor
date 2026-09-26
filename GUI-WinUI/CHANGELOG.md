# ChangeLog - FileEncryptor GUI (WinUI 3 / Windows)

本文件记录 **FileEncryptor GUI (WinUI 3)** 子项目的变更。Linux Qt6 版本的变更记录见 [`../GUI-Qt/CHANGELOG.md`](../GUI-Qt/CHANGELOG.md)，CLI 见 [`../CLI/CHANGELOG.md`](../CLI/CHANGELOG.md)。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [2.0.0] - 2026-09-26

Windows 侧界面从 Qt6 切换到 WinUI 3（Windows App SDK 1.5 / .NET 8），作为独立项目 `GUI-WinUI/` 存在。Linux 版本保持 Qt6，见 `GUI-Qt/`。

### Added
- **WinUI 3 界面**：布局与 Qt 版保持一致（菜单栏、文件列表、功能区、输出区、状态栏），全部功能无裁剪迁移。
- **文件勾选**：文件列表每项带勾选框，仅勾选的条目参与执行。
- **CLI 未找到提示**：启动时自动探测 CLI，未找到时弹窗列出预期文件名，可重试或前往下载。
- **自定义背景图**：视图设置中可选择图片作为主界面背景，也可随时清除恢复默认。
- **关于对话框**：分为「鸣谢」与「README 摘要」两页。
- **MSI 安装包**：WiX v4 打包，安装到 `%ProgramFiles%\FileEncryptor\`，含开始菜单与桌面快捷方式。
- **VS 解决方案**：根目录 `FileEncryptor.slnx`，VS2026 直接打开。

### Changed
- **背景统一为 Acrylic**：移除 Mica 选项。
- **主题精简**：删除浅色主题与切换选项，默认深色。
- **命令预览**：空闲时显示当前参数，运行时输出首行为完整命令；路径参数自动加引号。
- **加密模式下拉**：默认选中 XChaCha20-Poly1305，非对称项标注为「X25519 + ChaCha20-Poly1305（非对称）」。
- **版本号**：升至 2.0.0，配套 CLI 期望版本 2.4.2。

### Fixed
- 修复任务历史、视图设置等对话框点击无响应的问题。
- 修复「添加目录」报无效窗口句柄的问题。
- 修复 CLI 输出捕获导致界面卡顿的问题，改为直接控制台执行。
- 修复按钮悬停颜色异常，运行按钮绿色、取消按钮红色且悬停加深。

### Technical
- CLI 调用从 `QProcess` 迁移到 `System.Diagnostics.Process`，密钥仍经 stdin 注入。
- 进度帧解析、任务历史、密码强度、ETA 估算等逻辑从 C++ 移植为 C#。
