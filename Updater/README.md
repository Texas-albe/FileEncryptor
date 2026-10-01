# FileEncryptor Updater

FileEncryptor 的**独立自动更新器**，供 GUI（Qt / WinUI）以子进程方式调用，查询 GitHub Releases 最新版本并完成「下载 → 校验 → 安装」。

- **无自更新、无版本号**：本工具不检查自身更新，也不携带版本号——「当前版本」由调用方经 `--current` 传入，便于长期复用而无需随各子项目一起升版。
- **跨平台**：Windows / Linux 同构编译。HTTP 层使用静态链接的 [libcurl](https://curl.se/)（bundled 源码 `../third_party/curl`，双平台均静态链接 OpenSSL，Windows 亦非 Schannel），SHA-256 为内置纯 C++ 实现，JSON 为内置最小解析器——除系统库外**零外部依赖**。
- **单文件分发**：libcurl 静态链接进二进制（`CURL_STATICLIB` + `BUILD_SHARED_LIBS=OFF`），产物不依赖任何 curl/openssl 动态库。

## 用法

```text
Updater --check  --current <ver> --type <qt|winui> --platform <windows|linux> [--etag <etag>]
Updater --update --url <url> --sha256 <hex> --install-dir <dir> [--sig-url <url>] [--allow-any-host]
```

### `--check`：查询最新版本

请求 GitHub API 的 latest release，按调用方的框架/平台匹配资产，向 stdout 输出一行 JSON：

```json
{
  "ok": true,
  "has_update": true,
  "current_version": "2.0.3",
  "latest_version": "2.0.4",
  "tag": "GUI2.0.4_CLI2.4.5",
  "asset_name": "FileEncryptorGUI-2.0.4-Qt-Windows.exe",
  "download_url": "https://github.com/.../FileEncryptorGUI-2.0.4-Qt-Windows.exe",
  "sha256": "…（取自 release 资产的 API digest 字段）",
  "size": 24665600,
  "etag": "…",
  "notes": "…（release notes 全文）"
}
```

资产匹配规则（不区分大小写）：

| type | platform | 资产名模式 |
|---|---|---|
| `qt` | `windows` | `*Qt*Windows*.exe` |
| `qt` | `linux` | `*Qt*Linux` |
| `winui` | `windows` | `*WinUI*Windows*.msi` |

`has_update` 的判定：latest 版本号 > `--current` 传入版本（语义化版本比较）。携带 `--etag` 时若资源未变化返回 304，输出 `etag_unchanged: true`。

### `--update`：下载并安装

下载 `--url` 指向的资产到临时目录，依次执行：大小核对 → SHA-256 校验（`--sha256` 提供时）→ 复制进 `--install-dir`。过程中持续向 stdout 输出进度 JSON 行：

```json
{"progress": 42, "stage": "downloading"}
{"progress": 100, "stage": "verifying"}
{"progress": 100, "stage": "done", "path": "…"}
```

异常时输出 `{"stage": "error", "code": "download_failed"|"sha256_mismatch"|…}`。断点续传：目标文件已存在且小于远端大小时从已收字节续传（HTTP Range）。

> Minisign 签名校验（`--sig-url`）为预留接口：当前 release 未发布 `.minisig` 资产时自动跳过。

## 构建与测试

```bash
cmake -S . -B out/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build out/build
```

bundled libcurl 已关闭 FTP/LDAP/测试/示例等无关能力，仅保留 HTTPS；首次配置约数分钟（需编译 libcurl 静态库）。

## 与 GUI 的协作方式

- Qt（`MainWindow::onCheckForUpdate`）与 WinUI（`MainWindow::OnCheckForUpdate`）以 QProcess / Process 启动本工具，`--current` 传 GUI 自身版本、`--type` 传所属框架。
- GUI 侧（Qt / WinUI）的下载白名单与本工具一致（同一份四主机清单，各自代码注释互相指向）；安装目录约定由 GUI 自行维护。
- 工具查找顺序：`<GUI 同目录>/updater/Updater(.exe)` → `<GUI 同目录>/Updater(.exe)` → PATH。

## 注意

- **只访问 GitHub**：默认网络出口限定在 `github.com` / `api.github.com` / `objects.githubusercontent.com` / `codeload.github.com` 四个主机，且仅 `http(s)`。`--url` / `--sig-url` 指向白名单外主机时，在发起请求前即报错退出（`host_not_allowed`），不产生任何连接。主机匹配为**精确匹配**（无后缀模糊），`evilgithub.com` 这类无法绕过。调试第三方源时附加 `--allow-any-host` 临时放开（仅限自测，正式分发不要带）。重定向由 GitHub 自身发起（如 release 资产跳 `objects.githubusercontent.com`）不受影响。
- 网络访问强制 IPv4（`CURLOPT_IPRESOLVE_V4`）：部分环境无 IPv6 路由时避免连接失败，属无害限制。
- `--install-dir` 请传**原生路径**（Windows 上为 `E:\...` / `E:/...` 形式；Git Bash 的 `/e/...` 挂载路径不被 Win32 文件 API 识别）。
