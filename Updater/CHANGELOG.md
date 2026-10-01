# ChangeLog - FileEncryptor Updater

本文件记录 FileEncryptor 自动更新器（独立命令行工具）的重要变更。本工具**不携带版本号**（"当前版本"由调用方经 `--current` 传入），故本文件以日期分段。

格式参考 [Keep a Changelog](https://keepachangelog.com/)。

## 2026-10-01

### Fixed
- **Windows SDK 工具链路径推导**：`cmake/openssl_windows.cmake` 正确定位 `rc.exe` 及对应 SDK 版本的 INCLUDE / LIB，configure 不再因找不到 `rc.exe` 中断。`-DFE_RC_EXECUTABLE=<rc.exe>` 可覆盖（个别 SDK 无 bin 目录时）。
- **OpenSSL 静态库前缀改为仓库级共享**（`<Updater>/out/openssl`）：新构建目录直接复用已构建的静态库，VS 首次 configure 由约 30 分钟降到 30 秒。可用 `-DFE_OSSL_PREFIX=` 指定其它前缀。

### Security
- **访问范围收敛为「只访问 GitHub」**：`--check` 的 API 地址与 `--update` 的 `--url` / `--sig-url` 在发起请求前统一校验主机，仅放行 `github.com` / `api.github.com` / `objects.githubusercontent.com` / `codeload.github.com` 四个主机且仅 `http(s)`；白名单外直接以 `host_not_allowed` 报错退出，不建立任何连接。主机为**精确匹配**（不做后缀模糊，借用域名的地址无法绕过），并剥离 URL 凭据与端口。GitHub 自身发起的重定向（release 资产跳 `objects.githubusercontent.com`）不受影响。另提供 `--allow-any-host` 供调试使用，正式分发请勿带该开关。

### Added
- **VS 适配**：新增 `CMakePresets.json`（对齐 CLI/GUI 约定），含 `x64-Release`/`x64-Debug`（Visual Studio 18 2026 生成器）、`windows-release/debug`（Ninja）、`linux-release/debug`、`macos-release` 预设。
- **VS+WSL 自动打包**：新增 `cmake/package_linux.cmake`，由主目标 POST_BUILD 调用，构建后自动生成 DEB/RPM 到 `out/packages`。

### Changed
- **静态链接**：`CMakePresets.json` 的 `base` 预设显式声明 `BUILD_SHARED_LIBS=OFF`，与 `CMakeLists.txt` 的 `BUILD_SHARED_LIBS OFF` + `CURL_STATICLIB` + bundled 源码一致，静态链接的 `libcurl` 已验证进入 `Updater.exe`。
- **MSVC 加 `/EHsc`**：与 CLI/GUI 对齐，消除使用 `std::ofstream` 时的 C4530 警告。

### Fixed
- **Windows 改用静态 OpenSSL（与 Linux 对称）**：TLS 后端由 Schannel 换成 `CURL_USE_OPENSSL`，OpenSSL 从 `third_party/openssl` 源码构建为 `libcrypto.lib`/`libssl.lib`（`VC-WIN64A no-shared no-asm no-tests no-apps`），产物零 ssl/crypto DLL 依赖。`Updater/cmake/openssl_windows.cmake` 自动推导 MSVC/SDK 环境并构建（幂等，`-DFE_OSSL_PREFIX` 可外置复用）；bundled curl 路径统一为 `third_party/curl`。
  - 注意：curl 在 Windows 上用 OpenSSL 后端**不读 Windows 证书库**，需通过 `CURLOPT_CAINFO`（或构建期 `CURL_CAINFO`）指定 CA 包，否则目标机器上 HTTPS 会报证书校验失败。
- **VS 目标视图与启动项**：配置名与 CLI/GUI 一致的 `x64-Release`/`x64-Debug`、`architecture` 用字符串 `"x64"`；`CMakeSettings.json` 与 presets 的 `x64-Release` 重名冲突，已删除，构建配置统一走 presets。`.vs/launch.vs.json` 登记 `Updater.exe` 为启动目标；per-config `RUNTIME_OUTPUT_DIRECTORY` 使 exe 统一落在 `bin\Updater.exe`（不再出现 `bin\Release\`）；bundled curl 的目标归入 `third_party/curl` 文件夹，目标视图不再平铺一长串条目；其示例程序（curl 的 `BUILD_EXAMPLES`）一并关闭，可执行目标只剩 `Updater.exe`。
- **CMake 目标名统一为 `Updater`**：target 名与输出名一致（与 CLI/GUI 同构），VS 启动项可正常识别 `Updater.exe`。
- **curl 源码路径使用仓库相对路径**：WSL 构建环境的第三方库目录由软链接提供，`CMakeLists.txt` 不含本机绝对路径。
- **Linux 静态链接 zstd / jitterentropy**：Ubuntu 26.04 的 `libcrypto.a` 内置 zstd/jitterentropy，故关闭 curl 对 pkg-config 的依赖（`CURL_USE_PKGCONFIG OFF`）与 BROTLI/ZSTD 自动探测，静态构建前设置 `OPENSSL_USE_STATIC_LIBS ON` 再 `add_subdirectory(curl)`，并对 OpenSSL imported target 的 `INTERFACE_LINK_LIBRARIES` 清理后由 Updater 显式按序补链静态库（`libzstd.a`、`libjitterentropy.a`，其后接 Threads/dl）。缺库时 configure 直接提示所需开发包。`ldd` 实测产物零 ssl/crypto/curl/zstd/jitter 动态依赖。

## 2026-09-30

### Added
- **初始实现**：落地 `Updates/009` 自动更新器设计——`--check`（查 GitHub latest release、按框架/平台匹配资产、输出含 SHA256/size/ETag/notes 的 JSON）与 `--update`（下载 → 大小核对 → SHA-256 校验 → 安装到指定目录），进程全程向 stdout 输出 JSON 行；支持 If-None-Match/ETag（304 判定未变化）与 HTTP Range 断点续传。
- **内置最小 JSON 解析器**与**内置纯 C++17 SHA-256 实现**：不引入第三方依赖；SHA-256 已与 Python `hashlib` 对真实下载产物交叉校验一致。
- **Minisign 签名校验预留**：`--sig-url` 接口就绪，release 尚无 `.minisig` 资产时自动跳过。

### Changed
- **HTTP 层由 WinHTTP 迁移到 libcurl**：改静态链接 bundled `../third_party/curl` 源码（`CURL_STATICLIB`，`BUILD_SHARED_LIBS=OFF` 强制静态库），Windows TLS 后端 Schannel、Linux OpenSSL；文件操作改用 `std::filesystem`，SHA-256 不再依赖 BCrypt，工具可同构编译于 Windows / Linux。
- **强制 IPv4 解析**（`CURLOPT_IPRESOLVE_V4`）：修复无 IPv6 路由环境下下载 CDN 连接失败（rc=7）的问题；对有 IPv6 的环境属无害限制。
- **下载进度节流**：有总大小时百分比每变化 ≥5% 输出一行；无总大小时按已收字节间隔输出，避免逐 chunk 刷屏。

### Fixed
- **动态链接残留**：修正 CMake 配置后经 `dumpbin /dependents` 确认产物为纯静态单文件，无 `libcurl.dll` 依赖。
- **路径格式**：README 补充说明 `--install-dir` 须传原生 Windows / Linux 路径。

### 验证记录（真机）
- `--check` 三场景：qt/windows（无更新/有更新）、winui/windows（命中 .msi）全部正确，SHA256 与 size/ETag 提取无误。
- `--update` 真实下载 CLI 资产（约 2.7 MB）与 GUI 资产（约 24 MB）落盘，独立复算 SHA256 与 `--sha256` 校验通过；喂入错误哈希时正确报 `sha256_mismatch`。
