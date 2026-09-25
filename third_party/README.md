# third_party — 随仓库分发的依赖库

| 目录 | 内容 | 来源 |
|---|---|---|
| `libsodium/` | 预编译 MSVC 包（头文件 + x64/Release/v143 静态库等） | libsodium 官方预编译发行包 |
| `yaml-cpp/` | 完整源码（`include/` + `src/`）+ `/MT` 静态库 `lib/yaml-cpp.lib` | 上游源码；静态库用本机 MSVC 14.44 重建（/MT，与 smelibs 的 /MT CRT 匹配） |
| `rage/age-ffi/` | fe_age Rust 源码 + 构建脚本 + 预编译静态库（`lib/windows/`、`lib/linux/`）；`rage/` 同时收纳上游 rage 仓库源码 | 本项目配套的 rage/age C-ABI 封装 |
| `smelibs/` | 预编译静态 Qt6（Windows /MT，含主库与集成插件） | 按需下载，本仓库不再分发 |

构建系统优先使用本目录，系统安装路径作为回退：

- **CLI**：`CLI/CMakeLists.txt` 中 libsodium / yaml-cpp / fe_age 的查找均把 `third_party/` 放在首选（`SODIUM_ROOT` / `YAMLCPP_ROOT` / `FE_AGE_DIR` 仍可显式覆盖）；直编脚本 `CLI/out/build_cli.ps1` 的 INCLUDE/LIB 同样指向本目录。
- **GUI**：Windows 静态 Qt 前缀优先 `third_party/smelibs`，不存在时回退 `C:/Program Files/smelibs`；Linux 仍用系统 Qt。

Linux 下 CLI 的 libsodium / yaml-cpp 仍可用系统包（apt/dnf）或由 `third_party/yaml-cpp` 源码自行编译安装。
