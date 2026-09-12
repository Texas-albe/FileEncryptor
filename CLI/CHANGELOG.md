# ChangeLog - FileEncryptor CLI

本文件记录 **FileEncryptor CLI** 子项目的所有重要变更（命令行加密工具 `FileEncryptorCLI(.exe)`）。
图形界面项目的变更记录请见 `../GUI/CHANGELOG.md`。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **磁盘文件格式版本保持 v4**（向后兼容 v1 / v2 / v3，旧产物可直接解密，无需重加密）。
> CLI 主版本号历史上与合并项目同步；自 2.1.0 起 CLI/GUI 拆分独立发版。

---

## [2.1.1] - 2026-09-12

### Changed
- **【中·CLI】口令强策略**：交互式加密 / 口令派生（`-G`）套用统一口令策略（最小长度 8，且至少含 2 类字符或长度 ≥16；非 ASCII 口令直接放行），替代原先仅检查长度 ≥6 的弱校验。
- **【中·CLI】批量解密文件名还原改为可选项**：新增 `-rn` / `--restore-name`，默认关闭。关闭时不逐文件执行昂贵的 Argon2id KDF 还原完整原始文件名，仅保留输出文件扩展名（混淆名自带），显著加快批量解密；开启时还原完整文件名（性能较差，由 GUI 警告后用户选择）。

### Fixed
- **【高·安全】`set_global_config` 悬空指针修复**：改为按值拷贝并以 `shared_ptr<const Config>` 持有，杜绝调用方传入 `load_config()` 临时值后悬空（此前存裸 `const Config*`）。
- **【高·安全】收紧密钥文件权限**：`-g` / `-G` 生成的 `rage_private.txt` 私钥文件写入后收紧为仅拥有者可读（`chmod 0600` / Windows `_chmod _S_IREAD`），避免明文私钥被其它用户读取。
- **【高·安全】`anti_debug_check` 仅主线程调用约束**：补充注释——该函数检测到调试器时直接 `exit(1)`，务必只在 `main()` 启动期、任何工作线程创建前调用，切勿移入 `process_files` 并发 worker，否则会终止整个批量任务。
- **【高·CLI】修复中文 / Emoji 路径加密解密必崩溃**：`normalize_path_lexical` / `compute_progress_binding` 用 `fs::path` 的窄字符串构造（按 ANSI 代码页 / GBK 解释字节），含中文的 UTF-8 路径在 `.string()` 往返时抛 "No mapping for the Unicode character exists in the target multi-byte code page"，未捕获导致 `std::terminate` → fastfail（0xC0000409，GUI 侧表现为"进程崩溃"且无任何输出）。改为先经 `utf8_to_wstring` 转宽字符构造 `fs::path`、规范化后用 `wstring_to_utf8` 取回，全程无 ACP 往返。单文件加密 / 解密调用点另加异常兜底，未预期异常以干净错误退出而非崩溃。
- **【中·CLI】修复 `-o` 在非当前工作目录的盘上无法新建输出目录**：递归创建目录时对盘符分量（如 `"E:"`）做 `_wstat64` 依赖进程级"盘符当前目录"（CWD 在其他盘时失败）、`_wmkdir("E:")` 恒失败。改为用绝对根 `"E:/"` 探测盘可访问性，存在则继续创建剩余分量。此前 GUI 选择其他盘（含 U 盘）的输出目录会报 "Cannot create output directory"。

## [2.1.0] - 2026-09-12

### Added
- **【中·CLI】新增 `-G` / `--derive` 口令派生密钥对**：`Argon2id(口令, 盐) → X25519 密钥对`，输出与 `-g` 一致（公钥到 stdout、私钥到 `<dir>/rage_private.txt`），并额外写出 `<dir>/rage_derive_salt.txt`（16B 随机盐的 hex）。同一口令 + 同一盐永远得到同一对密钥，可用 `--salt <hex|file>` 复现；口令支持 `--key-stdin` / `-k` / `ENCRYPTOR_KEY` / 交互输入（≥6 字符）。已存在同名密钥文件时拒绝覆盖（除非 `-y`）。
- **【中·CLI】新增 `-Y` / `--pubkey` 由私钥导出公钥**：读取 `-k <私钥文件>` 的 `AGE-SECRET-KEY-...`，做一次 X25519 基点乘法反推 `age1...` 并打印到 stdout，等价 `rage-keygen -y`。
- **【中·算法】Bech32 编解码 + X25519 本地实现**（`core/asym_crypto.cpp`）：使上面两个动作**不依赖 `fe_age` 静态库**，未集成非对称加密的构建同样可用。实现要点：age 私钥串的 Bech32 **校验和按小写 HRP 展开**（串本身整体大写），按大写 HRP 展开会被 age 拒绝。
- **【中·CLI】新增 `-g` / `--keygen` 密钥对生成动作**：生成 X25519（rage）密钥对，**公钥打印到 stdout**（可重定向 / 管道），**私钥写入 `-o <dir>/rage_private.txt`**；所有提示信息走 stderr，保证 stdout 只有一行干净的 `age1...` 公钥。无需输入文件，私钥用后立即 `sodium_memzero` 清零。
- **【高·算法】非对称（混合）加密模式（`-m age`）**：基于 [rage/age](https://github.com/str4d/rage) 的 X25519 + ChaCha20-Poly1305 混合加密——每个文件用随机对称文件密钥加密，再用收件人 X25519 公钥包装该密钥，支持多收件人。集成 C-ABI 静态库 `fe_age`（`../age-ffi/`），对外提供 `fe_asym_encrypt` / `fe_asym_decrypt` / `fe_generate_keypair` 调用接口；`WITH_AGE` 默认 ON，未找到静态库时仅 WARNING 并回退为不含非对称加密的版本。
- **【中·CLI】新增 `-r <file>` / `--key-stdin`**：`-r` 指定 age 收件人公钥文件（每行一个 `age1...` 公钥，支持 `#` 注释 / 空行）；`--key-stdin` 从 stdin 读取整段密钥材料（密码或 age 身份私钥，二进制安全），对应 GUI 的安全注入通道。

### Changed
- **【中·版本】全量版本号同步至 2.1.0**：`FE_VERSION_*` 宏（`core/FileEncryptor.hpp`）、`project(FileEncryptorCLI VERSION 2.1.0)`、CPack 包名示例（`file-encryptor-cli_2.1.0-1`）、README / CHANGELOG 同步。本版本同时包含下方全部 rage/age 非对称加密能力，作为 CLI/GUI 拆分后独立发版的 2.1.0 里程碑。
- **【中·CLI】`-m age` 正式更名为 `-m rage`**：`rage` 为规范名，`age` 保留为兼容别名，既有脚本不受影响；帮助文本改为英文介绍混合加密原理（随机文件密钥 + X25519 包装）。
- **【中·CLI】`-r` 可直接接受公钥字符串**：`-r` 的值若以 `age1`（或 `publickey:`）开头即按公钥字符串处理，否则按公钥文件解析（新增 `collect_recipients()`）；文件模式新增公钥格式校验，非法行直接报错而非静默传入底层。
- **【高·CLI】非对称解密改为强制私钥文件**：`-m rage` 解密**必须**通过 `-k <私钥文件>` 提供身份私钥（自动去除首尾空白 / 换行），不再接受身份私钥经 stdin 传入；`--key-stdin` 现在只用于对称模式的密码。未提供 `-k` 时给出明确错误提示。

### Security
- **【高·密钥通道】密钥经 stdin 管道注入**：对称密码与非对称身份私钥统一通过 `--key-stdin` 由 stdin 传入，不再依赖 `ENCRYPTOR_KEY` 环境变量，降低被环境 / 进程列表窥探的风险。
- **【中·密钥通道】非对称私钥改走文件 `-k`**：身份私钥不再经 stdin 管道传递（管道会被 `QProcess` 等父进程完整持有），改为由 CLI 自行读取 `-k` 指定的私钥文件；公钥本身非机密，可安全地在 argv / stdout 中出现。

### Changed
- **【高·架构】项目独立化为 CLI 单一子项目**：本仓库原为「CLI + GUI 统一项目」（共享 `core/`），现拆分为两个独立构建单元：CLI 在本目录（`./`）独立编译产出 `FileEncryptorCLI(.exe)`；GUI 迁至 `../GUI/`，作为独立 Qt6 子项目，通过 `QProcess` 调用本 CLI。本 CLI 不再包含 GUI 相关的 `find_package(Qt6)` / `add_subdirectory(gui)` 逻辑，CMakeLists/CMakePresets/README/LICENSE 各自维护。CLI 行为零变更（加密 / 解密 / 续传 / 批量 / YAML 配置 / 磁盘格式 v4 完全不变）。
- **【中·构建】CMakeLists 路径本地化**：源文件引用由 `core/...` / `cli/...` 保持不变（项目内路径），但 `find_package` / `cp` / `install` 等绝对依赖路径不再继承合并项目的 hints；Windows 沙箱构建仍可通过 `-DSODIUM_ROOT="C:/Program Files/libsodium"` 显式覆盖。
- **【中·构建】CMakePresets 精简**：移除 GUI 相关的 `CMAKE_PREFIX_PATH` Qt 路径项（`E:/Qt/6.x.x/msvc2022_64`），CLI 预设只保留 YAML / libsodium 配置；VS2026 预设（`windows-vs2026-release` / `windows-vs2026-debug`）继续可用。

### Fixed
- **【中·跨平台】修复非 ASCII 文件名下的字符分类未定义行为**：`std::transform(..., ::tolower)` 直接把 `char` 传给 C 字符分类函数，中文等 UTF-8 多字节字节值为负，属未定义行为（glibc 下可能越界查表）。改为 `[](unsigned char c){ return (char)std::tolower(c); }`（`core/FileEncryptor.cpp` 批量 `.ptd` 后缀过滤、`cli/main.cpp` 单文件 `.ptd` 后缀校验、`core/config.cpp` 布尔 / 日志等级解析）。`core/FileEncryptor.cpp` 中盘符判断的 `isalpha()` 同样补 `(unsigned char)` 转换。
- **【低·构建】Linux 老工具链链接善后**：GCC < 9（Ubuntu 18.04 等）的 `std::filesystem` 需显式链接 `stdc++fs`（CMake 已按编译器版本自动追加）；Linux 下统一链接 `${CMAKE_DL_LIBS}`，避免静态链接 libsodium / yaml-cpp 时缺 `dl` 符号。

---

## [2.0.0] - 2026-09-05（程序版本号升级 / CLI 行为不变）

> CLI 主版本号升级（1.7.2 → 2.0.0）。CLI 行为零变更（加密 / 解密 / 续传 / 批量 / YAML 配置 / 磁盘格式 v4 完全不变）；此版本仅是版本号与项目结构层面的里程碑。

### Changed
- **【中·版本】全量版本号同步至 2.0.0**：`FE_VERSION_*` 宏（`core/FileEncryptor.hpp`）、`project(FileEncryptorCLI VERSION 2.0.0)`、CPack 包名示例（`file-encryptor-cli_2.0.0-1`）、README / CHANGELOG 同步。

---

## [1.7.2] - 2026-09-05（yaml-cpp 迁移 / 限速 / 删除 -j / 单位统一）

> 程序版本号 1.7.1 → 1.7.2。磁盘文件格式版本保持 **v4**（向后兼容 v1 / v2 / v3）。

### Added
- **【中·运维】进程级限速（`max_speed`）**：YAML 新增 `max_speed` 配置项，限制加/解密总吞吐（进程级，覆盖批处理全部并发线程）。单位支持 `KB` / `MB` / `GB`（1024 进制），可带 `/s` 后缀（如 `10MB/s`、`1.5GB/s`、`512KB/s`）；`0` 或省略 = 不限速。实现为令牌桶限速器，在加/解密主循环按已处理字节数记账，超出速率则休眠。新增统一的 `parse_size()`（单位解析，支持小数与 `/s` 后缀）与 `format_size()`（字节量格式化为 KB/MB/GB）辅助函数。
- **【中·依赖】配置解析迁移至 yaml-cpp**：YAML 配置解析由手写极简解析器改为 [yaml-cpp](https://github.com/jbeder/yaml-cpp) 库，支持标准 YAML 语法（注释、引号、序列等），解析失败给出明确错误（含 YAML 异常信息）并回退默认配置。CMake 自动查找（`find_package` 或手动定位 `C:/Program Files/yaml-cpp` / `YAMLCPP_ROOT`）；静态链接须以 `/MT` 构建并定义 `YAML_CPP_STATIC_DEFINE`（CMake 已自动处理）；Dockerfile 增加 `libyaml-cpp-dev`。

### Changed
- **【中·CLI】彻底删除 `-j` 参数**：此前已废弃（被忽略并警告）的 `-j <线程数>` 现完全移除，传入会报 `Unknown option: -j` 并退出（exit 1）。并发线程数只能由 YAML `worker_threads` 配置。
- **【低·UX】计量单位统一（KB / MB / GB，1024 进制）**：进度条（已处理/总量、吞吐率 `MB/s`）与批量"Total size"等所有面向用户的字节量显示统一为 `KB`/`MB`/`GB`（1024 进制），不再使用 `MiB` 等混用表述；`io_buffer_size` 等 YAML 字段支持带单位写法（如 `1MB`、`512KB`）。

### Fixed
- **【低·兼容性】`DEFAULT_CONFIG_YAML` 模板更新**：默认配置模板（CWD 自动生成）新增 `max_speed` 项并把 `io_buffer_size` 改为带单位写法 `1MB`（默认值不变，仍为 1048576 字节）。

---

## [1.7.1] - 2026-09-04（文件名加密存储加固）

> 程序版本号 1.7.0 → 1.7.1。磁盘文件格式版本保持 **v4**（向后兼容 v1 / v2 / v3 / 1.7.0）。

### Security
- **【高·隐私】原始文件名改为密文存储（修复 1.7.0 明文泄露）**：1.7.0 曾把混淆前的原始基名以**明文**追加到密文末尾（`FENM` 信封），导致源文件名可在 `.ptd` 中直接读出。现改用与主密文**相同加密配置**——XChaCha20-Poly1305、同一 Argon2 派生主密钥、nonce 由本文件 `salt` 派生并与 `salt` 绑定 AAD——加密后存入尾部（`FENX` 信封，含 16 字节 AEAD tag），解密须正确口令，源文件名不再以明文暴露。保留对 1.7.0 明文尾部（`FENM`）的兼容读取，但新写入一律加密。同时移除 YAML 配置中对"原始名存储位置"的注释，配置不再暴露存储细节。
- **【低·健壮性】加密名尾部改为始终写入**：不再受 YAML `obfuscate_names` 开关控制，无论是否混淆可见文件名，尾部均携带加密后的原始名，解密命名更稳健且不依赖 YAML 暴露存储行为。

---

## [1.7.0] - 2026-09-04（输出名 / 扩展名混淆）

> 程序版本号 1.6.0 → 1.7.0。磁盘文件格式版本保持 **v4**。

### Added
- **【中·隐私/混淆】输出文件名与扩展名混淆（默认开启）**：加密产出形如 `<16位十六进制>.<伪扩展名>.ptd`（`.ptd` 始终在最后），隐藏原始文件名与扩展名。伪扩展名取自 40+ 种常见类型（png / jpg / mp4 / mp3 / pdf / doc / docx / xls / xlsx / css …），由输入路径 + 密钥确定性派生。YAML `obfuscate_names: false` 可关闭，退化为 `<原名>.ptd`。
- **【中·隐私】原始名尾部安全还原**：混淆文件名不含原始信息，故把原始基名以明文（未认证）追加到密文**末尾**（8 字节头部 `FENM`(4) + 名称长度(4) + 名称）。解密据此还原原始输出名，多语言（UTF-8，含中文 / 西里尔 / 希腊等）文件名正确还原；尾部未做认证，还原前严格净化（拒绝 `..`、绝对路径、空名、超长）以防越权输出路径。

### Changed
- **【低·文档】精简 YAML 与部分代码注释**：去除配置模板与代码中的冗余注释，保留安全 / 设计意图相关的"为什么"注释；`fileencryptor.yaml`、`DEFAULT_CONFIG_YAML` 模板与 `build_test/fileencryptor.yaml` 三者现已一致。

---

## [1.6.0] - 2026-08-27（配置 / 日志 / 路径与健壮性加固）

> 程序版本号 1.5.2 → 1.6.0。磁盘文件格式版本保持 **v4**。

### Fixed
- **【中·正确性】配置行内注释剥离过严**：`strip_comment` 此前仅当 `#` 前为空白或行首才剥离注释，导致 `key:#comment`、`key = #comment` 等 YAML 合法写法（无前导空格）的注释被漏剥。现放宽至 `#` 前为 `:` / `=` / 空白 / 行首时均剥离；引号内 `#` 仍保留。
- **【中·健壮性/DoS】批量递归目录无深度上限**：`collect_files_from_dir` 此前无递归深度保护，超深目录（>10000 层）可致栈溢出崩溃。现增加 `depth` 参数，超过 1024 层时告警并跳过。
- **【低·健壮性】解密偏移潜在截断**：`decrypt_file` 对 `seekg` 偏移仅做 `(std::streamoff)` 强转，超大文件（理论 >9 EB）可能截断。现先校验偏移不超过 `std::numeric_limits<std::streamoff>::max()`。
- **【低·正确性】口令强度提示对非 ASCII 误判**：字符类检测（`isupper/islower/isdigit/ispunct`）此前对 UTF-8 多字节字节在 C locale 下行为不确定，纯中文等长口令可能被误报为弱口令。现仅对 ASCII 字节做类检测，非 ASCII 字符视为高熵不再误判。

### Changed
- **【中·运维排障】日志流异常自恢复**：`write_log` 检测到 `g_log_stream` 进入 `badbit`（磁盘满 / 权限变化）时，尝试 `clear()` + 以 `std::ios::ate` 重新打开日志文件，并在 stderr 给出警告。
- **【中·安全】Windows 长路径 / UNC 前缀归一化**：`normalize_path_lexical` 先做 `\\?\` 长路径前缀与 `\\?\UNC\` 归一化，剥离后再 `lexically_normal()`，防止攻击者用 `\\?\C:\..\` 绕过 `path_has_traversal` 与白名单校验。
- **【低·安全】`SecureBuffer::wipe()` 强制释放**：用 `std::vector<unsigned char>().swap(data_)` 代替 `clear()+shrink_to_fit()`，确保清零并 `sodium_munlock` 后立即真正释放后备内存。

### Added
- **【文档】`path_whitelist_enabled` 语义澄清**：仅当 `path_whitelist` 显式列出至少一项时才启用；空列表（仅写键名）不启用白名单。

---

## [1.5.2] - 2026-08-29（路径穿越安全加固 / 缺陷修复）

> 程序版本号 1.5.1 → 1.5.2。磁盘文件格式版本升至 **v4**（141 字节头，向后兼容 v1 / v2 / v3）。

### Fixed
- **【中·安全】输出目录 `..` 越权建目录修复**：`-o` 指定的输出目录此前在调用加/解密前先 `create_directory_recursive`，而 `..` 未被归一化，导致 `-o "a/out/../../ESCAPE_X"` 会在父级之外建出目录。现 `create_directory_recursive` 与 CLI 解析 `-o` 均先 `path_has_traversal()` 拒绝含 `..` 的路径。
- **【中·安全】白名单前缀比较 `..` 绕过修复**：`validate_io_paths` 此前仅对 `out_path` 做 `..` 检测、白名单用字符串前缀匹配且未归一化；输入 `C:/allowed/../../outside/x` 仍命中 `C:/allowed` 前缀被误放行。现任何 `..` 组件（输入/输出）一律拒绝后再做白名单比较。
- **【低·UB】非交互覆盖提示未初始化 `char ch` UB 修复**：`main.cpp` 覆盖确认与 AEGIS 回退提示中 `char ch;` 在 stdin 为空/EOF 时提取失败保持未初始化，随后读取属未定义行为。改为 `char ch='n';` 默认安全拒绝。

### Security
- **【高·防御文件头篡改】v4 头 HMAC 安全信封**：v4 在 v3 头部基础上追加 32 字节 `header_hmac`，由"元数据认证密钥"（与主密钥域分离派生，标签 `FE_header_auth_v4`）对文件头前 77 字节（magic / version / mode / Argon2 参数 / salt / iv）做独立 HMAC-SHA512/256 认证；替换 salt / iv / mode 等头字段的篡改会在解密端被拒绝（仅通用错误，不泄露细节）。`SecureBuffer` 锁页 + 析构清零确保中间密钥不残留；写头瞬间即计算 HMAC 落盘，即便中断也带合法 HMAC。

---

## [1.5.1] - 2026-08-26（运维与安全增强 / 缺陷修复）

> 设计原则（混合架构）：**所有运维类参数**（日志位置/级别、并发线程数、资源上限、路径安全策略、进度轮转）统一由 **YAML 配置文件** 提供，**CLI 不可覆盖**；CLI 仅保留动作与输入接口（密钥、密码、路径、模式等）。

### Added
- **【中·运维】密钥文件 / 环境变量输入（非交互）**：除交互式口令外，新增 `-k <keyfile>` 从文件读取密钥材料，或用环境变量 `ENCRYPTOR_KEY` 传入。优先级：`-k` > `ENCRYPTOR_KEY` > 交互式输入（适用无人值守 / CI 场景）。
- **【中·运维】结构化 JSON 日志**：运行时可输出结构化日志（`{"ts","level","msg",["fields"]}`），日志文件路径与级别由 YAML `log_file` / `log_level` 控制；控制台进度条不受影响。
- **【中·运维】资源与并发配置（YAML）**：`worker_threads`（并发线程数，0=自动）、`max_memory_bytes`（预留上限，暂未强制）、`io_buffer_size`（内部流式缓冲）。
- **【中·运维】进度文件轮转**：覆盖 `.progress` 前先备份为 `.progress.bak`（`progress_rotation`，默认开），降低写坏丢失断点的风险。
- **【中·安全】路径长度 / 白名单**：YAML `max_path_length`（UTF-8 字节上限）、`path_whitelist_enabled` + `path_whitelist`（启用后输入/输出必须位于白名单根目录之下）。
- **【低·供应链】供应链签名（发布脚本）**：`scripts/sign-release.sh` 对发布产物生成 SHA256SUMS 并可用 GPG 签名；日志默认命名格式 `{YY-MM-DD_HHMMSS}.log`。
- **【低·运维】容器化与静态发布（发布脚本）**：`Dockerfile` 提供基于 Debian 的构建/运行镜像；`scripts/build-release.sh` 产出各平台静态二进制与零依赖 DEB/RPM。

### Changed
- **【中·CLI】强制覆盖标志由 `-f` 改为 `-y` / `--force`**：与多数 Unix 工具一致；`-f` 仍接受为别名。
- **【低·CLI】`-j <线程数>` 已于 v1.7.2 彻底删除**（传入报 `Unknown option` 并退出）；并发数由 YAML `worker_threads` 配置。

---

## [1.4.1] - 2026-08-23（路径处理与多线程稳健性）

> 程序版本号 1.4.0 → 1.4.1。磁盘文件格式版本保持 v3。

### Fixed
- **【中·Windows】续传进度文件 `std::rename` 失败导致续传退化**：Windows 下 `.progress` 因 `std::rename` 在目标已存在时失败，导致仅第 1 块能记录进度、续传退化为从头重做；现改用 `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` 覆盖写。
- **【低·正确性】`unified_remove` UTF-8 文件名删除**：Windows 下走 `_wremove`（UTF-16）路径，规避 ANSI 代码页对中文 / Emoji 文件名误判导致删除失败。

### Changed
- **【低·UX】统一 UTF-8 文件名处理**：所有 `std::filesystem` API 切换到 UTF-8 直通模式（Windows 下底层走 `_w*` API），含中文 / Emoji 的文件名可正确加解密、批处理递归、解密命名还原。
- **【低·稳健性】批量并发线程数回退**：CLI 解析 `-j` 时若 `try_parse_int` 抛异常则回退默认线程数（避免崩溃）。

---

## [1.4.0] - 2026-08-20（批处理 / 多线程 / YAML 配置）

> 程序版本号 1.3.0 → 1.4.0。磁盘文件格式版本保持 v3。

### Added
- **【高·批量】批量加解密（`-be` / `-bd`）**：目录递归、并发处理、源文件删除（`-de`）、强制覆盖（`-y`）、断点续传（重跑自动）。
- **【中·并发】多线程并行**：批量模式下按 YAML `worker_threads`（默认 0 = 自动）开线程，单文件模式仍串行。
- **【中·运维】YAML 配置解析**：运维参数（worker_threads / max_open_files / max_path_length / path_whitelist 等）从命令行迁移到 YAML，CLI 不可覆盖。
- **【中·UX】进度条**：控制台实时显示已处理字节 / 总字节 / 吞吐率。

### Changed
- **【中·CLI】参数语义调整**：运维类参数（线程数、路径白名单等）从 CLI 选项移除，统一改由 YAML 配置。

---

## [1.3.0] - 2026-08-10（XChaCha20-Poly1305 默认 / v3 头）

> 程序版本号 1.2.0 → 1.3.0。磁盘文件格式版本升至 **v3**（向后兼容 v1 / v2）。

### Added
- **【高·算法】XChaCha20-Poly1305（IETF）默认**：扩展 nonce（24 字节）随机生成，无需计数器管理；AES-GCM 仍可用于解密旧版 v1 / v2 文件，新加密不再使用。
- **【中·可续传】`.progress` HMAC 认证**：进度文件带 HMAC-SHA512/256 认证，损坏或伪造的 `.progress` 被拒绝并安全从头重写。

### Changed
- **【中·稳健性】密钥派生中间值清零**：所有 Argon2 派生中间密钥在 `SecureBuffer` 中持有，析构自动 `sodium_memzero` + `sodium_munlock`。
- **【低·UX】进度条吞吐显示**：进度条新增 `MB/s` 实时显示。

### Security
- **【中·抗重放】每块 nonce = sodium_increment(iv)**：杜绝 nonce 复用风险；每块 AEAD tag 独立校验。

---

## [1.2.0] - 2026-07-15（v2 头 / AES-GCM 默认 / 路径安全）

> 程序版本号 1.1.x → 1.2.0。磁盘文件格式版本升至 **v2**（向后兼容 v1）。

### Added
- **【高·算法】AES-256-GCM 默认**：硬件加速友好（Intel AES-NI）；XChaCha20-Poly1305 作为备选。
- **【中·稳健性】续传（resume）**：大文件（>25 MB）中断后续传；进度文件记录已处理字节，重跑从中断点继续。

### Changed
- **【中·安全】路径白名单（YAML）**：`path_whitelist_enabled` + `path_whitelist` 控制输入/输出路径必须在白名单根目录下。
- **【中·安全】`path_has_traversal` 拒绝任何 `..` 组件**：防止构造越权输出路径。

### Security
- **【中·抗 TOCTOU】符号链接拒绝**：输入 / 输出路径若为符号链接 / 重解析点则拒绝处理（防止攻击者构造指向白名单外的链接）。

---

## [1.1.1] - 2026-07-01（基线版本）

> 程序版本号 1.0.0 → 1.1.1。磁盘文件格式版本 **v1**。

### Added
- **【高·算法】AES-256-GCM**：默认算法，硬件加速；密钥派生使用 Argon2id（`opslimit=3` / `memlimit=64 MB`）。
- **【中·特性】分块加密**：`CHUNK_SIZE = 1MiB`；每块独立 AEAD；支持大文件。
- **【中·特性】批处理（`-be` / `-bd`）**：目录递归、并发线程、源文件删除。
- **【低·特性】断点续传（基础）**：`.progress` 记录已处理字节。

### Security
- **【中·密钥内存】`sodium_mlock` 锁定**：派生后密钥锁页，防止换出到磁盘。
- **【低·POSIX 权限】`.part` 文件 `chmod 0600`**：防止半截明文被其他用户读取。
- **【低·稳健性】32/32 字节级测试（`_verify/verify.cpp`）**：回归套件覆盖 S1 畸形头、S2 真实重解析点、S4 路径穿越、V1 兼容性。

### Notes
- **回归套件**：`_verify/verify.cpp` 提供 32/32 字节级测试。该套件**保留在仓库作为固定验收**，但**不编入发布版 `FileEncryptorCLI.exe`**（与 `main.cpp` 的 `wmain` 冲突、依赖 `<windows.h>`），仅作独立测试目标。

---

> 早期版本（v0.x、1.0.x）变更历史不在此文件维护，详见 Git 提交记录。
