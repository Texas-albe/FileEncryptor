# ChangeLog - FileEncryptor CLI

本文件记录 **FileEncryptor CLI** 子项目的所有重要变更（命令行加密工具 `FileEncryptorCLI(.exe)`）。
图形界面项目的变更记录请见 `../GUI/CHANGELOG.md`。

格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **磁盘文件格式默认版本升级为 v6（可扩展加密容器）**：自 2.4.0 起，新加密默认写入 v6 容器
> —— 数据与「数据加密密钥（DEK）」分离，DEK 由口令派生的密钥加密密钥（KEK）包裹于头部容器区，
> 头部含预留扩展字段（key_version、wrapped DEK、保留区）以支持密钥轮换 / 多接收方 / 分块等未来能力。
> 不压缩且未启用容器扩展时仍写 v4 头以最大限度兼容；v6 与 v4 / v5 共用同一套 AEAD 载荷格式，
> 2.4.0 可读取并解密 v1 ~ v6 全部格式，旧产物无需重加密即可解密。
> CLI 主版本号历史上与合并项目同步；自 2.1.0 起 CLI/GUI 拆分独立发版。

## [2.4.0] - 2026-09-24

本版本引入可扩展加密容器（v6）与密钥轮换（rewrap）能力，并强化非交互场景下的
硬件能力适配与源文件安全处理。

### Added
- **可扩展加密容器 v6**：新加密默认写入 v6 容器。载荷由随机「数据加密密钥（DEK）」加密，
  DEK 再以口令派生的「密钥加密密钥（KEK，Argon2id）」包裹后写入头部容器扩展区
  （`wrapped DEK` + `key_version` + 预留字段）。容器区纳入头部 HMAC 认证，防篡改。
  该结构解耦「口令」与「密文」，为密钥轮换、多接收方、分块等未来能力预留接口。
- **密钥轮换 `--rewrap`**：对 v6 容器用新口令重裹 DEK（payload 密文原样不动，零重加密开销），
  `key_version` 自增并刷新头部 HMAC。旧口令经既有密码通道（`-k` / `--key-stdin` / `ENCRYPTOR_KEY`）
  提供，新口令经 `--new-key-file <文件>` 或 `--new-key-stdin` 提供。v4 / v5 旧格式需全量重加密，
  命令会明确提示。
- **源文件安全处理**：新增 `--wipe-source`（多遍覆写后删除，安全擦除）与 `--recycle-source`
  （移入系统回收站，受控删除）；保留 `-de`（直接删除）。加密成功后按所选方式处理源文件。
- **`zstd` 布尔开关 `-zstd`**：新增与 `-z` / `--compress` 等价的显式布尔开关（**不带任何参数值**），
  便于 GUI 等宿主以「布尔开关 + 可选级别」两段式下发；压缩级别仍由 `--compression-level <N>` 单独指定，
  未指定时用 zstd 默认级别 1。旧别名 `-z` / `--compress` 行为不变。
- **`--features` 新增 `aegis=` 探测行**（`aegis=1` / `aegis=0`），供 GUI 判断当前 CPU 是否支持
  AEGIS-256（AES-NI），无需 GUI 自行探测。

### Changed
- **AEGIS-256 非交互行为调整**：非交互场景（GUI 管道 / `--key-stdin` / cron 调度）下，
  若请求的 AEGIS-256 当前 CPU 不支持，**不再自动降级**——改为明确拒绝并以非零退出码退出，
  输出清晰警告（提示改用 XChaCha20-Poly1305）。交互终端仍会询问用户是否降级（默认降级）。
  此行为与 GUI 弹窗警告保持一致，杜绝自动化任务中静默的行为变更。
- **代码结构模块化**：将职责独立、与加密主流程弱耦合的逻辑从 `core/FileEncryptor.cpp` 拆出为
  独立模块——`core/ptd_format.{hpp,cpp}`（磁盘头部结构与格式级操作）、`core/kdf.{hpp,cpp}`
  （Argon2 参数、密钥派生与并发内存预算）、`core/source_handling.{hpp,cpp}`（加密后源文件处置）。
  调用关系与行为不变；同时精简注释，仅保留解释复杂逻辑与关键设计决策的部分。
- **版本号提升至 2.4.0**。

### Fixed
- **回收站处置误报失败**：`--recycle-source` 在 `SHFileOperationW` 返回异常或
  `fAnyOperationsAborted` 被误置时，会以「could not process source file」报错退出（文件实际已移走）。
  现以「原路径是否仍存在」为最终判据，成功时不再误报。
- **`-H` 头部查看器的 `original size` 恒为 0**：该字段不在任何版本的头部结构内，而是位于头部之后的
  16 字节块元数据（`chunk_size` / `total_chunks` / `orig_size`）中，此前未读取。现已正确解析，
  并为 v6 容器新增 `key version` 行（便于确认密钥轮换是否生效）。

### 解密流程修复与进度帧增强（配套 GUI 1.4.0）

### Added
- **进度帧末行 `FILES done/total SKIP n FAIL n`**：批量模式（`-be` / `-bd`）每个渲染帧新增一行
  文件级计数（完成/跳过/失败），供宿主（GUI）实时解析展示，无需为每文件额外打印一行
  （批量上千文件时会刷屏）。由 `BatchProgress::setFileStats()` 驱动，`process_files` 的 worker 与
  预扫描阶段维护 `files_done` / `files_failed` 原子计数，`display_thread` 每帧随 `setProcessed` 一并下发。
- **解密失败计数准确化**：worker 失败路径与「输出路径越界被跳过」路径各新增 `++files_failed`，
  与成功路径的 `++files_done` 配套，使末行 FAIL/完成计数与实际一致。

### Fixed
- **解密失败不中断整批任务**：密码错误 / 文件损坏 / 头部校验不通过的单文件，统一打印
  `Failed: <path> (skipped, continuing with remaining files)`（stderr，红色）并继续后续文件，
  不再中断整批；错误文件列表在末尾统一汇总（`Total N files failed.`）。
- **解密成功亦按源处理处置（含 `-de`）**：批量解密在 `ok` 后同样调用 `secure_handle_source()`
  （删除 `.ptd` / 安全擦除 / 移回收站），修复此前仅加密侧执行、解密侧遗漏的问题；
  「已存在且有效」的跳过条目也按 `-de` 等处置，避免重跑永远清不掉 `.ptd`。

### 性能优化（解密正确性已逐字节验证）

- **批量解密 `-rn` 的 Argon2id KDF 冗余消除（#1）**：`restore_name` 批量解密此前每文件派生 KEK 3 次
  （预扫描 `read_original_name` + worker `read_original_name` + `decrypt_file` 内部）。现 `process_files`
  在预扫描阶段派生 KEK 后按输入路径缓存；`read_original_name` 新增 `pre_kek` 参数复用该 KEK、
  `decrypt_file` 新增 `ext_kek` 参数（仅跳过 Argon2id，仍按版本解裹 DEK），worker 直接复用缓存。
  效果：开启 `-rn` 的批量解密从每文件 3× → 1× Argon2id（普通批量解密本就 1×，无影响）。
- **全程序优化 LTO（#2）**：`CMakeLists.txt` 增加 `set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)`
  （Release 配置 `/GL` + `/LTCG`），对跨 TU 热点（KDF 调用、AEAD 循环）生效。
- 安全：进程退出前对缓存的派生密钥 `sodium_memzero` 清零，避免明文残留。

### 安全审计与缺陷修复（CLI `FileEncryptor.cpp` / `config.cpp` 相关）

- **修复 `compute_progress_binding` 栈缓冲区越界读（高危，#F1）**：原实现用固定 256 字节栈缓冲 +
  `snprintf` 后再 `std::string(buf, n)` 构造字符串；`snprintf` 返回的是“本应写入的长度”，
  当输入路径很长（Windows 长路径 / UNC 可达数十 KB）时 `n` 远超 255，导致从 256 字节缓冲
  **越界读取栈内存（未定义行为）**。在 LTO（`/GL`）下优化器可据此假设 `n≤256` 而误编译；
  同时把相邻栈内容混入了续传防重放绑定的 HMAC 输入，导致长路径文件续传 HMAC 失配。
  改为直接用 `std::string` 拼接，彻底消除固定缓冲与越界读。
- **修复 v6 批量解密 `-rn` 无法还原原始文件名（#F2）**：
  `read_original_name` 此前仅派生 KEK，而文件名信封由 **DEK** 加密（encrypt_file 第 1973 行
  此时 `key` 已为 DEK）。现 v6 分支在派生 KEK 后先 `unwrap_dek` 解出 DEK，再以 DEK 还原文件名；
  v1~v5 仍直接以 KEK（载荷密钥）解密，行为不变。已用 3 文件批量 `-rn` 往返验证
  md5 逐字节一致、文件名正确还原。
- **加固旧格式（v1/v2）`iv_len` 输入校验（#F3）**：旧格式头部 `iv` 字段仅 24 字节，若伪造文件
  声称更大的 `iv_len`，后续 `memcpy(nonce, iv, iv_len)` 会越界读到相邻未初始化栈区。
  新增 `ver==1||ver==2 && iv_len>24` 直接拒绝，作为纵深防御（此类文件本就无法解密）。
- **MSVC `/O2 /GL`（LTO）优化安全性复核**：并发层 `std::atomic` 用法正确——CLI 显示线程的
  `display_stop` 经 `join()` 正确同步、`memory_order_relaxed` 仅用于终止标志；GUI 异步扫描取消
  用 `std::shared_ptr<std::atomic<bool>>` 正确跨线程同步；口令清零处的 `volatile` 写属合理用法
  （防 dead-store 消除），未发现可被子优化器利用的未定义行为。唯一遗留的可移植性事项为
  头结构 `reinterpret_cast` 类型双关（严格别名规则下的 UB）：MSVC 优化器不对其进行破坏式重排，
  故 Windows/MSVC 目标无运行异常，仅作为 GCC/Clang `-fstrict-aliasing` 下的可移植性待办。
---
## [2.3.0] - 2026-09-19

本次版本聚焦批量模式的「帧式进度」体验与磁盘侧车文件的扩展名收敛，并清理了若干遗留开关。

### Added
- **【批量进度·CLI】帧式原地刷新（终端 / 宿主双通道）**：新增 `core/progress_frame.cpp` 独立模块，批量模式（`-be` / `-bd`）按帧原地刷新输出，不再滚动刷屏。帧布局固定为「第 1 行汇总行：总大小 | 已处理大小 | 总速率 | ETA」+「第 2 ~ n+1 行每线程一行：文件路径 | 进度条 | 速率 | ETA」（n = 并发线程数）。体积与速率按 B / KB / MB / GB / TB 自适应单位与精度；进度条宽度随终端宽度伸缩；空闲线程行按相同列宽占位渲染，布局稳定不跳动。
- **帧模式开关（宿主友好）**：宿主（如 GUI）显式设置环境变量 `FILEENCRYPTOR_PROGRESS_FRAME=1` 时，每帧以哨兵行 `\x1b[FEPRG+` / `\x1b[FEPRG-` 包裹，GUI 等宿主可整帧解析后自行原地渲染，字段顺序、分隔符与单位格式与终端显示完全一致；普通重定向 / 管道场景回退旧的单行 `\r` 进度条，不产生任何哨兵。
- **进度帧路径缩写规则**：帧内路径超出路径列宽时只缩写目录部分（`...\文件名`），文件名完整保留；仅当文件名本身也放不下时，才缩短文件名主部并保留扩展名（`...\he...txt`）；连该方案都放不下时整体头部截断。确保每条进度行连路径完整显示在一行内不折行。
- **【zstd 压缩】新增 `-z` / `--compress` 与 `--compression-level <N>`（`-cl`）**：对称加密（`-e` / `-be`）可选逐块 zstd 压缩，压缩率参照上游约定——常规档 `1..22`（越大越慢、压缩率越高，`-z` 不带级别时默认 1）、快速档 `-1..-5`。启用后磁盘头升级为 **v5**（v4 头追加 `compression` / `comp_level` 两字节，AAD / HMAC 覆盖范围同步扩展到 79B），每个 1MB 明文块独立压缩后按「4 字节小端帧长前缀 + AEAD 密文」写盘（前缀值已含认证标签，续传扫描据此定位截断点）；解密按头部标记自动识别并解压，未压缩的 v4 及更旧产物行为不变。非对称（rage）与解密方向传入压缩参数会被明确拒绝；未集成 zstd 的构建（`FE_WITHOUT_ZSTD`）在请求压缩时报错退出，`--features` 新增 `zstd=1` / `zstd=0` 行供宿主（GUI）探测能力。zstd 库由 `third_party/zstd` 源码随项目工具链直接编译（`ZSTD_DISABLE_ASM`、/MT 静态 CRT，Windows 与 Linux 均无需预编译库），避免预编译库与本地 MSVC 的 ABI 不匹配问题。

### Changed
- **【扩展名收敛】所有运行时侧车文件扩展名统一为 3 个字符**：进度文件 `.progress` → `.prs`、临时文件 `.part` → `.prt`、SHA-256 校验单 `.sha256` → `.vry`、密钥库索引 `library.yaml` → `library.yml`、主配置文件 `fileencryptor.yaml` → `fileencryptor.yml`、任务历史 `tasks.jsonl` → `tasks.log`。旧名在读取时回退兼容（新写入一律用 3 字符扩展名）。
- **SHA-256 校验单后缀恢复 `.sha256`**：`--sha256` / `write_sha256` 生成的校验单为 `<out>.ptd.sha256`（该后缀是外部校验工具链的通用形式，3 字符收敛对它弊大于利）。
- **单文件 `-e` / `-d` 拒绝目录输入**：目录仅由批量动作 `-be` / `-bd` 递归处理；此前目录会被当作文件处理，打印 `Encrypting:` 后才报打不开，语义误导。现给出明确提示改用批量动作。
- **输出路径分隔符统一**：`-o` 拼接的输出路径在 Windows 下统一为 `\`（不再出现 `E:\1/name.ptd` 混排），单文件与 `-m rage` 路径均适用。
- **YAML 文件后缀统一为 `.yaml`**：主配置文件 `fileencryptor.yaml`、密钥库索引 `library.yaml`（`.yml` 为 2.3.0 开发过程中的过渡形态，读取时仍兼容，升级无感）。
- **age-ffi 依赖移至 `third_party/rage/age-ffi/`**：fe_age 静态库随上游 rage 仓库源码整体收纳，CMake 默认查找根同步更新（`-DFE_AGE_DIR` 仍可显式覆盖）。
- **AEGIS-256 硬件能力自适应（P0）**：请求 `-m aegis256` 但本机缺 AES-NI 时，按交互性决定行为——交互终端询问用户（默认降级到 XChaCha20-Poly1305），非交互场景（GUI 经管道传参、`--key-stdin`、cron 等）一律自动降级并打印 `Selected XChaCha20-Poly1305 based on hardware capability.`，**不再调用 `std::cin` 读取**，杜绝吞掉密码流或卡死。单文件与批量入口统一经 `resolve_encrypt_mode()` 解析；原 `process_files` 内的阻塞式交互询问已移除，仅保留非交互防御性兜底。

### Removed
- **移除 `progress_rotation` 开关**：不再在覆盖 `.prs` 前备份 `.prs.bak`（简化逻辑，避免产生冗余备份文件；进度续传仍由 `.prs` 自身 HMAC 绑定路径 + size + mtime 保证安全）。

## [2.2.0] - 2026-09-18

本次版本在 2.1.2 安全修复基线之上，补齐了一批运维与可审计能力，并修复了若干长期遗留的健壮性问题。所有新增 CLI 选项与 YAML 键均为增量、向后兼容：旧配置与旧密文不受影响。

### Added
- **【功能2·CLI】新增 `-H` / `--info` 只读头元数据查看器**：在不解密、不校验密钥正确性的前提下，打印密文头的版本、算法模式、`argon2` 参数、`salt`、`iv/nonce`、原始大小、明文 Blake2b 摘要与是否携带加密文件名信封。用于快速甄别文件格式、确认 KDF 强度，不会泄露明文内容。
- **【功能3·CLI】新增 `-V` / `--verify` 完整性校验（只验不解）**：对单文件执行与解密等价的完整性验证（重算明文 Blake2b、比对头部摘要），但**不向磁盘写出任何明文**，通过后输出 `OK`、失败输出 `FAILED`。适合在不可信环境下批量核验文件是否完好。
- **【功能10·CLI】新增 `--sha256` 自动生成校验单**：加密成功后额外写出 `<out>.ptd.sha256`（内容为密文 SHA-256 十六进制 + 文件名）。等价开关 `write_sha256`（YAML）默认关闭，`--sha256` 可针对单次任务强制开启。
- **【功能7·CLI】可配置口令策略**：YAML 新增 `min_password_length`（最小长度，默认 8）与 `min_password_classes`（至少包含的字符类别数，默认 2；非 ASCII 口令直接放行）。交互式加密 / `-G` 派生时策略不满足会明确拒绝并说明原因。`ENCRYPTOR_KEY` 等非交互密钥源仍只做最小长度兜底，避免破坏脚本化调用。
- **【功能14·CLI】KDF 强度预设**：YAML 新增 `kdf_preset`，取值 `fast` / `standard` / `strong`（或 `0` / `1` / `2`）。`fast`=`ops3/mem64MB`、`standard`=`ops4/mem128MB`（默认）、`strong`=`ops6/mem512MB`，供在弱设备与高安全需求之间权衡。仅作用于本程序新写入的密文头。
- **【功能15·CLI】新增 `-R` / `--recover-name` 离线还原混淆文件名**：用口令从密文尾部 `FENX` 信封中恢复原始文件名并打印；配合 `--rename` 可将 `.ptd` 自身原地重命名为 `<原始名>.ptd`（内容不变，目标已存在则拒绝以防覆盖）。在文件名混淆场景下无损找回原始文件名。
- **【功能1·CLI】新增密钥库与 `-L` / `-K` 管理**：本机 age 身份与收件人公钥统一存放于 `<用户配置目录>/keys/`（索引 `library.yaml` + 每把密钥一个 `.key` 材料文件，GUI 与 CLI 共用同一布局）。`-L list|add|remove|show|pub|export` 覆盖导入、别名/备注、公钥派生缓存与导出；导入身份时自动派生并缓存公钥，材料文件权限收紧为仅拥有者可读。加密时 `-K <name>[,...]` 直接按名称解析收件人（可与 `-r` 叠加，重复公钥自动去重），解密时 `-K <name>` 等价于引用库内私钥文件，脚本化调用不再需要手写长路径。

### Changed
- **【中·构建】依赖库随仓库分发**：libsodium 预编译包、yaml-cpp 源码与 /MT 静态库、age-ffi 源码与预编译静态库统一放入仓库根 `third_party/`，CMake 与 `out/build_cli.ps1` 的查找顺序改为 third_party 优先、系统安装回退（`SODIUM_ROOT` / `YAMLCPP_ROOT` / `FE_AGE_DIR` 仍可覆盖）。yaml-cpp 静态库输出位置改为 `third_party/yaml-cpp/lib/`。
- **【缺陷7·安全】批量 KDF 增加进程级内存预算**：`derive_key()` 引入 `KdfSemaphore` 信号量，按 `max_memory_bytes`（默认 0 = 不限）上限约束并发 Argon2 内存占用（约 `上限/128MB` 个并发槽）。防止大量并发任务各自申请数百 MB 内存导致宿主机内存耗尽 / 大量分页。
- **【缺陷14·安全】YAML 别名炸弹防护**：配置文件超过 `1 MiB` 时直接拒绝加载并回退默认配置，避免恶意构造的别名引用使解析器展开为超大规模对象。
- **【缺陷13·健壮】YAML 类型 / 单位解析错误不再静默吞掉**：`parse_size`、布尔、日志等级等解析失败时通过 `warn` 参数汇总，加载配置时统一打印告警（仍不致命），便于发现配置笔误。
- **【缺陷15·健壮】只读工作目录配置降级**：当前工作目录不可写（只读介质 / 无写权限）时，默认配置模板回退写入用户配置目录而非静默失败。

### Fixed
- **【缺陷2·构建】AEGIS-256 编译期 libsodium 版本校验**：CMake 解析 `sodium_VERSION` 或从头文件 `version.h` 的 `SODIUM_VERSION_STRING` 取版本，要求 `>= 1.0.19`（AEGIS-256 所需），不足则在配置阶段 `FATAL_ERROR` 并提示；两者皆缺时回退到 `crypto_aead_aegis256` 头文件存在性探测。
- **【缺陷4·安全】续传进度绑定加强防重放**：`compute_progress_binding` 在原有（规范化路径 + 大小 + mtime）之外，新增文件内容令牌（`file_content_token`：头 64 KB + 尾 64 KB + 大小的 Blake2b）。即使攻击者复用合法 `.progress`，只要文件内容被替换即 HMAC 失配，阻断续传劫持。
- **【缺陷5·安全】还原文件名补全 Windows 保留名处理**：`sanitize_restored_name` 现拒绝 `CON/PRN/AUX/NUL/COM1-9/LPT1-9` 等保留设备名，并剥离尾随的点与空格（Windows 会静默丢弃），避免还原出的文件名在 Windows 上无法创建或被映射为设备。
- **【缺陷6·内存】`wipe()` 真正释放缓冲**：`asym_crypto.cpp` 中 `wipe(std::vector<>` / `std::string&)` 在 `sodium_memzero` 后通过 `swap` 空容器强制释放底层缓冲，不再仅清零而长期占用堆内存。
- **【缺陷11·并发】`aegis256_supported()` 线程安全**：改为 C++11 magic static 局部初始化，消除原先非线程安全的 `static bool cached` 先读后写竞争，并发批量任务首次调用不再可能得到错误结果。
- **【缺陷12·内存】`mlock` 静默失败告警**：`SecureBuffer` 构造时若 `sodium_mlock` 失败，调用一次性告警 `fe_report_mlock_warning_once()`（原子守卫，仅打印一次 `mlock_failed`），提示密钥页可能未被锁住；不再无声降级。
- **【缺陷19·整洁】修正 `config.cpp` 中放错位置的注释**：原挂在 `parse_bool` 上方的注释实际描述的是另一个解析函数，已归位。
- **【路径·规范】密钥库与用户配置路径分隔符统一**：新增 `to_native_path()`（Windows 将 `/` 归一化为 `\`，POSIX 原样），`user_config_dir()`、`keylib_dir()`、`keylib_index_path()` 及全部密钥材料路径拼接统一走该函数；消除 `%APPDATA%`（原生反斜杠）与代码拼接 `/` 混用产生的 `AppData/Roaming/FileEncryptor/keys` 类混合分隔符路径，目录创建与访问在不同 Windows 账户下保持一致。

> 磁盘格式仍为 **v4**，与 v1/v2/v3 双向兼容，本次未引入任何格式变更。

## [2.1.2] - 2026-09-13

本次为安全修复版本，对应 `out/SECURITY_AUDIT_2026-09-13.md`（2 高危 / 4 中危 / 4 低危）。

### Added
- **【中·CLI】新增 `--obfuscate-name` / `-on`**（仅 `-m rage`）：把输出文件名混淆为 `<16 位十六进制>.<混淆扩展名>.age`，避免原始文件名明文泄露。**注意**：rage 模式没有"加密文件名信封"（对称模式的文件名存在密文尾部），混淆后原始名**不可恢复**，故需显式开启而不跟随 `obfuscate_names` 默认值；未开启时程序会打印元数据泄露提示。

### Changed
- **【中·CLI】`-m rage` 元数据提示**：未加 `--obfuscate-name` 时，明确提示输出文件名为明文及如何开启混淆。
- **【低·安全】CWD 配置降级为低信任**：来自当前工作目录的 `fileencryptor.yaml` 不再能控制 `log_file` 与 `path_whitelist*`——这些安全敏感键只信任环境变量指定 / exe 目录 / 用户配置目录的配置；命中时打印告警。避免在共享目录、临时目录下被预置配置劫持日志落点与路径管控。

### Fixed
- **【高·安全】修复 KDF 参数无上限导致的资源耗尽 DoS**：文件头里的 `opslimit` / `memlimit_kb` 完全由（可能是攻击者构造的）密文头控制且无任何 clamp，而 v4 的 `header_hmac` 在 KDF 之后才校验，无法在认证前区分正常文件。实测 125 字节的恶意 `.ptd` 即可让解密方持续占用 CPU 并申请 4 GB 内存（>121 s），批量 `-bd` 按文件数线性放大。现统一在唯一派生入口 `derive_key()` 处校验：`opslimit > 10` 或 `memlimit > 1 GiB` 一律**直接拒绝并报错**（不做降级——降级仍会白跑一次 1 GiB 的 Argon2，实测约 13 s，批量场景照样可被放大），并补齐下界（防头里填 0）。本程序写出的头恒为 ops=4 / mem=128MB，正常文件完全不受影响；实测恶意样本由 >121 s 降为 1 s 内拒绝退出。
- **【高·安全】修复 `-m rage` 完全绕过路径白名单与 `max_path_length`**：`validate_io_paths()` 此前是 `FileEncryptor.cpp` 内的 static 函数，只有 `encrypt_file()` / `decrypt_file()` 调用；`run_asym()` 走完全独立的分支，从未做任何路径策略校验（实测白名单外文件可直接加密进白名单目录）。现去掉 static 并在头文件暴露，`run_asym()` 内对每个 `in_path` / `out_path` 调用，同时补 `path_has_traversal(in_path)`（此前仅 `-o` 在参数解析处查过）。
- **【中·安全】`-m rage` 输出补符号链接守卫与原子落盘**：此前 rage 分支一处符号链接守卫都没有，且直接写目标文件（对称路径有三处守卫 + `.part` 原子替换）。现写入前拒绝已存在的符号链接 / 重解析点，并改为先写 `<out>.part`、成功后再 `replace_file_utf8()` 原子替换，失败即清理，避免半截明文残留与被重定向写穿。
- **【中·安全】修复 `-g` 无覆盖保护静默覆盖已有私钥**：`run_keygen()` 此前直接写 `rage_private.txt`，无任何存在性检查，私钥一旦被覆盖，用它加密的所有 `.age` 文件永久不可解密。现复用 `run_derive()` 的策略：非 `-y` 时拒绝覆盖。
- **【中·安全】修复 Windows 权限收紧无效且误伤**：`_chmod(path, _S_IREAD)` 只是"只读"文件属性位而非访问控制，实测生成的文件仍是 `-r--r--r--`（所有用户可读）；副作用是二次 `-g` 写入时报 `Cannot write`。现改为写入真正的 DACL（仅当前令牌用户 + SYSTEM，`PROTECTED_DACL` 阻断继承），真正达到 0600 语义；ACL 失败时静默回退（不把文件变只读）。另加 `clear_readonly_attribute()`，覆盖前清掉旧版本遗留的只读属性。
- **【低·安全】`rage` 私钥内存残留**：解密时 `identity` 经 `substr` 重建会另开缓冲，旧缓冲（完整私钥文件内容）无法再被擦除；改为就地 `erase`，保证只存在一份可擦除的缓冲。
- **【低·CLI】日志文件支持中文路径**：`init_logger()` 原用窄字符 `std::ofstream::open`（Windows 按 ANSI 代码页解析，非 ASCII 路径打开失败），改为 UTF-8 → 宽字符打开。

## [2.1.1] - 2026-09-12

### Changed
- **【中·CLI】口令强策略**：交互式加密 / 口令派生（`-G`）套用统一口令策略（最小长度 8，且至少含 2 类字符或长度 ≥16；非 ASCII 口令直接放行），替代原先仅检查长度 ≥6 的弱校验。
- **【中·CLI】批量解密文件名还原改为可选项**：新增 `-rn` / `--restore-name`，默认关闭。关闭时不逐文件执行昂贵的 Argon2id KDF 还原完整原始文件名，仅保留输出文件扩展名（混淆名自带），显著加快批量解密；开启时还原完整文件名（性能较差，由 GUI 警告后用户选择）。

### Fixed
- **【高·安全】`set_global_config` 悬空指针修复**：改为按值拷贝并以 `shared_ptr<const Config>` 持有，杜绝调用方传入 `load_config()` 临时值后悬空（此前存裸 `const Config*`）。
- **【高·安全】收紧密钥文件权限**：`-g` / `-G` 生成的 `rage_private.txt` 私钥文件写入后收紧为仅拥有者可读（`chmod 0600` / Windows `_chmod _S_IREAD`），避免明文私钥被其它用户读取。
- **【高·安全】`anti_debug_check` 仅主线程调用约束**：补充注释——该函数检测到调试器时直接 `exit(1)`，务必只在 `main()` 启动期、任何工作线程创建前调用，切勿移入 `process_files` 并发 worker，否则会终止整个批量任务。
- **【高·CLI】修复中文 / Emoji 路径加密解密必崩溃**：`normalize_path_lexical` / `compute_progress_binding` 用 `fs::path` 的窄字符串构造（按 ANSI 代码页 / GBK 解释字节），含中文的 UTF-8 路径在 `.string()` 往返时抛 "No mapping for the Unicode character exists in the target multi-byte code page"，未捕获导致 `std::terminate` → fastfail（0xC0000409，GUI 侧表现为"进程崩溃"且无任何输出）。改为先经 `utf8_to_wstring` 转宽字符构造 `fs::path`、规范化后用 `wstring_to_utf8` 取回，全程无 ACP 往返。单文件加密 / 解密调用点另加异常兜底，未预期异常以干净错误退出而非崩溃。
- **【中·CLI】修复 `-o` 在非当前工作目录的盘上无法新建输出目录**：递归创建目录时对盘符分量（如 `"H:"`）做 `_wstat64` 依赖进程级"盘符当前目录"（CWD 在其他盘时失败）、`_wmkdir("H:")` 恒失败。改为用绝对根 `"H:/"` 探测盘可访问性，存在则继续创建剩余分量。此前 GUI 选择其他盘（含 U 盘）的输出目录会报 "Cannot create output directory"。

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

## [2.0.0] - 2026-09-05（程序版本号升级 / CLI 行为不变）

> CLI 主版本号升级（1.7.2 → 2.0.0）。CLI 行为零变更（加密 / 解密 / 续传 / 批量 / YAML 配置 / 磁盘格式 v4 完全不变）；此版本仅是版本号与项目结构层面的里程碑。

### Changed
- **【中·版本】全量版本号同步至 2.0.0**：`FE_VERSION_*` 宏（`core/FileEncryptor.hpp`）、`project(FileEncryptorCLI VERSION 2.0.0)`、CPack 包名示例（`file-encryptor-cli_2.0.0-1`）、README / CHANGELOG 同步。

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

## [1.7.1] - 2026-09-04（文件名加密存储加固）

> 程序版本号 1.7.0 → 1.7.1。磁盘文件格式版本保持 **v4**（向后兼容 v1 / v2 / v3 / 1.7.0）。

### Security
- **【高·隐私】原始文件名改为密文存储（修复 1.7.0 明文泄露）**：1.7.0 曾把混淆前的原始基名以**明文**追加到密文末尾（`FENM` 信封），导致源文件名可在 `.ptd` 中直接读出。现改用与主密文**相同加密配置**——XChaCha20-Poly1305、同一 Argon2 派生主密钥、nonce 由本文件 `salt` 派生并与 `salt` 绑定 AAD——加密后存入尾部（`FENX` 信封，含 16 字节 AEAD tag），解密须正确口令，源文件名不再以明文暴露。保留对 1.7.0 明文尾部（`FENM`）的兼容读取，但新写入一律加密。同时移除 YAML 配置中对"原始名存储位置"的注释，配置不再暴露存储细节。
- **【低·健壮性】加密名尾部改为始终写入**：不再受 YAML `obfuscate_names` 开关控制，无论是否混淆可见文件名，尾部均携带加密后的原始名，解密命名更稳健且不依赖 YAML 暴露存储行为。

## [1.7.0] - 2026-09-04（输出名 / 扩展名混淆）

> 程序版本号 1.6.0 → 1.7.0。磁盘文件格式版本保持 **v4**。

### Added
- **【中·隐私/混淆】输出文件名与扩展名混淆（默认开启）**：加密产出形如 `<16位十六进制>.<伪扩展名>.ptd`（`.ptd` 始终在最后），隐藏原始文件名与扩展名。伪扩展名取自 40+ 种常见类型（png / jpg / mp4 / mp3 / pdf / doc / docx / xls / xlsx / css …），由输入路径 + 密钥确定性派生。YAML `obfuscate_names: false` 可关闭，退化为 `<原名>.ptd`。
- **【中·隐私】原始名尾部安全还原**：混淆文件名不含原始信息，故把原始基名以明文（未认证）追加到密文**末尾**（8 字节头部 `FENM`(4) + 名称长度(4) + 名称）。解密据此还原原始输出名，多语言（UTF-8，含中文 / 西里尔 / 希腊等）文件名正确还原；尾部未做认证，还原前严格净化（拒绝 `..`、绝对路径、空名、超长）以防越权输出路径。

### Changed
- **【低·文档】精简 YAML 与部分代码注释**：去除配置模板与代码中的冗余注释，保留安全 / 设计意图相关的"为什么"注释；`fileencryptor.yaml`、`DEFAULT_CONFIG_YAML` 模板与 `build_test/fileencryptor.yaml` 三者现已一致。

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

## [1.5.2] - 2026-08-29（路径穿越安全加固 / 缺陷修复）

> 程序版本号 1.5.1 → 1.5.2。磁盘文件格式版本升至 **v4**（141 字节头，向后兼容 v1 / v2 / v3）。

### Fixed
- **【中·安全】输出目录 `..` 越权建目录修复**：`-o` 指定的输出目录此前在调用加/解密前先 `create_directory_recursive`，而 `..` 未被归一化，导致 `-o "a/out/../../ESCAPE_X"` 会在父级之外建出目录。现 `create_directory_recursive` 与 CLI 解析 `-o` 均先 `path_has_traversal()` 拒绝含 `..` 的路径。
- **【中·安全】白名单前缀比较 `..` 绕过修复**：`validate_io_paths` 此前仅对 `out_path` 做 `..` 检测、白名单用字符串前缀匹配且未归一化；输入 `C:/allowed/../../outside/x` 仍命中 `C:/allowed` 前缀被误放行。现任何 `..` 组件（输入/输出）一律拒绝后再做白名单比较。
- **【低·UB】非交互覆盖提示未初始化 `char ch` UB 修复**：`main.cpp` 覆盖确认与 AEGIS 回退提示中 `char ch;` 在 stdin 为空/EOF 时提取失败保持未初始化，随后读取属未定义行为。改为 `char ch='n';` 默认安全拒绝。

### Security
- **【高·防御文件头篡改】v4 头 HMAC 安全信封**：v4 在 v3 头部基础上追加 32 字节 `header_hmac`，由"元数据认证密钥"（与主密钥域分离派生，标签 `FE_header_auth_v4`）对文件头前 77 字节（magic / version / mode / Argon2 参数 / salt / iv）做独立 HMAC-SHA512/256 认证；替换 salt / iv / mode 等头字段的篡改会在解密端被拒绝（仅通用错误，不泄露细节）。`SecureBuffer` 锁页 + 析构清零确保中间密钥不残留；写头瞬间即计算 HMAC 落盘，即便中断也带合法 HMAC。

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

## [1.4.1] - 2026-08-23（路径处理与多线程稳健性）

> 程序版本号 1.4.0 → 1.4.1。磁盘文件格式版本保持 v3。

### Fixed
- **【中·Windows】续传进度文件 `std::rename` 失败导致续传退化**：Windows 下 `.progress` 因 `std::rename` 在目标已存在时失败，导致仅第 1 块能记录进度、续传退化为从头重做；现改用 `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` 覆盖写。
- **【低·正确性】`unified_remove` UTF-8 文件名删除**：Windows 下走 `_wremove`（UTF-16）路径，规避 ANSI 代码页对中文 / Emoji 文件名误判导致删除失败。

### Changed
- **【低·UX】统一 UTF-8 文件名处理**：所有 `std::filesystem` API 切换到 UTF-8 直通模式（Windows 下底层走 `_w*` API），含中文 / Emoji 的文件名可正确加解密、批处理递归、解密命名还原。
- **【低·稳健性】批量并发线程数回退**：CLI 解析 `-j` 时若 `try_parse_int` 抛异常则回退默认线程数（避免崩溃）。

## [1.4.0] - 2026-08-20（批处理 / 多线程 / YAML 配置）

> 程序版本号 1.3.0 → 1.4.0。磁盘文件格式版本保持 v3。

### Added
- **【高·批量】批量加解密（`-be` / `-bd`）**：目录递归、并发处理、源文件删除（`-de`）、强制覆盖（`-y`）、断点续传（重跑自动）。
- **【中·并发】多线程并行**：批量模式下按 YAML `worker_threads`（默认 0 = 自动）开线程，单文件模式仍串行。
- **【中·运维】YAML 配置解析**：运维参数（worker_threads / max_open_files / max_path_length / path_whitelist 等）从命令行迁移到 YAML，CLI 不可覆盖。
- **【中·UX】进度条**：控制台实时显示已处理字节 / 总字节 / 吞吐率。

### Changed
- **【中·CLI】参数语义调整**：运维类参数（线程数、路径白名单等）从 CLI 选项移除，统一改由 YAML 配置。

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

> 早期版本（v0.x、1.0.x）变更历史不在此文件维护，详见 Git 提交记录。
