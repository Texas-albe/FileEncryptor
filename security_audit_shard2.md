# FileEncryptor 源代码安全审计报告（Shard 2）

- 审计范围：`CLI/cli/main.cpp`、`CLI/core/config.cpp`、`CLI/core/config.hpp`、`CLI/core/keylib.cpp`、`CLI/core/keylib.hpp`、`CLI/core/password_policy.cpp`、`CLI/core/password_policy.hpp`
- 审计方式：纯静态人工审计，未修改任何源码
- 已知基线（2.1.2 / 2.4.2 / 2.4.3 / 2.4.4）已按要求跳过，不重复报告
- 审计重点：缓冲区溢出、密钥内存清零、路径遍历、命令注入、整数溢出、未初始化变量、竞态/TOCTOU、硬编码密钥、不安全随机数、加密误用、空指针、资源泄漏、格式化串、文件权限

---

## 一、发现汇总（按严重程度排序）

| # | 严重程度 | 文件 | 行号 | 类别 |
|---|----------|------|------|------|
| 1 | 中 | CLI/cli/main.cpp | 702–714 | 路径遍历（还原文件名未净化） |
| 2 | 低 | CLI/core/keylib.cpp | 83–88 | 资源耗尽（先全量读再判大小） |
| 3 | 低 | CLI/cli/main.cpp | 819, 1252, 1267 | 资源耗尽（无上限读取密钥/输入文件） |
| 4 | 低 | CLI/core/keylib.cpp | 174–185 | 路径遍历（索引反序列化未再校验字段） |
| 5 | 低 | CLI/core/config.cpp | 525–540 | 信任边界（CWD 配置白名单收口不完整） |
| 6 | 低 | CLI/core/config.cpp | 495 vs 331–334 | TOCTOU（大小预检后流式读取不再封顶） |
| 7 | 低 | CLI/core/keylib.cpp | 170 | 拒绝服务（YAML 索引无大小/别名展开上限） |
| 8 | 低 | CLI/cli/main.cpp | 1279–1284 | 密钥残留（环境变量副本未擦除，固有局限） |

未发现“高”严重级别问题：本批次文件中无缓冲区溢出、无 `system()/popen()` 命令拼接、无硬编码密钥/IV、无 `rand()`、无 ECB/nonce 复用、无格式化串、无 `memcpy/strcpy/sprintf` 等危险 API 调用。

---

## 二、详细发现

### 【中】1. run_recover 还原文件名直接拼接导致路径遍历
- **文件**：`CLI/cli/main.cpp`
- **行号**：702–714（核心拼接在 705 行）
- **类别**：路径遍历（Path Traversal）
- **描述**：
  ```cpp
  std::string dir=path;
  size_t bs=dir.find_last_of("/\\");
  std::string base=(bs!=std::string::npos)?dir.substr(0,bs+1):"";
  std::string newpath=base+orig+".ptd";   // <-- orig 未做 basename 净化
  ...
  if(replace_file_utf8(path,newpath)) { ... }
  ```
  `orig` 来自 `read_original_name(path, orig, pw)`，即从 `.ptd` 密文尾部“文件名信封”解密出来的原始文件名。该值是**数据可控**的（由加密时所用文件名决定），但此处直接与目录前缀拼接后用于 `replace_file_utf8`（原地重命名）。若信封中的文件名包含 `..\..\..\Windows\Temp\evil` 或绝对路径（如 `C:\...`），则 `newpath` 会逃逸出原目录，把 `.ptd` 移动到任意可写位置。
- **利用前提**：需 `--rename` 开关 + 受害者持有口令可解密信封。属于“ crafted .ptd + 社会工程”场景，概率有限，但属防御性编码缺口（对称解密主路径走的是 `replace_basename()`，本函数却直接字符串拼接，不一致）。
- **修复建议**：在拼接前对 `orig` 取 basename 并拒绝目录分隔符与 `..`，例如：
  ```cpp
  size_t s1=orig.find_last_of("/\\");
  std::string safe = (s1!=std::string::npos)? orig.substr(s1+1) : orig;
  if(safe.empty() || safe=="." || safe==".." || path_has_traversal(safe)) { /* 拒绝 */ }
  std::string newpath=base+safe+".ptd";
  ```
  与对称路径统一走同一套 basename 净化函数。

---

### 【低】2. read_key_material 先全量读入再判定 256 KB 上限
- **文件**：`CLI/core/keylib.cpp`
- **行号**：83–88
- **类别**：资源耗尽（内存 DoS）
- **描述**：
  ```cpp
  std::string buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  f.close();
  if (buf.size() > 256 * 1024) { err="Key file too large..."; return false; }
  ```
  文档注释声称“读密钥材料（上限 256 KB）”，但实际上是先用 `istreambuf_iterator` 把**整个文件**读进 `buf` 后才比较大小。一个数 GB 的“密钥文件”会被完整读入内存后才被拒绝，上限形同虚设。
- **修复建议**：流式读取并在累积量超过 256 KB 时立即中断返回；或用 `read()` 分块累加、超限即停。

---

### 【低】3. 多处密钥/输入读取无大小上限
- **文件**：`CLI/cli/main.cpp`
- **行号**：819（`read_trimmed`）、1252–1253（`-k` 密钥文件 `kbuf`）、1267–1268（`--key-stdin` `sbuf`）
- **类别**：资源耗尽（内存 DoS）
- **描述**：三处均以 `istreambuf_iterator` 一次性把整个文件/管道读入 `std::string` / `std::vector<char>`，没有任何上限：
  - `read_trimmed`（`-L pub <keyfile>`）：与 keylib.cpp 的 256 KB 上限不一致；
  - `-k <keyfile>`：任意大小密钥文件全量入内存；
  - `--key-stdin`：从管道读到 EOF，恶意大管道可撑爆内存。
- **修复建议**：统一引入流式上限（例如密钥材料 ≤ 256 KB、stdin 密钥 ≤ 1 MB），超限即报错停止。

---

### 【低】4. keylib_load 反序列化索引时未再校验 name/file 字段
- **文件**：`CLI/core/keylib.cpp`
- **行号**：174–185（配合 148–152 `keylib_file_path`、353、405）
- **类别**：路径遍历（信任已落盘的索引）
- **描述**：`keylib_valid_name()`（154–161）在 `keylib_add` 写入时校验名称，但 `keylib_load` 读取 `library.yaml` 时直接采信 `n["file"].as<std::string>()`，未重新校验。`e.file` 随后被 `keylib_file_path()` 直接拼到 `keylib_dir()` 后用于读/写/导出（353、405）。若 `library.yaml` 被本地篡改（或经由其他可写进程注入），把 `file:` 写成 `../../evil`，则后续 `keylib_key_path` / `keylib_export` 会读写库目录之外的文件。
- **利用前提**：需要对用户配置目录下的 `library.yaml` 已有写权限，属纵深防御缺口。
- **修复建议**：`keylib_load` 对每条记录重新跑 `keylib_valid_name(e.name)`，并校验 `e.file` 不含 `/`、`\`、`..` 且以 `.key` 结尾，不合法的记录跳过。

---

### 【低】5. CWD 低信任配置的安全敏感键收口不完整
- **文件**：`CLI/core/config.cpp`
- **行号**：525–540
- **类别**：信任边界 / 加密强度弱化
- **描述**：代码已正确识别 CWD 来源配置“不可信”，但 `clamp` 只回退了 `log_file` 与 `path_whitelist*` 两项。以下安全相关键仍来自被植入的 CWD `fileencryptor.yaml`：
  - `kdf_preset: fast`（Argon2 opslimit=3/64 MB，而非默认 standard）——直接降低口令派生的暴力破解成本；
  - `min_password_length: 1` / `min_password_classes: 0`——弱化口令策略；
  - `obfuscate_names: false`——关闭输出文件名混淆。
- **场景**：攻击者在一个可写目录预置 `fileencryptor.yaml`，诱导受害者 `cd` 进去运行本工具。
- **修复建议**：把 `kdf_preset`、`min_password_length`、`min_password_classes`、`obfuscate_names` 也纳入 CWD 来源的默认值回退白名单（或仅允许从 ExeDir/UserConfig 读取这些键）。

---

### 【低】6. 配置文件大小预检与实际读取之间存在 TOCTOU
- **文件**：`CLI/core/config.cpp`
- **行号**：495（`get_file_size_raw > kMaxConfigBytes` 预检） vs 331–334（`read_file_utf8` 循环 append）
- **类别**：竞态 / 资源耗尽
- **描述**：用 `_wstat64`/`stat` 判定配置 ≤ 1 MB 后才读入，但 `read_file_utf8` 内 `while((n=fread(...))>0) out.append(buf,n)` 会一直读到 EOF，不再检查累计大小。两次系统调用之间文件若被增长（符号链接替换 / 另一个进程追加），最终读入内存的 YAML 仍可超过 1 MB，使“Billion Laughs 防护”被绕过。
- **修复建议**：在 `read_file_utf8` 的循环里同时累计字节数，超过 `kMaxConfigBytes` 立即停止并返回失败。

---

### 【低】7. keylib 索引 YAML 解析无大小/别名展开上限
- **文件**：`CLI/core/keylib.cpp`
- **行号**：170（`YAML::LoadFile(path)`）
- **类别**：拒绝服务（YAML 实体/别名炸弹）
- **描述**：`config.cpp` 已为配置文件加了 `kMaxConfigBytes`（1 MB）硬限制以防 Billion Laughs，但 `keylib_load` 直接 `YAML::LoadFile()` 读 `library.yaml`，既无大小预检也无别名展开限制。虽然索引位于用户自己的配置目录、利用门槛较高，但与配置侧防护不一致。
- **修复建议**：复用 `config.cpp` 的 1 MB 预检（抽出 `get_file_size_raw` 共用），或在 `YAML::LoadFile` 前以相同阈值拦截。

---

### 【低】8. ENCRYPTOR_KEY 环境变量副本未擦除
- **文件**：`CLI/cli/main.cpp`
- **行号**：1279–1284
- **类别**：密钥内存残留
- **描述**：
  ```cpp
  const char* ek=std::getenv("ENCRYPTOR_KEY");
  if(ek&&*ek) { password = SecureBuffer(ek, std::strlen(ek)); ... }
  ```
  已正确把口令拷贝进 RAII `SecureBuffer`（析构自动清零），但进程环境块中原有的 `ENCRYPTOR_KEY=...` 字符串副本未被擦除。环境块在 `/proc/<pid>/environ`、core dump、其他进程读取 environ 等场景仍可暴露。
- **说明**：这是环境变量传密的固有局限，Windows 下尤其难完全清除（`_putenv` 删除后原串仍驻留环境块内存）。记录在案，供设计权衡（推荐 GUI 走 `--key-stdin` 而非 env）。
- **修复建议（可选）**：读完后 `_putenv("ENCRYPTOR_KEY=")` / `unsetenv("ENCRYPTOR_KEY")` 尽量缩短窗口；文档中明确 env 方式不如 stdin 安全。

---

## 三、逐文件结论

| 文件 | 结论 |
|------|------|
| `CLI/cli/main.cpp` | 存在发现 1（中）、3、8（低）。密钥/口令在各路径均正确使用 `sodium_memzero` + `SecureBuffer` RAII；无命令注入、无格式化串、无危险字符串 API；`salt_hex[33]` 与 16B→32hex 精确匹配，无溢出。 |
| `CLI/core/config.cpp` | 存在发现 5、6（低）。JSON 日志做了 `json_escape`；`snprintf` 均带长度参数；UTF-16↔UTF-8 转换缓冲区大小与写入长度精确匹配；Billion Laughs 已有 1 MB 阈值（见发现 6 的 TOCTOU 缺口）。 |
| `CLI/core/config.hpp` | **未发现安全问题**（纯结构体声明与函数原型）。 |
| `CLI/core/keylib.cpp` | 存在发现 2、4、7（低）。私钥材料在 `keylib_add`/`run_pubkey` 等路径均 `sodium_memzero`；索引写采用临时文件 + 原子替换；密钥文件 `tighten_file_permissions` 已收紧。 |
| `CLI/core/keylib.hpp` | **未发现安全问题**（纯结构体与函数原型）。 |
| `CLI/core/password_policy.cpp` | **未发现安全问题**。字符分类统一以 `unsigned char` 调用 `std::is*`，避免 UB；非 ASCII 直通为文档化设计。 |
| `CLI/core/password_policy.hpp` | **未发现安全问题**（纯函数原型）。 |

---

## 四、已核查且确认无问题的项（对应审计清单）

- **缓冲区溢出/越界**：未使用 `memcpy/strcpy/strcat/sprintf`；`WideCharToMultiByte`/`MultiByteToWideChar` 目的缓冲长度与写入长度一致；`salt_hex[33]` 与 `sodium_bin2hex` 输出 32hex+NUL 精确匹配。
- **密钥内存清零**：口令/私钥在所有返回路径（含错误分支）均 `sodium_memzero`；`SecureBuffer` RAII 持有；`get_password_win/posix` 的临时 `std::string line` 已清零。
- **命令注入**：未出现 `system()`/`popen()`/shell 拼接；全部为直接文件 I/O。
- **整数溢出**：`parse_size` 拒绝负数；`kdf_preset` 限定 0..2；`compress_level` 范围校验 -5..22；`opt_size/opt_int` 均 try/catch 包裹。
- **未初始化变量**：`get_password_posix` 的 `oldt` 仅在 `tcgetattr` 成功后使用（注释已说明）；`tm_buf` 由 `gmtime_s/r` 填充；`now_string` 用 `std::tm tmv{}` 初始化。
- **硬编码密钥/IV**：无。`DEFAULT_CONFIG_YAML` 仅为运维参数模板。
- **不安全随机数**：未出现 `rand()`/`srand()`；盐与密钥均由 libsodium 提供。
- **加密算法误用**：本批次文件不直接操作 nonce/IV，封装在外部模块；未发现 ECB/nonce 复用模式。
- **空指针解引用**：`getenv`/`GetConsoleMode`/`CommandLineToArgvW`/`WideCharToMultiByte` 返回值均已判空。
- **资源泄漏**：文件句柄走 RAII（`ifstream/ofstream`）；`LocalFree(argv_w)` 已配对；`FILE*` 均 `fclose`。
- **格式化字符串**：所有 `printf/fprintf` 均为字面量格式串 + `%s/%d` 参数。
- **文件权限**：私钥文件（`rage_private.txt`、`<name>.key`、导出副本）均调用 `tighten_file_permissions`；盐文件为公开值，未收紧可接受。

---

*报告结束。共 1 项中危、7 项低危，无高危。*
