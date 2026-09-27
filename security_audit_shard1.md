# FileEncryptor CLI 核心加密模块 — 源代码安全审计报告（shard 1）

- 审计日期：2026-09-27
- 审计版本基线：2.4.4（FE_VERSION_STRING）
- 审计范围：本报告仅覆盖用户指定的 22 个文件，未审计范围外代码。
- 审计方式：静态人工白盒审查，未修改任何源码。
- 已知基线（用户声明已修复，本报告不重复列出）：secure_zero.hpp 补齐、BufferPool release 清零、force-decrypt 明文清零改用 secure_zero、salt_ptr 悬垂指针、v6 恒判 corrupted、白名单相对路径、rage 模式路径白名单绕过。

---

## 一、结论概览

| 严重程度 | 数量 |
|---|---|
| 高 | 0 |
| 中 | 3 |
| 低 | 6 |

整体结论：核心加密路径（Argon2id 派生 / XChaCha20-Poly1305 / AEGIS-256 / AES-GCM legacy / v6 DEK 包裹 / header_hmac / 续传 HMAC 防重放）实现规范，随机数全部来自 libsodium（randombytes_buf），未发现硬编码密钥/IV、未发现 ECB 或 nonce 复用、未发现可被远程触发的栈/堆溢出。发现的问题集中在**密钥派生中间值的内存擦除不彻底**、**Windows 下半成品明文文件的 ACL 未收紧**、以及若干防御纵深类低危项。

---

## 二、安全问题清单（按严重程度排序）

### 【中-1】主密钥派生子密钥时，把主密钥拷进普通堆 vector，析构时未擦除

- 文件：`CLI/core/kdf.cpp`
- 行号：92-98（`derive_progress_auth_key`）、100-106（`derive_header_auth_key`）；同类问题见 `CLI/core/FileEncryptor.cpp:1038-1045`（`derive_name_key`）
- 类别：密码/密钥内存未彻底清零（审计重点 #2）
- 描述：
  ```cpp
  std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
  in.insert(in.end(), master_key, master_key+ARGON2_OUTPUT_LEN); // 主密钥 32 字节副本进堆
  crypto_generichash(auth_key, ..., in.data(), in.size(), nullptr, 0);
  ```
  `in` 是普通 `std::vector<unsigned char>`：① 它**没有 mlock**（不像 SecureBuffer），这 32 字节主密钥副本可被换出到 swap / 写入 core；② 离开作用域时 vector 析构只释放堆内存，**不做 sodium_memzero**，这块堆随后被分配器复用，残留主密钥材料。`derive_name_key`（FileEncryptor.cpp:1041-1042）把同一份 master_key 拼进 `in`，问题相同。salt 进 `derive_name_nonce` 的 `in` 不是秘密，可不计入。
- 影响：进程内存/交换分区中残留与主密钥等价的派生输入副本；对具备本机取证或 swap 读取能力的攻击者削弱了"密钥只驻留于 mlock 页"的保证。
- 修复建议：
  1. 用 `SecureBuffer`（自带 mlock + 析构 sodium_memzero + swap 释放）承接拼接缓冲；或
  2. 在 `crypto_generichash` 返回后、vector 析构前，显式 `sodium_memzero(in.data(), in.size());`；
  3. 三个派生函数统一处理（progress / header / name）。

### 【中-2】Windows 下半成品明文 `.prt` 与输出文件未收紧 DACL（明文可被同机其他用户读取）

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：543-547（`restrict_permissions`）、2419 与 2494（解密 `restrict_permissions(part_path)`）、1763（加密输出）
- 类别：不安全的文件权限（审计重点 #13）
- 描述：`restrict_permissions` 在 `#ifndef _WIN32` 内才 `chmod(path,0600)`，Windows 分支为空：
  ```cpp
  static void restrict_permissions(const std::string& path) {
  #ifndef _WIN32
      chmod(path.c_str(),0600);
  #endif
  }
  ```
  解密流程在最终原子改名前，把明文先写到 `<out>.prt`（FileEncryptor.cpp:2415/2490），该 `.prt` **包含逐块还原出的明文**，却只调用了空操作的 `restrict_permissions`。在 Windows 上它继承父目录默认 DACL，多用户/服务器环境下同机其他主体可在落盘到 `replace_file_utf8` 完成前读取明文。加密侧 `.ptd` 是密文，影响较低；但 `.prt` 是明文，影响实质。项目已有 `tighten_file_permissions`（FileEncryptor.cpp:671，写 PROTECTED_DACL）却只用于密钥文件，未复用到 `.prt`。
- 修复建议：在 `restrict_permissions` 的 Windows 分支复用 `tighten_file_permissions(path)`（或在创建 `.prt` 后立即调用它），保证半成品明文在 Windows 上也是仅所有者可访问。

### 【中-3】解密失败时半成品明文 `.prt` 直接 unlink，未覆写

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：2771（`remove_file_utf8(part_path)`）；对照 `CLI/core/source_handling.cpp:45-80` 的 Wipe 实现
- 类别：敏感数据残留（审计重点 #2 的延伸）
- 描述：解密中途失败时执行 `remove_file_utf8(part_path)` 删除 `.prt`。`.prt` 中是已经还原、落盘的明文片段，此处仅做普通删除（unlink），不做任何覆写。这与产品自带的 `SourceDisposition::Wipe`（0x00/0xFF/随机三遍覆写，source_handling.cpp:61-75）理念不一致：源文件能被多遍擦除，解密失败产物却裸删。未覆写的明文片段在文件系统层仍可被取证恢复。
- 修复建议：失败清理 `.prt` 前，对其调用与 Wipe 相同的覆写（或至少一次随机/0x00 覆写）后再 `remove_file_utf8`；注意 SSD 磨损均衡的固有局限（source_handling 注释已说明）。

---

### 【低-1】混淆基名派生时栈上 `key[32]`/`seed[32]` 未清零

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：1067-1075（`make_obfuscated_basename`）
- 类别：密钥内存未清零（#2）
- 描述：
  ```cpp
  unsigned char key[32];  crypto_generichash(key,sizeof(key),password.data(),password.size(),...);
  unsigned char seed[32]; crypto_generichash(seed,sizeof(seed), ..., key, sizeof(key));
  ```
  `key` 是 `Blake2b(口令)` 的结果（口令派生密钥材料），`seed` 再由其派生。二者均为栈上 32 字节，函数返回前未 `sodium_memzero`，栈帧随后被复用残留。
- 修复建议：函数末尾 `sodium_memzero(key,sizeof(key)); sodium_memzero(seed,sizeof(seed));`（`seed` 已转 hex 字符串后即可清）。

### 【低-2】多处栈上派生子密钥 `hdr_auth[]` 数组未擦除

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：1587、1613、1838、2005、2363（`unsigned char hdr_auth[HEADER_HMAC_SIZE];`）；同类 1085-1086 `name_key/nonce`
- 类别：密钥内存未清零（#2）
- 描述：header HMAC 子密钥由主密钥派生得到，放在栈上 `hdr_auth[32]`，`crypto_auth(_verify)` 用完后未 `sodium_memzero`。属防御纵深问题（栈残留窗口小）。
- 修复建议：每个作用域用完后 `sodium_memzero(hdr_auth, sizeof(hdr_auth));`；`name_key`/`nonce`（1085-1086）同样处理。

### 【低-3】输出文件先以默认 0644 创建，再 chmod 0600，存在短暂窗口

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：1759→1763、2415→2419、2490→2494
- 类别：不安全文件权限（#13）/ 竞态
- 描述：POSIX 上 `ofstream` 创建文件受 umask 影响（通常 0644），之后才 `restrict_permissions` 收紧到 0600。open 与 chmod 之间的极短窗口内文件可被同机其他用户读。
- 修复建议：以 `O_CREAT|O_EXCL` + mode 0600 直接创建（`open(...,0600)`），或在 ofstream 打开前先 `umask(0077)`，消除窗口期。

### 【低-4】符号链接检查与实际打开输出之间存在 TOCTOU 窗口

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：加密 1712（`path_is_symlink(out_path)`）对比 1752/1759（`open_stream(fout,...)`）；解密 2374（`path_is_symlink(part_path)`）对比 2490（打开 `.prt`）
- 类别：竞态 / TOCTOU（#6）
- 描述：已做"写前拒绝既有符号链接/重解析点"的守卫，方向正确；但 check 与 open 不是原子的，能写输出目录的本地进程理论上可在间隙把路径换成 symlink 写穿到别处。已有跨进程输出锁（acquire_output_lock）显著收窄了窗口，但未完全消除。
- 修复建议：在持有输出锁的前提下，用"O_NOFOLLOW / FILE_FLAG_OPEN_REPARSE_POINT 拒绝"方式直接以不跟随符号链接的标志打开文件，把检查与打开合并为一次系统调用。

### 【低-5】MappedFile 在 32 位构建下文件大小截断为 size_t

- 文件：`CLI/core/mapped_file.cpp`
- 行号：62（`size_=(size_t)sz.QuadPart;`）、75（`size_=(size_t)st.st_size;`）
- 类别：整数截断（#4）
- 描述：`LARGE_INTEGER.QuadPart` 强制转 `size_t`；在 32 位构建上 >4GB 文件会被截断，后续按 `size_` 做边界判断时可能把实际更大的文件当成较小者。当前 MappedFile 主要用于元数据只读映射，不直接读写密文，触发后果有限。
- 修复建议：32 位构建下对 `sz.QuadPart > SIZE_MAX` 直接报错返回 false，而非静默截断。

### 【低-6】跨进程锁的"失效锁回收"存在极小竞争

- 文件：`CLI/core/FileEncryptor.cpp`
- 行号：584-596（Windows）、613-622（POSIX）
- 类别：竞态（#6）
- 描述：读取锁内 pid → 判定进程已死 → `DeleteFileW`/`unlink` → 重新 `CREATE_NEW`。两个进程可能同时判定同一把死锁可回收，随后其中一个的 `CREATE_NEW`/`O_EXCL` 会失败并落到 CANNOT_CREATE 分支——行为保守（拒绝），不会双写，但极端情况下会把本可成功的加锁误报为"无法创建"。
- 修复建议：回收后重新创建失败时，按"锁已被他人接管"处理为 LOCKED 并重试一次，而非直接 CANNOT_CREATE。

---

## 三、逐文件结论

| 文件 | 结论 |
|---|---|
| `CLI/core/FileEncryptor.hpp` | 未发现安全问题。UTF-8↔宽字符转换、open_stream/remove_file_utf8 内联辅助均正确。 |
| `CLI/core/FileEncryptor.cpp` | 见 中-1(局部)、中-2、中-3、低-1、低-2、低-3、低-4、低-6。整体加固充分：路径穿越双重校验、续传 HMAC 防重放、v4+ 头 HMAC、v6 DEK 包裹、nonce 递增、压缩长度前缀越界检查（2617）、seek 溢出检查（2549-2557）均到位。 |
| `CLI/core/ptd_format.hpp` | 未发现安全问题。packed 头部结构、static_assert 尺寸校验、`load_header` memcpy 防 strict-aliasing UB，设计正确。 |
| `CLI/core/ptd_format.cpp` | 未发现安全问题。`wrap_dek/unwrap_dek` 使用随机 nonce + AEAD + sodium_memzero 清零 48 字节明文临时缓冲，marker 用 sodium_memcmp 恒定时间比较。 |
| `CLI/core/mapped_file.hpp` | 未发现安全问题。RAII、禁拷贝、移动语义正确。 |
| `CLI/core/mapped_file.cpp` | 见 低-5。句柄/映射在 close() 全部释放，无资源泄漏。 |
| `CLI/core/buffer_pool.hpp` | 未发现安全问题（release 已 secure_zero，与基线一致）。互斥保护 pool_，无数据竞争。 |
| `CLI/core/secure_buffer.hpp` | 未发现安全问题。mlock + 析构 sodium_memzero + munlock + swap 强制释放，移动语义正确转移 locked_。 |
| `CLI/core/secure_zero.hpp` | 未发现安全问题（与基线一致）。volatile 逐字节写零防 dead-store 优化，空指针/零长已处理。 |
| `CLI/core/util/byte_io.hpp` | 未发现安全问题。裸指针读写均为定长；`xor_le64_tail` 有 `j<len` 边界保护。 |
| `CLI/core/util/endian.hpp` | 未发现安全问题。纯编译期/constexpr 转换，无运行时指针操作。 |
| `CLI/core/util/hex.hpp` | 未发现安全问题。`from_hex` 校验偶数长度与合法字符，逐半字节解析无越界。 |
| `CLI/core/kdf.cpp` | 见 中-1。KDF 参数上界拒绝（拒绝而非降级）、并发 Argon2 信号量、原子序双重检查锁均正确。 |
| `CLI/core/kdf.hpp` | 未发现安全问题。参数上界常量定义合理（ops≤10、mem≤1GiB）。 |
| `CLI/core/asym_crypto.hpp` | 未发现安全问题。纯声明。 |
| `CLI/core/asym_crypto.cpp` | 未发现安全问题。Bech32 解码有长度(8..90)、大小写、字符集、校验和校验；`fe_derive_keypair` 的 seed/pk 均 sodium_memzero，私钥串用 wipe() 清零并 swap 释放。 |
| `CLI/core/source_handling.hpp` | 未发现安全问题。纯枚举声明。 |
| `CLI/core/source_handling.cpp` | 未发现安全问题（Wipe 三遍覆写用 sodium_memzero 擦除 buf；Delete/Recycle 失败回退直接删除避免明文残留）。 |
| `CLI/core/progress_frame.hpp` | 未发现安全问题。 |
| `CLI/core/progress_frame.cpp` | 未发现安全问题。所有 snprintf 均带 size 且格式串为字面量；宽字符宽度计算有 `i+seq>size` 越界保护；互斥保护共享槽位，无格式化字符串漏洞。 |

---

## 四、按审计重点的逐项核查结论

1. **缓冲区溢出/越界**：未发现可被触发的越界。压缩长度前缀（FileEncryptor.cpp:2613-2620）、IV 长度（2279-2294）、头部读取（hdrbuf[320]，最大头 256）均有边界检查；`xor_le64_tail`、`from_hex` 有保护。
2. **密钥内存清零**：SecureBuffer/sodium_memzero 主线正确；残留问题见 中-1、低-1、低-2。
3. **路径遍历**：`path_has_traversal` 组件法 + `normalize_path_lexical` 双重防护，`build_batch_out_path`、`sanitize_restored_name`（拒绝 `..`、分隔符、盘符冒号、Windows 保留设备名）均到位。
4. **整数溢出**：块计数受 UINT32_MAX 拒绝（1501）；解密 seek 偏移有显式溢出检查（2549）；KDF 头参数有上界拒绝。仅 低-5 的 32 位 size_t 截断。
5. **未初始化变量**：头部/进度/密钥缓冲均零初始化（`{}` 或 `{0}`），未发现使用未初始化值。
6. **竞态条件**：输出跨进程锁、KDF 信号量、限速器、进度槽互斥均正确；残余 TOCTOU 见 低-4、低-6。
7. **硬编码密钥/密码/IV**：未发现。DEK_MARKER 是公开常量非秘密。
8. **不安全随机数**：全部使用 `randombytes_buf`/libsodium，未使用 `rand()`。
9. **加密算法误用**：salt/nonce 随机生成，nonce 逐块 `sodium_increment` 无复用；文件名信封 nonce 由随机 salt 经 BLAKE2b 域分离派生，每文件唯一；AAD 绑定头与块元数据；未发现 ECB。
10. **空指针解引用**：所有外部密钥入参均有长度判空（1258、2318、2348）。
11. **资源泄漏**：文件句柄/映射/锁均 RAII（MappedFile、OutputLockGuard、fstream 析构），未发现泄漏。
12. **格式化字符串**：全部 `fprintf/snprintf` 格式串为字面量，外部数据均以 `%s` 参数传入。
13. **不安全文件权限**：POSIX 输出 0600 到位；Windows `.prt` 明文 ACL 未收紧，见 中-2；另见 低-3。

---

## 五、修复优先级建议

1. **优先**：中-2（Windows `.prt` 明文 ACL）——直接关系运行中明文机密性。
2. **其次**：中-1（派生子密钥 vector 主密钥副本擦除）、中-3（失败 `.prt` 覆写）。
3. **择机**：低-1～低-6 防御纵深项。
