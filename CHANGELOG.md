# Changelog

## 3.0.1

### 密码输入次数收敛（WinUI / Qt）
- 解锁、解密、解包、预览等"本就单次"的流程改为只输入一次密码；设置密码、批量加密（非入已初始化盘）、密钥派生、包装、改密码（新密码）保持两次。
- 根因修复：WinUI `PasswordDialog` 的 `NeedConfirm` 原为 `init` 属性，但确认框在构造函数内按该属性建树；C# 对象初始化器在构造后才赋值，导致构造期恒读到默认 `true`、所有"单次"流程仍多弹一个确认框。已改为构造函数参数 `PasswordDialog(bool needConfirm = true)`，调用点显式传值。

### 程序内文案行业化（中文 / 英文 / 俄文三语）
- `完成。` → `操作成功完成。`（En: Operation completed successfully.）
- `预览完成。预览不会写出解密文件。` → `预览完成，未写出任何解密文件。`
- `盘已清空，现在可以继续往里存入文件。` → `加密盘已成功清空，可继续存入文件。`
- `任务完成` → `操作完成`（标题与通知均统一）
- 改动集中在 `GUI-WinUI/Services/L10n.cs` 的 Zh/En/Ru 三张映射表，并同步所有引用点（MainWindow、PreviewWindow、TaskSummaryDialog、TaskNotificationWindow）。

### 稳定性与资源管理器卡顿（FE-Mounter）
- 现象：读取加密盘一段时间后盘符莫名消失、GUI 提示未响应。
- 根因：`wf_ReadDirectory` 每轮枚举对大目录做两次全量 `readdir`（计数+取数）；`pid_is_fg_locked` 在持有 `g_idle_mtx` 时调用 `EnumWindows` 枚举前台窗口，把全部并发 I/O 串行化，资源管理器（后台轮询缩略图/属性）被卡死乃至挂载超时掉盘。
- 修复：
  - 前台窗口枚举移出 I/O 热路径——新增后台线程每 ~1s 刷新前台快照（`g_fg_snap_mtx` 保护），`pid_is_fg_locked` 仅原子读快照，不再阻塞 I/O；`wf_SvcStop` 先停该线程再置 `g_ipc_stop`。
  - 读缓存维持 64MB（曾上调 256MB，因首次访问集中预热回退，见下节）。
  - 目录枚举缓存曾引入（2s TTL）后移除，原因见下节。

### vault.meta 加密存储（CLI / 核心库）
- 新增格式 `format==2`：`salt / opslimit / memlimit_kb / mount_point` 仍保持明文（解锁前需派生密钥、且需可改挂载点），仅 `root` / `created` 移入 `crypto_secretbox_easy` 密文，随 `meta_nonce`(hex) + `meta_enc`(base64) 落盘。
- 旧明文库（format==1）首次解锁时由 `vdisk_unlock` 透明改写为 format==2（用派生 KEK 重存），用户无感升级。
- FEIndex 此前已以 `FEIDX1 + nonce + secretbox` 加密，本版补齐 vault.meta 的明文字段加密，至此元数据全密文化。

### 挂载回归修复（3.0.1 热修）
部署后出现三项回归，均源于上一节的 mounter 改动：

- **初次读取时 FE-Mounter 占 ~25% CPU 约 20s、期间任何操作无效**
  - 根因：后台快照线程在**持有** `g_fg_snap_mtx` 时调用 `EnumWindows`（遍历全部顶层窗口，耗时不可控）。而 `pid_is_fg_locked` 在每个 I/O 上都要取同一把锁，于是窗口枚举一慢，所有文件操作全部排队等锁。
  - 修复：改为**无锁枚举 + 短暂持锁换入**——`fg_build_snapshot()` 先在局部快照上完成 `EnumWindows`（不持任何锁），再只做一次极短的 `g_fg_snap = std::move(s)`。I/O 侧永不被窗口枚举阻塞。同时 `pid_is_fg_locked` 改为锁内直接判定，不再拷贝整个可见窗口集合。
- **回滚目录（Explorer）提示「目录无效」但目录实际可访问**
  - 根因：目录枚举缓存（2s TTL）在过期窗口内返回与实盘不一致的快照。
  - 修复：**移除目录枚举缓存**。卡顿真因是窗口枚举串行化 I/O，已单独修复，无需缓存兜底，避免引入一致性风险。
- **挂载后读取文件提示「无权限」**
  - 根因一（主要）：`wf_ReadDirectory` 未调用 `fe_note_if_fg`，只翻目录、不打开任何文件时不刷新前台活动时刻，M5 空闲守护在窗口到期后**误锁**，随后读文件 `read_file` 返回 `VDISK_E_LOCKED` → `wf_st` 映射为 `STATUS_ACCESS_DENIED`。修复：目录浏览同样计入前台活动。
  - 根因二（连带）：读缓存 256MB 使首次访问集中分配/预热，加剧首个操作卡顿。已回退 64MB。
  - 附带修正（非本次症状，但为真实缺陷）：`vault_meta_decrypt` 此前从未被调用，format==2 的 `root`/`created` 解密后恒为空；已在 `vdisk_unlock` 中补全解密，并让升级后内存状态与落盘格式一致。

### 构建 / 部署
- 全组件构建通过：WinUI GUI（`dotnet build`，0 错误）、CLI（`build_cli.py` Ninja）、FE-Mounter（`build_mounter.py` Release）。
- 已将 5 个变更二进制覆盖部署至 `C:\Program Files\FileEncryptor (WinUI)\`：`FileEncryptorGUI.WinUI3.dll/.exe`、`vdisk.dll`、`FE-Mounter.exe`、`FileEncryptorCLI.exe`。
- 热修另部署 `vdisk.dll`、`FE-Mounter.exe`（GUI 未改动，无需重出）。
