/*
 * libvdisk — 加密盘动态链接库对外契约（C ABI，二进制稳定）
 * 对应设计文档 The Next Release/加密盘方案.md §5.2。
 * 库由 FE-Mounter 进程加载，句柄在 holder 进程内持有；GUI/CLI 经受限 IPC 驱动。
 */
#ifndef VDISK_H
#define VDISK_H

#include <stdint.h>
#include <stddef.h>   // size_t

#ifdef __cplusplus
extern "C" {
#endif

/* 导出控制：仅 vdisk_* 对外可见（§5.1 符号最小化）。构建 DLL 时定义 VDISK_BUILD。 */
#ifndef VDISK_API
#  ifdef VDISK_BUILD
#    ifdef _WIN32
#      define VDISK_API __declspec(dllexport)
#    else
#      define VDISK_API __attribute__((visibility("default")))
#    endif
#  else
#    define VDISK_API
#  endif
#endif

typedef struct VDiskHandle VDiskHandle;  /* 不透明，库外不可见内部结构 */

typedef enum {
    VDISK_OK = 0,
    VDISK_E_BADARG = -1,
    VDISK_E_AUTH = -2,        /* 密码/恢复密钥错误 */
    VDISK_E_LOCKED = -3,      /* 未解锁 */
    VDISK_E_NOMEM = -4,
    VDISK_E_IO = -5,
    VDISK_E_WIPE = -6,        /* 原明文擦除失败，按 §4.5 拒绝完成 */
    VDISK_E_NOTIMPL = -7,     /* M6 写支持未实现 */
    VDISK_E_NOTFOUND = -8,    /* 虚拟路径不存在 */
    VDISK_E_RO = -9,          /* 只读挂载拒绝写 */
    VDISK_E_EXIST = -10,      /* 目标已存在（重命名冲突） */
    VDISK_E_CANCELLED = -11,  /* 调用方取消：剩余项未处理（新增值，不改既有布局） */
    VDISK_E_INTERNAL = -99
} VDiskStatus;

/*
 * ABI 版本（构建期常量）。加载方（FE-Mounter / SAF vdisk host）绑定符号后必须调 vdisk_abi_version() 校验，
 * 与构建期 VDISK_ABI_VERSION 不符即拒绝加载——旧版/第三方 DLL 可能符号齐全但语义或结构体布局已漂移。
 * 破坏性变更（函数语义 / VDiskEntry 布局）必须递增此版本号；仅新增符号可不增。
 */
#define VDISK_ABI_VERSION 0x00010000u
VDISK_API uint32_t vdisk_abi_version(void);

/* 仅新增符号与 vault.meta 可缺省字段，未改动既有语义/结构体布局，故不 bump ABI 版本 */

/* 新写入默认算法（与 fe_mobile.h 的 FE_M_MODE_* 同值） */
#define VDISK_MODE_XCHACHA20 1
#define VDISK_MODE_AEGIS256  2
#define VDISK_MODE_AES_GCM   3
#define VDISK_MODE_SM4       4

/* 新写入压缩策略：AUTO=试压自适应；0=关；1..22 / -1..-5=zstd 级别 */
#define VDISK_COMPRESS_AUTO 100
/* 单次导入沿用库默认策略 */
#define VDISK_COMPRESS_DEFAULT 127

/*
 * 保留命名空间：库根下的隐藏目录（回收站）。三端（native / CLI / 桌面端）共用本常量，
 * 任何枚举、列表、容量统计入口都必须过滤该路径，不得各自写死字符串以免漂移。
 * 语义：路径的第一段（根层组件）等于该名即视为保留路径；回收站内部条目不再视为保留路径，
 * 仅供回收站页按需显式列举。
 */
#define VDISK_RESERVED_TRASH ".fe-trash"
VDISK_API const char* vdisk_reserved_name(void);          /* 返回 VDISK_RESERVED_TRASH */
VDISK_API int vdisk_is_reserved_path(const char* vpath);   /* 1=保留路径（根层 .fe-trash 及其子树） */

/* 生命周期 */
VDISK_API VDiskStatus vdisk_init(const char* library_dir);    /* 建库（幂等），无挂载平台须先调 */
/* 建库并指定之后新写入的默认算法/压缩策略；已有库只改策略，不动盐/KDF/密文段 */
VDISK_API VDiskStatus vdisk_init_ex(const char* library_dir, int mode, int compress_policy);
VDISK_API VDiskHandle* vdisk_open(const char* library_dir);   /* 打开库（不解锁） */
VDISK_API void         vdisk_close(VDiskHandle*);

/* 解锁 / 锁定（§4.1 密钥生命周期） */
VDISK_API VDiskStatus vdisk_unlock(VDiskHandle*, const char* passphrase, int use_recovery);

/*
 * 只读口令校验（局域网共享用）：仅与当前已解锁会话的主密码做常数时间比对，
 * 不读/写索引、不刷新时间戳、不改 vault.meta、不设置解锁态。
 * 前置条件：句柄已处于解锁态（局域网共享本身也只允许此时对外服务）。
 * 返回 VDISK_OK / VDISK_E_AUTH；未解锁返回 VDISK_E_LOCKED。
 */
VDISK_API VDiskStatus vdisk_verify_password(VDiskHandle*, const char* passphrase, int use_recovery);
VDISK_API VDiskStatus vdisk_lock(VDiskHandle*);               /* 全清 KEK/索引密钥 */
VDISK_API void        vdisk_purge_on_suspend(VDiskHandle*);    /* 睡眠/待机回调，同源清密钥 */

/* 进度/取消回调：供 vdisk_reindex_ex 等需要反馈与中断的接口使用（提前声明，
 * 因索引段的函数签名也要引用）。 */
typedef void (*VDiskProgressFn)(uint64_t done, uint64_t total, void* user);
typedef int (*VDiskCancelFn)(void* user);

/* 索引（§3 / §5） */
VDISK_API VDiskStatus vdisk_reindex(VDiskHandle*, const char* root);
/* 带进度/取消的重建索引：progress 收 (已扫 .ptd 文件数, 目标总数)，可为 NULL；
 * cancel 非 NULL 时每处理一项探询一次，命中返回 VDISK_E_CANCELLED（已重建部分照常落盘生效）。
 * 其余语义与 vdisk_reindex 一致。 */
VDISK_API VDiskStatus vdisk_reindex_ex(VDiskHandle*, const char* root,
                                      VDiskProgressFn progress, void* user,
                                      VDiskCancelFn cancel, void* cancel_user);
VDISK_API VDiskStatus vdisk_mount_readonly(VDiskHandle*, const char* mount_point);
VDISK_API VDiskStatus vdisk_unmount(VDiskHandle*);

/*
 * 目录枚举（两段式调用，出参数组由调用方分配）：
 *   1) out_entries=NULL 调用 → *out_count 置为子项数；
 *   2) 调用方按 *out_count 分配 VDiskEntry 数组后，传「数组指针的地址」再调 → 填充。
 *
 * 形参是 VDiskEntry**（指针的指针），第二段必须传 &数组指针：
 *   VDiskEntry* arr = malloc(n * sizeof(VDiskEntry));
 *   vdisk_readdir(h, path, &arr, &n);
 * 直接把数组首地址传进去会被二次解引用（把数组头 8 字节当指针）→ 写进野地址。
 * P/Invoke 侧（.NET）尤其易错：须先分配一个存放数组地址的槽位，再传槽位地址。
 * 第二段返回后 *out_count 是实际回填条目数，调用方须按它取有效条目。
 * name 指向库内存储，生命周期到下一次 readdir / lock / close 为止。
 */
typedef struct VDiskEntry {
    const char* name;     /* 目录项名（不含路径） */
    uint8_t     is_dir;   /* 1=目录 0=文件 */
    uint64_t    size;     /* 文件大小 */
    uint64_t    mtime;    /* 修改时间（unix 秒） */
} VDiskEntry;
VDISK_API VDiskStatus vdisk_readdir(VDiskHandle*, const char* vpath,
                                    VDiskEntry** out_entries, uint64_t* out_count);
VDISK_API VDiskStatus vdisk_getattr(VDiskHandle*, const char* vpath,
                                    uint64_t* out_size, uint64_t* out_mtime, uint8_t* out_is_dir);

/* 读（§1 随机块读，非压缩块 O(1)）。out 由调用方分配，容量 = *len；回填实际读到的字节数。 */
VDISK_API VDiskStatus vdisk_read_file(VDiskHandle*, const char* vpath,
                                      uint64_t offset, uint8_t* out, uint64_t* len);

/* 写（M6 实现：块级覆盖就地加密；大小变化走全文件重写为 64KB 非压缩 .ptd.tmp + 原子 rename） */
VDISK_API VDiskStatus vdisk_write_file(VDiskHandle*, const char* vpath,
                                       uint64_t offset, const uint8_t* in, uint64_t len);

/* 可写挂载（替代 readonly；要求全部文件为 64KB 非压缩对称块，否则写前先全量重加密） */
VDISK_API VDiskStatus vdisk_mount_rw(VDiskHandle*, const char* mount_point);
/* 无挂载场景（Android：无 WinFSP/FUSE）开/关写权限。不设挂载点、不做 M7 占用。
 * 解锁后默认 rw=0，建/写/删前须先置 1。 */
VDISK_API VDiskStatus vdisk_set_writable(VDiskHandle*, int rw);
/* 改库默认算法/压缩策略（单密码不变），立即持久化到 vault.meta；仅影响之后的写入 */
VDISK_API VDiskStatus vdisk_set_default_mode(VDiskHandle*, int mode, int compress_policy);
/* 创建/删除/截断（M6 写支持；写后原子更新 .feindex） */
VDISK_API VDiskStatus vdisk_create_file(VDiskHandle*, const char* vpath);
/* 目录感知创建：is_dir≠0 时只登记目录条目（不建 .ptd），供挂载盘 mkdir / 拷文件夹保留目录树 */
VDISK_API VDiskStatus vdisk_create_file_ex(VDiskHandle*, const char* vpath, int is_dir);
/* 建目录并指定 mtime（unix 秒；≤0 取当前时间）：整目录移入保留源目录时间戳 */
VDISK_API VDiskStatus vdisk_mkdir_ex(VDiskHandle*, const char* vpath, int64_t mtime);
VDISK_API VDiskStatus vdisk_delete_file(VDiskHandle*, const char* vpath);
VDISK_API VDiskStatus vdisk_truncate_file(VDiskHandle*, const char* vpath, uint64_t new_size);
/* 重命名 / 移动（挂载盘 Explorer 改名）。文件改 rel_path 并搬 .ptd；目录按前缀批量改并重搬所有子 .ptd */
VDISK_API VDiskStatus vdisk_rename(VDiskHandle*, const char* old_vpath, const char* new_vpath);

/* 批量移动/重命名：一次索引整写；out_status 可空，非空须容纳 count 项逐项结果 */
VDISK_API VDiskStatus vdisk_rename_many(VDiskHandle*, const char* const* old_paths,
    const char* const* new_paths, uint32_t count, VDiskStatus* out_status);

/*
 * 库内文件复制（O(1) 内存、不落明文）：同一库内 .ptd 由统一口令加密，
 * 直接按字节流复制密文容器并登记新索引条目（沿用源算法/压缩/大小），
 * 不重新解密再加密，因此大文件也只占用固定缓冲区。
 * 限制：不复制目录（返回 NOTIMPL）。新名字会重写进 footer 加密文件名信封，
 * 解密端（含索引丢失走信封恢复）看到的是目标文件名，不再是源文件名。
 * progress 按明文口径回报 (已复制, 源文件明文大小)；cancel 非空时可在复制中取消。
 */
VDISK_API VDiskStatus vdisk_copy_file(VDiskHandle*, const char* from, const char* to,
                                      VDiskProgressFn progress, void* user,
                                      VDiskCancelFn cancel, void* cancel_user);

/* 复制增强版：rewrite_name != 0 时把尾部加密文件名信封重写为新文件名
 * （此前 vdisk_copy_file 只复制字节，解密端会回退显示旧名）。新符号，不改既有布局。 */
VDISK_API VDiskStatus vdisk_copy_file_ex(VDiskHandle*, const char* from, const char* to,
                                         int rewrite_name,
                                         VDiskProgressFn progress, void* user,
                                         VDiskCancelFn cancel, void* cancel_user);

/* 全库完整性自检（仅新增符号）：逐文件按口令校验密文块/明文哈希（不解出、不落盘），
 * 并核对索引条目对应的 .ptd 是否仍在盘面、盘面是否有索引未登记的孤儿 .ptd。
 * progress 收 (已完成文件数, 目标文件数)；cancel 非 NULL 时每文件探询一次，
 * 命中返回 VDISK_E_CANCELLED（out 内为已完成部分的结果）。fsck 不修改任何索引/文件。 */
typedef struct VDiskCheckResult {
    uint64_t files_total;     /* 索引内文件条目总数（含回收站条目） */
    uint64_t files_checked;   /* 本次已处理文件数（取消时可能小于总数） */
    uint64_t files_failed;    /* 解密/校验失败的文件数 */
    uint64_t files_missing;   /* 索引有登记但盘面 .ptd 已缺失 */
    uint64_t orphans;         /* 盘面存在但索引未登记的 .ptd 数 */
    uint64_t bytes_checked;   /* 校验通过的文件明文总大小 */
} VDiskCheckResult;

VDISK_API VDiskStatus vdisk_check_library(VDiskHandle*, VDiskCheckResult* out,
                                          VDiskProgressFn progress, void* user,
                                          VDiskCancelFn cancel, void* cancel_user);

/* 自检增强版：on_file 在开始校验每个文件前回调其虚拟路径（供界面显示"正在处理"，
 * 调用方不得把该路径写入日志）；可为 NULL。其余语义与 vdisk_check_library 相同。 */
typedef void (*VDiskNameFn)(const char* vpath, void* user);

VDISK_API VDiskStatus vdisk_check_library_ex(VDiskHandle*, VDiskCheckResult* out,
                                             VDiskProgressFn progress, void* user,
                                             VDiskNameFn on_file, void* name_user,
                                             VDiskCancelFn cancel, void* cancel_user);

/* 错误串（GUI 报错文案） */
VDISK_API const char* vdisk_strerror(VDiskStatus);

/* ---- M4 恢复密钥（§4.4）---- */
/* 生成 48 位十进制恢复密钥（调用方须提供 ≥49 字节缓冲）。 */
VDISK_API VDiskStatus vdisk_recovery_gen(char* out_code, uint64_t code_cap);
/* 建立/重建保险文件 .fevault（存主密码副本；已有则覆盖）。 */
VDISK_API VDiskStatus vdisk_recovery_create(VDiskHandle*, const char* code);
/* 用恢复密钥解出主密码副本。*len 入参为 out_pass 容量，成功时出参为实际长度；
 * 容量不足返回 VDISK_E_BADARG 且 *len 保持调用方原值不被改写（需要更大缓冲由调用方自行决定）。不入常驻状态。 */
VDISK_API VDiskStatus vdisk_recovery_open(VDiskHandle*, const char* code,
                                          char* out_pass, uint64_t* len);
VDISK_API VDiskStatus vdisk_recovery_remove(VDiskHandle*);

/* ---- M5 增强 ---- */
/* 空闲超时自动锁（秒）。0 = 关闭。到点后任何数据访问都先自动 lock（返回 VDISK_E_LOCKED）。 */
VDISK_API VDiskStatus vdisk_set_idle_timeout(VDiskHandle*, uint32_t seconds);
VDISK_API uint32_t    vdisk_idle_remaining(VDiskHandle*);   /* 剩余秒数（无超时返回 UINT32_MAX） */

/* 流式导入/导出（移动端 fd 直读直写）：输入 fd 直接流式加密为 .ptd，
 * 不经明文 vector、不落明文临时文件，大文件内存 O(缓冲)。
 * progress 收 (done,total) 字节，可为 NULL。仅 Android 构建提供此两符号。 */

VDISK_API VDiskStatus vdisk_import_fd(VDiskHandle*, const char* vpath, int in_fd,
                                      VDiskProgressFn progress, void* user);
VDISK_API VDiskStatus vdisk_export_fd(VDiskHandle*, const char* vpath, int out_fd,
                                      VDiskProgressFn progress, void* user);

/* 单次导入覆盖算法/压缩策略；mode=0 或 policy=VDISK_COMPRESS_DEFAULT 表示沿用库默认 */
VDISK_API VDiskStatus vdisk_import_fd_ex(VDiskHandle*, const char* vpath, int in_fd,
                                          VDiskProgressFn progress, void* user,
                                          int mode, int compress_policy);

/* 读单文件实际算法与压缩标记（属性面板用）。mode 返回 VDISK_MODE_*；
 * out_compression: 0=无 1=zstd；out_comp_level: 实际级别。任一出参可为 NULL。 */
VDISK_API VDiskStatus vdisk_get_file_info(VDiskHandle*, const char* vpath,
                                          int* out_mode, int* out_compression,
                                          int* out_comp_level);

/* 批量并行导入（移动端小文件密集场景）：各项互不依赖（各自随机 salt/DEK），
 * 内部按核数并行做「加密写盘」，整批一次 Argon2id；索引在调用线程逐项登记，
 * 只重建一次派生缓存（单文件逐个导入是 N 次整索引重写 + N 次 rebuild）。
 * progress 收全批聚合字节 (done,total)，可为 NULL。
 * done 为「每完成一项即回调」：在调用线程触发（无需考虑重入），此时该项索引已登记、
 * h->index 已可见；可为 NULL。results 可为 NULL，非 NULL 时由调用方提供 count 个槽位。
 * fd 仍由调用方开闭。 */
typedef struct VDiskImportItem {
    const char* vpath;
    int         in_fd;
} VDiskImportItem;

typedef void (*VDiskItemDoneFn)(size_t index, VDiskStatus st, void* user);

/* 逐项进度：index 为本次 items 下标；done/total 为该文件明文已读 / 总字节。
 * 在 worker 线程触发（多个文件并行时可能并发），实现须线程安全且廉价，
 * 且不得在回调内重入本库（索引登记仍只在调用线程进行）。可为 NULL。 */
typedef void (*VDiskItemProgressFn)(size_t index, uint64_t done, uint64_t total, void* user);

/* 导入标志：跨批共享 KEK 时，中间批跳过 O(N) 全库索引缓存重建，末批或 import_end 才建一次。 */
typedef enum {
    VDISK_IMPORT_DEFAULT     = 0,         // 本批末尾重建索
    VDISK_IMPORT_NO_FINALIZE = (1 << 0)   // 本批不重建
} VDiskImportFlags;

/* 取消探针：返回非 0 即请求取消。在 worker 线程高频调用，实现须廉价（读一个标志）。
 * 批量导入/删除用它把「取消」响应时间从「整批跑完」压到「当前文件跑完」。 */

VDISK_API VDiskStatus vdisk_import_many(VDiskHandle*, const VDiskImportItem* items, size_t count,
                                        VDiskProgressFn progress, void* user,
                                        VDiskStatus* results,
                                        VDiskItemDoneFn done, void* done_user);
/* 带取消的批量导入：cancel 非 NULL 时每处理一项都探询一次，剩余项以 VDISK_E_CANCELLED
 * 结算（done 仍逐项回调，索引只登记已完成的项）。其余语义与 vdisk_import_many 一致。
 * flags：传 VDISK_IMPORT_NO_FINALIZE 可跳过末尾 O(N) 全库索引缓存重建（跨批导入的中间批），
 * 由随后调用的 vdisk_import_end 统一重建一次；传 0 则本批自重建（独立调用兼容旧行为）。 */
VDISK_API VDiskStatus vdisk_import_many_ex(VDiskHandle*, const VDiskImportItem* items, size_t count,
                                           VDiskProgressFn progress, void* user,
                                           VDiskStatus* results,
                                           VDiskItemDoneFn done, void* done_user,
                                           VDiskCancelFn cancel, void* cancel_user,
                                           uint32_t flags);
/* 同 vdisk_import_many_ex，但本批显式指定算法/压缩策略：只作用于这次调用，
 * 不写 vault.meta（导入时临时选用多算法而不改库默认）。mode 传 VDISK_MODE_*，
 * compress_policy 传 VDISK_COMPRESS_DEFAULT 表示沿用库默认压缩策略。 */
VDISK_API VDiskStatus vdisk_import_many_ex_mode(VDiskHandle*, const VDiskImportItem* items, size_t count,
                                                VDiskProgressFn progress, void* user,
                                                VDiskStatus* results,
                                                VDiskItemDoneFn done, void* done_user,
                                                VDiskCancelFn cancel, void* cancel_user,
                                                uint32_t flags, int mode, int compress_policy);
/* 同 vdisk_import_many_ex_mode，另提供逐项（单文件）进度回调 item_progress：
 * 并行加密时各文件同时在途，item_progress 按项回报 done/total，供单文件进度条使用。
 * item_user 原样回传；其余参数语义与 vdisk_import_many_ex_mode 一致。 */
VDISK_API VDiskStatus vdisk_import_many_ex2(VDiskHandle*, const VDiskImportItem* items, size_t count,
                                            VDiskProgressFn progress, void* user,
                                            VDiskItemProgressFn item_progress, void* item_user,
                                            VDiskStatus* results,
                                            VDiskItemDoneFn done, void* done_user,
                                            VDiskCancelFn cancel, void* cancel_user,
                                            uint32_t flags, int mode, int compress_policy);
/* 跨批导入：begin 派生一次 KEK 缓存于句柄，各 vdisk_import_many_ex（NO_FINALIZE）复用同一 KEK，
 * 省掉每批一次 Argon2id；end 清空缓存并重建一次索引派生缓存。未调用 begin 时各批自派生自重建。 */
VDISK_API VDiskStatus vdisk_import_begin(VDiskHandle*);
VDISK_API VDiskStatus vdisk_import_end(VDiskHandle*);

/* 带进度/取消的删除（目录即整棵子树）：progress 收 (已完成文件数, 目标总数) 文件计数，
 * 从调用线程触发；cancel 非 NULL 时逐文件探询，命中则停止删剩余项、返回
 * VDISK_E_CANCELLED（已删文件与索引改动照常生效，剩余文件保留）。 */
VDISK_API VDiskStatus vdisk_delete_file_ex(VDiskHandle*, const char* vpath,
                                           VDiskProgressFn progress, void* user,
                                           VDiskCancelFn cancel, void* cancel_user);
/* 预读缓存：开启后按 64KB 段缓存并预读后续段；cap_bytes=0 关闭。 */
VDISK_API VDiskStatus vdisk_set_read_cache(VDiskHandle*, uint64_t cap_bytes, uint32_t ahead_segments);

/* 容量统计：已用 = 索引内所有文件明文大小之和；total 由 max_bytes 限制（0 = 用默认动态上限）。
 * 供挂载层按实际占用回填卷容量，避免固定 1TiB 造成磁盘管理误导。 */
VDISK_API VDiskStatus vdisk_stat_space(VDiskHandle*, uint64_t* out_used, uint64_t* out_total);
/* 容量统计增强（仅新增符号，ABI 版本不变）：out_used 仍为全库明文总量（含回收站），
 * out_trash 单独回报回收站明文占用，供 UI 显示「已用 X（回收站 Y）」。任一出参可为 NULL。 */
VDISK_API VDiskStatus vdisk_stat_space_ex(VDiskHandle*, uint64_t* out_used,
                                          uint64_t* out_trash, uint64_t* out_total);

/* ---- M5+ 忙闲续期（挂载层防误锁）---- */
/* note_activity：把空闲计时推到当前。前台程序持着打开的文件句柄时（播放器读缓存命中后
 * 不再发读 I/O，touch_activity 无从刷新），或外部进程正在写库时，挂载层调它续期，
 * 避免「电影看一半被自动锁」「入盘入一半盘被锁」。锁态下为空操作。 */
VDISK_API void        vdisk_note_activity(VDiskHandle*);
/* 索引版本戳（.feindex.d/.stamp 单调计数）。外部进程（GUI/CLI 入盘、recrypt 等）每写一次
 * 索引戳就变；挂载层据此判定「库正被外部使用」，与前台句柄同等续期。句柄无效返回 0。 */
VDISK_API uint64_t    vdisk_index_stamp(VDiskHandle*);
/* 真实锁态查询（1=已解锁，0=已锁）。idle_remaining 在「超时关闭(0)」时也返回 UINT32_MAX，
 * 与「已锁定」无法区分；挂载层纠正 g_ipc_unlocked 标志必须用本函数，否则 suspend 关掉
 * 库层计时后会被误判成已锁（曾真实发生：设了暂停 1 秒内盘就被标锁）。 */
VDISK_API int         vdisk_is_unlocked(VDiskHandle*);
/* 索引「损坏放行」态查询（1=损坏已放行，0=正常/已锁）。unlock 时索引读失败
 * （写一半被杀、掉电、分片误删）不再报错拒绝，而是置空索引放行，用户进库后
 * 调 vdisk_reindex 从盘面 .ptd 重建条目。AUTH（错密码）仍照常拒绝。 */
VDISK_API int         vdisk_index_damaged(VDiskHandle*);

#ifdef __cplusplus
}
#endif

#endif /* VDISK_H */
