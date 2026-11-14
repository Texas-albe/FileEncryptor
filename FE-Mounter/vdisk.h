/*
 * libvdisk — 加密盘动态链接库对外契约（C ABI，二进制稳定）
 * 对应设计文档 The Next Release/加密盘方案.md §5.2。
 * 库由 FE-Mounter 进程加载，句柄在 holder 进程内持有；GUI/CLI 经受限 IPC 驱动。
 */
#ifndef VDISK_H
#define VDISK_H
// vdisk.h 副本提示
// 本文件是 CLI/include/vdisk.h
// 。改 ABI 时必须两边同
// 校验
// 副本提示结束

#include <stdint.h>

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
    VDISK_E_INTERNAL = -99
} VDiskStatus;

/*
 * ABI 版本（构建期常量）。加载方（FE-Mounter / SAF vdisk host）绑定符号后必须调 vdisk_abi_version() 校验，
 * 与构建期 VDISK_ABI_VERSION 不符即拒绝加载——旧版/第三方 DLL 可能符号齐全但语义或结构体布局已漂移。
 * 破坏性变更（函数语义 / VDiskEntry 布局）必须递增此版本号；仅新增符号可不增。
 */
#define VDISK_ABI_VERSION 0x00010000u
VDISK_API uint32_t vdisk_abi_version(void);

/* 生命周期 */
VDISK_API VDiskHandle* vdisk_open(const char* library_dir);   /* 打开库（不解锁） */
VDISK_API void         vdisk_close(VDiskHandle*);

/* 解锁 / 锁定（§4.1 密钥生命周期） */
VDISK_API VDiskStatus vdisk_unlock(VDiskHandle*, const char* passphrase, int use_recovery);
VDISK_API VDiskStatus vdisk_lock(VDiskHandle*);               /* 全清 KEK/索引密钥 */
VDISK_API void        vdisk_purge_on_suspend(VDiskHandle*);    /* 睡眠/待机回调，同源清密钥 */

/* 索引（§3 / §5） */
VDISK_API VDiskStatus vdisk_reindex(VDiskHandle*, const char* root);
VDISK_API VDiskStatus vdisk_mount_readonly(VDiskHandle*, const char* mount_point);
VDISK_API VDiskStatus vdisk_unmount(VDiskHandle*);

/*
 * 目录枚举（两段式调用，出参数组由调用方分配）：
 *   1) out_entries=NULL 调用 → *out_count 置为子项数；
 *   2) 调用方按 *out_count 分配 VDiskEntry 数组后再调 → 填充。
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
/* 创建/删除/截断（M6 写支持；写后原子更新 .feindex） */
VDISK_API VDiskStatus vdisk_create_file(VDiskHandle*, const char* vpath);
/* 目录感知创建：is_dir≠0 时只登记目录条目（不建 .ptd），供挂载盘 mkdir / 拷文件夹保留目录树 */
VDISK_API VDiskStatus vdisk_create_file_ex(VDiskHandle*, const char* vpath, int is_dir);
VDISK_API VDiskStatus vdisk_delete_file(VDiskHandle*, const char* vpath);
VDISK_API VDiskStatus vdisk_truncate_file(VDiskHandle*, const char* vpath, uint64_t new_size);
/* 重命名 / 移动（挂载盘 Explorer 改名）。文件改 rel_path 并搬 .ptd；目录按前缀批量改并重搬所有子 .ptd */
VDISK_API VDiskStatus vdisk_rename(VDiskHandle*, const char* old_vpath, const char* new_vpath);

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
/* 预读缓存：开启后按 64KB 段缓存并预读后续段；cap_bytes=0 关闭。 */
VDISK_API VDiskStatus vdisk_set_read_cache(VDiskHandle*, uint64_t cap_bytes, uint32_t ahead_segments);

/* 容量统计：已用 = 索引内所有文件明文大小之和；total 由 max_bytes 限制（0 = 用默认动态上限）。
 * 供挂载层按实际占用回填卷容量，避免固定 1TiB 造成磁盘管理误导。 */
VDISK_API VDiskStatus vdisk_stat_space(VDiskHandle*, uint64_t* out_used, uint64_t* out_total);

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

#ifdef __cplusplus
}
#endif

#endif /* VDISK_H */
