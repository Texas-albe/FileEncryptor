/*
 * libvdisk — 加密盘动态链接库对外契约（C ABI，二进制稳定）
 * 对应设计文档 The Next Release/加密盘方案.md §5.2。
 * 库由 FE-Mounter 进程加载，句柄在 holder 进程内持有；GUI/CLI 经受限 IPC 驱动。
 */
#ifndef VDISK_H
#define VDISK_H

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
    VDISK_E_INTERNAL = -99
} VDiskStatus;

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
VDISK_API VDiskStatus vdisk_delete_file(VDiskHandle*, const char* vpath);
VDISK_API VDiskStatus vdisk_truncate_file(VDiskHandle*, const char* vpath, uint64_t new_size);

/* 错误串（GUI 报错文案） */
VDISK_API const char* vdisk_strerror(VDiskStatus);

/* ---- M4 恢复密钥（§4.4）---- */
/* 生成 48 位十进制恢复密钥（调用方须提供 ≥49 字节缓冲）。 */
VDISK_API VDiskStatus vdisk_recovery_gen(char* out_code, uint64_t code_cap);
/* 建立/重建保险文件 .fevault（存主密码副本；已有则覆盖）。 */
VDISK_API VDiskStatus vdisk_recovery_create(VDiskHandle*, const char* code);
/* 用恢复密钥解出主密码副本（写入 out，*len 为容量/实际长度）；不入常驻状态。 */
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

#ifdef __cplusplus
}
#endif

#endif /* VDISK_H */
