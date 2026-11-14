// vdisk C ABI
// 对应 CLI/include/vdisk.h；库
using System.Runtime.InteropServices;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

// 布局必须
// 顺序写错
[StructLayout(LayoutKind.Sequential)]
internal struct VDiskEntryNative
{
    public IntPtr Name;      // 目录项名
    public byte IsDir;
    public ulong Size;
    public ulong Mtime;
}

public enum VDiskStatus
{
    Ok = 0,
    BadArg = -1,
    Auth = -2,          // 密码或恢复密钥
    Locked = -3,
    NoMem = -4,
    Io = -5,
    Wipe = -6,
    NotImpl = -7,
    NotFound = -8,
    ReadOnly = -9,
    Exist = -10,
    Cancelled = -11,   // 调用方取消
    Internal = -99,
}

internal static unsafe partial class VdiskNative
{
    // .NET for Android
    private const string Lib = "vdisk";

    internal const uint ExpectedAbiVersion = 0x00010000u;

    // 与 vdisk.h
    internal const int CompressAuto = 100;
    internal const int CompressDefault = 127;

    internal static int SizeOfEntry => sizeof(VDiskEntryNative);

    [LibraryImport(Lib)]
    internal static partial uint vdisk_abi_version();

    // 生命周期
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_init(string library_dir);

    // 建库并指定
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_init_ex(string library_dir, int mode, int compress_policy);

    [LibraryImport(Lib)]
    internal static partial int vdisk_set_default_mode(IntPtr h, int mode, int compress_policy);

    // 单文件实际算法
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_get_file_info(IntPtr h, string vpath,
        out int out_mode, out int out_compression, out int out_comp_level);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr vdisk_open(string library_dir);

    [LibraryImport(Lib)]
    internal static partial void vdisk_close(IntPtr h);

    // 解锁 / 锁定
    [LibraryImport(Lib)]
    internal static partial int vdisk_unlock(IntPtr h, byte* passphrase, int use_recovery);

    // 只读口令校验
    [LibraryImport(Lib)]
    internal static partial int vdisk_verify_password(IntPtr h, byte* passphrase, int use_recovery);

    [LibraryImport(Lib)]
    internal static partial int vdisk_lock(IntPtr h);

    [LibraryImport(Lib)]
    internal static partial void vdisk_purge_on_suspend(IntPtr h);

    // Android 无挂载盘
    [LibraryImport(Lib)]
    internal static partial int vdisk_set_writable(IntPtr h, int rw);

    [LibraryImport(Lib)]
    internal static partial int vdisk_is_unlocked(IntPtr h);

    // 索引
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_reindex(IntPtr h, string root);

    // 带进度/取消
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_reindex_ex(IntPtr h, string root,
        IntPtr progress, IntPtr user, IntPtr cancel, IntPtr cancelUser);

    // 索引是否处于「损
    [LibraryImport(Lib)]
    internal static partial int vdisk_index_damaged(IntPtr h);

    // 目录枚举
    // 第一段
    // 第二段 调用方分
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_readdir(IntPtr h, string vpath,
        IntPtr out_entries, ulong* out_count);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_getattr(IntPtr h, string vpath,
        ulong* out_size, ulong* out_mtime, byte* out_is_dir);

    // 读写
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_read_file(IntPtr h, string vpath,
        ulong offset, byte* out_buf, ulong* len);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_write_file(IntPtr h, string vpath,
        ulong offset, byte* in_buf, ulong len);

    // 创建 / 删除 / 截断 / 重
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_create_file(IntPtr h, string vpath);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_create_file_ex(IntPtr h, string vpath, int is_dir);

    // 库内复制
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_copy_file(IntPtr h, string from, string to,
        IntPtr progress, IntPtr user, IntPtr cancel, IntPtr cancelUser);

    // 复制增强版
    // 新符号，不改既有
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_copy_file_ex(IntPtr h, string from, string to,
        int rewriteName, IntPtr progress, IntPtr user, IntPtr cancel, IntPtr cancelUser);

    // 建目录并指定 mtime
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_mkdir_ex(IntPtr h, string vpath, long mtime);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_delete_file(IntPtr h, string vpath);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_truncate_file(IntPtr h, string vpath, ulong new_size);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_rename(IntPtr h, string old_vpath, string new_vpath);

    // 批量移动
    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_rename_many(IntPtr h,
        IntPtr* oldPaths, IntPtr* newPaths, uint count, int* status);

    // 错误信息
    [LibraryImport(Lib)]
    internal static partial IntPtr vdisk_strerror(int status);

    // M4 恢复密钥
    [LibraryImport(Lib)]
    internal static partial int vdisk_recovery_gen(byte* out_code, ulong code_cap);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_recovery_create(IntPtr h, string code);

    [LibraryImport(Lib)]
    internal static partial int vdisk_recovery_open(IntPtr h, byte* code,
        byte* out_pass, ulong* len);

    [LibraryImport(Lib)]
    internal static partial int vdisk_recovery_remove(IntPtr h);

    // M5 空闲超
    [LibraryImport(Lib)]
    internal static partial int vdisk_set_idle_timeout(IntPtr h, uint seconds);

    [LibraryImport(Lib)]
    internal static partial uint vdisk_idle_remaining(IntPtr h);

    [LibraryImport(Lib)]
    internal static partial int vdisk_set_read_cache(IntPtr h, ulong cap_bytes, uint ahead_segments);

    [LibraryImport(Lib)]
    internal static partial int vdisk_stat_space(IntPtr h, ulong* out_used, ulong* out_total);

    // 容量统计增强
    [LibraryImport(Lib)]
    internal static partial int vdisk_stat_space_ex(IntPtr h, ulong* out_used,
        ulong* out_trash, ulong* out_total);

    // 保留命名空间查
    [LibraryImport(Lib)]
    internal static partial IntPtr vdisk_reserved_name();

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_is_reserved_path(string vpath);

    // M5+ 忙闲续期
    [LibraryImport(Lib)]
    internal static partial void vdisk_note_activity(IntPtr h);

    [LibraryImport(Lib)]
    internal static partial ulong vdisk_index_stamp(IntPtr h);

    // 流式导入/导出
    // progress 传静态 thunk
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_import_fd(IntPtr h, string vpath,
        int in_fd, IntPtr progress, IntPtr user);

    // 单次导入覆盖算
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_import_fd_ex(IntPtr h, string vpath, int in_fd,
        IntPtr progress, IntPtr user, int mode, int compress_policy);

    // 批量并行导入
    // vpath 为 UTF-8
    [StructLayout(LayoutKind.Sequential)]
    internal struct VDiskImportItemNative
    {
        public IntPtr VPath;
        public int InFd;
    }

    // 单项完成回调
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void ItemDoneThunk(nuint index, int st, IntPtr user);

    // 取消探针
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int CancelThunk(IntPtr user);

    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_import_many(IntPtr h, VDiskImportItemNative* items,
        nuint count, IntPtr progress, IntPtr user, int* results, IntPtr done, IntPtr doneUser);

    // 带取消
    // flags
    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_import_many_ex(IntPtr h, VDiskImportItemNative* items,
        nuint count, IntPtr progress, IntPtr user, int* results, IntPtr done, IntPtr doneUser,
        IntPtr cancel, IntPtr cancelUser, uint flags);

    // 本批显式指定算
    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_import_many_ex_mode(IntPtr h, VDiskImportItemNative* items,
        nuint count, IntPtr progress, IntPtr user, int* results, IntPtr done, IntPtr doneUser,
        IntPtr cancel, IntPtr cancelUser, uint flags, int mode, int compressPolicy);

    // 逐项进度回调
    // 实现只允许
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void ItemProgressThunk(nuint index, ulong done, ulong total, IntPtr user);

    // 同 ex_mode
    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_import_many_ex2(IntPtr h, VDiskImportItemNative* items,
        nuint count, IntPtr progress, IntPtr user, IntPtr itemProgress, IntPtr itemUser,
        int* results, IntPtr done, IntPtr doneUser,
        IntPtr cancel, IntPtr cancelUser, uint flags, int mode, int compressPolicy);

    // 跨批导入
    [LibraryImport(Lib)]
    internal static partial int vdisk_import_begin(IntPtr h);

    [LibraryImport(Lib)]
    internal static partial int vdisk_import_end(IntPtr h);

    // 带进度/取消
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_delete_file_ex(IntPtr h, string vpath,
        IntPtr progress, IntPtr user, IntPtr cancel, IntPtr cancelUser);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int vdisk_export_fd(IntPtr h, string vpath,
        int out_fd, IntPtr progress, IntPtr user);

    // 全库完整性自检
    [StructLayout(LayoutKind.Sequential)]
    internal struct VDiskCheckResultNative
    {
        public ulong FilesTotal;
        public ulong FilesChecked;
        public ulong FilesFailed;
        public ulong FilesMissing;
        public ulong Orphans;
        public ulong BytesChecked;
    }

    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_check_library(IntPtr h, VDiskCheckResultNative* outResult,
        IntPtr progress, IntPtr user, IntPtr cancel, IntPtr cancelUser);

    // 逐项文件名字回
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void NameThunk(IntPtr vpath, IntPtr user);

    // 自检增强版
    [LibraryImport(Lib)]
    internal static unsafe partial int vdisk_check_library_ex(IntPtr h, VDiskCheckResultNative* outResult,
        IntPtr progress, IntPtr user, IntPtr onFile, IntPtr nameUser, IntPtr cancel, IntPtr cancelUser);

    internal static string ErrorText(int status)
        => Marshal.PtrToStringUTF8(vdisk_strerror(status)) ?? L10n.T("未知错误");
}
