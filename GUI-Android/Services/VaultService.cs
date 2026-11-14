// vdisk C ABI
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

public sealed class VaultItem : INotifyPropertyChanged
{
    static VaultItem()
    {
        // 系统主题变化失效
        var app = Microsoft.Maui.Controls.Application.Current;
        if (app is not null) app.RequestedThemeChanged += (_, _) => s_themeReady = false;
    }

    public string Name { get; init; } = "";
    public string RelPath { get; init; } = "";   // 虚拟路径
    public bool IsDir { get; init; }
    public ulong Size { get; init; }
    public DateTimeOffset Mtime { get; init; }

    private string? _sizeText;
    public string SizeText => _sizeText ??= IsDir ? "" : FormatSize(Size);

    // 多选态
    private bool _selected;
    public bool IsSelected
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RowBg));
            OnPropertyChanged(nameof(TitleFg));
            OnPropertyChanged(nameof(MetaFg));
            OnPropertyChanged(nameof(SwipeHint));
        }
    }

    // 仍是不透明实色
    public Microsoft.Maui.Graphics.Color RowBg => _selected
        ? Microsoft.Maui.Graphics.Color.FromArgb("#4A72C8")
        : (IsDarkTheme ? Microsoft.Maui.Graphics.Color.FromArgb("#16181C")
                       : Microsoft.Maui.Graphics.Color.FromArgb("#F6F7F9"));

    // 蓝底上默认灰字/
    public Microsoft.Maui.Graphics.Color TitleFg => _selected
        ? Microsoft.Maui.Graphics.Colors.White
        : (IsDarkTheme ? Microsoft.Maui.Graphics.Color.FromArgb("#F1F3F6") : Microsoft.Maui.Graphics.Color.FromArgb("#1B1F24"));
    // 与 Colors.xaml
    public Microsoft.Maui.Graphics.Color MetaFg => _selected
        ? Microsoft.Maui.Graphics.Colors.White
        : (IsDarkTheme ? Microsoft.Maui.Graphics.Color.FromArgb("#A6AEBA") : Microsoft.Maui.Graphics.Color.FromArgb("#5B6472"));
    private static bool s_darkTheme;
    private static bool s_themeReady;
    private static bool IsDarkTheme
    {
        get
        {
            if (!s_themeReady)
            {
                s_darkTheme = Microsoft.Maui.Controls.Application.Current?.RequestedTheme.ToString() == "Dark";
                s_themeReady = true;
            }
            return s_darkTheme;
        }
    }

    // 缓存失效
    internal static void InvalidateTheme() => s_themeReady = false;
    internal static void InvalidateText()
    {
        s_hintOn = L10n.T("滑到底\n取消");
        s_hintOff = L10n.T("滑到底\n选中");
    }

    // 左滑揭示区提示
    private static string s_hintOn = L10n.T("滑到底\n取消");
    private static string s_hintOff = L10n.T("滑到底\n选中");
    public string SwipeHint => _selected ? s_hintOn : s_hintOff;

    // 后缀集合唯一真
    private static readonly HashSet<string> ImgExt = new(StringComparer.OrdinalIgnoreCase)
    { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".avif" };
    private static readonly HashSet<string> VidExt = new(StringComparer.OrdinalIgnoreCase)
    { ".mp4", ".m4v", ".mkv", ".mov", ".avi", ".3gp", ".webm", ".ts", ".flv", ".wmv" };
    private static readonly HashSet<string> AudExt = new(StringComparer.OrdinalIgnoreCase)
    { ".mp3", ".flac", ".wav", ".m4a", ".aac", ".ogg", ".opus" };
    // 可内置文本预览
    private static readonly HashSet<string> TxtExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".json", ".xml", ".ini", ".cfg", ".conf", ".md", ".csv",
        ".yaml", ".yml", ".sql", ".js", ".ts", ".jsx", ".tsx", ".cs", ".py",
        ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".java", ".kt", ".sh", ".ps1",
        ".html", ".htm", ".css", ".xaml", ".gradle", ".properties", ".toml", ".bat",
    };

    private static string ExtOf(string name)
    {
        int i = name.LastIndexOf('.');
        return i < 0 ? "" : name[i..];
    }

    public static bool IsImageName(string name) => ImgExt.Contains(ExtOf(name));
    public static bool IsVideoName(string name) => VidExt.Contains(ExtOf(name));
    public static bool IsAudioName(string name) => AudExt.Contains(ExtOf(name));
    public static bool IsTextName(string name) => TxtExt.Contains(ExtOf(name));

    // 缩略图未
    public string Placeholder => IsDir ? L10n.T("目录")
        : IsImageName(Name) ? L10n.T("图片")
        : IsVideoName(Name) ? L10n.T("视频")
        : IsAudioName(Name) ? L10n.T("音频")
        : L10n.T("文件");
    public bool ShowPlaceholder => !HasThumb;

    // 缩略图路径
    private string? _thumb;
    public string? ThumbSource
    {
        get => _thumb;
        set
        {
            if (_thumb == value) return;
            _thumb = value;
            OnPropertyChanged(nameof(ThumbSource));
            OnPropertyChanged(nameof(HasThumb));
            OnPropertyChanged(nameof(ShowPlaceholder));
        }
    }

    public bool HasThumb => _thumb is not null;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

    public static string FormatSize(ulong bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024UL * 1024 * 1024 => $"{bytes / 1048576.0:F1} MB",
        _ => $"{bytes / 1073741824.0:F2} GB",
    };
}

public sealed record VaultFileInfo(int Mode, int Compression, int CompLevel);

// 全库自检结果
public sealed record CheckReport(bool Cancelled, ulong FilesTotal, ulong FilesChecked,
    ulong FilesFailed, ulong FilesMissing, ulong Orphans, ulong BytesChecked);

public sealed class VaultException : Exception
{
    public VDiskStatus Status { get; }
    public VaultException(VDiskStatus status, string message) : base(message)
        => Status = status;
}

// native 进度回调签名
internal delegate void VdProgressNative(ulong done, ulong total, IntPtr user);

public sealed unsafe class VaultService : IDisposable
{
    // 读缓存
    private const ulong ReadCacheBytes = 32UL * 1024 * 1024;
    private const uint ReadCacheAhead = 8;
    private const int ChunkSize = 1024 * 1024;   // 分块读

    private IntPtr _h;
    private bool _disposed;

    // 当前活动实例
    public static VaultService? Active { get; private set; }

    // 锁库通知
    public static event Action? SessionLocked;

    // 会话单例
    private static VaultService? s_shared;
    public static VaultService Shared => s_shared ??= new VaultService();

    public VaultService() => Active = this;

    // 进行
    // 若切后台立刻锁
    // 且锁
    // 故长任务期间只
    public static int LongOps;

    private static volatile bool _lockPending;
    private static bool _leaveVaultPending;

    // 锁定原因
    private static string s_lockReason = "";
    // 托管侧解锁提示
    private static volatile bool s_unlockedHint;
    // 离页后台锁
    private static int s_locking;
    private static Task s_lockTask = Task.CompletedTask;
    public static void NoteLockReason(string reason) => s_lockReason = reason;
    public static string ConsumeLockReason()
    {
        string r = s_lockReason;
        s_lockReason = "";
        return r;
    }

    // 待锁只读态
    public static bool IsLockPending => _lockPending;

    // 锁库代次
    // 解锁是异步
    // 回调返回后若代
    // 离页后仍
    private static int s_lockEpoch;
    public static int LockEpoch => Volatile.Read(ref s_lockEpoch);

    public static bool IsLockEpochCurrent(int epoch)
        => Volatile.Read(ref s_lockEpoch) == epoch;

    // 页面离开时调用
    public static void InvalidatePendingUnlock() => Interlocked.Increment(ref s_lockEpoch);

    // 切后台自动锁定
    public static void LockActive()
    {
        InvalidatePendingUnlock();
        NoteLockReason(L10n.T("切后台，已自动锁定"));
        if (LongOps > 0) { _lockPending = true; return; }
        DoLockActive();
    }

    private static void DoLockActive()
    {
        // 锁两个引用
        var active = Active;
        var shared = s_shared;
        try { if (active is { IsUnlocked: true }) active.Lock(); }
        catch { /* 锁失败不影响界面切换 */ }
        if (shared is null || ReferenceEquals(shared, active)) return;
        try { if (shared.IsUnlocked) shared.Lock(); }
        catch { /* 锁失败不影响界面切换 */ }
    }

    // 长任务开始/结束
    public static void BeginLongOp() => Interlocked.Increment(ref LongOps);

    public static void EndLongOp()
    {
        if (Interlocked.Decrement(ref LongOps) != 0) return;
        if (_leaveVaultPending)
        {
            _leaveVaultPending = false;
            DoLeaveVaultLock();
        }
        if (!_lockPending) return;
        _lockPending = false;
        // 切过后台即锁
        NoteLockReason(L10n.T("长时间任务结束，已按后台规则锁定"));
        DoLockActive();
    }

    public bool IsOpen => _h != IntPtr.Zero;
    public bool IsUnlocked => _h != IntPtr.Zero && VdiskNative.vdisk_is_unlocked(_h) == 1;
    // unlock 时索引读失败
    public bool IsIndexDamaged => _h != IntPtr.Zero && VdiskNative.vdisk_index_damaged(_h) == 1;
    public string RootDir { get; private set; } = "";

    // 库加载即校验 ABI
    public static void VerifyAbi()
    {
        uint v = VdiskNative.vdisk_abi_version();
        if (v != VdiskNative.ExpectedAbiVersion)
            throw new VaultException(VDiskStatus.Internal,
                L10n.F("native ABI 版本不匹配：库 0x{0:X8}，期望 0x{1:X8}", v, VdiskNative.ExpectedAbiVersion));
    }

    // 只读口令校验
    // zPass 为 NUL 结尾 UTF-8，调用方负
    public bool VerifyPassword(byte[] zPass, bool useRecovery = false)
    {
        if (!IsOpen) throw new VaultException(VDiskStatus.Locked, L10n.T("加密库未打开"));
        fixed (byte* p = zPass)
        {
            int rc = VdiskNative.vdisk_verify_password(_h, p, useRecovery ? 1 : 0);
            if (rc == (int)VDiskStatus.Ok) return true;
            if (rc == (int)VDiskStatus.Auth) return false;
            throw new VaultException((VDiskStatus)rc, StatusText((VDiskStatus)rc));
        }
    }

    // 建库并指定
    public static void InitEx(string libraryDir, int mode, int compressPolicy)
    {
        int rc = VdiskNative.vdisk_init_ex(libraryDir, mode, compressPolicy);
        if (rc == 0) return;
        var st = (VDiskStatus)rc;
        string msg = st == VDiskStatus.Io
            ? L10n.F("无法创建加密库：{0}\n请检查「所有文件访问」权限与剩余空间。", libraryDir)
            : StatusText(st);
        throw new VaultException(st, msg);
    }

    // 运行中切换库默
    public void SetDefaultMode(int mode, int compressPolicy)
    {
        EnsureOpen();
        Check(VdiskNative.vdisk_set_default_mode(_h, mode, compressPolicy));
    }

    // 属性面板
    public VaultFileInfo? GetFileInfo(string vpath)
    {
        EnsureUnlocked();
        int rc = VdiskNative.vdisk_get_file_info(_h, vpath,
            out int mode, out int comp, out int lvl);
        return rc == 0 ? new VaultFileInfo(mode, comp, lvl) : null;
    }

    // 该文件是否压缩
    public bool IsCompressed(string vpath)
    {
        try { return GetFileInfo(vpath)?.Compression == 1; }
        catch { return false; }
    }

    // 库是否已建
    public static bool Exists(string libraryDir)
        => File.Exists(Path.Combine(libraryDir, "vault.meta"));

    public void Open(string libraryDir)
    {
        // 旧句柄关闭时索
        // ；事后可用「重建索
        try { Close(); }
        catch (VaultException) { }
        if (!Directory.Exists(libraryDir)) Directory.CreateDirectory(libraryDir);
        IntPtr h = VdiskNative.vdisk_open(libraryDir);
        if (h == IntPtr.Zero)
            throw new VaultException(VDiskStatus.Io, L10n.T("打开加密库失败"));
        _h = h;
        RootDir = libraryDir;
    }

    // 关闭
    // 该返回值若
    public void Close()
    {
        WaitForPendingLock();
        s_unlockedHint = false;
        ResetStreamMode();
        if (_h == IntPtr.Zero) return;
        int rc = VdiskNative.vdisk_lock(_h);
        VdiskNative.vdisk_close(_h);
        _h = IntPtr.Zero;
        if (rc != 0)
            throw new VaultException((VDiskStatus)rc,
                L10n.T("关闭时索引保存失败，最后一批更改可能未保存。"));
    }

    // 口令
    public void Unlock(byte[] passphrase, bool useRecovery = false)
    {
        WaitForPendingLock();
        EnsureOpen();
        fixed (byte* p = passphrase)
            Check(VdiskNative.vdisk_unlock(_h, p, useRecovery ? 1 : 0));
        // 移动端无挂载
        Check(VdiskNative.vdisk_set_writable(_h, 1));
        ResetStreamMode();   // 锁库
        VdiskNative.vdisk_set_read_cache(_h, ReadCacheBytes, ReadCacheAhead);
        ApplyIdleTimeout();
        s_unlockedHint = true;
    }

    // 流式播放
    private int _streamRef;

    public void EnterStreamMode()
    {
        if (_h == IntPtr.Zero) return;
        if (Interlocked.Increment(ref _streamRef) > 1) return;
        VdiskNative.vdisk_set_read_cache(_h, 0, 0);
    }

    public void LeaveStreamMode()
    {
        int n = Interlocked.Decrement(ref _streamRef);
        if (n < 0) { Interlocked.Exchange(ref _streamRef, 0); return; }
        if (n > 0) return;
        if (_h != IntPtr.Zero)
            VdiskNative.vdisk_set_read_cache(_h, ReadCacheBytes, ReadCacheAhead);
    }

    // 锁库、关闭、重解锁
    private void ResetStreamMode() => Interlocked.Exchange(ref _streamRef, 0);

    // 设置页改档位
    public void ApplyIdleTimeout()
    {
        if (_h != IntPtr.Zero)
            VdiskNative.vdisk_set_idle_timeout(_h, VaultIdle.Seconds);
    }

    // 切到别
    public static void LockOnLeaveVault()
    {
        InvalidatePendingUnlock();
        if (LongOps > 0) { _leaveVaultPending = true; return; }
        DoLeaveVaultLock();
    }

    private static void DoLeaveVaultLock()
    {
        NoteLockReason(L10n.T("离开加密库，已自动锁定"));
        var v = Shared;
        if (!s_unlockedHint || !v.IsUnlocked) return;
        // 逻辑锁立即生效
        s_unlockedHint = false;
        Volatile.Write(ref s_locking, 1);
        // native 清场放后台
        s_lockTask = Task.Run(() =>
        {
            try { v.Lock(); }
            catch { }
            finally { Volatile.Write(ref s_locking, 0); }
        });
    }

    // 等后台锁收尾
    private static void WaitForPendingLock()
    {
        Task t = s_lockTask;
        if (!t.IsCompleted) t.GetAwaiter().GetResult();
    }

    public void Lock()
    {
        InvalidatePendingUnlock();
        s_unlockedHint = false;
        ResetStreamMode();
        if (_h == IntPtr.Zero) return;
        if (s_lockReason.Length == 0) s_lockReason = L10n.T("已手动锁定加密库");
        Check(VdiskNative.vdisk_lock(_h));
        // 锁库即清解密派
        // cim_* 不在范围
        _ = Task.Run(CacheJanitor.PurgeOnLock);
        try { SessionLocked?.Invoke(); } catch { }
    }

    public void NoteActivity()
    {
        if (_h != IntPtr.Zero) VdiskNative.vdisk_note_activity(_h);
    }

    // 目录枚举
    public List<VaultItem> ListDir(string vpath)
    {
        EnsureUnlocked();
        ulong count = 0;
        Check(VdiskNative.vdisk_readdir(_h, vpath, IntPtr.Zero, &count));

        var list = new List<VaultItem>((int)Math.Min(count, 10000));
        if (count == 0) return list;

        int esz = VdiskNative.SizeOfEntry;
        IntPtr buf = Marshal.AllocHGlobal((nint)(count * (ulong)esz));
        // native 形参是 VDiskEntry**：必须传「存
        // 把数组首
        // 条目
        // name 指针 → PtrToStringUTF8 段错误
        IntPtr slot = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.WriteIntPtr(slot, buf);
            ulong cap = count;
            Check(VdiskNative.vdisk_readdir(_h, vpath, slot, &cap));
            // 第二段 native
            // 必须
            ulong valid = Math.Min(cap, count);
            for (ulong i = 0; i < valid; i++)
            {
                var e = Marshal.PtrToStructure<VDiskEntryNative>(
                    IntPtr.Add(buf, (int)(i * (ulong)esz)));
                string name = Marshal.PtrToStringUTF8(e.Name) ?? "";
                if (name.Length == 0) continue;
                string rel = vpath.Length == 0 ? name : $"{vpath}/{name}";
                list.Add(new VaultItem
                {
                    Name = name,
                    RelPath = rel,
                    IsDir = e.IsDir != 0,
                    Size = e.Size,
                    Mtime = DateTimeOffset.FromUnixTimeSeconds((long)e.Mtime),
                });
            }
        }
        finally { Marshal.FreeHGlobal(slot); Marshal.FreeHGlobal(buf); }

        // 目录
        list.Sort((a, b) => a.IsDir != b.IsDir
            ? (a.IsDir ? -1 : 1)
            : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return list;
    }

    public bool TryGetAttr(string vpath, out ulong size, out bool isDir)
    {
        size = 0; isDir = false;
        if (_h == IntPtr.Zero) return false;
        ulong sz = 0, mt = 0; byte dir = 0;
        int rc = VdiskNative.vdisk_getattr(_h, vpath, &sz, &mt, &dir);
        if (rc != 0) return false;
        size = sz; isDir = dir != 0;
        return true;
    }

    // 建空文件
    public void CreateFile(string vpath)
    {
        EnsureUnlocked();
        Check(VdiskNative.vdisk_create_file(_h, vpath));
    }

    // 建目录
    public void CreateDir(string vpath, long mtime = 0)
    {
        EnsureUnlocked();
        Check(VdiskNative.vdisk_mkdir_ex(_h, vpath, mtime));
    }

    public void Delete(string vpath)
    {
        EnsureUnlocked();
        Check(VdiskNative.vdisk_delete_file(_h, vpath));
    }

    public void Rename(string from, string to)
    {
        EnsureUnlocked();
        Check(VdiskNative.vdisk_rename(_h, from, to));
    }

    // 批量移动
    public int[] RenameMany(IReadOnlyList<(string From, string To)> items)
    {
        EnsureUnlocked();
        int n = items.Count;
        int[] status = new int[n];
        if (n == 0) return status;
        // 全部路径拼进单
        byte[] buf;
        int[] off = new int[2 * n];
        {
            int total = 0;
            var segs = new (byte[] B, int Len)[2 * n];
            for (int i = 0; i < n; i++)
            {
                var ob = System.Text.Encoding.UTF8.GetBytes(items[i].From);
                var nb = System.Text.Encoding.UTF8.GetBytes(items[i].To);
                segs[2 * i] = (ob, ob.Length + 1);
                segs[2 * i + 1] = (nb, nb.Length + 1);
            }
            total = segs.Sum(s => s.Len);
            buf = new byte[total];
            int pos = 0;
            for (int i = 0; i < 2 * n; i++)
            {
                off[i] = pos;
                Array.Copy(segs[i].B, 0, buf, pos, segs[i].B.Length);
                pos += segs[i].Len;
            }
        }
        unsafe
        {
            IntPtr* op = stackalloc IntPtr[n];
            IntPtr* np = stackalloc IntPtr[n];
            fixed (byte* bp = buf)
            fixed (int* sp = status)
            {
                for (int i = 0; i < n; i++)
                {
                    op[i] = (IntPtr)(bp + off[2 * i]);
                    np[i] = (IntPtr)(bp + off[2 * i + 1]);
                }
                Check(VdiskNative.vdisk_rename_many(_h, op, np, (uint)n, sp));
            }
        }
        return status;
    }

    // native 进度回调 thunk：GCHandle 托管
    // 必须静态只读
    // 回调跳进已回收
    static readonly VdProgressNative ProgressThunk = (d, t, user) =>
    {
        var h = GCHandle.FromIntPtr(user);
        ((Action<ulong, ulong>)h.Target!)(d, t);
    };

    // 单项完成回调 thunk
    // 回调发生
    static readonly VdiskNative.ItemDoneThunk DoneThunk = (i, st, user) =>
    {
        try
        {
            var h = GCHandle.FromIntPtr(user);
            ((Action<int, VDiskStatus>)h.Target!)((int)i, (VDiskStatus)st);
        }
        catch { /* 收尾异常不中断整批 */ }
    };

    // 逐项进度回调 thunk
    // 实现只应
    static readonly VdiskNative.ItemProgressThunk ItemProgressThunk = (i, d, t, user) =>
    {
        try
        {
            var h = GCHandle.FromIntPtr(user);
            ((Action<int, ulong, ulong>)h.Target!)((int)i, d, t);
        }
        catch { /* 进度异常不影响整批 */ }
    };

    // 取消探针 thunk
    static readonly VdiskNative.CancelThunk CancelThunk = user =>
    {
        try
        {
            var h = GCHandle.FromIntPtr(user);
            return ((Func<bool>)h.Target!)() ? 1 : 0;
        }
        catch { return 0; }   // 探询失败
    };

    // 库内复制
    // rewriteName=true
    public void CopyFile(string from, string to,
        Action<ulong, ulong>? progress = null, Func<bool>? cancel = null, bool rewriteName = true)
    {
        EnsureUnlocked();
        var ph = GCHandle.Alloc(progress ?? ((d, t) => { }));
        var ch = GCHandle.Alloc(cancel ?? (() => false));
        try
        {
            Check(VdiskNative.vdisk_copy_file_ex(_h, from, to, rewriteName ? 1 : 0,
                Marshal.GetFunctionPointerForDelegate(ProgressThunk), GCHandle.ToIntPtr(ph),
                Marshal.GetFunctionPointerForDelegate(CancelThunk), GCHandle.ToIntPtr(ch)));
        }
        finally { ph.Free(); ch.Free(); }
    }

    // 当前文件名字回
    static readonly VdiskNative.NameThunk NameThunk = (vpath, user) =>
    {
        try
        {
            var h = GCHandle.FromIntPtr(user);
            ((Action<string>)h.Target!)(Marshal.PtrToStringUTF8(vpath) ?? "");
        }
        catch { /* 展示失败不影响校验 */ }
    };

    // 全库完整性自检
    public CheckReport CheckLibrary(Action<ulong, ulong>? progress = null, Func<bool>? cancel = null,
        Action<string>? onFile = null)
    {
        EnsureUnlocked();
        var ph = GCHandle.Alloc(progress ?? ((d, t) => { }));
        var ch = GCHandle.Alloc(cancel ?? (() => false));
        GCHandle nh = default;
        if (onFile is not null) nh = GCHandle.Alloc(onFile);
        try
        {
            var r = new VdiskNative.VDiskCheckResultNative();
            IntPtr nfn = onFile is not null
                ? Marshal.GetFunctionPointerForDelegate(NameThunk) : IntPtr.Zero;
            IntPtr nuser = nh.IsAllocated ? GCHandle.ToIntPtr(nh) : IntPtr.Zero;
            int rc = VdiskNative.vdisk_check_library_ex(_h, &r,
                Marshal.GetFunctionPointerForDelegate(ProgressThunk), GCHandle.ToIntPtr(ph),
                nfn, nuser,
                Marshal.GetFunctionPointerForDelegate(CancelThunk), GCHandle.ToIntPtr(ch));
            var rep = new CheckReport(rc == (int)VDiskStatus.Cancelled,
                r.FilesTotal, r.FilesChecked, r.FilesFailed, r.FilesMissing, r.Orphans, r.BytesChecked);
            if (rc != (int)VDiskStatus.Ok && rc != (int)VDiskStatus.Cancelled)
                throw new VaultException((VDiskStatus)rc, StatusText((VDiskStatus)rc));
            return rep;
        }
        finally
        {
            if (nh.IsAllocated) nh.Free();
            ph.Free(); ch.Free();
        }
    }

    // 流式导入
    public void ImportFd(string vpath, int inFd, Action<ulong, ulong>? progress = null)
    {
        EnsureUnlocked();
        var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
        try
        {
            IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
            Check(VdiskNative.vdisk_import_fd(_h, vpath, inFd, fn, GCHandle.ToIntPtr(handle)));
        }
        finally { handle.Free(); }
    }

    // 单次导入覆盖算
    public void ImportFdEx(string vpath, int inFd, int mode, int compressPolicy,
        Action<ulong, ulong>? progress = null)
    {
        EnsureUnlocked();
        var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
        try
        {
            IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
            Check(VdiskNative.vdisk_import_fd_ex(_h, vpath, inFd, fn,
                GCHandle.ToIntPtr(handle), mode, compressPolicy));
        }
        finally { handle.Free(); }
    }

    // 批量并行导入
    // 进度
    // 带取消
    // 取消后剩余项
    // mode=0 沿用库默认
    public List<VDiskStatus> ImportManyEx(List<(string Rel, int Fd)> items,
        Action<ulong, ulong>? progress = null, Action<int, VDiskStatus>? onDone = null,
        Func<bool>? cancel = null, bool finalize = true,
        int mode = 0, int compressPolicy = VdiskNative.CompressDefault,
        Action<int, ulong, ulong>? onItemProgress = null)
    {
        EnsureUnlocked();
        int n = items.Count;
        var results = new List<VDiskStatus>(n);
        if (n == 0) return results;

        var arr = new VdiskNative.VDiskImportItemNative[n];
        var vpaths = new IntPtr[n];
        var resArr = new int[n];
        try
        {
            for (int i = 0; i < n; i++)
            {
                vpaths[i] = Marshal.StringToCoTaskMemUTF8(items[i].Rel);
                arr[i].VPath = vpaths[i];
                arr[i].InFd = items[i].Fd;
                resArr[i] = (int)VDiskStatus.Ok;
            }
            var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
            GCHandle doneHandle = default;
            if (onDone is not null) doneHandle = GCHandle.Alloc(onDone);
            GCHandle cancelHandle = default;
            if (cancel is not null) cancelHandle = GCHandle.Alloc(cancel);
            GCHandle itemHandle = default;
            if (onItemProgress is not null) itemHandle = GCHandle.Alloc(onItemProgress);
            try
            {
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
                IntPtr dfn = onDone is not null
                    ? Marshal.GetFunctionPointerForDelegate(DoneThunk) : IntPtr.Zero;
                IntPtr duser = doneHandle.IsAllocated ? GCHandle.ToIntPtr(doneHandle) : IntPtr.Zero;
                IntPtr cfn = cancel is not null
                    ? Marshal.GetFunctionPointerForDelegate(CancelThunk) : IntPtr.Zero;
                IntPtr cuser = cancelHandle.IsAllocated ? GCHandle.ToIntPtr(cancelHandle) : IntPtr.Zero;
                IntPtr ifn = onItemProgress is not null
                    ? Marshal.GetFunctionPointerForDelegate(ItemProgressThunk) : IntPtr.Zero;
                IntPtr iuser = itemHandle.IsAllocated ? GCHandle.ToIntPtr(itemHandle) : IntPtr.Zero;
                // finalize=false
                uint flags = finalize ? 0u : 1u;   // VDISK_IMPORT_NO_FINALIZE
                unsafe
                {
                    fixed (VdiskNative.VDiskImportItemNative* pa = arr)
                    fixed (int* pr = resArr)
                    {
                        if (onItemProgress is not null || compressPolicy != VdiskNative.CompressDefault)
                            Check(VdiskNative.vdisk_import_many_ex2(_h, pa, (nuint)n, fn,
                                GCHandle.ToIntPtr(handle), ifn, iuser, pr, dfn, duser, cfn, cuser, flags,
                                mode, compressPolicy));
                        else if (mode != 0)
                            Check(VdiskNative.vdisk_import_many_ex_mode(_h, pa, (nuint)n, fn,
                                GCHandle.ToIntPtr(handle), pr, dfn, duser, cfn, cuser, flags,
                                mode, compressPolicy));
                        else
                            Check(VdiskNative.vdisk_import_many_ex(_h, pa, (nuint)n, fn,
                                GCHandle.ToIntPtr(handle), pr, dfn, duser, cfn, cuser, flags));
                    }
                }
            }
            finally
            {
                if (itemHandle.IsAllocated) itemHandle.Free();
                if (cancelHandle.IsAllocated) cancelHandle.Free();
                if (doneHandle.IsAllocated) doneHandle.Free();
                handle.Free();
            }
        }
        finally
        {
            for (int i = 0; i < n; i++)
                if (vpaths[i] != IntPtr.Zero) Marshal.ZeroFreeCoTaskMemUTF8(vpaths[i]);
        }
        foreach (int r in resArr) results.Add((VDiskStatus)r);
        return results;
    }

    // 跨批导入
    // 省掉每批一次 Argon2id
    public void ImportBegin()
    {
        EnsureUnlocked();
        Check(VdiskNative.vdisk_import_begin(_h));
    }
    // 结束跨批导入
    public void ImportEnd()
    {
        if (_h == IntPtr.Zero) return;
        Check(VdiskNative.vdisk_import_end(_h));
    }

    // 带进度/取消
    // 返回 false =
    public bool DeleteEx(string vpath,
        Action<ulong, ulong>? progress = null, Func<bool>? cancel = null)
    {
        EnsureUnlocked();
        var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
        GCHandle cancelHandle = default;
        if (cancel is not null) cancelHandle = GCHandle.Alloc(cancel);
        try
        {
            IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
            IntPtr cfn = cancel is not null
                ? Marshal.GetFunctionPointerForDelegate(CancelThunk) : IntPtr.Zero;
            IntPtr cuser = cancelHandle.IsAllocated ? GCHandle.ToIntPtr(cancelHandle) : IntPtr.Zero;
            int rc = VdiskNative.vdisk_delete_file_ex(_h, vpath, fn,
                GCHandle.ToIntPtr(handle), cfn, cuser);
            if (rc == (int)VDiskStatus.Cancelled) return false;
            Check(rc);
            return true;
        }
        finally
        {
            if (cancelHandle.IsAllocated) cancelHandle.Free();
            handle.Free();
        }
    }

    // 流式导出
    public void ExportFd(string vpath, int outFd, Action<ulong, ulong>? progress = null)
    {
        EnsureUnlocked();
        var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
        try
        {
            IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
            Check(VdiskNative.vdisk_export_fd(_h, vpath, outFd, fn, GCHandle.ToIntPtr(handle)));
        }
        finally { handle.Free(); }
    }

    // 带进度/取消
    public bool ReindexEx(Action<ulong, ulong>? progress = null, Func<bool>? cancel = null)
    {
        EnsureUnlocked();
        var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
        GCHandle cancelHandle = default;
        if (cancel is not null) cancelHandle = GCHandle.Alloc(cancel);
        try
        {
            IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
            IntPtr cfn = cancel is not null
                ? Marshal.GetFunctionPointerForDelegate(CancelThunk) : IntPtr.Zero;
            IntPtr cuser = cancelHandle.IsAllocated ? GCHandle.ToIntPtr(cancelHandle) : IntPtr.Zero;
            int rc = VdiskNative.vdisk_reindex_ex(_h, "", fn,
                GCHandle.ToIntPtr(handle), cfn, cuser);
            if (rc == (int)VDiskStatus.Cancelled) return false;
            Check(rc);
            return true;
        }
        finally
        {
            if (cancelHandle.IsAllocated) cancelHandle.Free();
            handle.Free();
        }
    }

    public (ulong Used, ulong Total) StatSpace()
    {
        EnsureUnlocked();
        ulong used = 0, total = 0;
        Check(VdiskNative.vdisk_stat_space(_h, &used, &total));
        return (used, total);
    }

    // 容量统计
    public (ulong Used, ulong Trash, ulong Total) StatSpaceEx()
    {
        EnsureUnlocked();
        ulong used = 0, trash = 0, total = 0;
        Check(VdiskNative.vdisk_stat_space_ex(_h, &used, &trash, &total));
        return (used, trash, total);
    }

    // 保留命名空间
    private static string? s_reservedName;
    public static string ReservedName
        => s_reservedName ??= (Marshal.PtrToStringUTF8(VdiskNative.vdisk_reserved_name())
            ?? throw new VaultException(VDiskStatus.Internal, L10n.T("native 未提供保留目录名")));

    // 根层保留路径判
    public static bool IsReservedPath(string relPath)
        => VdiskNative.vdisk_is_reserved_path(relPath) != 0;

    // 随机块读
    public byte[] ReadRange(string vpath, ulong offset, int len)
    {
        EnsureUnlocked();
        if (len <= 0) return Array.Empty<byte>();
        var buf = new byte[len];
        ulong want = (ulong)len;
        fixed (byte* p = buf)
            Check(VdiskNative.vdisk_read_file(_h, vpath, offset, p, &want));
        if (want < (ulong)len) Array.Resize(ref buf, (int)want);
        return buf;
    }

    // 随机块读进调用
    public int ReadRangeTo(string vpath, ulong offset, byte[] dst, int dstOffset, int len)
    {
        EnsureUnlocked();
        if (len <= 0 || dstOffset < 0 || dstOffset >= dst.Length) return 0;
        if (dstOffset + len > dst.Length) len = dst.Length - dstOffset;
        ulong want = (ulong)len;
        fixed (byte* p = dst)
            Check(VdiskNative.vdisk_read_file(_h, vpath, offset, p + dstOffset, &want));
        return (int)want;
    }

    // 整文件写入
    // 目标文件必须先
    public void WriteFile(string vpath, byte[] data)
    {
        EnsureUnlocked();
        fixed (byte* p = data)
            Check(VdiskNative.vdisk_write_file(_h, vpath, 0, p, (ulong)data.Length));
    }

    // 恢复密钥
    public string GenRecoveryCode()
    {
        var buf = new byte[64];
        fixed (byte* p = buf)
            Check(VdiskNative.vdisk_recovery_gen(p, (ulong)buf.Length));
        int n = Array.IndexOf(buf, (byte)0);
        return System.Text.Encoding.UTF8.GetString(buf, 0, n < 0 ? buf.Length : n);
    }

    public void CreateRecovery(string code)
    {
        EnsureUnlocked();
        Check(VdiskNative.vdisk_recovery_create(_h, code));
    }

    // 使用恢复密钥取
    // 返回 NUL 结尾 byte[]
    public byte[]? RecoverPassphrase(byte[] code)
    {
        EnsureOpen();
        var buf = new byte[512];
        ulong len = (ulong)buf.Length;
        int rc;
        fixed (byte* p = buf)
        fixed (byte* c = code)
            rc = VdiskNative.vdisk_recovery_open(_h, c, p, &len);
        if (rc != 0) { Secret.Wipe(buf); return null; }
        int n = Array.IndexOf(buf, (byte)0);
        int take = (int)Math.Min(len, (ulong)(n < 0 ? buf.Length : n));
        var pass = new byte[take + 1];
        Array.Copy(buf, pass, take);
        Secret.Wipe(buf);
        return pass;
    }

    public void RemoveRecovery()
    {
        EnsureOpen();
        Check(VdiskNative.vdisk_recovery_remove(_h));
    }

    private void EnsureOpen()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_h == IntPtr.Zero)
            throw new VaultException(VDiskStatus.BadArg, L10n.T("加密库尚未打开"));
    }

    private void EnsureUnlocked()
    {
        EnsureOpen();
        if (Volatile.Read(ref s_locking) != 0 || VdiskNative.vdisk_is_unlocked(_h) != 1)
            throw new VaultException(VDiskStatus.Locked, L10n.T("加密库已锁定"));
    }

    // native 英文错误码转
    internal static string StatusText(VDiskStatus st) => st switch
    {
        VDiskStatus.Auth => L10n.T("密码或恢复密钥错误"),
        VDiskStatus.Locked => L10n.T("加密库已锁定"),
        VDiskStatus.NoMem => L10n.T("内存不足"),
        VDiskStatus.Io => L10n.T("读写失败"),
        VDiskStatus.NotFound => L10n.T("文件或目录不存在"),
        VDiskStatus.ReadOnly => L10n.T("加密库为只读状态"),
        VDiskStatus.Exist => L10n.T("目标已存在"),
        VDiskStatus.NotImpl => L10n.T("当前平台不支持该操作"),
        VDiskStatus.Wipe => L10n.T("安全擦除失败"),
        _ => VdiskNative.ErrorText((int)st),
    };

    private static void Check(int rc)
    {
        if (rc == 0) return;
        var st = (VDiskStatus)rc;
        throw new VaultException(st, StatusText(st));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { Close(); }
        catch { /* 释放路径不抛：刷盘失败已由使用方在 Close 显式调用时感知 */ }
        if (Active == this) Active = null;
        GC.SuppressFinalize(this);
    }

    // 页面
    ~VaultService()
    {
        if (!_disposed) { try { Close(); } catch { } }
    }
}
