// 加密库主页面
using System.Text.RegularExpressions;
using Android.App;
using Android.Content;
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile;

public partial class VaultPage : ContentPage
{
    private readonly VaultService _vault = VaultService.Shared;
    private string _vaultDir = "";
    private string _curPath = "";   // 当前虚拟路径
    private string? _loadedPath;    // 最近一次 LoadDir
    private int _navDir;              // 目录切换动画方
    private int _rangeAnchor = -1;    // 上一次左滑行号
    // 恢复密钥
    private const string RecoveryKey = "vault_recovery_code";
    // 权限浮层
    private const string PermDismissedKey = "perm_overlay_dismissed";
    // 上次浏览目录
    private static readonly object s_noteGate = new();
    private static long s_lastNoteMs;
    private bool _permDismissed;
    // 本次解锁用
    // byte[]
    private static byte[]? s_passphrase;
    // 缩略图批次取消
    private CancellationTokenSource? _thumbCts;
    // 懒加载
    private List<VaultItem>? _thumbItems;
    private readonly object _thumbSync = new();
    private readonly HashSet<string> _thumbQueued = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _thumbTries = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _thumbGate = new(2);
    // 画廊优先
    // 缩略图
    private bool _thumbsPaused;
    private const int InitialThumbWindow = 16;   // 进目录先生成
    private const int ThumbLookahead = 24;        // 滚动时额外
    // 空闲续期计时器
    private IDispatcherTimer? _keepAlive;

    // 多选
    private bool _multiSelect;
    private bool _bulkUpdating;      // 批量改选中态
    private long _longPressAt;             // 长按
    private long _lastMenuAt;              // 双路长
    private bool _suppressTap;             // 长按抬手
    private CancellationTokenSource? _lpCts;
    private float _lpX, _lpY;
    private readonly Dictionary<IntPtr, Grid> _gridByNative = new();
    private readonly HashSet<IntPtr> _touchHooked = new();
    private TaskCompletionSource<string?>? _pwdTcs;    // 页内遮罩密码输
    private CancellationTokenSource? _propsCts;       // 属性页渐进统计
    private List<VaultItem> _renameTargets = new();
    private List<CipherModeInfo> _setupAlgos = new();
    private int _setupAlgoIndex = -1;
    private int _setupCompressIndex;
    private bool _setupAlgosLoaded;
    private List<CipherModeInfo> _vaultSettingsAlgos = new();

    private static string[] CompressNames() => new[]
        { L10n.T("自动"), L10n.T("关闭"), L10n.T("极速"), L10n.T("标准"), L10n.T("最佳") };
    private static readonly int[] CompressLevels =
        { VdiskNative.CompressAuto, 0, -3, 3, 9 };

    // 排序
    private const string SortKey = "vault_sort_mode";
    private static readonly string[] SortNames =
        { L10n.T("名称 ↑"), L10n.T("名称 ↓"), L10n.T("大小 ↑"), L10n.T("大小 ↓"), L10n.T("修改时间 ↓"), L10n.T("修改时间 ↑"), L10n.T("类型") };

    // 会话口令随库锁
    static VaultPage() => VaultService.SessionLocked += () =>
    {
        Secret.Wipe(s_passphrase);
        s_passphrase = null;
    };

    public VaultPage()
    {
        InitializeComponent();
        VaultStorageHelper.DirectoryPicked += OnDirPicked;
        MainActivity.Resumed += OnAppResumed;
        ChoiceUi.BuildChips(SetupCompressChoices, CompressNames(), 0,
            i =>
            {
                _setupCompressIndex = i;
                SetupCompressHint.Text = CryptoPage.CompressHintText(i);
            });
        SetupCompressHint.Text = CryptoPage.CompressHintText(0);
        // 权限横幅占据顶
        // 横幅
        _permDismissed = Preferences.Default.Get(PermDismissedKey, false);
        UpdatePermBanner();
    }

    // native 加载后才敢查算
    private void LoadSetupAlgos()
    {
        if (_setupAlgosLoaded) return;
        try
        {
            FileCryptoService.VerifyAbi();
            // 全量列出并标注
            var list = FileCryptoService.Modes().ToList();
            _setupAlgos = list;
            _setupAlgoIndex = list.FindIndex(m => m.Available);
            ChoiceUi.BuildModeRows(SetupAlgoChoices, list, _setupAlgoIndex,
                i => _setupAlgoIndex = i, SetupAlgoDetail);
            _setupAlgosLoaded = true;
        }
        catch { /* 建库页稍后重试 */ }
    }

    // 页面分离时退订
    protected override void OnHandlerChanged()
    {
        base.OnHandlerChanged();
        if (Handler is null)
        {
            VaultService.InvalidatePendingUnlock();   // 页面销毁
            VaultStorageHelper.DirectoryPicked -= OnDirPicked;
            MainActivity.Resumed -= OnAppResumed;
        }
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        // 整页纯淡入
        // 操作
        // 位移残留
        UiFx.AppearFade(this, dy: 0, ms: 220);
        _keepAlive?.Stop();      // 页面重建
        _keepAlive = null;
        _permDismissed = Preferences.Default.Get(PermDismissedKey, false);
        if (_vaultDir.Length == 0)
        {
            // 默认库目录
            _vaultDir = VaultStorageHelper.CurrentVaultDir();
            try { VaultService.VerifyAbi(); }
            catch (Exception ex) { ShowError(L10n.T("native 库加载异常"), ex.Message); }
        }
        LoadSetupAlgos();
        DirLabel.Text = L10n.F("库目录：{0}", _vaultDir);
        UpdatePermBanner();
        // SAF 选择进行
        if (VaultStorageHelper.PickInProgress)
        {
            VaultStorageHelper.DirectoryPicked -= OnDirPicked;
            VaultStorageHelper.DirectoryPicked += OnDirPicked;
        }
        RefreshState();
        ResumeThumbs();   // 从画廊返回
        // 页面可见期间每
        _keepAlive = Dispatcher.CreateTimer();
        _keepAlive.Interval = TimeSpan.FromSeconds(60);
        _keepAlive.Tick += (_, _) => NoteActivity();
        _keepAlive.Start();
    }

    protected override void OnDisappearing()
    {
        // 锁库
        // 栈顶拍照
        // 但页面若确实离
        VaultService.InvalidatePendingUnlock();
        _keepAlive?.Stop();
        _keepAlive = null;
        CloseProps();   // 页面切走时停掉
        if (_pwdTcs is not null) ClosePwd(null);
        UiFx.Hide(VaultSettingsOverlay);
        base.OnDisappearing();
    }

    // 返回键能力
    // 不覆写 OnBackButtonPressed覆
    // 全局「先回主页
    // 当前是否处于浏
    public bool IsBrowsing => BrowseView.IsVisible;

    // 库内子目录返回
    public bool HandleBackInVault()
    {
        if (!BrowseView.IsVisible) return false;   // 未解锁 / 未建库
        if (PwdOverlay.IsVisible) { ClosePwd(null); return true; }
        if (PropsOverlay.IsVisible) { CloseProps(); return true; }
        if (Sheet.IsOpen) { Sheet.Cancel(); return true; }
        if (VaultSettingsOverlay.IsVisible) { UiFx.Hide(VaultSettingsOverlay); return true; }
        if (RenameOverlay.IsVisible) { UiFx.Hide(RenameOverlay); return true; }
        if (_multiSelect) { SetMultiSelect(false); return true; }
        if (_curPath.Length > 0) { OnUp(this, EventArgs.Empty); return true; }
        return false;                                // 已在库根
    }

    // 锁定加密库
    public void LockVault()
    {
        try { _vault.Lock(); } catch { }
        Secret.Wipe(s_passphrase);
        s_passphrase = null;
        _curPath = "";
        RefreshState();
    }

    // 权限横幅 + 浮层
    private void UpdatePermBanner()
    {
        bool ok = VaultStorageHelper.HasAllFilesAccess();
        PermBanner.IsVisible = !ok;
        SetView(PermOverlay, !ok && !_permDismissed);
        if (ok) _permDismissed = false;
    }

    private void OnGrantPerm(object? sender, EventArgs e)
    {
        if (Platform.CurrentActivity is Activity act)
        {
            MainActivity.NoteExternalLaunch();   // 跳设置页期间
            VaultStorageHelper.RequestAllFilesAccess(act);
        }
        UpdatePermBanner();
    }

    // 「暂不」
    private void OnPermLater(object? sender, EventArgs e)
    {
        _permDismissed = true;
        Preferences.Default.Set(PermDismissedKey, true);
        UiFx.Hide(PermOverlay);
    }

    // 返回前台
    private void OnAppResumed()
    {
        if (Handler is null) return;
        try { UpdatePermBanner(); }
        catch { /* 权限横幅刷新失败不阻断 */ }
        // 长任务中 native 持库互
        if (VaultService.LongOps > 0)
        {
            // 切过后台已挂起
            if (VaultService.IsLockPending) ShowLockedUi();
            return;
        }
        try { RefreshState(); }
        catch { /* 刷新失败不阻断 */ }
    }

    // 视图显隐
    private static void SetView(VisualElement v, bool on)
    {
        if (!on) { UiFx.Hide(v); return; }
        if (v.IsVisible) { v.Opacity = 1; v.TranslationY = 0; return; }
        UiFx.FadeIn(v);
    }

    // 不碰 native
    private void ShowLockedUi()
    {
        Secret.Wipe(s_passphrase);
        s_passphrase = null;
        CancelThumbs();
        string r = VaultService.ConsumeLockReason();
        LblLockReason.Text = r.Length > 0 ? r : L10n.T("切后台，已自动锁定");
        LblLockReason.IsVisible = true;
        bool exists = VaultService.Exists(_vaultDir);
        SetView(SetupView, !exists);
        SetView(UnlockView, exists);
        SetView(BrowseView, false);
        DamageBanner.IsVisible = false;
        UpdateBioButtons(exists, false);
    }

    // 三态切换
    private void RefreshState()
    {
        bool exists = VaultService.Exists(_vaultDir);
        bool unlocked = exists && SafeOpen() && _vault.IsUnlocked;
        bool wasBrowsing = BrowseView.IsVisible;
        if (!unlocked)
        {
            Secret.Wipe(s_passphrase); s_passphrase = null; CancelThumbs();
            // 从浏览态掉到锁
            if (wasBrowsing && !LblLockReason.IsVisible)
            {
                string r = VaultService.ConsumeLockReason();
                LblLockReason.Text = r.Length > 0 ? r : L10n.T("空闲超时，已自动锁定");
                LblLockReason.IsVisible = true;
            }
        }
        else LblLockReason.IsVisible = false;
        SetView(SetupView, !exists);
        SetView(UnlockView, exists && !unlocked);
        SetView(BrowseView, unlocked);
        // 索引损坏放行
        DamageBanner.IsVisible = unlocked && _vault.IsIndexDamaged;

        if (unlocked)
        {
            // 已在浏览同一目
            if (!wasBrowsing || _curPath != _loadedPath) LoadDir();
            NoteActivity();
        }
        UpdateBioButtons(exists, unlocked);
        UpdatePqcButtons(exists, unlocked);
    }

    // 空闲续期
    private void NoteActivity()
    {
        // 长任务进行
        if (VaultService.LongOps > 0) return;
        // 检查
        lock (s_noteGate)
        {
            long now = Environment.TickCount64;
            if (now - s_lastNoteMs < 1000) return;
            s_lastNoteMs = now;
        }
        _ = Task.Run(() =>
        {
            try { if (_vault.IsUnlocked) _vault.NoteActivity(); } catch { }
        });
    }

    // 列表滚动
    private void OnListScrolled(object? sender, ItemsViewScrolledEventArgs e)
    {
        NoteActivity();
        if (e.FirstVisibleItemIndex >= 0 && e.LastVisibleItemIndex >= e.FirstVisibleItemIndex)
            EnsureThumbsForRange(e.FirstVisibleItemIndex, e.LastVisibleItemIndex + ThumbLookahead);
    }

    // 生物识别
    private void UpdateBioButtons(bool exists, bool unlocked)
    {
        bool on = exists && BiometricVault.HasCredential(_vaultDir);
        bool avail = BiometricVault.IsAvailable();
        bool pqc = exists && PqcVault.HasCredential(_vaultDir);
        BtnBioUnlock.IsVisible = exists && !unlocked && avail && (pqc || on);
        // 解锁态下已有
        bool canToggle = exists && avail && (on || !unlocked || s_passphrase is not null);
        BtnBioToggle.IsVisible = canToggle;
        BtnBioToggle.Text = on ? L10n.T("关闭指纹或面容解锁") : L10n.T("开启指纹或面容解锁");
        BioItem.Text = on ? L10n.T("关闭指纹或面容") : L10n.T("开启指纹或面容");
    }

    // 二级菜单
    private async void OnPqcManage(object? sender, EventArgs e)
    {
        if (!PqcVault.IsAvailable())
        {
            await DisplayAlertAsync(L10n.T("后量子保护"),
                L10n.T("当前版本不支持后量子保护。"), L10n.T("确定"));
            return;
        }
        if (PqcVault.HasCredential(_vaultDir))
        {
            bool yes = await DisplayAlertAsync(L10n.T("后量子保护"),
                L10n.T("关闭后量子保护？密码解锁不受影响。"), L10n.T("关闭"), L10n.T("取消"));
            if (!yes) return;
            PqcVault.Clear(_vaultDir);
            Preferences.Default.Set(PqcOffKey(_vaultDir), true);
            RefreshState();
            return;
        }
        if (s_passphrase is null)
        {
            await DisplayAlertAsync(L10n.T("后量子保护"),
                L10n.T("请先解锁加密库，再开启后量子保护。"), L10n.T("确定"));
            return;
        }
        if (!PqcVault.CanEnable())
        {
            await DisplayAlertAsync(L10n.T("后量子保护"),
                L10n.T("当前设备不支持生物ID验证。"), L10n.T("确定"));
            return;
        }
        byte[] tmp = (byte[])s_passphrase.Clone();
        string? err = null;
        try { err = await PqcVault.EnableAsync(_vaultDir, tmp); }
        finally
        {
            MainActivity.ReleaseExternalLaunch();
            Secret.Wipe(tmp);
        }
        if (err is not null)
            await DisplayAlertAsync(L10n.T("后量子保护"), err, L10n.T("确定"));
        else
            Preferences.Default.Remove(PqcOffKey(_vaultDir));
        RefreshState();
    }

    private void UpdatePqcButtons(bool exists, bool unlocked)
    {
        bool on = exists && PqcVault.HasCredential(_vaultDir);
        PqcItem.Text = on ? L10n.T("关闭后量子保护") : L10n.T("开启后量子保护");
    }

    // 生物识别解锁
    private async void OnBioUnlock(object? sender, EventArgs e)
    {
        SetBusy(true);
        byte[]? pwd = null;
        bool pqc = PqcVault.HasCredential(_vaultDir);
        try
        {
            int epoch = VaultService.LockEpoch;
            // 优先后量子凭据
            pwd = pqc ? await PqcVault.UnsealAsync(_vaultDir)
                      : await BiometricVault.LoadAsync(_vaultDir);
            if (!VaultService.IsLockEpochCurrent(epoch)) return;
            if (pwd is null)
            {
                UnlockMsg.Text = pqc ? L10n.T("免密解锁失败，请用密码解锁或重新开启")
                                     : L10n.T("指纹或面容验证未通过");
                UnlockMsg.IsVisible = true;
                return;
            }
            await DoUnlock(pwd, false, epoch);
        }
        catch (Exception ex) { UnlockMsg.Text = ex.Message; UnlockMsg.IsVisible = true; }
        finally
        {
            MainActivity.ReleaseExternalLaunch();
            Secret.Wipe(pwd);
            SetBusy(false);
        }
    }

    // 开关切换
    private async void OnBioToggle(object? sender, EventArgs e) => await ToggleBio();

    private async Task ToggleBio()
    {
        if (BiometricVault.HasCredential(_vaultDir)) { await DisableBio(); return; }
        await EnableBio();
    }

    // 启用
    private async Task EnableBio()
    {
        byte[]? pwd = null;
        if (_vault.IsUnlocked && s_passphrase is not null)
        {
            pwd = (byte[])s_passphrase.Clone();   // 会话口令取副本
        }
        else
        {
            string t = UnlockPwd.Text ?? "";
            if (t.Length == 0)
            { UnlockMsg.Text = L10n.T("请先输入加密库密码"); UnlockMsg.IsVisible = true; return; }
            UnlockPwd.Text = "";
            await DoUnlock(Secret.FromZ(t), false, VaultService.LockEpoch);   // 入参所有权移交 DoUnlock
            if (!_vault.IsUnlocked) return;   // 密码错误
            pwd = s_passphrase is not null ? (byte[])s_passphrase.Clone() : null;
        }
        if (pwd is null) return;
        SetBusy(true);
        try
        {
            // 同 OnBioUnlock
            string? err = await BiometricVault.SaveAsync(_vaultDir, pwd);
            if (err is not null) { await ReportBioError(L10n.T("未开启"), err); return; }
            RefreshState();
            await DisplayAlertAsync(L10n.T("已开启"), L10n.T("下次解锁加密库时，可直接使用指纹或面容。"), L10n.T("确定"));
        }
        catch (Exception ex) { await ReportBioError(L10n.T("未开启"), ex.Message); }
        finally
        {
            MainActivity.ReleaseExternalLaunch();
            Secret.Wipe(pwd);
            SetBusy(false);
        }
    }

    // 解锁页用内联提
    private async Task ReportBioError(string title, string msg)
    {
        if (_vault.IsUnlocked) { await DisplayAlertAsync(title, msg, L10n.T("确定")); return; }
        UnlockMsg.Text = msg;
        UnlockMsg.IsVisible = true;
        await Task.CompletedTask;
    }

    // 关闭
    private async Task DisableBio()
    {
        if (!await DisplayAlertAsync(L10n.T("关闭指纹或面容解锁"),
                L10n.T("关闭前需要先验证指纹或面容。"), L10n.T("验证"), L10n.T("取消"))) return;
        SetBusy(true);
        byte[]? pwd = null;
        try
        {
            // 同 OnBioUnlock
            pwd = await BiometricVault.LoadAsync(_vaultDir);
            if (pwd is null)
            {
                await DisplayAlertAsync(L10n.T("未关闭"), L10n.T("指纹或面容验证未通过。"), L10n.T("确定"));
                return;
            }
            // 解锁态下顺手补
            if (s_passphrase is null) s_passphrase = (byte[])pwd.Clone();
            BiometricVault.Clear(_vaultDir);
            RefreshState();
            await DisplayAlertAsync(L10n.T("已关闭"), L10n.T("已关闭指纹/面容解锁，记录已删除。"), L10n.T("确定"));
        }
        finally
        {
            MainActivity.ReleaseExternalLaunch();
            Secret.Wipe(pwd);
            SetBusy(false);
        }
    }

    // 工具栏入口
    private async void OnBioManage(object? sender, EventArgs e)
    {
        if (!VaultService.Exists(_vaultDir))
        { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先创建加密库"), L10n.T("确定")); return; }
        if (!BiometricVault.IsAvailable())
        {
            await DisplayAlertAsync(L10n.T("不可用"),
                L10n.T("当前设备未录入指纹或面容，或系统版本不支持。"), L10n.T("确定"));
            return;
        }
        await ToggleBio();
    }

    private bool SafeOpen()
    {
        try
        {
            if (!_vault.IsOpen) _vault.Open(_vaultDir);
            return true;
        }
        catch (Exception ex) { ShowError(L10n.T("打开加密库失败"), ex.Message); return false; }
    }

    private int _loadVer;

    // 恢复上次浏览目
    private string RestoreLastPath()
    {
        string saved = VaultLastPos.Load(_vault);
        if (saved.Length == 0) return "";
        try { return _vault.TryGetAttr(saved, out _, out bool isDir) && isDir ? saved : ""; }
        catch { return ""; }
    }

    private async void LoadDir()
    {
        int ver = ++_loadVer;
        string path = _curPath;
        _ = Task.Run(() => VaultLastPos.Save(_vault, path));
        int dir = _navDir;
        _navDir = 0;
        EmptyBox.IsVisible = false;   // 加载中不闪空态
        try
        {
            // 只等目录列举
            var items = await Task.Run(() => SortItems(_vault.ListDir(path))).ConfigureAwait(false);
            if (ver != _loadVer) return;
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                if (ver != _loadVer) return;
                _rangeAnchor = -1;
                SetMultiSelect(false, skipItemReset: true);   // 旧列表即
                FileList.ItemsSource = items;
                EmptyBox.IsVisible = items.Count == 0;
                _loadedPath = path;
                PathLabel.Text = "/" + path;
                BtnUp.IsEnabled = path.Length > 0;
                SpaceLabel.Text = L10n.T("已用 —");
                _ = AnimateListAsync(dir);
                // 列表先渲染完
                _ = Task.Run(async () =>
                {
                    await Task.Delay(120);
                    MainThread.BeginInvokeOnMainThread(() =>
                    { if (ver == _loadVer && IsBrowsing) StartThumbs(items); });
                });
            });
            // 空间统计独立回
            _ = Task.Run(() =>
            {
                try
                {
                    var (used, trash, total) = _vault.StatSpaceEx();
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        if (ver != _loadVer) return;
                        string t = trash > 0 ? L10n.F("（回收站 {0}）", VaultItem.FormatSize(trash)) : "";
                        SpaceLabel.Text = total > 0
                            ? L10n.F("已用 {0}{1} / {2}", VaultItem.FormatSize(used), t, VaultItem.FormatSize(total))
                            : L10n.F("已用 {0}{1}", VaultItem.FormatSize(used), t);
                    });
                }
                catch { }
            });
        }
        catch (Exception ex)
        {
            MainThread.BeginInvokeOnMainThread(() => ShowError(L10n.T("读取目录失败"), ex.Message));
        }
    }

    // 目录切换滑入
    // 先等重布局落定
    // 看起来像没动画）
    private int _listAnimVer;

    private async Task AnimateListAsync(int dir)
    {
        int ver = ++_listAnimVer;
        try
        {
            FileList.CancelAnimations();
            FileList.Opacity = 0;
            FileList.TranslationX = dir * 60;
            await Task.Delay(16);
            if (ver != _listAnimVer) return;   // 已有
            if (FileList.Handler is null) { FileList.Opacity = 1; return; }
            await Task.WhenAll(
                FileList.FadeTo(1, 220, Easing.CubicOut),
                FileList.TranslateTo(0, 0, 280, Easing.CubicOut));
        }
        catch
        {
            try { FileList.Opacity = 1; } catch { }
        }
    }

    // 缩略图后台补图
    // 进目录
    private void StartThumbs(List<VaultItem> items)
    {
        CancelThumbs();
        _thumbCts = new CancellationTokenSource();
        _thumbItems = items;
        EnsureThumbsForRange(0, InitialThumbWindow);
    }

    // 仅给
    private void EnsureThumbsForRange(int from, int to)
    {
        if (_thumbItems is null) return;
        var cts = _thumbCts;
        if (cts is null) return;
        int n = _thumbItems.Count;
        from = Math.Max(0, from);
        to = Math.Min(n - 1, to);
        for (int i = from; i <= to; i++)
        {
            var it = _thumbItems[i];
            if (it.IsDir || !ThumbnailHelper.IsMedia(it.Name)) continue;
            if (it.ThumbSource is not null) continue;
            lock (_thumbSync)
            {
                if (_thumbQueued.Contains(it.RelPath)) continue;
                // 失败最多重试
                if (_thumbTries.GetValueOrDefault(it.RelPath) >= 3) continue;
                _thumbQueued.Add(it.RelPath);
            }
            QueueThumb(it, cts);
        }
    }

    private void QueueThumb(VaultItem it, CancellationTokenSource cts)
    {
        var ct = cts.Token;
        _ = Task.Run(async () =>
        {
            bool ok = false;
            try
            {
                await _thumbGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (ct.IsCancellationRequested) return;
                    string? p = ThumbnailHelper.Build(_vault, it);
                    ok = p is not null;
                    if (p is null || ct.IsCancellationRequested) return;
                    MainThread.BeginInvokeOnMainThread(() => it.ThumbSource = p);
                }
                finally { _thumbGate.Release(); }
            }
            catch { }
            finally
            {
                // 代次不符则丢弃
                lock (_thumbSync)
                {
                    if (ReferenceEquals(_thumbCts, cts))
                    {
                        _thumbQueued.Remove(it.RelPath);
                        if (ok) _thumbTries.Remove(it.RelPath);
                        else _thumbTries[it.RelPath] = _thumbTries.GetValueOrDefault(it.RelPath) + 1;
                    }
                }
            }
        }, ct);
    }

    // 暂停缩略图队列
    private void PauseThumbs()
    {
        _thumbsPaused = true;
        CancelThumbs();
    }

    // 恢复缩略图队列
    private void ResumeThumbs()
    {
        if (!_thumbsPaused) return;
        _thumbsPaused = false;
        var items = _thumbItems;
        if (items is null) return;
        // 错峰启动
        _ = Task.Run(async () =>
        {
            await Task.Delay(180);
            MainThread.BeginInvokeOnMainThread(() =>
            { if (!_thumbsPaused && IsBrowsing) StartThumbs(items); });
        });
    }

    private void CancelThumbs()
    {
        try { _thumbCts?.Cancel(); } catch { }
        try { _thumbCts?.Dispose(); } catch { }
        _thumbCts = null;
        lock (_thumbSync) { _thumbQueued.Clear(); _thumbTries.Clear(); }
    }

    private async void OnCreateVault(object? sender, EventArgs e)
    {
        // 建库前预检
        if (!VaultStorageHelper.HasAllFilesAccess())
        {
            SetupMsg.Text = L10n.T("请先授予「所有文件访问」权限");
            SetupMsg.IsVisible = true;
            _permDismissed = false;   // 显式点击创建
            Preferences.Default.Set(PermDismissedKey, false);
            UpdatePermBanner();
            return;
        }
        string p1 = SetupPwd.Text ?? "";
        string p2 = SetupPwd2.Text ?? "";
        if (p1.Length == 0) { SetupMsg.Text = L10n.T("密码不能为空"); SetupMsg.IsVisible = true; return; }
        if (p1 != p2) { SetupMsg.Text = L10n.T("两次输入不一致"); SetupMsg.IsVisible = true; return; }
        // 强度不足给二次
        if (!PasswordPolicy.Check(p1, out string weak))
        {
            if (!await DisplayAlertAsync(L10n.T("密码强度不足"), weak + L10n.T("\n仍要使用这个密码？"), L10n.T("继续"), L10n.T("重新输入")))
                return;
        }

        int mode = _setupAlgoIndex >= 0 && _setupAlgoIndex < _setupAlgos.Count
            ? (int)_setupAlgos[_setupAlgoIndex].Mode : 1;
        int ci = _setupCompressIndex;
        int comp = ci >= 0 && ci < CompressLevels.Length
            ? CompressLevels[ci] : VdiskNative.CompressAuto;

        SetBusy(true);
        string? recoveryCode = null;
        string? pqcErr = null;
        byte[]? pw = null;
        try
        {
            pw = Secret.FromZ(p1);
            await Task.Run(() =>
            {
                VaultService.InitEx(_vaultDir, mode, comp);   
                _vault.Open(_vaultDir);
                _vault.Unlock(pw!);
                // 建库即生成恢复
                recoveryCode = _vault.GenRecoveryCode();
                _vault.CreateRecovery(recoveryCode);
            });
            await SecureStorage.Default.SetAsync(RecoveryKey, recoveryCode!);
            // 建库即登记
            if (PqcVault.CanEnable())
                pqcErr = await PqcVault.EnableAsync(_vaultDir, pw!);
            else
                pqcErr = L10n.T("当前设备不支持生物ID验证，后量子保护未开启；密码解锁不受影响。");
            SetupPwd.Text = ""; SetupPwd2.Text = "";
            SetupMsg.IsVisible = false;
            // 建库口令即
            Secret.Wipe(s_passphrase);
            s_passphrase = (byte[])pw!.Clone();
            RefreshState();
            if (recoveryCode != null)
                await ShowRecoveryCode(recoveryCode, firstTime: true);
            if (pqcErr is not null)
                await DisplayAlertAsync(L10n.T("后量子保护"), pqcErr, L10n.T("确定"));
        }
        catch (Exception ex) { SetupMsg.Text = ex.Message; SetupMsg.IsVisible = true; }
        finally { MainActivity.ReleaseExternalLaunch(); Secret.Wipe(pw); SetBusy(false); }
    }

    private async void OnUnlock(object? sender, EventArgs e)
    {
        byte[] pwd = Secret.FromZ(UnlockPwd.Text ?? "");
        UnlockPwd.Text = "";
        if (pwd.Length == 1)
        { Secret.Wipe(pwd); UnlockMsg.Text = L10n.T("请输入密码"); UnlockMsg.IsVisible = true; return; }
        await DoUnlock(pwd, false, VaultService.LockEpoch);   // 入参所有权移交
    }

    private async void OnUnlockRecovery(object? sender, EventArgs e)
    {
        byte[] code = Secret.FromZ(UnlockPwd.Text ?? "");
        UnlockPwd.Text = "";
        if (code.Length == 1)
        { Secret.Wipe(code); UnlockMsg.Text = L10n.T("请输入恢复密钥"); UnlockMsg.IsVisible = true; return; }
        await DoUnlock(code, true, VaultService.LockEpoch);   // 入参所有权移交
    }

    // secret 为 NUL 结尾 byte[]；本方法接
    // epoch 由调用方
    // 期间离开加密库
    private async Task DoUnlock(byte[] secret, bool isRecovery, int epoch)
    {
        SetBusy(true);
        byte[]? real = null;
        try
        {
            // 失败退避
            var left = AttemptLimiter.Remaining();
            if (left > TimeSpan.Zero)
            {
                UnlockMsg.Text = L10n.F("尝试过于频繁，请 {0} 秒后再试", Math.Ceiling(left.TotalSeconds));
                UnlockMsg.IsVisible = true;
                return;
            }
            bool completed = await Task.Run(() =>
            {
                if (!VaultService.IsLockEpochCurrent(epoch)) return false;
                if (!_vault.IsOpen) _vault.Open(_vaultDir);
                if (isRecovery)
                {
                    // 恢复密钥先换出
                    real = _vault.RecoverPassphrase(secret);
                    if (real is null) throw new Exception(L10n.T("恢复密钥无效"));
                    _vault.Unlock(real);
                }
                else
                {
                    _vault.Unlock(secret);
                    real = secret;   // 同一引用
                }
                // native 解锁期间用户已
                if (!VaultService.IsLockEpochCurrent(epoch))
                {
                    try { _vault.Lock(); } catch { }
                    return false;
                }
                return true;
            });
            if (!completed)
            {
                _reindexAfterUnlock = false;   // 离页作废
                return;
            }
            // Task 收尾到 UI continuation
            if (!VaultService.IsLockEpochCurrent(epoch))
            {
                try { _vault.Lock(); } catch { }
                _reindexAfterUnlock = false;
                return;
            }
            AttemptLimiter.OnSuccess();
            Secret.Wipe(s_passphrase);
            s_passphrase = (byte[])real!.Clone();   // 会话内留存
            UnlockPwd.Text = "";
            UnlockMsg.IsVisible = false;
            _curPath = RestoreLastPath();
            RefreshState();
            // 老库补登记
            await AutoEnablePqcAsync(real!, epoch);
            // 解锁
            _ = Task.Run(() =>
            {
                VaultService.BeginLongOp();
                try { VaultTrash.PurgeExpired(_vault, VaultTrash.RetentionDays); }
                catch { }
                finally { VaultService.EndLongOp(); }
            });
            // 锁态下点
            if (_reindexAfterUnlock)
            {
                _reindexAfterUnlock = false;
                await RunReindexAsync();
            }
        }
        catch (Exception ex)
        {
            AttemptLimiter.OnFailure();
            _reindexAfterUnlock = false;   // 密码错误不带病
            UnlockMsg.Text = ex.Message; UnlockMsg.IsVisible = true;
        }
        finally
        {
            Secret.Wipe(secret);
            Secret.Wipe(real);
            SetBusy(false);
        }
    }

    // 老库自动补开
    private static readonly HashSet<string> s_pqcAutoTried = new(StringComparer.Ordinal);
    private static string PqcOffKey(string dir) => "pqc_user_off_" + dir;

    private async Task AutoEnablePqcAsync(byte[] pass, int epoch)
    {
        if (!PqcVault.CanEnable() || PqcVault.HasCredential(_vaultDir)) return;
        if (Preferences.Default.Get(PqcOffKey(_vaultDir), false)) return;
        if (!s_pqcAutoTried.Add(_vaultDir)) return;
        if (!VaultService.IsLockEpochCurrent(epoch)) return;
        byte[] tmp = (byte[])pass.Clone();
        try { await PqcVault.EnableAsync(_vaultDir, tmp); }
        catch { }
        finally
        {
            MainActivity.ReleaseExternalLaunch();
            Secret.Wipe(tmp);
        }
        if (VaultService.IsLockEpochCurrent(epoch)) RefreshState();
    }

    private void OnLock(object? sender, EventArgs e)
    {
        try { _vault.Lock(); } catch (Exception ex) { ShowError(L10n.T("锁定失败"), ex.Message); }
        Secret.Wipe(s_passphrase);
        s_passphrase = null;
        _curPath = "";
        _reindexAfterUnlock = false;   // 中途锁定
        RefreshState();
    }

    // 更改库目录
    private void OnChangeDir(object? sender, EventArgs e)
    {
        try
        {
            if (Platform.CurrentActivity is not Activity act)
            { ShowError(L10n.T("无法选择目录"), L10n.T("当前界面不可用")); return; }
            var intent = new Intent(Intent.ActionOpenDocumentTree);
            intent.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
            VaultStorageHelper.PickInProgress = true;
            MainActivity.NoteExternalLaunch();   // 选目录期间不锁
            act.StartActivityForResult(intent, VaultStorageHelper.PickDirRequestCode);
        }
        catch (Exception ex)
        {
            VaultStorageHelper.PickInProgress = false;
            ShowError(L10n.T("无法选择目录"), ex.Message);
        }
    }

    private void OnDirPicked(string? path)
    {
        if (Handler is null) return;   // 页面已分离
        if (path is null) return;   // 取消选择
        if (path.Length == 0)
        {
            ShowError(L10n.T("不支持的目录"), L10n.T("仅支持内部存储目录，SD 卡暂不支持。"));
            return;
        }
        try
        {
            // 切换目录前关闭
            try { _vault.Close(); } catch { }
            _vaultDir = path;
            _loadedPath = null;   // 强制下轮 RefreshState 全量重
            Preferences.Default.Set(VaultStorageHelper.VaultDirKey, path);
            DirLabel.Text = L10n.F("库目录：{0}", _vaultDir);
            UpdatePermBanner();
            if (!VaultStorageHelper.HasAllFilesAccess() && Platform.CurrentActivity is Activity act)
                VaultStorageHelper.RequestAllFilesAccess(act);
            RefreshState();
        }
        catch (Exception ex) { ShowError(L10n.T("切换目录失败"), ex.Message); }
    }

    // 平台选择已关闭
    private async void OnItemTapped(object? sender, TappedEventArgs e)
    {
        if (_bulkUpdating) return;
        if (_suppressTap) { _suppressTap = false; return; }   // 长按抬手
        if (_longPressAt != 0 && Environment.TickCount64 - _longPressAt < 450)
        { _longPressAt = 0; return; }
        if (e.Parameter is not VaultItem item) return;
        _rangeAnchor = -1;
        if (_multiSelect) { item.IsSelected = !item.IsSelected; UpdateSelectHint(); return; }
        await OpenOrEnter(item);
    }

    // 点目录进入；点文
    private async Task OpenOrEnter(VaultItem item)
    {
        if (item.IsDir) { _navDir = 1; _curPath = item.RelPath; LoadDir(); return; }

        // 视频
        if (VaultItem.IsVideoName(item.Name))
        {
            await OpenVideo(item);
            return;
        }

        // 图片
        if (VaultItem.IsImageName(item.Name))
        {
            var all = (FileList.ItemsSource as List<VaultItem>) ?? _vault.ListDir(_curPath);
            var imgs = all.Where(i => !i.IsDir && VaultItem.IsImageName(i.Name)).ToList();
            int idx = imgs.FindIndex(i => i.RelPath == item.RelPath);
            if (idx < 0) { imgs.Add(item); idx = imgs.Count - 1; }
            PauseThumbs();   // 画廊优先
            var page = new ImageViewerPage(_vault, imgs, idx);
            // 画廊关闭即恢复
            // OnAppearing
            page.Disappearing += (_, _) => ResumeThumbs();
            // 画廊里勾选
            page.Disappearing += (_, _) =>
            {
                if (imgs.Any(i => i.IsSelected))
                {
                    SetMultiSelect(true);
                    UpdateSelectHint();
                }
            };
            // animate=false
            await Navigation.PushAsync(page, false);
            return;
        }

        // 文本类后缀
        if (VaultItem.IsTextName(item.Name))
        {
            await OpenPreview(item, false);
            return;
        }

        string? act = await Sheet.ShowAsync(item.Name, L10n.T("取消"), null,
            L10n.T("文本预览"), L10n.T("十六进制预览"), L10n.T("打开"), L10n.T("移出加密库"), L10n.T("导出到文件"));
        switch (act)
        {
            case var _ when act == L10n.T("文本预览"): await OpenPreview(item, false); break;
            case var _ when act == L10n.T("十六进制预览"): await OpenPreview(item, true); break;
            case var _ when act == L10n.T("打开"): await OpenItem(item); break;
            case var _ when act == L10n.T("移出加密库"): await MoveOut(item); break;
            case var _ when act == L10n.T("导出到文件"): await ExportFile(item); break;
        }
    }

    // 只读预览
    private async Task OpenPreview(VaultItem item, bool hex)
    {
        try
        {
            SetBusy(true);
            await Navigation.PushAsync(new PreviewPage(_vault, item.RelPath, item.Name, item.Size, hex), false);
        }
        catch (Exception ex) { ShowError(L10n.T("打开预览失败"), ex.Message); }
        finally { SetBusy(false); }
    }

    // 视频
    private async Task OpenVideo(VaultItem item)
    {
        string dir = "";
        try
        {
            SetBusy(true);
            // 与「打开」共用 cache/preview 分目
            string root = Path.Combine(FileSystem.CacheDirectory, "preview");
            Directory.CreateDirectory(root);
            dir = Path.Combine(root, Hash8(item.RelPath));
            Directory.CreateDirectory(dir);
            PrunePreview(root, keep: dir);
            // 虚拟路径
            string virtualPath = Path.Combine(dir, item.Name);

            PauseThumbs();   // 播放优先
            await ExportSiblingSubtitleAsync(item, dir);
            // 页面重进时字幕
            var page = new VideoViewerPage(virtualPath, item.Name, dir, _vault, item.RelPath,
                async () => await ExportSiblingSubtitleAsync(item, dir));
            // 播放页关闭即恢
            page.Disappearing += (_, _) => ResumeThumbs();
            await Navigation.PushAsync(page, false);
        }
        catch (Exception ex)
        {
            try { if (dir.Length > 0) Directory.Delete(dir, true); } catch { }
            ShowError(L10n.T("打开失败"), ex.Message);
        }
        finally { SetBusy(false); }
    }

    // 库内同名 .srt/.ass 一并导
    // 边界
    private async Task ExportSiblingSubtitleAsync(VaultItem item, string dir)
    {
        try
        {
            await Task.Run(() =>
            {
                string baseName = Path.GetFileNameWithoutExtension(item.Name);
                int slash = item.RelPath.LastIndexOf('/');
                string parent = slash > 0 ? item.RelPath.Substring(0, slash) : "";
                var siblings = _vault.ListDir(parent);
                string? srt = null, ass = null;
                foreach (var s in siblings)
                {
                    if (s.IsDir) continue;
                    if (!string.Equals(Path.GetFileNameWithoutExtension(s.Name), baseName,
                        StringComparison.OrdinalIgnoreCase)) continue;
                    string e = Path.GetExtension(s.Name);
                    if (e.Equals(".srt", StringComparison.OrdinalIgnoreCase)) srt = s.RelPath;
                    else if (e.Equals(".ass", StringComparison.OrdinalIgnoreCase)) ass = s.RelPath;
                }
                string? pick = srt ?? ass;
                if (pick is null) return;
                string dest = Path.Combine(dir, Path.GetFileName(pick));
                int fd = LibcNative.open(dest,
                    LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
                if (fd < 0) return;
                try { _vault.ExportFd(pick, fd, null); }
                finally { LibcNative.close(fd); }
            });
        }
        catch (Exception ex) { MainApplication.LogCaught("video-subtitle-export", ex); }
    }

    // 打开
    private async Task OpenItem(VaultItem item)
    {
        string tmp = "";
        try
        {
            SetBusy(true);
            // 按条目分目录、文
            // 又能让系统应用
            string root = Path.Combine(FileSystem.CacheDirectory, "preview");
            Directory.CreateDirectory(root);
            string dir = Path.Combine(root, Hash8(item.RelPath));
            Directory.CreateDirectory(dir);
            PrunePreview(root, keep: dir);
            tmp = Path.Combine(dir, item.Name);
            int fd = LibcNative.open(tmp,
                LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
            if (fd < 0) throw new Exception(L10n.T("无法创建预览缓存"));
            try { await Task.Run(() => _vault.ExportFd(item.RelPath, fd, OnVaultProgress)); }
            finally { LibcNative.close(fd); }

            MainActivity.NoteExternalLaunch();   // 第三方应用期间
            ExternalAppGuard.TrackPreview(dir);  // 回前台即清掉
            if (SystemOpenHelper.OpenFile(tmp)) return;
            // 无匹配应用
            await Share.Default.RequestAsync(new ShareFileRequest(new ShareFile(tmp)) { Title = item.Name });
        }
        catch (Exception ex) { ShowError(L10n.T("打开失败"), ex.Message); }
        finally { SetBusy(false); }
    }

    // 导入/导出进度
    private void OnVaultProgress(ulong done, ulong total)
    {
        if (total == 0) return;
        double pct = (double)done / total * 100;
        MainThread.BeginInvokeOnMainThread(() => { PathLabel.Text = L10n.F("处理中 {0:F0}%", pct); });
    }
    // 移出加密库
    private async Task MoveOut(VaultItem item)
    {
        bool confirmed = await DisplayAlertAsync(L10n.T("移出加密库"),
            L10n.F("解密「{0}」回原位置，并从库中移除。", item.Name), L10n.T("移出"), L10n.T("取消"));
        if (!confirmed) return;
        try
        {
            SetBusy(true);
            string? origin = GetOrigin(item.RelPath);
            string dst = "";
            bool restored = false;
            if (!string.IsNullOrEmpty(origin) && !origin.StartsWith("content://", StringComparison.Ordinal))
            {
                try
                {
                    string? dir = Path.GetDirectoryName(origin);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    if (!File.Exists(origin))
                    {
                        // 流式解密直写目
                        int ofd = LibcNative.open(origin,
                            LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
                        if (ofd < 0) throw new Exception(L10n.T("无法写入原路径"));
                        try { await Task.Run(() => _vault.ExportFd(item.RelPath, ofd, OnVaultProgress)); }
                        finally { LibcNative.close(ofd); }
                        dst = origin;
                        restored = true;
                    }
                }
                catch { restored = false; }
            }
            if (!restored)
            {
                // 原路径不可用/已
                string dir2 = VaultStorageHelper.ExportDir();
                dst = Path.Combine(dir2, item.Name);
                if (File.Exists(dst))
                {
                    string nm = Path.GetFileNameWithoutExtension(item.Name);
                    string ex = Path.GetExtension(item.Name);
                    for (int i = 1; i < 1000 && File.Exists(dst); i++)
                        dst = Path.Combine(dir2, $"{nm}({i}){ex}");
                }
                int ofd = LibcNative.open(dst,
                    LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
                if (ofd < 0) throw new Exception(L10n.T("无法创建输出文件"));
                try { await Task.Run(() => _vault.ExportFd(item.RelPath, ofd, OnVaultProgress)); }
                finally { LibcNative.close(ofd); }
            }
            await Task.Run(() => _vault.Delete(item.RelPath));
            ClearOrigin(item.RelPath);
            LoadDir();
            string? act = await Sheet.ShowAsync(L10n.F("已恢复为明文：{0}", dst), L10n.T("关闭"), null,
                L10n.T("分享"), L10n.T("删除明文输出"));
            if (act == L10n.T("分享"))
            {
                MainActivity.NoteExternalLaunch();
                await Share.Default.RequestAsync(new ShareFileRequest(new ShareFile(dst)) { Title = item.Name });
            }
            else if (act == L10n.T("删除明文输出"))
            {
                try { File.Delete(dst); }
                catch (Exception ex) { ShowError(L10n.T("删除失败"), ex.Message); }
            }
        }
        catch (Exception ex) { ShowError(L10n.T("移出失败"), ex.Message); }
        finally { SetBusy(false); }
    }

    // 原路径记录
    private const string OriginPrefix = "vault_origin:";

    private static void RememberOrigin(string rel, string origin)
    {
        if (string.IsNullOrEmpty(origin)) return;
        try { Preferences.Default.Set(OriginPrefix + rel, origin); } catch { }
    }

    private static string? GetOrigin(string rel)
    {
        try { return Preferences.Default.Get(OriginPrefix + rel, ""); } catch { return null; }
    }

    private static void ClearOrigin(string rel)
        => Preferences.Default.Remove(OriginPrefix + rel);

    private void OnUp(object? sender, EventArgs e)
    {
        int i = _curPath.LastIndexOf('/');
        _navDir = -1;
        _curPath = i < 0 ? "" : _curPath[..i];
        LoadDir();
    }

    // 移入
    private async void OnMoveIn(object? sender, EventArgs e)
    {
        string? mode = await Sheet.ShowAsync(L10n.T("移入加密库"), L10n.T("取消"), null,
            L10n.T("移入单文件"), L10n.T("移入整个目录"), L10n.T("导入 .ptd 文件"), L10n.T("导入 zip 压缩包"));
        if (mode is null || mode == L10n.T("取消")) return;
        if (mode == L10n.T("导入 zip 压缩包")) { await ImportZipAsync(); return; }
        int algo = await PickImportAlgoAsync();
        if (algo < 0) return;
        if (mode == L10n.T("移入单文件")) await MoveInFiles(algo);
        else if (mode == L10n.T("移入整个目录")) await MoveInDirectory(algo);
        else if (mode == L10n.T("导入 .ptd 文件")) await ImportPtdFiles(algo);
    }

    // 本次导入
    private async Task<int> PickImportAlgoAsync()
    {
        var list = FileCryptoService.Modes()
            .Where(m => m.Available && m.Mode != FeMMode.XChaCha20).ToList();
        var names = new List<string> { L10n.T("默认 XChaCha20") };
        names.AddRange(list.Select(m => m.Name));
        string? pick = await Sheet.ShowAsync(L10n.T("本次导入的加密算法"), L10n.T("取消"), null,
            names.ToArray());
        if (pick is null || pick == L10n.T("取消")) return -1;
        if (pick == L10n.T("默认 XChaCha20")) return 1;   // VDISK_MODE_XCHACHA20
        var chosen = list.FirstOrDefault(x => x.Name == pick);
        return chosen is null ? -1 : (int)chosen.Mode;
    }

    // zip 导入
    private async Task ImportZipAsync()
    {
        FileResult? picked;
        try
        {
            MainActivity.NoteExternalLaunch();
            picked = await FilePicker.Default.PickAsync();
        }
        catch (Exception ex) { ShowError(L10n.T("选择文件失败"), ex.Message); return; }
        if (picked is null) return;
        string name = picked.FileName ?? "";
        if (!name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            ShowError(L10n.T("不是 zip 压缩包"), L10n.T("目前仅支持 .zip；加密 zip / 7z / rar 暂不支持。"));
            return;
        }
        int fd;
        try { fd = FileCryptoService.OpenRead(picked.FullPath ?? ""); }
        catch (Exception ex) { ShowError(L10n.T("打开压缩包失败"), ex.Message); return; }
        try
        {
            var r = await ProgressPage.RunAsync(this, L10n.T("导入 zip"),
                (tracker, ct) => Task.Run(() =>
                    ZipImportService.Import(_vault, fd, _curPath, tracker, ct)));
            LoadDir();
            string msg = L10n.F("完成 {0} · 失败 {1}", r.Ok, r.Failed);
            if (r.Errors.Count > 0) msg += "\n" + string.Join("\n", r.Errors);
            await DisplayAlertAsync(r.Cancelled ? L10n.T("已取消") : L10n.T("导入完成"), msg, L10n.T("确定"));
        }
        catch (Exception ex) { ShowError(L10n.T("导入失败"), ex.Message); }
    }

    // 单文件移入
    private async Task MoveInFiles(int algo)
    {
        List<FileResult> picked;
        try
        {
            MainActivity.NoteExternalLaunch();   // 选文件期间不锁
            var res = await FilePicker.Default.PickMultipleAsync();
            picked = res?.ToList() ?? new List<FileResult>();
        }
        catch (Exception ex) { ShowError(L10n.T("选择文件失败"), ex.Message); return; }
        if (picked.Count == 0) return;

        string? del = await Sheet.ShowAsync(
            L10n.F("将移入 {0} 个文件到加密库", picked.Count), L10n.T("取消"), null,
            L10n.T("移入并删除原文件"), L10n.T("保留原文件"));
        if (del is null || del == L10n.T("取消")) return;
        bool removeSrc = del == L10n.T("移入并删除原文件");

        var jobs = new List<ImportJob>();
        foreach (var f in picked)
        {
            string src = f.FullPath ?? "";
            if (src.Length == 0) continue;
            string name = f.FileName ?? Path.GetFileName(src);
            if (name.Length == 0) name = "file";
            jobs.Add(new ImportJob
            {
                Src = src,
                Name = name,
                Rel = _curPath.Length == 0 ? name : $"{_curPath}/{name}",
            });
        }
        await RunImport(jobs, removeSrc, null, algo: algo);
    }

    // 整目录移入
    private async Task MoveInDirectory(int algo)
    {
        try
        {
            if (Platform.CurrentActivity is not Android.App.Activity act)
            { ShowError(L10n.T("无法选择目录"), L10n.T("当前界面不可用")); return; }
            // native 按真实路径直开
            if (!VaultStorageHelper.HasAllFilesAccess())
            {
                ShowError(L10n.T("需要「所有文件访问」权限"),
                    L10n.T("整目录移入需要存储权限，点顶部「去授权」。"));
                return;
            }
            MainActivity.NoteExternalLaunch();   // 选目录期间不锁
            string? root = await VaultStorageHelper.PickDirectoryAsync(act);
            if (root is null) return;   // 取消选择
            if (root.Length == 0)
            { ShowError(L10n.T("不支持的目录"), L10n.T("仅支持内部存储目录，SD 卡暂不支持。")); return; }

            var files = VaultStorageHelper.CollectFiles(root);
            string top = Path.GetFileName(root.TrimEnd('/'));
            if (string.IsNullOrEmpty(top)) top = L10n.T("目录");
            if (files.Count == 0)
            { ShowError(L10n.T("没有可移入的文件"), L10n.F("目录「{0}」下没有文件。", top)); return; }

            string? del = await Sheet.ShowAsync(
                L10n.F("将移入目录「{0}」共 {1} 个文件", top, files.Count), L10n.T("取消"), null,
                L10n.T("移入并删除原文件"), L10n.T("保留原文件"));
            if (del is null || del == L10n.T("取消")) return;
            bool removeSrc = del == L10n.T("移入并删除原文件");

            var jobs = new List<ImportJob>();
            // 目录时间戳映射
            var dirMtimes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            string relTop = _curPath.Length == 0 ? top : $"{_curPath}/{top}";
            foreach (var f in files)
            {
                string inner = Path.GetRelativePath(root, f).Replace('\\', '/');
                jobs.Add(new ImportJob
                {
                    Src = f,
                    Name = inner,
                    Rel = _curPath.Length == 0 ? $"{top}/{inner}" : $"{_curPath}/{top}/{inner}",
                    MakeDirs = true,
                });
                // 自顶向下登记每
                string rel = relTop;
                string sd = root;
                if (!dirMtimes.ContainsKey(rel)) dirMtimes[rel] = DirMtime(root);
                int slash = inner.LastIndexOf('/');
                if (slash <= 0) continue;
                foreach (var seg in inner[..slash].Split('/'))
                {
                    if (seg.Length == 0) continue;
                    rel += "/" + seg;
                    sd = Path.Combine(sd, seg);
                    if (!dirMtimes.ContainsKey(rel)) dirMtimes[rel] = DirMtime(sd);
                }
            }
            await RunImport(jobs, removeSrc, removeSrc ? root : null, dirMtimes, algo);
        }
        catch (Exception ex) { ShowError(L10n.T("移入失败"), ex.Message); }
    }

    private async Task RunImport(List<ImportJob> jobs, bool removeSrc, string? pruneRoot,
        Dictionary<string, long>? dirMtimes = null, int algo = 1)
    {
        try
        {
            // 入库前空间预检
            long need = 0;
            foreach (var j in jobs) need += Math.Max(0, SrcSize(j.Src));
            long avail = 0;
            try { avail = new global::Android.OS.StatFs(_vault.RootDir).AvailableBytes; }
            catch { }
            if (avail > 0 && need > avail - 64L * 1024 * 1024)
            {
                await DisplayAlertAsync(L10n.T("存储空间不足"),
                    L10n.F("本次移入需要约 {0}，库所在存储仅剩 {1}。请清理空间后重试。",
                        VaultItem.FormatSize((ulong)need), VaultItem.FormatSize((ulong)avail)),
                    L10n.T("确定"));
                return;
            }
            // 结果展示放
            // 展示完
            await ProgressPage.RunAsync(this, L10n.T("移入加密库"),
                (tracker, ct) => Task.Run(() => ImportBatch(tracker, ct, jobs, removeSrc, dirMtimes, algo)),
                after: r => FinishImport(r, removeSrc, pruneRoot));
        }
        catch (Exception ex) { ShowError(L10n.T("移入失败"), ex.Message); }
    }

    private async Task FinishImport(BatchResult r, bool removeSrc, string? pruneRoot)
    {
        if (Handler is null) return;   // Activity 已重建
        LoadDir();
        if (r.Remaining > 0 && r.Ok + r.Failed == 0)
        {
            await DisplayAlertAsync(L10n.T("已取消"),
                L10n.F("未处理 {0} 个文件，已保留在原位置。", r.Remaining), L10n.T("确定"));
            return;
        }
        string msg = L10n.F("成功 {0} 个", r.Ok);
        if (r.Failed > 0) msg += L10n.F("，失败 {0} 个", r.Failed);
        if (r.Remaining > 0) msg += L10n.F("，剩余 {0} 个未处理", r.Remaining);
        if (removeSrc) msg += L10n.T("，原文件已删除");
        if (r.Notes is { Count: > 0 }) msg += "\n" + string.Join("\n", r.Notes);
        if (r.Errors.Count > 0) msg += "\n" + string.Join("\n", r.Errors);
        // 仅在全部成功
        if (removeSrc && r.Failed == 0 && pruneRoot is not null)
            VaultStorageHelper.PruneEmptyDirs(pruneRoot);
        await DisplayAlertAsync(r.Remaining > 0 ? L10n.T("已取消") : L10n.T("移入完成"), msg, L10n.T("确定"));
    }

    // 批量入库
    // 不分批
    // native 每完成一项即回
    private BatchResult ImportBatch(BatchTracker tracker, CancellationToken ct,
        List<ImportJob> jobs, bool removeSrc, Dictionary<string, long>? dirMtimes, int algo)
    {
        const int ChunkSize = 200;
        long total = 0;
        foreach (var j in jobs) total += Math.Max(0, SrcSize(j.Src));
        // 每项一个进度槽
        tracker.Begin(jobs.Count, total);

        int ok = 0, failed = 0, remaining = 0;
        var errors = new List<string>();
        var notes = new List<string>();
        var made = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 本次操作已占用
        var claimed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _vault.ImportBegin();   // 整次任务只派生
        try
        {
        for (int s = 0; s < jobs.Count; s += ChunkSize)
        {
            if (ct.IsCancellationRequested) break;
            int n = Math.Min(ChunkSize, jobs.Count - s);
            // 本批
            var items = new List<(string Rel, int Fd)>(n);
            var meta = new List<(ImportJob Job, long Len)>(n);
            for (int k = 0; k < n; k++)
            {
                var job = jobs[s + k];
                try
                {
                    // 同名冲突
                    string reserved = ReserveImportRel(job.Rel, claimed);
                    if (!string.Equals(reserved, job.Rel, StringComparison.Ordinal))
                    {
                        string oldLeaf = LeafOf(job.Rel);
                        string newLeaf = LeafOf(reserved);
                        notes.Add(L10n.F("「{0}」与库内文件同名，已保存为「{1}」", oldLeaf, newLeaf));
                        job.Rel = reserved;
                        job.Name = job.MakeDirs ? ReplaceLeaf(job.Name, newLeaf) : newLeaf;
                    }
                    if (job.MakeDirs) EnsureVaultDirs(job.Rel, made, dirMtimes);
                    long len = Math.Max(0, SrcSize(job.Src));
                    int fd = FileCryptoService.OpenRead(job.Src);
                    items.Add((job.Rel, fd));
                    meta.Add((job, len));
                }
                catch (Exception ex)
                {
                    failed++;
                    tracker.StartSlot(s + k, s + k + 1, job.Name, 0);
                    tracker.EndSlot(s + k, false);
                    if (errors.Count < 20) errors.Add(L10n.F("失败：{0}：{1}", job.Name, ex.Message));
                }
            }

            // 单文件槽
            var started = new HashSet<int>();
            var startLock = new object();
            void EnsureStarted(int k, ulong size)
            {
                if (k < 0 || k >= meta.Count) return;
                lock (startLock) { if (!started.Add(k)) return; }
                tracker.StartSlot(s + k, s + k + 1, meta[k].Job.Name, size);
            }

            // 单项收尾
            bool[] settled = new bool[meta.Count];
            void FinishOne(int k, VDiskStatus st)
            {
                if (k < 0 || k >= meta.Count || settled[k]) return;
                settled[k] = true;
                var job = meta[k].Job;
                // 早失败/取消
                EnsureStarted(k, (ulong)Math.Max(0, meta[k].Len));
                if (st == VDiskStatus.Cancelled)
                {   // 取消
                    remaining++;
                    tracker.CancelSlot(s + k, s + k + 1, job.Name);
                    return;
                }
                if (st != VDiskStatus.Ok)
                {
                    failed++;
                    tracker.EndSlot(s + k, false);
                    if (errors.Count < 20) errors.Add(L10n.F("失败：{0}：{1}", job.Name, VdiskNative.ErrorText((int)st)));
                    return;
                }
                long srcLen = meta[k].Len;
                // 入库大小必须
                if (srcLen > 0 && _vault.TryGetAttr(job.Rel, out ulong got, out _) && got != (ulong)srcLen)
                    errors.Add(L10n.F("注意：{0}：入库 {1} 字节，源 {2} 字节（大小不符，已存残缺）", job.Name, got, srcLen));
                RememberOrigin(job.Rel, job.Src);
                if (removeSrc)
                {
                    // content
                    // 失败必须报出来
                    string? delErr = SourceCleaner.Delete(job.Src);
                    if (delErr is not null) errors.Add(L10n.F("注意：{0}：{1}", job.Name, delErr));
                }
                ok++;
                tracker.EndSlot(s + k, true);
            }

            var segStates = new List<(List<int> Idxs, List<VDiskStatus> St)>();
            if (items.Count > 0)
            {
                try
                {
                    // 取消探针
                    // 压到「当前文件跑
                    // 逐项进度回调来
                    // 跨批导入
                    // 视频拆子批不压
                    // 子批回调索引映
                    var norm = new List<int>(meta.Count);
                    var vids = new List<int>(meta.Count);
                    for (int k = 0; k < meta.Count; k++)
                        (VaultItem.IsVideoName(meta[k].Job.Rel) ? vids : norm).Add(k);

                    void RunSeg(List<int> idxs, int policy)
                    {
                        if (idxs.Count == 0) return;
                        var sub = new List<(string Rel, int Fd)>(idxs.Count);
                        foreach (int k in idxs) sub.Add((meta[k].Job.Rel, items[k].Fd));
                        try
                        {
                            var st = _vault.ImportManyEx(sub,
                                null,
                                (i, st2) => { if (i >= 0 && i < idxs.Count) FinishOne(idxs[i], st2); },
                                () => ct.IsCancellationRequested,
                                finalize: false, mode: algo, compressPolicy: policy,
                                onItemProgress: (i, d, t) =>
                                {
                                    if (i < 0 || i >= idxs.Count) return;
                                    int ki = idxs[i];
                                    EnsureStarted(ki, t);
                                    tracker.ReportSlot(s + ki, d, t);
                                });
                            segStates.Add((idxs, st));
                        }
                        catch (Exception ex)
                        {
                            // 单段失败不吞另
                            if (errors.Count < 20) errors.Add(L10n.F("批量导入失败：{0}", ex.Message));
                            segStates.Add((idxs,
                                Enumerable.Repeat(VDiskStatus.Internal, idxs.Count).ToList()));
                        }
                    }

                    RunSeg(norm, VdiskNative.CompressDefault);
                    RunSeg(vids, 0);
                }
                catch (Exception ex)
                {
                    if (errors.Count < 20) errors.Add(L10n.F("批量导入失败：{0}", ex.Message));
                }
                finally { foreach (var it in items) LibcNative.close(it.Fd); }
            }

            // 兜底
            // 剩余项整体
            if (ct.IsCancellationRequested)
            {
                for (int k = 0; k < meta.Count; k++)
                    if (!settled[k]) remaining++;
                remaining += Math.Max(0, jobs.Count - (s + n));   // 后续未开始
            }
            else
            {
                var stMap = new Dictionary<int, VDiskStatus>();
                foreach (var seg in segStates)
                    for (int j = 0; j < seg.Idxs.Count && j < seg.St.Count; j++)
                        stMap[seg.Idxs[j]] = seg.St[j];
                for (int k = 0; k < meta.Count; k++)
                    FinishOne(k, stMap.TryGetValue(k, out var st2) ? st2 : VDiskStatus.Internal);
            }
        }
        }
        finally
        {
            try { _vault.ImportEnd(); }   // 清空 KEK 缓存 + 重建一
            catch { /* 条目已 flush+登记，end 仅收尾缓存/密钥，失败不阻断结果返回 */ }
        }
        return new BatchResult(ok, failed, remaining, "", errors, notes);
    }

    // 库内同名冲突改
    private string ReserveImportRel(string rel, HashSet<string> claimed)
    {
        if (!claimed.Contains(rel) && !_vault.TryGetAttr(rel, out _, out _))
        {
            claimed.Add(rel);
            return rel;
        }
        int slash = rel.LastIndexOf('/');
        string dir = slash >= 0 ? rel[..slash] : "";
        string leaf = LeafOf(rel);
        int dot = leaf.LastIndexOf('.');
        string stem = dot > 0 ? leaf[..dot] : leaf;
        string ext = dot > 0 ? leaf[dot..] : "";
        for (int i = 1; i < 1000; i++)
        {
            string candLeaf = $"{stem} ({i}){ext}";
            string cand = dir.Length == 0 ? candLeaf : $"{dir}/{candLeaf}";
            if (!claimed.Contains(cand) && !_vault.TryGetAttr(cand, out _, out _))
            {
                claimed.Add(cand);
                return cand;
            }
        }
        claimed.Add(rel);
        return rel;
    }

    private static string LeafOf(string rel)
    {
        int slash = rel.LastIndexOf('/');
        return slash >= 0 ? rel[(slash + 1)..] : rel;
    }

    private static string ReplaceLeaf(string rel, string leaf)
    {
        int slash = rel.LastIndexOf('/');
        return slash >= 0 ? rel[..(slash + 1)] + leaf : leaf;
    }

    // 源大小
    private static long SrcSize(string src)
    {
        try
        {
            if (!src.StartsWith("content://", StringComparison.Ordinal))
                return new FileInfo(src).Length;
            var uri = Android.Net.Uri.Parse(src);
            var afd = Platform.AppContext.ContentResolver?.OpenAssetFileDescriptor(uri!, "r");
            if (afd is null) return 0;
            long n = afd.Length;
            afd.Close();
            return n < 0 ? 0 : n;
        }
        catch { return 0; }
    }

    private sealed class ImportJob
    {
        public string Src = "";      // 源：本
        public string Name = "";     // 进度页显示名
        public string Rel = "";      // 库内相对路径
        public bool MakeDirs;        // 整目录移入
    }

    // 逐层建库内目录
    // dirMtimes 给「库内相对目录 →
    // 取不到传 0
    private void EnsureVaultDirs(string relFile, HashSet<string> made, Dictionary<string, long>? dirMtimes)
    {
        int idx = relFile.LastIndexOf('/');
        if (idx <= 0) return;
        string dirRel = relFile[..idx];
        var parts = dirRel.Split('/');
        string cur = "";
        foreach (var seg in parts)
        {
            if (seg.Length == 0) continue;
            cur = cur.Length == 0 ? seg : $"{cur}/{seg}";
            if (!made.Add(cur)) continue;              // 本轮已处理
            if (_vault.TryGetAttr(cur, out _, out bool isDir) && isDir) continue;
            long mt = dirMtimes is not null && dirMtimes.TryGetValue(cur, out var v) ? v : 0;
            try { _vault.CreateDir(cur, mt); } catch { }   // 并发/隐式目录已
        }
    }

    // 源目录时间戳
    private static long DirMtime(string dir)
    {
        try { return new DateTimeOffset(Directory.GetLastWriteTimeUtc(dir)).ToUnixTimeSeconds(); }
        catch { return 0; }
    }

    // 预览缓存短哈希
    private static string Hash8(string s)
        => System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes(s))
            .Take(4).Aggregate("", (a, b) => a + b.ToString("x2"));

    // 清掉 1 天
    private static void PrunePreview(string root, string keep)
    {
        try
        {
            var cut = DateTime.Now.AddDays(-1);
            foreach (var d in Directory.GetDirectories(root))
            {
                if (d == keep) continue;
                try
                {
                    if (Directory.GetLastWriteTime(d) > cut) continue;
                    Directory.Delete(d, true);
                }
                catch { }
            }
        }
        catch { }
    }

    private async void OnNewFolder(object? sender, EventArgs e)
    {
        string? name = await DisplayPromptAsync(L10n.T("新建目录"), L10n.T("目录名"));
        if (string.IsNullOrWhiteSpace(name)) return;
        try
        {
            string rel = _curPath.Length == 0 ? name : $"{_curPath}/{name}";
            await Task.Run(() => _vault.CreateDir(rel));
            LoadDir();
        }
        catch (Exception ex) { ShowError(L10n.T("创建失败"), ex.Message); }
    }

    private async Task DeleteOneAsync(VaultItem item)
    {
        string msg = item.IsDir
            ? L10n.F("目录「{0}」移入回收站？可稍后恢复或彻底删除。", item.Name)
            : L10n.F("「{0}」移入回收站？可稍后恢复或彻底删除。", item.Name);
        if (!await DisplayAlertAsync(L10n.T("移入回收站"), msg, L10n.T("移入"), L10n.T("取消"))) return;
        try
        {
            SetBusy(true);
            await Task.Run(() => VaultTrash.MoveToTrash(_vault, item.RelPath, item.Name,
                item.IsDir, item.Size));
            ClearOrigin(item.RelPath);
            if (Handler is not null) LoadDir();   // 页面已分离
            await DisplayAlertAsync(L10n.T("已移入回收站"),
                L10n.F("「{0}」已移入回收站。", item.Name), L10n.T("确定"));
        }
        catch (Exception ex) { ShowError(L10n.T("移入回收站失败"), ex.Message); }
        finally { SetBusy(false); }
    }

    // 恢复密钥管理
    private async void OnRecovery(object? sender, EventArgs e)
    {
        if (!_vault.IsUnlocked) { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先解锁加密库"), L10n.T("确定")); return; }
        try
        {
            string? existing = await SecureStorage.Default.GetAsync(RecoveryKey);
            if (existing is null)
            {
                if (!await DisplayAlertAsync(L10n.T("恢复密钥"),
                        L10n.T("尚未生成恢复密钥。生成并保存好，忘记密码时可找回。"), L10n.T("生成"), L10n.T("取消")))
                    return;
                await GenerateRecovery();
                return;
            }
            string? act = await Sheet.ShowAsync(L10n.T("恢复密钥"), L10n.T("取消"), null,
                L10n.T("复制密钥"), L10n.T("重新生成"), L10n.T("删除恢复密钥"));
            switch (act)
            {
                case var _ when act == L10n.T("复制密钥"):
                    await CopySensitiveAsync(existing);
                    await DisplayAlertAsync(L10n.T("已复制"), L10n.T("已复制到剪贴板，30 秒后自动清除。"), L10n.T("确定"));
                    break;
                case var _ when act == L10n.T("重新生成"):
                    if (await DisplayAlertAsync(L10n.T("确认"), L10n.T("重新生成后旧密钥立即失效。"), L10n.T("重新生成"), L10n.T("取消")))
                        await GenerateRecovery();
                    break;
                case var _ when act == L10n.T("删除恢复密钥"):
                    if (await DisplayAlertAsync(L10n.T("确认"), L10n.T("删除后将无法使用恢复密钥找回主密码。"), L10n.T("删除"), L10n.T("取消")))
                    {
                        await Task.Run(() => _vault.RemoveRecovery());
                        SecureStorage.Default.Remove(RecoveryKey);
                        await DisplayAlertAsync(L10n.T("已删除"), L10n.T("恢复密钥已删除。"), L10n.T("确定"));
                    }
                    break;
            }
        }
        catch (Exception ex) { ShowError(L10n.T("恢复密钥操作失败"), ex.Message); }
    }

    private async Task GenerateRecovery()
    {
        string code = await Task.Run(() =>
        {
            string c = _vault.GenRecoveryCode();
            _vault.CreateRecovery(c);
            return c;
        });
        await SecureStorage.Default.SetAsync(RecoveryKey, code);
        await ShowRecoveryCode(code);
    }

    private async Task ShowRecoveryCode(string code, bool firstTime = false)
    {
        string msg = (firstTime
            ? L10n.T("请立即保存这 48 位恢复密钥，忘记密码时靠它找回：\n\n")
            : "") + code;
        string? act = await Sheet.ShowAsync(L10n.T("恢复密钥"), L10n.T("关闭"), null, L10n.T("复制"));
        if (act == L10n.T("复制"))
        {
            await CopySensitiveAsync(code);
            await DisplayAlertAsync(L10n.T("已复制"), L10n.T("已复制到剪贴板，30 秒后自动清除。"), L10n.T("确定"));
        }
    }

    // 剪贴板敏感内容
    // 30s 后自动清空
    private static async Task CopySensitiveAsync(string text)
    {
        try
        {
            var cm = (Android.Content.ClipboardManager?)Platform.AppContext
                .GetSystemService(Android.Content.Context.ClipboardService);
            if (cm is not null)
            {
                var clip = Android.Content.ClipData.NewPlainText("recovery", text);
                var desc = clip.Description;
                if (desc is not null)
                {
                    // 13+ 标记敏感
                    var extras = new Android.OS.PersistableBundle();
                    extras.PutBoolean(Android.Content.ClipDescription.ExtraIsSensitive, true);
                    desc.Extras = extras;
                    cm.PrimaryClip = clip;
                }
                else await Clipboard.Default.SetTextAsync(text);
            }
            else
            {
                await Clipboard.Default.SetTextAsync(text);
            }
        }
        catch { await Clipboard.Default.SetTextAsync(text); }
        _ = ClearClipboardLaterAsync(text);
    }

    private static async Task ClearClipboardLaterAsync(string expected)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30));
            if (!Clipboard.Default.HasText) return;
            if (await Clipboard.Default.GetTextAsync() == expected)
                await Clipboard.Default.SetTextAsync(string.Empty);
        }
        catch { /* 剪贴板可能被系统清理 */ }
    }

    // 重建索引
    // 未解锁时先走本
    // 锁态下不暴露任
    private bool _reindexAfterUnlock;

    private async void OnReindex(object? sender, EventArgs e)
    {
        if (!VaultService.Exists(_vaultDir))
        { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先创建加密库"), L10n.T("确定")); return; }

        if (!_vault.IsUnlocked)
        {
            _reindexAfterUnlock = true;
            UnlockMsg.Text = L10n.T("输入密码解锁后将重建索引。");
            UnlockMsg.IsVisible = true;
            UnlockPwd.Focus();
            return;
        }
        await RunReindexAsync();
    }

    // 全库完整性自检
    private async void OnIntegrityCheck(object? sender, EventArgs e)
    {
        if (!VaultService.Exists(_vaultDir))
        { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先创建加密库"), L10n.T("确定")); return; }
        if (!_vault.IsUnlocked)
        {
            UnlockMsg.Text = L10n.T("请先解锁，再点「完整性自检」。");
            UnlockMsg.IsVisible = true;
            UnlockPwd.Focus();
            return;
        }
        CheckReport rep;
        try
        {
            rep = await ProgressPage.RunAsync(this, L10n.T("完整性自检"), (tracker, ct) => Task.Run(() =>
            {
                tracker.BeginCount(0);   // 文件总数
                int n = 0;               // 当前文件序号
                return _vault.CheckLibrary(
                    (d, t) => tracker.ReportAggregate(d, t),
                    () => ct.IsCancellationRequested,
                    name => tracker.SetCurrent(++n, name));   // 名字只
            }));
        }
        catch (Exception ex) { ShowError(L10n.T("自检失败"), ex.Message); return; }
        if (Handler is null) return;

        var lines = new List<string>
        {
            rep.Cancelled
                ? L10n.F("已取消：处理了 {0} / {1} 个文件。", rep.FilesChecked, rep.FilesTotal)
                : L10n.F("已校验 {0} / {1} 个文件。", rep.FilesChecked, rep.FilesTotal),
            L10n.F("校验通过：{0}", VaultItem.FormatSize(rep.BytesChecked)),
        };
        if (rep.FilesFailed > 0) lines.Add(L10n.F("校验失败（密文损坏或口令不符）：{0} 个", rep.FilesFailed));
        if (rep.FilesMissing > 0) lines.Add(L10n.F("索引有登记但 .ptd 缺失：{0} 个", rep.FilesMissing));
        if (rep.Orphans > 0)
            lines.Add(L10n.F("{0} 个 .ptd 文件未登记在索引（孤儿文件）\n点「重建索引」可纳入。", rep.Orphans));
        bool ok = !rep.Cancelled && rep.FilesFailed == 0 && rep.FilesMissing == 0 && rep.Orphans == 0;
        await DisplayAlertAsync(ok ? L10n.T("自检通过") : L10n.T("自检发现问题"), string.Join("\n", lines), L10n.T("确定"));
    }

    // 局域网只读共享
    private async void OnLanShare(object? sender, EventArgs e)
    {
        if (!VaultService.Exists(_vaultDir))
        { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先创建加密库"), L10n.T("确定")); return; }
        await Navigation.PushModalAsync(new LanSharePage());
    }

    private async Task RunReindexAsync()
    {
        try
        {
            // 模态进度页 + 通知
            bool cancelled = await ProgressPage.RunAsync<bool>(this, L10n.T("重建索引"),
                (tracker, ct) => Task.Run(() =>
                {
                    tracker.BeginCount(0);   // 文件总数
                    return _vault.ReindexEx(
                        (d, t) => tracker.ReportAggregate(d, t),
                        () => ct.IsCancellationRequested);
                }));
            if (Handler is null) return;     // Activity 已重建
            RefreshState();                  // 重建后刷新列表
            if (!cancelled)
                await DisplayAlertAsync(L10n.T("完成"), L10n.T("索引已重建。"), L10n.T("确定"));
            else
                await DisplayAlertAsync(L10n.T("已取消"), L10n.T("索引未改动，文件全部保留在库中。"), L10n.T("确定"));
        }
        catch (Exception ex) { ShowError(L10n.T("重建索引失败"), ex.Message); }
    }

    private static List<VaultItem> SortItems(List<VaultItem> items)
    {
        int mode = Math.Clamp(Preferences.Default.Get(SortKey, 0), 0, SortNames.Length - 1);
        int Cmp(VaultItem a, VaultItem b)
        {
            switch (mode)
            {
                case 1: return string.Compare(b.Name, a.Name, StringComparison.OrdinalIgnoreCase);
                case 2: return a.Size.CompareTo(b.Size);
                case 3: return b.Size.CompareTo(a.Size);
                case 4: return b.Mtime.CompareTo(a.Mtime);
                case 5: return a.Mtime.CompareTo(b.Mtime);
                case 6:
                    string ea = Path.GetExtension(a.Name), eb = Path.GetExtension(b.Name);
                    int c = string.Compare(ea, eb, StringComparison.OrdinalIgnoreCase);
                    return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                default: return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            }
        }
        // 目录始终优先
        return items.OrderByDescending(i => i.IsDir).ThenBy(i => i, Comparer<VaultItem>.Create(Cmp)).ToList();
    }

    private async void OnSort(object? sender, EventArgs e)
    {
        if (!_vault.IsUnlocked) { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先解锁加密库"), L10n.T("确定")); return; }
        int cur = Math.Clamp(Preferences.Default.Get(SortKey, 0), 0, SortNames.Length - 1);
        string? pick = await Sheet.ShowAsync(L10n.T("排序方式"), L10n.T("取消"), null, SortNames);
        if (pick is null) return;
        int idx = Array.IndexOf(SortNames, pick);
        if (idx < 0 || idx == cur) return;
        Preferences.Default.Set(SortKey, idx);
        LoadDir();
    }

    private async void OnSearch(object? sender, EventArgs e)
    {
        if (!_vault.IsUnlocked) { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先解锁加密库"), L10n.T("确定")); return; }
        await Navigation.PushAsync(new SearchPage(_vault, _curPath, item => { _ = OpenOrEnter(item); }));
    }

    private async void OnFavorites(object? sender, EventArgs e)
    {
        if (!_vault.IsUnlocked) { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先解锁加密库"), L10n.T("确定")); return; }
        await Navigation.PushAsync(new FavoritesPage(_vault, item => { _ = OpenOrEnter(item); }));
    }
    private async void OnTrash(object? sender, EventArgs e)
    {
        if (!_vault.IsUnlocked)
        {
            await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先解锁加密库"), L10n.T("确定"));
            return;
        }
        try { await Navigation.PushModalAsync(new TrashPage()); }
        catch (Exception ex) { ShowError(L10n.T("打开回收站失败"), ex.Message); }
    }

    // 重命名
    private async Task RenameOneAsync(VaultItem item)
    {
        string? name = await DisplayPromptAsync(L10n.T("重命名"), L10n.T("新名称"), initialValue: item.Name);
        if (string.IsNullOrWhiteSpace(name) || name == item.Name) return;
        try
        {
            string newRel = _curPath.Length == 0 ? name : $"{_curPath}/{name}";
            await Task.Run(() => _vault.Rename(item.RelPath, newRel));
            // 原路径记录随条
            string? origin = GetOrigin(item.RelPath);
            if (origin is not null) { RememberOrigin(newRel, origin); ClearOrigin(item.RelPath); }
            LoadDir();
        }
        catch (Exception ex) { ShowError(L10n.T("重命名失败"), ex.Message); }
    }

    // 导出
    private async Task ExportFile(VaultItem item)
    {
        try
        {
            SetBusy(true);
            string dir = VaultStorageHelper.ExportDir();
            string dst = Path.Combine(dir, item.Name);
            if (File.Exists(dst))
            {
                string nm = Path.GetFileNameWithoutExtension(item.Name);
                string ex = Path.GetExtension(item.Name);
                for (int i = 1; i < 1000 && File.Exists(dst); i++)
                    dst = Path.Combine(dir, $"{nm}({i}){ex}");
            }
            int fd = LibcNative.open(dst,
                LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
            if (fd < 0) throw new Exception(L10n.T("无法创建输出文件"));
            try { await Task.Run(() => _vault.ExportFd(item.RelPath, fd, OnVaultProgress)); }
            finally { LibcNative.close(fd); }
            string? act = await Sheet.ShowAsync(L10n.F("已导出到：{0}", dst), L10n.T("关闭"), null, L10n.T("分享"));
            if (act == L10n.T("分享"))
            {
                MainActivity.NoteExternalLaunch();   // 分享面板期间
                await Share.Default.RequestAsync(new ShareFileRequest(new ShareFile(dst)) { Title = item.Name });
            }
        }
        catch (Exception ex) { ShowError(L10n.T("导出失败"), ex.Message); }
        finally { SetBusy(false); }
    }

    // 库设置
    private async void OnVaultSettings(object? sender, EventArgs e)
    {
        if (!_vault.IsUnlocked)
        { await DisplayAlertAsync(L10n.T("提示"), L10n.T("请先解锁加密库"), L10n.T("确定")); return; }
        try
        {
            RefreshVaultSettingsChoices();
            UiFx.Reveal(VaultSettingsOverlay);
        }
        catch (Exception ex) { ShowError(L10n.T("库设置失败"), ex.Message); }
    }

    // vault.meta 的 default_mode /
    private (int Mode, int Policy) ReadVaultDefaults()
    {
        try
        {
            string dir = _vault.RootDir.Length > 0 ? _vault.RootDir : _vaultDir;
            string path = System.IO.Path.Combine(dir, "vault.meta");
            if (!System.IO.File.Exists(path)) return (1, VdiskNative.CompressAuto);
            using var doc = System.Text.Json.JsonDocument.Parse(System.IO.File.ReadAllText(path));
            var root = doc.RootElement;
            int mode = root.TryGetProperty("default_mode", out var m) && m.TryGetInt32(out int mv)
                ? mv : 1;
            int policy = root.TryGetProperty("compress_policy", out var p) && p.TryGetInt32(out int pv)
                ? pv : VdiskNative.CompressAuto;
            if (policy == VdiskNative.CompressDefault) policy = VdiskNative.CompressAuto;
            return (mode, policy);
        }
        catch { return (1, VdiskNative.CompressAuto); }
    }

    private void RefreshVaultSettingsChoices()
    {
        var (mode, policy) = ReadVaultDefaults();
        // 全量列出
        _vaultSettingsAlgos = FileCryptoService.Modes().ToList();
        int algoIdx = _vaultSettingsAlgos.FindIndex(m => (int)m.Mode == mode);
        int compIdx = Array.IndexOf(CompressLevels, policy);
        VaultSettingsAlgoLabel.Text = algoIdx >= 0 ? L10n.T("默认算法")
            : L10n.F("默认算法（当前：未知 {0}）", mode);
        VaultSettingsCompressLabel.Text = compIdx >= 0 ? L10n.T("压缩策略")
            : L10n.F("压缩策略（当前：自定义档位 {0}）", policy);
        ChoiceUi.BuildModeRows(VaultSettingsAlgoChoices,
            _vaultSettingsAlgos, algoIdx, OnVaultSettingsAlgoSelected,
            VaultSettingsAlgoDetail, check: true);
        ChoiceUi.BuildChips(VaultSettingsCompressChoices, CompressNames(), compIdx,
            OnVaultSettingsCompressSelected, check: true);
        VaultSettingsCompressHint.Text = CryptoPage.CompressHintText(compIdx >= 0 ? compIdx : 0);
    }

    private async void OnVaultSettingsAlgoSelected(int index)
    {
        if (index < 0 || index >= _vaultSettingsAlgos.Count) return;
        if (!_vaultSettingsAlgos[index].Available) return;   // 不可用算法不能
        try
        {
            await Task.Run(() => _vault.SetDefaultMode((int)_vaultSettingsAlgos[index].Mode,
                VdiskNative.CompressDefault));
        }
        catch (Exception ex)
        {
            RefreshVaultSettingsChoices();
            ShowError(L10n.T("库设置失败"), ex.Message);
        }
    }

    private async void OnVaultSettingsCompressSelected(int index)
    {
        if (index < 0 || index >= CompressLevels.Length) return;
        try
        {
            await Task.Run(() => _vault.SetDefaultMode(0, CompressLevels[index]));
        }
        catch (Exception ex)
        {
            RefreshVaultSettingsChoices();
            ShowError(L10n.T("库设置失败"), ex.Message);
        }
    }

    private void OnVaultSettingsClose(object? sender, EventArgs e)
        => UiFx.Hide(VaultSettingsOverlay);

    private void OnVaultSettingsBackdropTapped(object? sender, TappedEventArgs e)
        => UiFx.Hide(VaultSettingsOverlay);

    // 区块
    private IEnumerable<VaultItem> CurrentItems()
        => (FileList.ItemsSource as IEnumerable<VaultItem>) ?? Enumerable.Empty<VaultItem>();

    private List<VaultItem> SelectedItems() => CurrentItems().Where(i => i.IsSelected).ToList();

    private void SetMultiSelect(bool on, bool skipItemReset = false)
    {
        if (_multiSelect == on) return;
        _bulkUpdating = true;
        try
        {
            if (!on && !skipItemReset)
                foreach (var it in CurrentItems()) it.IsSelected = false;
        }
        finally { _bulkUpdating = false; }
        _multiSelect = on;
        if (!on) _rangeAnchor = -1;
        SetView(NormalBar, !on);
        SetView(SelectBar, on);
        if (on) UpdateSelectHint();
        else PathLabel.Text = "/" + _curPath;
    }

    private void UpdateSelectHint()
    {
        if (_multiSelect) PathLabel.Text = L10n.F("已选 {0} 项", SelectedItems().Count);
    }

    private void RebuildSelection(List<VaultItem> want)
    {
        _bulkUpdating = true;
        try
        {
            var set = want.ToHashSet();
            foreach (var it in CurrentItems()) it.IsSelected = set.Contains(it);
        }
        finally { _bulkUpdating = false; }
        UpdateSelectHint();
    }

    private void AddSelection(VaultItem item)
    {
        item.IsSelected = true;
        UpdateSelectHint();
    }

    // 左滑到底切换选
    private void OnSelectSwipe(object? sender, EventArgs e)
    {
        VaultItem? item = sender switch
        {
            SwipeItemView sv => sv.CommandParameter as VaultItem,
            SwipeItem si => si.CommandParameter as VaultItem,
            _ => null
        };
        if (item is null) return;
        // 显式收起
        if (FindSwipeView(sender as Element) is SwipeView hostSwipe)
            MainThread.BeginInvokeOnMainThread(() => { try { hostSwipe.Close(false); } catch { } });
        if (!_multiSelect) { SetMultiSelect(true); _rangeAnchor = -1; }

        var items = CurrentItems().ToList();
        int idx = items.IndexOf(item);
        if (item.IsSelected)
        {
            item.IsSelected = false;
            _rangeAnchor = -1;
            UpdateSelectHint();
        }
        else if (_rangeAnchor >= 0 && _rangeAnchor < items.Count && idx >= 0 && _rangeAnchor != idx)
        {
            // 与上一次左滑
            int lo = Math.Min(_rangeAnchor, idx), hi = Math.Max(_rangeAnchor, idx);
            var want = SelectedItems();
            for (int i = lo; i <= hi; i++)
                if (!want.Contains(items[i])) want.Add(items[i]);
            RebuildSelection(want);
            _rangeAnchor = idx;
        }
        else
        {
            AddSelection(item);
            _rangeAnchor = idx;
        }
    }

    private static SwipeView? FindSwipeView(Element? e)
    {
        while (e is not null)
        {
            if (e is SwipeView sv) return sv;
            e = e.Parent;
        }
        return null;
    }

    // 松手一律收起
    private readonly HashSet<SwipeView> _closingSwipes = new();

    private void OnSwipeEnded(object? sender, SwipeEndedEventArgs e)
    {
        if (sender is not SwipeView sv) return;
        if (!_closingSwipes.Add(sv)) return;
        MainThread.BeginInvokeOnMainThread(() =>
        {
            try { sv.Close(false); } catch { }
            _closingSwipes.Remove(sv);
        });
    }

    private void OnSelectAll(object? sender, EventArgs e)
    {
        _rangeAnchor = -1;
        RebuildSelection(CurrentItems().ToList());
    }

    // 取消 = 清空选择并
    private void OnSelectNone(object? sender, EventArgs e) => SetMultiSelect(false);

    private void OnSelectInvert(object? sender, EventArgs e)
    {
        _rangeAnchor = -1;
        var cur = SelectedItems().ToHashSet();
        RebuildSelection(CurrentItems().Where(i => !cur.Contains(i)).ToList());
    }

    // 区块
    // TapGestureRecognizer 会消费
    // 改在 Touch 事件里自计
    private void OnItemGridHandlerChanged(object? sender, EventArgs e)
    {
        if (sender is not Grid g) return;
        if (g.Handler?.PlatformView is not Android.Views.View pv) return;
        pv.LongClickable = true;
        pv.LongClick -= OnNativeLongClick;
        pv.LongClick += OnNativeLongClick;
        // 去掉平台选中态 ripple /
        try { pv.Foreground = null; pv.StateListAnimator = null; } catch { }
        Android.Views.IViewParent? p = pv.Parent;
        for (int i = 0; i < 3 && p is Android.Views.View v; i++)
        {
            try { v.Foreground = null; v.StateListAnimator = null; } catch { }
            p = v.Parent;
        }
        // 只挂行视图
        _gridByNative[pv.Handle] = g;
        if (_touchHooked.Add(pv.Handle))
        {
            pv.Touch -= OnNativeRowTouch;
            pv.Touch += OnNativeRowTouch;
        }
    }

    private void OnNativeRowTouch(object? sender, Android.Views.View.TouchEventArgs e)
    {
        var ev = e.Event;
        if (ev is null || sender is not Android.Views.View v) return;
        switch (ev.ActionMasked)
        {
            case Android.Views.MotionEventActions.Down:
                // 长按后若 Tap 未触发
                if (_suppressTap && Environment.TickCount64 - _lastMenuAt > 2500) _suppressTap = false;
                _lpX = ev.RawX; _lpY = ev.RawY;
                StartLongPress(v);
                break;
            case Android.Views.MotionEventActions.Move:
                if (global::System.Math.Abs(ev.RawX - _lpX) > 20 ||
                    global::System.Math.Abs(ev.RawY - _lpY) > 20) CancelLongPress();
                break;
            case Android.Views.MotionEventActions.Up:
            case Android.Views.MotionEventActions.Cancel:
                CancelLongPress();
                break;
        }
        // 不碰 e.Handled
    }

    private void StartLongPress(Android.Views.View v)
    {
        CancelLongPress();
        var cts = new CancellationTokenSource();
        _lpCts = cts;
        _ = Task.Run(async () =>
        {
            try { await Task.Delay(550, cts.Token); } catch { return; }
            if (cts.IsCancellationRequested || _lpCts != cts) return;
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (cts.IsCancellationRequested || _lpCts != cts) return;
                _lpCts = null;
                FireLongPress(v);
            });
        });
    }

    private void CancelLongPress()
    {
        var c = _lpCts; _lpCts = null;
        try { c?.Cancel(); c?.Dispose(); } catch { }
    }

    private void OnNativeLongClick(object? sender, Android.Views.View.LongClickEventArgs e)
    {
        e.Handled = true;
        if (sender is Android.Views.View pv) FireLongPress(pv);
    }

    private void FireLongPress(Android.Views.View v)
    {
        long now = Environment.TickCount64;
        if (now - _lastMenuAt < 1000) return;   // LongClick 与 Touch 双路去重
        _lastMenuAt = now;
        _longPressAt = now;
        _suppressTap = true;
        CancelLongPress();
        if (!_gridByNative.TryGetValue(v.Handle, out var g)) return;
        ResetRowState(v);
        if (FindSwipeView(g) is SwipeView sv)
            MainThread.BeginInvokeOnMainThread(() => { try { sv.Close(false); } catch { } });
        if (g.BindingContext is VaultItem item) ShowItemMenu(item);
    }

    // 清掉平台
    private static void ResetRowState(Android.Views.View v)
    {
        try { v.Pressed = false; v.Selected = false; } catch { }
        Android.Views.IViewParent? p = v.Parent;
        for (int i = 0; i < 6 && p is Android.Views.View up; i++)
        {
            try { up.Pressed = false; up.Selected = false; up.Foreground = null; } catch { }
            p = up.Parent;
        }
    }

    // 页内无标题菜单
    private Task<string?> ShowMenuAsync(params string[] actions)
        => Sheet.ShowAsync(null, L10n.T("取消"),
            L10n.T("直接删除（不经过回收站）"), actions);

    // 密码输入
    private Task<string?> PromptPasswordAsync(string title, string hint)
    {
        _pwdTcs?.TrySetResult(null);
        PwdTitle.Text = title;
        PwdHint.Text = hint;
        PwdEntry.Text = "";
        _pwdTcs = new TaskCompletionSource<string?>();
        UiFx.Reveal(PwdOverlay);
        return _pwdTcs.Task;
    }

    private void ClosePwd(string? value)
    {
        UiFx.Hide(PwdOverlay);
        PwdEntry.Text = "";
        var tcs = _pwdTcs; _pwdTcs = null;
        tcs?.TrySetResult(value);
    }

    private void OnPwdOk(object? sender, EventArgs e) => ClosePwd(PwdEntry.Text);
    private void OnPwdCancel(object? sender, EventArgs e) => ClosePwd(null);
    private void OnPwdBackdropTapped(object? sender, TappedEventArgs e) => ClosePwd(null);

    // 无标题列表
    private async void ShowItemMenu(VaultItem clicked, List<VaultItem>? forced = null)
    {
        var targets = forced ?? (_multiSelect && clicked.IsSelected && SelectedItems().Count > 1
            ? SelectedItems() : new List<VaultItem> { clicked });
        if (targets.Count == 0) return;
        bool hasFile = targets.Any(t => !t.IsDir);
        // 「直接删除」紧跟
        var acts = new List<string> { L10n.T("移出"), L10n.T("重命名"), L10n.T("移动到…"), L10n.T("删除"),
            L10n.T("直接删除（不经过回收站）"), L10n.T("属性") };
        if (hasFile) acts.AddRange(new[] { L10n.T("文本预览"), L10n.T("十六进制预览") });
        if (hasFile) acts.Add(L10n.T("复制到…"));
        if (targets.Count == 1)
            acts.Add(VaultFavorites.Contains(_vault, targets[0].RelPath) ? L10n.T("取消收藏") : L10n.T("收藏"));
        acts.Add(L10n.T("导出为 .ptd"));
        string? act = await ShowMenuAsync(acts.ToArray());
        switch (act)
        {
            case var _ when act == L10n.T("移出"):
                if (targets.Count == 1) await MoveOut(targets[0]);
                else await MoveOutManyAsync(targets);
                break;
            case var _ when act == L10n.T("重命名"):
                if (targets.Count == 1) await RenameOneAsync(targets[0]);
                else OpenRenameOverlay(targets);
                break;
            case var _ when act == L10n.T("复制到…"): await CopyToAsync(targets.Where(t => !t.IsDir).ToList()); break;
            case var _ when act == L10n.T("移动到…"): await MoveToAsync(targets); break;
            case var _ when act == L10n.T("删除"):
                if (targets.Count == 1) await DeleteOneAsync(targets[0]);
                else await DeleteManyAsync(targets);
                break;
            case var _ when act == L10n.T("直接删除（不经过回收站）"): await DeleteForeverAsync(targets); break;
            case var _ when act == L10n.T("属性"): ShowProperties(targets); break;
            case var _ when act == L10n.T("文本预览"):
            case var _ when act == L10n.T("十六进制预览"):
                if (targets.Any(t => !t.IsDir))
                {
                    var f = targets.First(t => !t.IsDir);
                    await OpenPreview(f, act == L10n.T("十六进制预览"));
                }
                break;
            case var _ when act == L10n.T("收藏"):
            case var _ when act == L10n.T("取消收藏"):
                if (targets.Count == 1)
                {
                    bool added = VaultFavorites.Toggle(_vault, targets[0].RelPath);
                    await DisplayAlertAsync(L10n.T("收藏"), added ? L10n.T("已加入收藏") : L10n.T("已取消收藏"), L10n.T("确定"));
                }
                break;
            case var _ when act == L10n.T("导出为 .ptd"): await ExportPtdManyAsync(targets); break;
        }
    }

    // 库内复制
    private async Task CopyToAsync(List<VaultItem> files)
    {
        if (files.Count == 0) return;
        await Navigation.PushAsync(new DirPickerPage(_vault, _curPath,
            dest => CopyIntoDirAsync(files, dest)));
    }

    private async Task CopyIntoDirAsync(List<VaultItem> files, string destDir)
    {
        var r = await ProgressPage.RunAsync(this, L10n.T("复制"),
            (tracker, ct) => Task.Run(() =>
            {
                long total = 0;
                foreach (var f in files) total += (long)f.Size;
                tracker.Begin(files.Count, total);
                int ok = 0;
                var errs = new List<string>();
                int idx = 0;
                foreach (var f in files)
                {
                    if (ct.IsCancellationRequested) break;
                    idx++;
                    string name = f.Name;
                    string dst = UniqueDest(destDir, name, false);
                    string dstName = dst.Length == 0 ? "" : (dst.Contains('/') ? dst[(dst.LastIndexOf('/') + 1)..] : dst);
                    tracker.StartSlot(idx, idx, dstName, f.Size);
                    try
                    {
                        _vault.CopyFile(f.RelPath, dst, (d, t) =>
                        {
                            // native 现已
                            tracker.ReportSlot(idx, d, f.Size);
                        }, () => ct.IsCancellationRequested, rewriteName: true);
                        tracker.EndSlot(idx, true);
                        ok++;
                    }
                    catch (Exception ex)
                    {
                        tracker.EndSlot(idx, false);
                        if (errs.Count < 5) errs.Add(L10n.F("{0}：{1}", f.Name, ex.Message));
                    }
                }
                return (ok, errs.ToArray());
            }));
        LoadDir();
        string msg = L10n.F("已复制 {0} 项", r.Item1);
        if (r.Item2.Length > 0) msg += "\n" + string.Join("\n", r.Item2);
        await DisplayAlertAsync(L10n.T("复制完成"), msg, L10n.T("确定"));
    }

    // 库内移动
    private async Task MoveToAsync(List<VaultItem> targets)
    {
        if (targets.Count == 0) return;
        await Navigation.PushAsync(new DirPickerPage(_vault, _curPath,
            dest => MoveIntoDirAsync(targets, dest)));
    }

    private async Task MoveIntoDirAsync(List<VaultItem> targets, string destDir)
    {
        var r = await ProgressPage.RunAsync(this, L10n.T("移动到"),
            (tracker, ct) => Task.Run(() =>
            {
                tracker.Begin(targets.Count, targets.Sum(t => (long)t.Size));
                var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var pairs = new List<(string From, string To)>();
                var names = new List<string>();
                var slots = new List<int>();
                int idx = 0;
                foreach (var it in targets)
                {
                    if (ct.IsCancellationRequested) break;
                    idx++;
                    tracker.StartSlot(idx, idx, it.Name, it.Size);
                    string srcParent = ParentOf(it.RelPath);
                    if (srcParent == destDir) { tracker.EndSlot(idx, true); continue; }   // 已在目标目录
                    if (it.IsDir && (destDir == it.RelPath || destDir.StartsWith(it.RelPath + "/")))
                    {
                        tracker.EndSlot(idx, false);
                        continue;   // 移到自身/子目录
                    }
                    string dest = UniqueDest(destDir, it.Name, it.IsDir, used);
                    used.Add(dest);
                    pairs.Add((it.RelPath, dest));
                    names.Add(it.Name);
                    slots.Add(idx);
                }
                // native 一次批量
                int[] st = pairs.Count > 0 ? _vault.RenameMany(pairs) : Array.Empty<int>();
                int ok = 0;
                var errs = new List<string>();
                for (int i = 0; i < st.Length; i++)
                {
                    tracker.EndSlot(slots[i], st[i] == 0);
                    if (st[i] == 0) { ok++; ClearOrigin(pairs[i].From); }
                    else if (errs.Count < 5)
                        errs.Add(L10n.F("{0}：{1}", names[i],
                            VaultService.StatusText((VDiskStatus)st[i])));
                }
                return (ok, errs.ToArray());
            }));
        SetMultiSelect(false);
        LoadDir();
        string msg = L10n.F("已移动 {0} 项", r.Item1);
        if (r.Item2.Length > 0) msg += "\n" + string.Join("\n", r.Item2);
        await DisplayAlertAsync(L10n.T("移动到"), msg, L10n.T("确定"));
    }

    private static string ParentOf(string rel)
    {
        int slash = rel.LastIndexOf('/');
        return slash < 0 ? "" : rel[..slash];
    }

    private string UniqueDest(string destDir, string name, bool isDir, HashSet<string>? used = null)
    {
        string stem = name, ext = "";
        if (!isDir)
        {
            int dot = name.LastIndexOf('.');
            if (dot > 0) { stem = name[..dot]; ext = name[dot..]; }
        }
        for (int i = 0; i < 1000; i++)
        {
            string candName = i == 0 ? name : $"{stem} ({i}){ext}";
            string cand = destDir.Length == 0 ? candName : $"{destDir}/{candName}";
            // used
            if ((used is null || !used.Contains(cand)) && !_vault.TryGetAttr(cand, out _, out _)) return cand;
        }
        return (destDir.Length == 0 ? "" : destDir + "/") + $"{stem}-{Guid.NewGuid():N}{ext}";
    }

    // 区块
    private async Task MoveOutManyAsync(List<VaultItem> items)
    {
        var files = items.Where(i => !i.IsDir).ToList();
        if (files.Count == 0)
        { await DisplayAlertAsync(L10n.T("提示"), L10n.T("所选均为目录，暂不支持批量移出。"), L10n.T("确定")); return; }
        if (!await DisplayAlertAsync(L10n.T("移出加密库"),
                L10n.F("解密 {0} 个文件回原位置，并从库中移除。", files.Count),
                L10n.T("移出"), L10n.T("取消"))) return;
        int ok = 0;
        var errs = new List<string>();
        string last = "";
        var r = await ProgressPage.RunAsync(this, L10n.T("移出加密库"),
            (tracker, ct) => Task.Run(() =>
            {
                tracker.Begin(files.Count, files.Sum(t => (long)t.Size));
                int ok2 = 0;
                var errs2 = new List<string>();
                string last2 = "";
                int idx = 0;
                foreach (var it in files)
                {
                    if (ct.IsCancellationRequested) break;
                    idx++;
                    tracker.StartSlot(idx, idx, it.Name, it.Size);
                    string? origin = GetOrigin(it.RelPath);
                    bool useOrigin = !string.IsNullOrEmpty(origin)
                        && !origin!.StartsWith("content://", StringComparison.Ordinal)
                        && !File.Exists(origin);
                    string dst = "";
                    if (useOrigin)
                    {
                        try
                        {
                            string? dir = Path.GetDirectoryName(origin!);
                            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                            dst = origin!;
                        }
                        catch { useOrigin = false; }
                    }
                    if (!useOrigin)
                    {
                        string d2 = VaultStorageHelper.ExportDir();
                        dst = Path.Combine(d2, it.Name);
                        if (File.Exists(dst))
                            dst = Path.Combine(d2, Path.GetFileNameWithoutExtension(it.Name)
                                + "_" + Guid.NewGuid().ToString("N")[..6] + Path.GetExtension(it.Name));
                    }
                    int ofd = LibcNative.open(dst,
                        LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
                    if (ofd < 0)
                    {
                        tracker.EndSlot(idx, false);
                        if (errs2.Count < 5) errs2.Add(L10n.F("{0}：无法创建输出文件", it.Name));
                        continue;
                    }
                    bool exported = false;
                    try { _vault.ExportFd(it.RelPath, ofd, (d, t) => tracker.ReportSlot(idx, d, it.Size)); exported = true; }
                    catch (Exception ex) { if (errs2.Count < 5) errs2.Add(L10n.F("{0}：{1}", it.Name, ex.Message)); }
                    finally { LibcNative.close(ofd); }
                    if (!exported) { tracker.EndSlot(idx, false); continue; }
                    try
                    {
                        _vault.Delete(it.RelPath);
                        ClearOrigin(it.RelPath);
                        tracker.EndSlot(idx, true);
                        ok2++; last2 = dst;
                    }
                    catch (Exception ex)
                    {
                        tracker.EndSlot(idx, false);
                        if (errs2.Count < 5) errs2.Add(L10n.F("{0}：{1}", it.Name, ex.Message));
                    }
                }
                return (ok2, errs2.ToArray(), last2);
            }));
        ok = r.Item1; errs.AddRange(r.Item2); last = r.Item3;
        SetMultiSelect(false);
        LoadDir();
        string msg = L10n.F("已移出 {0} 个", ok);
        if (errs.Count > 0) msg += "\n" + string.Join("\n", errs);
        if (last.Length > 0) msg += L10n.F("\n最后输出：{0}", last);
        await DisplayAlertAsync(L10n.T("移出完成"), msg, L10n.T("确定"));
    }

    private async Task DeleteManyAsync(List<VaultItem> items)
    {
        if (!await DisplayAlertAsync(L10n.T("移入回收站"),
                L10n.F("将 {0} 项移入回收站？目录连同内容一起移入，可恢复。", items.Count),
                L10n.T("移入"), L10n.T("取消"))) return;
        var r = await ProgressPage.RunAsync(this, L10n.T("移入回收站"),
            (tracker, ct) => Task.Run(() =>
            {
                tracker.Begin(items.Count, items.Sum(t => (long)t.Size));
                int ok = 0;
                var errs = new List<string>();
                int idx = 0;
                foreach (var it in items)
                {
                    if (ct.IsCancellationRequested) break;
                    idx++;
                    tracker.StartSlot(idx, idx, it.Name, it.Size);
                    try
                    {
                        VaultTrash.MoveToTrash(_vault, it.RelPath, it.Name, it.IsDir, it.Size);
                        ClearOrigin(it.RelPath);
                        tracker.EndSlot(idx, true);
                        ok++;
                    }
                    catch (Exception ex)
                    {
                        tracker.EndSlot(idx, false);
                        if (errs.Count < 5) errs.Add(L10n.F("{0}：{1}", it.Name, ex.Message));
                    }
                }
                return (ok, errs.ToArray());
            }));
        SetMultiSelect(false);
        LoadDir();
        string msg = L10n.F("已移入回收站 {0} 项", r.Item1);
        if (r.Item2.Length > 0) msg += "\n" + string.Join("\n", r.Item2);
        await DisplayAlertAsync(L10n.T("移入回收站"), msg, L10n.T("确定"));
    }

    // 永久删除
    // 回收站页面
    private async Task DeleteForeverAsync(List<VaultItem> items)
    {
        if (items.Count == 0) return;
        string what = items.Count == 1 ? L10n.F("「{0}」", items[0].Name) : L10n.F("所选 {0} 项", items.Count);
        string body = items.Any(t => t.IsDir)
            ? L10n.F("{0}将彻底删除，不进回收站，无法恢复。", what)
            : L10n.F("{0}将彻底删除，无法恢复。", what);
        if (await DisplayAlertAsync(L10n.T("永久删除"), body, L10n.T("永久删除"), L10n.T("取消")))
        {
            var r = await ProgressPage.RunAsync(this, L10n.T("永久删除"),
                (tracker, ct) => Task.Run(() =>
                {
                    tracker.Begin(items.Count, items.Sum(t => (long)t.Size));
                    int ok = 0;
                    var errs = new List<string>();
                    int idx = 0;
                    foreach (var it in items)
                    {
                        if (ct.IsCancellationRequested) break;
                        idx++;
                        tracker.StartSlot(idx, idx, it.Name, it.Size);
                        try
                        {
                            _vault.DeleteEx(it.RelPath, null, null);
                            ClearOrigin(it.RelPath);
                            tracker.EndSlot(idx, true);
                            ok++;
                        }
                        catch (Exception ex)
                        {
                            tracker.EndSlot(idx, false);
                            if (errs.Count < 5) errs.Add(L10n.F("{0}：{1}", it.Name, ex.Message));
                        }
                    }
                    return (ok, errs.ToArray());
                }));
            SetMultiSelect(false);
            LoadDir();
            string msg = L10n.F("已永久删除 {0} 项", r.Item1);
            if (r.Item2.Length > 0) msg += "\n" + string.Join("\n", r.Item2);
            await DisplayAlertAsync(L10n.T("永久删除"), msg, L10n.T("确定"));
        }
    }

    // 区块
    private static string AlgoName(int mode) => mode switch
    {
        1 => "XChaCha20-Poly1305",
        2 => "AEGIS-256",
        3 => "AES-256-GCM",
        4 => "SM4-GCM",
        _ => L10n.F("未知({0})", mode),
    };

    private static string AlgoSummary(List<string> algos)
        => algos.Count == 0 ? "—"
         : algos.Count <= 2 ? string.Join(L10n.T("、"), algos)
         : L10n.F("{0}、{1} 等 {2} 种", algos[0], algos[1], algos.Count);

    private static string FileTypeOf(string name)
    {
        string ext = Path.GetExtension(name).TrimStart('.');
        string kind = VaultItem.IsImageName(name) ? L10n.T("图片")
            : VaultItem.IsVideoName(name) ? L10n.T("视频")
            : VaultItem.IsAudioName(name) ? L10n.T("音频") : L10n.T("文件");
        return ext.Length == 0 ? kind : $"{ext.ToUpperInvariant()} {kind}";
    }

    private sealed class PropStat
    {
        public ulong Total;
        public int FileCount, Compressed, Plain;
        public List<string> Algos = new();
        // 单文件
        public bool Single;
        public int SingleComp = -1, SingleLevel;

        public PropStat Copy() => new()
        {
            Total = Total, FileCount = FileCount,
            Compressed = Compressed, Plain = Plain,
            Algos = new List<string>(Algos),
            Single = Single, SingleComp = SingleComp, SingleLevel = SingleLevel,
        };
    }

    private static string LevelText(int lvl) => lvl switch
    {
        3 => L10n.T("标准档（Zstd 3）"),
        9 => L10n.T("最佳档（Zstd 9）"),
        -3 => L10n.T("极速档（Zstd -3）"),
        < 0 and > -6 => L10n.F("快速档（Zstd {0}）", lvl),
        > 0 and <= 22 => L10n.F("Zstd {0} 级", lvl),
        _ => L10n.F("档位 {0}", lvl),
    };

    private static string CompressSummary(PropStat st)
    {
        if (st.Single && st.SingleComp >= 0)
            return st.SingleComp == 0 ? L10n.T("关闭（未压缩）") : L10n.F("已压缩 · {0}", LevelText(st.SingleLevel));
        return st.Compressed == 0 && st.Plain == 0 ? "—"
             : st.Compressed == 0 ? L10n.T("未压缩")
             : st.Plain == 0 ? L10n.F("已压缩 {0} 项", st.Compressed)
             : L10n.F("已压缩 {0} 项、未压缩 {1} 项", st.Compressed, st.Plain);
    }

    // 先弹框
    private async void ShowProperties(List<VaultItem> items)
    {
        int dirs = items.Count(i => i.IsDir);
        int files = items.Count - dirs;
        string type = dirs > 0 && files > 0 ? L10n.F("目录 {0} 项、文件 {1} 项", dirs, files)
            : dirs > 0 ? L10n.F("目录 {0} 项", dirs)
            : files == 1 ? FileTypeOf(items[0].Name)
            : L10n.F("文件 {0} 项", files);
        PropsName.Text = items.Count == 1 ? items[0].Name : L10n.F("{0} 个所选项目", items.Count);
        PropsType.Text = type;
        PropsMtime.Text = items.Count == 1
            ? items[0].Mtime.ToString("yyyy-MM-dd HH:mm:ss")
            : L10n.T("—（多选）");
        PropsCountLabel.IsVisible = PropsCount.IsVisible = dirs > 0 || items.Count > 1;
        PropsSize.Text = PropsCount.Text = PropsAlgo.Text = PropsCompress.Text = L10n.T("计算中…");
        PropsStatus.Text = L10n.T("正在统计…");
        UiFx.Reveal(PropsOverlay);

        _propsCts?.Cancel();
        _propsCts = new CancellationTokenSource();
        var ct = _propsCts.Token;
        try { await Task.Run(async () => await StatPropertiesAsync(items, ct)); }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!ct.IsCancellationRequested)
            {
                PropsStatus.Text = L10n.T("统计中断");
                ShowError(L10n.T("读取属性失败"), ex.Message);
            }
        }
    }

    // 无文件数上限
    private async Task StatPropertiesAsync(List<VaultItem> items, CancellationToken ct)
    {
        var st = new PropStat();
        st.Single = items.Count == 1 && !items[0].IsDir;
        var dirs = new Queue<string>();
        foreach (var it in items)
        {
            if (it.IsDir) dirs.Enqueue(it.RelPath);
            else AddFileStat(st, it);
        }
        long last = Environment.TickCount64;
        while (dirs.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            List<VaultItem> children;
            try { children = _vault.ListDir(dirs.Dequeue()); }
            catch { continue; }
            foreach (var ch in children)
            {
                ct.ThrowIfCancellationRequested();
                if (ch.IsDir) dirs.Enqueue(ch.RelPath);
                else AddFileStat(st, ch);
                if (Environment.TickCount64 - last > 200)
                {
                    var snap = st.Copy();
                    await MainThread.InvokeOnMainThreadAsync(() => RefreshProps(snap, false));
                    last = Environment.TickCount64;
                }
            }
        }
        var fin = st.Copy();
        await MainThread.InvokeOnMainThreadAsync(() => RefreshProps(fin, true));
    }

    private void RefreshProps(PropStat st, bool done)
    {
        PropsSize.Text = VaultItem.FormatSize(st.Total);
        PropsCount.Text = L10n.F("{0} 个", st.FileCount);
        PropsAlgo.Text = AlgoSummary(st.Algos);
        PropsCompress.Text = CompressSummary(st);
        PropsStatus.Text = done ? L10n.T("统计完成") : L10n.F("正在统计… 已扫描 {0} 个文件", st.FileCount);
    }

    private void AddFileStat(PropStat st, VaultItem it)
    {
        st.Total += it.Size;
        st.FileCount++;
        try
        {
            var fi = _vault.GetFileInfo(it.RelPath);
            if (fi is null) return;
            string nm = AlgoName(fi.Mode);
            if (!st.Algos.Contains(nm)) st.Algos.Add(nm);
            if (fi.Compression != 0) st.Compressed++; else st.Plain++;
            if (st.Single) { st.SingleComp = fi.Compression; st.SingleLevel = fi.CompLevel; }
        }
        catch { /* 单文件读头失败不中断统计 */ }
    }

    private void CloseProps()
    {
        UiFx.Hide(PropsOverlay);
        var c = _propsCts; _propsCts = null;
        try { c?.Cancel(); c?.Dispose(); } catch { }
    }

    private void OnPropsClose(object? sender, EventArgs e) => CloseProps();
    private void OnPropsBackdropTapped(object? sender, TappedEventArgs e) => CloseProps();

    // 区块
    private void OpenRenameOverlay(List<VaultItem> targets)
    {
        _renameTargets = targets.Where(t => !t.IsDir).ToList();
        if (_renameTargets.Count == 0) return;
        RenamePattern.Text = "^(.*)$";
        RenameReplace.Text = "{name}";
        UiFx.Reveal(RenameOverlay);
        RefreshRenamePreview();
    }

    private List<(VaultItem Item, string NewName)> BuildRenamePlan(out string? error)
    {
        error = null;
        string pat = RenamePattern.Text ?? "";
        string rep = RenameReplace.Text ?? "";
        if (pat.Length == 0) { error = L10n.T("请输入匹配正则"); return new(); }
        Regex re;
        try { re = new Regex(pat, RegexOptions.None, TimeSpan.FromMilliseconds(200)); }
        catch (Exception ex) { error = L10n.T("正则无效：") + ex.Message; return new(); }
        var plan = new List<(VaultItem, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < _renameTargets.Count; i++)
        {
            var it = _renameTargets[i];
            string stem = Path.GetFileNameWithoutExtension(it.Name);
            string ext = Path.GetExtension(it.Name);
            string body;
            try
            {
                body = re.Replace(stem, rep)
                    .Replace("{n}", (i + 1).ToString("D3"))
                    .Replace("{name}", stem)
                    .Replace("{ext}", ext.TrimStart('.'));
            }
            catch (RegexMatchTimeoutException) { error = L10n.T("正则匹配超时"); return new(); }
            string nn = body + ext;
            if (nn.Length == 0 || nn.IndexOfAny(new[] { '/', '\\' }) >= 0)
            { error = L10n.T("新名称非法：") + nn; return new(); }
            if (!seen.Add(nn)) { error = L10n.T("目标重名：") + nn; return new(); }
            plan.Add((it, nn));
        }
        return plan;
    }

    private void OnRenameTextChanged(object? sender, TextChangedEventArgs e)
        => RefreshRenamePreview();

    private void RefreshRenamePreview()
    {
        var plan = BuildRenamePlan(out string? err);
        if (err is not null)
        {
            RenamePreview.TextColor = Microsoft.Maui.Graphics.Color.FromArgb(
                Microsoft.Maui.Controls.Application.Current?.RequestedTheme.ToString() == "Dark" ? "#E36A71" : "#C7363F");
            RenamePreview.Text = err;
            return;
        }
        RenamePreview.TextColor = Microsoft.Maui.Graphics.Color.FromArgb(
            Microsoft.Maui.Controls.Application.Current?.RequestedTheme.ToString() == "Dark" ? "#A6AEBA" : "#5B6472");
        var lines = plan.Take(8).Select(p => $"{p.Item.Name} → {p.NewName}").ToList();
        if (plan.Count > 8) lines.Add(L10n.F("… 其余 {0} 项", plan.Count - 8));
        RenamePreview.Text = string.Join("\n", lines);
    }

    private void OnRenameCancel(object? sender, EventArgs e)
        => UiFx.Hide(RenameOverlay);

    private async void OnRenameApply(object? sender, EventArgs e)
    {
        var plan = BuildRenamePlan(out string? err);
        if (err is not null) { RenamePreview.Text = err; return; }
        foreach (var (it, nn) in plan)
        {
            if (nn == it.Name) continue;
            string rel = _curPath.Length == 0 ? nn : $"{_curPath}/{nn}";
            if (_vault.TryGetAttr(rel, out _, out _)) { err = L10n.F("目标已存在：{0}", nn); break; }
        }
        if (err is not null) { RenamePreview.Text = err; return; }
        UiFx.Hide(RenameOverlay);
        int ok = 0;
        var errs = new List<string>();
        try
        {
            SetBusy(true);
            await Task.Run(() =>
            {
                foreach (var (it, nn) in plan)
                {
                    if (nn == it.Name) continue;
                    string rel = _curPath.Length == 0 ? nn : $"{_curPath}/{nn}";
                    try
                    {
                        _vault.Rename(it.RelPath, rel);
                        string? origin = GetOrigin(it.RelPath);
                        if (!string.IsNullOrEmpty(origin))
                        { RememberOrigin(rel, origin); ClearOrigin(it.RelPath); }
                        ok++;
                    }
                    catch (Exception ex) { if (errs.Count < 5) errs.Add(L10n.F("{0}：{1}", it.Name, ex.Message)); }
                }
            });
            SetMultiSelect(false);
            LoadDir();
        }
        catch (Exception ex) { ShowError(L10n.T("批量重命名失败"), ex.Message); }
        finally { SetBusy(false); }
        string msg = L10n.F("已重命名 {0} 个", ok);
        if (errs.Count > 0) msg += "\n" + string.Join("\n", errs);
        await DisplayAlertAsync(L10n.T("重命名完成"), msg, L10n.T("确定"));
    }

    // 区块
    // 库内明文 → 独立 .ptd
    private async Task ExportPtdManyAsync(List<VaultItem> items)
    {
        var files = items.Where(i => !i.IsDir).ToList();
        if (files.Count == 0) return;
        string? p1 = await PromptPasswordAsync(L10n.T("导出为 .ptd"), L10n.T("设置单文件加密密码"));
        if (string.IsNullOrEmpty(p1)) return;
        string? p2 = await PromptPasswordAsync(L10n.T("导出为 .ptd"), L10n.T("确认密码"));
        if (p2 != p1) { await DisplayAlertAsync(L10n.T("提示"), L10n.T("两次输入不一致"), L10n.T("确定")); return; }
        if (!PasswordPolicy.Check(p1!, out string weak)
            && !await DisplayAlertAsync(L10n.T("密码强度不足"), weak + L10n.T("\n仍要使用这个密码？"),
                L10n.T("继续"), L10n.T("重新输入"))) return;
        byte[] pw = Secret.From(p1);
        int ok = 0;
        var errs = new List<string>();
        string last = "";
        try
        {
            SetBusy(true);
            await Task.Run(() =>
            {
                string outDir = VaultStorageHelper.ExportDir();
                foreach (var it in files)
                {
                    string tmp = Path.Combine(FileSystem.CacheDirectory,
                        "ptd_" + Guid.NewGuid().ToString("N"));
                    try
                    {
                        int ofd = FileCryptoService.OpenWrite(tmp);
                        try { _vault.ExportFd(it.RelPath, ofd, null); }
                        finally { LibcNative.close(ofd); }
                        string dst = Path.Combine(outDir, it.Name + ".ptd");
                        if (File.Exists(dst))
                            dst = Path.Combine(outDir, Path.GetFileNameWithoutExtension(it.Name)
                                + "_" + Guid.NewGuid().ToString("N")[..6] + ".ptd");
                        FileCryptoService.Encrypt(tmp, dst, pw, FeMMode.XChaCha20,
                            FileCryptoNative.CompressAuto, null);
                        ok++; last = dst;
                    }
                    catch (Exception ex) { if (errs.Count < 5) errs.Add(L10n.F("{0}：{1}", it.Name, ex.Message)); }
                    finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
                }
            });
        }
        finally { Secret.Wipe(pw); SetBusy(false); }
        string msg = L10n.F("已导出 {0} 个 .ptd", ok);
        if (errs.Count > 0) msg += "\n" + string.Join("\n", errs);
        if (last.Length > 0) msg += L10n.F("\n输出目录：{0}", VaultStorageHelper.ExportDir());
        await DisplayAlertAsync(L10n.T("导出完成"), msg, L10n.T("确定"));
    }

    // 外部 .ptd → 解密到私有 cache →
    // algo=0 沿用库默认
    private async Task ImportPtdFiles(int algo)
    {
        List<FileResult> picked;
        try
        {
            MainActivity.NoteExternalLaunch();
            var res = await FilePicker.Default.PickMultipleAsync();
            picked = res?.ToList() ?? new List<FileResult>();
        }
        catch (Exception ex) { ShowError(L10n.T("选择文件失败"), ex.Message); return; }
        if (picked.Count == 0) return;
        string? pwd = await PromptPasswordAsync(L10n.T("导入 .ptd"), L10n.T("输入这些 .ptd 的加密密码"));
        if (string.IsNullOrEmpty(pwd)) return;
        byte[] pw = Secret.From(pwd);
        int ok = 0;
        var errs = new List<string>();
        try
        {
            SetBusy(true);
            await Task.Run(() =>
            {
                foreach (var f in picked)
                {
                    string src = f.FullPath ?? "";
                    if (src.Length == 0) continue;
                    string name = f.FileName ?? Path.GetFileName(src);
                    if (name.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
                    string tmp = Path.Combine(FileSystem.CacheDirectory,
                        "ptdi_" + Guid.NewGuid().ToString("N"));
                    int fd = -1;
                    try
                    {
                        FileCryptoService.Decrypt(src, tmp, pw, false, null);
                        string rel = _curPath.Length == 0 ? name : $"{_curPath}/{name}";
                        fd = FileCryptoService.OpenRead(tmp);
                        _vault.ImportFdEx(rel, fd, algo, VdiskNative.CompressDefault, null);
                        ok++;
                    }
                    catch (Exception ex) { if (errs.Count < 5) errs.Add(L10n.F("{0}：{1}", name, ex.Message)); }
                    finally
                    {
                        if (fd >= 0) LibcNative.close(fd);
                        try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                    }
                }
            });
            LoadDir();
        }
        catch (Exception ex) { ShowError(L10n.T("导入 .ptd 失败"), ex.Message); }
        finally { Secret.Wipe(pw); SetBusy(false); }
        string msg = L10n.F("已导入 {0} 个文件", ok);
        if (errs.Count > 0) msg += "\n" + string.Join("\n", errs);
        await DisplayAlertAsync(L10n.T("导入完成"), msg, L10n.T("确定"));
    }

    private void SetBusy(bool on)
    {
        Busy.IsRunning = on;
        Busy.IsVisible = on;
    }

    // 页面已分离
    // 对已销毁页面弹
    private async void ShowError(string title, string msg)
    {
        if (Handler is null) return;
        try { await DisplayAlertAsync(title, msg, L10n.T("确定")); } catch { }
    }
}
