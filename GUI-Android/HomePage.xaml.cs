// 主页
// 任务
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile;

public partial class HomePage : ContentPage
{
    private BatchRun? _subRun;

    public HomePage()
    {
        InitializeComponent();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        VaultService.LockOnLeaveVault();   // 离开加密库 Tab 即锁
        UiFx.AppearFade(this);   // Tab 切换淡入过渡
        RefreshStatus();
        SubscribeTask();
        // 加密中退出
        BatchRuns.ShowProgress();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        UnsubscribeTask();
    }

    private int _statusVer;

    private void RefreshStatus()
    {
        LblVersion.Text = L10n.F("版本 {0}（Build {1}）", AppInfo.Current.VersionString, AppInfo.Current.BuildString);
        string dir = VaultStorageHelper.CurrentVaultDir();
        LblVaultDir.Text = dir;
        int ver = ++_statusVer;
        if (!VaultService.Exists(dir))
        {
            LblVaultState.Text = L10n.T("未创建");
            LblVaultSpace.Text = L10n.T("点击「打开加密库」创建。");
            return;
        }
        // 锁定态
        LblVaultState.Text = L10n.T("读取中");
        LblVaultSpace.Text = "";
        _ = Task.Run(() =>
        {
            string state = L10n.T("已锁定");
            string space = L10n.T("打开加密库后输入密码即可解锁。");
            try
            {
                var v = VaultService.Active;
                bool unlocked = v is { IsOpen: true, IsUnlocked: true } && v.RootDir == dir;
                if (unlocked)
                {
                    state = L10n.T("已解锁");
                    var (used, trash, total) = v!.StatSpaceEx();
                    string t = trash > 0 ? L10n.F("（回收站 {0}）", VaultItem.FormatSize(trash)) : "";
                    space = total > 0
                        ? L10n.F("已用 {0}{1} / {2}", VaultItem.FormatSize(used), t, VaultItem.FormatSize(total))
                        : L10n.F("已用 {0}{1}", VaultItem.FormatSize(used), t);
                }
            }
            catch { space = ""; }
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (ver != _statusVer) return;
                LblVaultState.Text = state;
                LblVaultSpace.Text = space;
            });
        });
    }

    // 任务卡
    private void SubscribeTask()
    {
        UnsubscribeTask();
        BatchRuns.Changed += OnRunsChanged;
        var run = BatchRuns.Current;
        if (run is not null)
        {
            _subRun = run;
            run.Tracker.Updated += OnTrackerUpdated;
        }
        ApplyTask(run);
    }

    private void UnsubscribeTask()
    {
        BatchRuns.Changed -= OnRunsChanged;
        if (_subRun is not null) _subRun.Tracker.Updated -= OnTrackerUpdated;
        _subRun = null;
    }

    private void OnRunsChanged() => MainThread.BeginInvokeOnMainThread(SubscribeTask);

    private void ApplyTask(BatchRun? run)
    {
        TaskCard.IsVisible = run is not null;
        if (run is null) return;
        OnTrackerUpdated(run.Tracker.Snapshot());
    }

    private void OnTrackerUpdated(BatchSnapshot s)
    {
        if (!TaskCard.IsVisible) return;
        LblTaskTitle.Text = L10n.F("{0} {1:F1}%", _subRun?.Title ?? L10n.T("后台任务"), s.OverallPct);
        string info = s.Total > 0
            ? (s.CountMode ? L10n.F("{0} / {1} 个文件", s.Processed, s.Total) : L10n.F("{0} / {1}", Fmt.Bytes(s.Processed), Fmt.Bytes(s.Total)))
            : L10n.T("正在准备…");
        info += L10n.F("　完成 {0} · 失败 {1}", s.Done, s.Failed);
        LblTaskInfo.Text = info;
    }

    private void OnOpenTask(object? sender, EventArgs e) => ProgressPage.Show(this);

    // 切 Tab
    private static void GoTab(string route) => BackPolicy.GoTab(Shell.Current, route);

    private void OnOpenVault(object? sender, EventArgs e) => GoTab(nameof(VaultPage));

    private void OnOpenCrypto(object? sender, EventArgs e) => GoTab(nameof(CryptoPage));

    private void OnOpenSettings(object? sender, EventArgs e) => GoTab(nameof(SettingsPage));

    // 检查
    private void OnCheckUpdate(object? sender, EventArgs e)
        => _ = SettingsPage.CheckUpdateAsync(this, BtnUpdate);
}
