// 设置页
using System.Net.Http;
using System.Threading;
using Android.Content;
using Microsoft.Maui.ApplicationModel;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class SettingsPage : ContentPage
{
    // 取值
    private const string ThemeKey = "app_theme";
    private static string[] ThemeNames() => new[] { L10n.T("跟随系统"), L10n.T("浅色"), L10n.T("深色") };
    // 应用锁
    private const string AppLockKey = "app_lock";

    // 回收站保留天数
    private static readonly int[] TrashDayOptions = { 0, 7, 30, 90, 180, 365 };

    // 选项数组
    private static string[]? s_idleNames, s_trashNames, s_langNames;
    public static void InvalidateChoices()
    {
        s_idleNames = null; s_trashNames = null; s_langNames = null;
    }

    public SettingsPage()
    {
        InitializeComponent();
        LblVersion.Text = L10n.F("版本 {0}（Build {1}）", AppInfo.Current.VersionString, AppInfo.Current.BuildString);
        RefreshThemeChoices();
        SwAppLock.IsToggled = Preferences.Default.Get(AppLockKey, false);
        SwSecure.IsToggled = ScreenSecurity.Enabled;
        LblSecureWarn.IsVisible = !ScreenSecurity.Enabled;
        SwDiag.IsToggled = MainApplication.DiagnosticLogging;
        SyncTrashDays();
        SyncIdleMinutes();
        SyncLang();
    }

    // 诊断日志开关
    private void OnDiagToggled(object? sender, ToggledEventArgs e)
        => Preferences.Default.Set(MainApplication.DiagLogKey, e.Value);

    // 空闲锁档位
    private void SyncIdleMinutes()
    {
        var src = s_idleNames ??= VaultIdle.Minutes.Select(m => L10n.F("{0} 分钟", m)).ToArray();
        if (!ReferenceEquals(PkIdleMinutes.ItemsSource, src)) PkIdleMinutes.ItemsSource = src;
        int idx = Array.IndexOf(VaultIdle.Minutes, VaultIdle.CurrentMinutes);
        int want = idx >= 0 ? idx : 1;
        if (PkIdleMinutes.SelectedIndex != want) PkIdleMinutes.SelectedIndex = want;
    }

    private void OnIdleMinutesChanged(object? sender, EventArgs e)
    {
        int idx = PkIdleMinutes.SelectedIndex;
        if (idx < 0 || idx >= VaultIdle.Minutes.Length) return;
        VaultIdle.CurrentMinutes = VaultIdle.Minutes[idx];
        var v = VaultService.Active;
        if (v is null || !v.IsUnlocked) return;   // 锁库态等解锁
        try { v.ApplyIdleTimeout(); } catch { /* 设置失败不阻断 */ }
    }

    private void SyncTrashDays()
    {
        var src = s_trashNames ??= TrashDayOptions.Select(
            x => x == 0 ? L10n.T("不自动清理") : L10n.F("{0} 天", x)).ToArray();
        if (!ReferenceEquals(PkTrashDays.ItemsSource, src)) PkTrashDays.ItemsSource = src;
        int d = VaultTrash.RetentionDays;
        int idx = Array.IndexOf(TrashDayOptions, d);
        int want = idx >= 0 ? idx : 2;   // 默认 30 天
        if (PkTrashDays.SelectedIndex != want) PkTrashDays.SelectedIndex = want;
    }

    private void OnTrashDaysChanged(object? sender, EventArgs e)
    {
        int idx = PkTrashDays.SelectedIndex;
        if (idx < 0 || idx >= TrashDayOptions.Length) return;
        VaultTrash.RetentionDays = TrashDayOptions[idx];
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        HideSecureOverlays();   // 进入页面时复位
        VaultService.LockOnLeaveVault();   // 离开加密库 Tab 即锁
        UiFx.AppearFade(this);   // Tab 切换淡入过渡
        SwAppLock.IsToggled = Preferences.Default.Get(AppLockKey, false);
        SwSecure.IsToggled = ScreenSecurity.Enabled;
        LblSecureWarn.IsVisible = !ScreenSecurity.Enabled;
        SwDiag.IsToggled = MainApplication.DiagnosticLogging;
        SyncTrashDays();
        SyncIdleMinutes();
        Player.OnPageAppearing();   // 内联音乐播放器
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        // 只解绑界面
        Player.OnPageDisappearing();
    }

    // 明文清理
    private async void OnCleanPlaintext(object? sender, EventArgs e)
    {
        if (VaultService.LongOps > 0)
        {
            await DisplayAlertAsync(L10n.T("暂不可清理"), L10n.T("有批量任务正在运行，请等完成后再试。"), L10n.T("确定"));
            return;
        }
        string dir = "";
        try { dir = FileEncryptorMobile.Platforms.Android.VaultStorageHelper.ExportDir(); } catch { }
        string msg = L10n.T("删除预览缓存和明文输出文件。")
            + (dir.Length > 0 ? L10n.T("\n\n目录：") + dir : "")
            + L10n.T("\n\n此操作不可撤销。");
        if (!await DisplayAlertAsync(L10n.T("清理明文缓存与导出"), msg, L10n.T("确认删除"), L10n.T("取消"))) return;
        int n = await Task.Run(() =>
        {
            CacheJanitor.PurgeSensitive();
            return CacheJanitor.PurgeExports();
        });
        await DisplayAlertAsync(L10n.T("已清理"), L10n.F("已删除 {0} 个明文输出文件与全部预览缓存。", n), L10n.T("确定"));
    }

    private void RefreshThemeChoices()
        => ChoiceUi.BuildChips(ThemeChoices, ThemeNames(),
            ThemeIndex(Preferences.Default.Get(ThemeKey, "system")), OnThemeSelected);

    private void OnThemeSelected(int index)
    {
        string v = index switch
        {
            1 => "light",
            2 => "dark",
            _ => "system",
        };
        Preferences.Default.Set(ThemeKey, v);
        ApplyTheme(v);
    }

    private static int ThemeIndex(string v) => v switch
    {
        "light" => 1,
        "dark" => 2,
        _ => 0,
    };

    // 语言显示序
    private static string[] LangNames() => s_langNames ??= new[]
    {
        L10n.T("跟随系统"), L10n.T("中文"), "English", "Русский",
    };
    private void SyncLang()
    {
        var src = LangNames();
        if (!ReferenceEquals(PkLang.ItemsSource, src)) PkLang.ItemsSource = src;
        int want = L10n.Lang switch { 1 => 2, 2 => 3, _ => 0 };
        if (PkLang.SelectedIndex != want) PkLang.SelectedIndex = want;
    }
    // 切语言
    private void OnLangChanged(object? sender, EventArgs e)
    {
        int idx = PkLang.SelectedIndex;
        if (idx < 0) return;
        string code = idx switch { 1 => "zh", 2 => "en", 3 => "ru", _ => "" };
        if (code == Preferences.Default.Get(L10n.PrefKey, "")) return;
        L10n.SetLang(code);
        VaultService.LockActive();
        var win = Microsoft.Maui.Controls.Application.Current?.Windows.FirstOrDefault();
        if (win is not null) win.Page = new AppShell();
    }
    // 启动
    public static void ApplyTheme(string v)
    {
        var app = Microsoft.Maui.Controls.Application.Current;
        if (app is null) return;
        app.UserAppTheme = v switch
        {
            "light" => AppTheme.Light,
            "dark" => AppTheme.Dark,
            _ => AppTheme.Unspecified,
        };
        VaultItem.InvalidateTheme();
    }

    // 应用锁开关
    private async void OnAppLockToggled(object? sender, ToggledEventArgs e)
    {
        bool on = e.Value;
        if (on)
        {
            var ctx = Platform.CurrentActivity;
            var km = ctx is null ? null : (Android.App.KeyguardManager?)ctx.GetSystemService(Android.Content.Context.KeyguardService);
            if (km is null || !km.IsKeyguardSecure)
            {
                SwAppLock.IsToggled = false;
                await DisplayAlertAsync(L10n.T("无法开启"),
                    L10n.T("当前设备未设置锁屏密码，无法使用应用锁。"), L10n.T("确定"));
                return;
            }
        }
        Preferences.Default.Set(AppLockKey, on);
    }

    // 截屏保护开关
    private void OnSecureToggled(object? sender, ToggledEventArgs e)
    {
        bool wantBlock = e.Value;   // true = 禁止截屏
        if (wantBlock)
        {
            Preferences.Default.Set(ScreenSecurity.Key, true);
            ScreenSecurity.Apply(Platform.CurrentActivity?.Window);
            LblSecureWarn.IsVisible = false;
            return;
        }
        ShowWarn();   // 第一步
    }

    // 淡入浮层
    private async void FadeIn(Grid g)
    {
        if (g.IsVisible) return;
        g.Opacity = 0;
        g.IsVisible = true;
        await g.FadeTo(1, 140);
    }

    // 淡出浮层
    private async void FadeOut(Grid g, Action? after = null)
    {
        if (!g.IsVisible) { after?.Invoke(); return; }
        await g.FadeTo(0, 140);
        g.IsVisible = false;
        g.Opacity = 1;
        after?.Invoke();
    }

    // 第一步确认浮层
    private void ShowWarn()
    {
        SecureConfirmOverlay.IsVisible = false;
        SecureConfirmOverlay.Opacity = 1;
        FadeIn(SecureWarnOverlay);
    }

    private void OnWarnCancel(object? sender, EventArgs e)
    {
        SwSecure.IsToggled = true;   // 取消
        FadeOut(SecureWarnOverlay);
    }

    private void OnWarnContinue(object? sender, EventArgs e)
    {
        // 第一步淡出
        FadeOut(SecureWarnOverlay, ShowSecureConfirm);
    }

    private CancellationTokenSource? _secureCts;

    // 第二步确认浮层
    private void ShowSecureConfirm()
    {
        StartConfirmCooldown();
        FadeIn(SecureConfirmOverlay);
    }

    // 启动 5 秒冷静期
    private void StartConfirmCooldown()
    {
        BtnSecureConfirm.IsEnabled = false;
        BtnSecureConfirm.Text = L10n.T("确定关闭 (5)");
        _secureCts?.Cancel();
        var cts = _secureCts = new CancellationTokenSource();
        int left = 5;
        _ = Task.Run(async () =>
        {
            while (left > 0)
            {
                try { await Task.Delay(1000, cts.Token); }
                catch { return; }
                left--;
                int n = left;
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    if (n > 0) BtnSecureConfirm.Text = L10n.F("确定关闭 ({0})", n);
                    else { BtnSecureConfirm.Text = L10n.T("确定关闭"); BtnSecureConfirm.IsEnabled = true; }
                });
            }
        });
    }

    // 即时复位两层浮
    private void HideSecureOverlays()
    {
        _secureCts?.Cancel();
        SecureWarnOverlay.IsVisible = false;
        SecureWarnOverlay.Opacity = 1;
        SecureConfirmOverlay.IsVisible = false;
        SecureConfirmOverlay.Opacity = 1;
    }

    private void OnSecureCancel(object? sender, EventArgs e)
    {
        SwSecure.IsToggled = true;   // 取消
        _secureCts?.Cancel();
        FadeOut(SecureConfirmOverlay);
    }

    private void OnSecureConfirm(object? sender, EventArgs e)
    {
        if (!BtnSecureConfirm.IsEnabled) return;
        _secureCts?.Cancel();
        FadeOut(SecureConfirmOverlay, () =>
        {
            Preferences.Default.Set(ScreenSecurity.Key, false);
            ScreenSecurity.Apply(Platform.CurrentActivity?.Window);
            LblSecureWarn.IsVisible = true;
        });
    }

    // 检查
    private void OnCheckUpdate(object? sender, EventArgs e)
        => _ = CheckUpdateAsync(this, BtnCheckUpdate);

    internal static async Task CheckUpdateAsync(ContentPage page, Button? btn)
    {
        if (btn is not null) { btn.IsEnabled = false; btn.Text = L10n.T("检查中…"); }
        try
        {
            var info = await UpdateService.CheckAsync(AppInfo.Current.VersionString);
            if (!info.HasUpdate)
            {
                await page.DisplayAlertAsync(L10n.T("检查更新"), L10n.F("已是最新版本 {0}。", info.Current), L10n.T("确定"));
                return;
            }
            string pre = info.IsPreRelease ? L10n.T("（Pre-Release 版）") : "";
            string body = L10n.F("发现新版本 {0}{1}。", info.Latest, pre);
            if (info.Notes.Length > 0) body += L10n.F("\n\n{0}", info.Notes);
            body += L10n.F("\n\n当前版本：{0}", info.Current);
            if (!await page.DisplayAlertAsync(L10n.T("发现新版本"), body, L10n.T("下载并安装"), L10n.T("关闭"))) return;
            await DownloadAndInstallAsync(page, info, btn);
        }
        catch (Exception ex)
        {
            string detail = ex is HttpRequestException or TaskCanceledException or TimeoutException
                ? L10n.T("网络连接异常，请检查网络后重试。") : ex.Message;
            await page.DisplayAlertAsync(L10n.T("检查更新"), L10n.F("检查失败：{0}", detail), L10n.T("确定"));
        }
        finally
        {
            if (btn is not null) { btn.Text = L10n.T("检查更新"); btn.IsEnabled = true; }
        }
    }

    private static async Task DownloadAndInstallAsync(ContentPage page, UpdateInfo info, Button? btn)
    {
        // 无 APK 资产
        if (info.ApkUrl.Length == 0)
        {
            bool open = await page.DisplayAlertAsync(L10n.T("没有安装包"),
                L10n.T("此版本没有 Android 安装包，要打开发布页吗？"), L10n.T("打开发布页"), L10n.T("取消"));
            if (open && info.ReleaseUrl.Length > 0)
                await Launcher.Default.OpenAsync(new Uri(info.ReleaseUrl));
            return;
        }
        if (btn is not null) btn.Text = L10n.T("下载中 0%");
        try
        {
            var prog = new Progress<double>(p =>
            { if (btn is not null) btn.Text = L10n.F("下载中 {0}%", (int)(p * 100)); });
            string apk = await UpdateService.DownloadApkAsync(info, prog);
            InstallApk(apk);
        }
        catch (Exception ex)
        {
            await page.DisplayAlertAsync(L10n.T("下载失败"), ex.Message, L10n.T("确定"));
        }
    }

    // 经 FileProvider
    private static void InstallApk(string path)
    {
        var ctx = Platform.CurrentActivity;
        if (ctx is null) return;
        var uri = FileProvider.GetUriForFile(ctx,
            $"{ctx.PackageName}.fileprovider", new Java.IO.File(path));
        var intent = new Intent(Intent.ActionView);
        intent.SetDataAndType(uri, "application/vnd.android.package-archive");
        intent.AddFlags(ActivityFlags.GrantReadUriPermission);
        intent.AddFlags(ActivityFlags.NewTask);
        ctx.StartActivity(intent);
    }

    private async void OnCredits(object? sender, EventArgs e)
    {
        await Navigation.PushModalAsync(new CreditsPage());
    }
}
