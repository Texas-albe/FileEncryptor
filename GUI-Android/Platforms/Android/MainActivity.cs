// 入口 Activity
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Views;
using Android.Widget;
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;
using Microsoft.Maui.Storage;
using System.Threading;

namespace FileEncryptorMobile;

[Activity(Name = "com.yaoyingluo.fileencryptor.MainActivity", Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTop, Exported = true, SupportsPictureInPicture = true, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
[IntentFilter(new[] { Intent.ActionSend }, Categories = new[] { Intent.CategoryDefault }, DataMimeType = "*/*")]
[IntentFilter(new[] { Intent.ActionSendMultiple }, Categories = new[] { Intent.CategoryDefault }, DataMimeType = "*/*")]
[IntentFilter(new[] { Intent.ActionView }, Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable }, DataMimeType = "application/octet-stream")]
public class MainActivity : MauiAppCompatActivity
{
    private Android.Widget.TextView? _mask;
    private const int AppLockRequestCode = 7302;
    private const int NotifyPermRequestCode = 9911;
    private bool _promptShowing;   // 系统验证界面已
    private DateTime _promptAtUtc; // 拉起时刻
    private const int PromptTimeoutSec = 30;
    private bool _bgPaused;        // 上一次 pause 是切后台
    private bool _pipHold;         // PiP 待补锁
    // 是否处于后台
    public static bool AppInBackground;
    // 主动拉起
    private static int s_externalHolds;
    // 挂起锁
    private static int s_deferLock;
    private const int DeferLockSec = 120;

    // 返回前台事件
    public static event Action? Resumed;

    // 调用方
    public static void NoteExternalLaunch() => Interlocked.Increment(ref s_externalHolds);

    // 归还一张预留票
    // 票若不归
    // 重复调用安全
    public static void ReleaseExternalLaunch()
    {
        int cur;
        do
        {
            cur = Volatile.Read(ref s_externalHolds);
            if (cur <= 0) return;
        }
        while (Interlocked.CompareExchange(ref s_externalHolds, cur - 1, cur) != cur);
    }

    // 取并清空持锁
    private static bool ConsumeExternalHold() => Interlocked.Exchange(ref s_externalHolds, 0) > 0;

    // 挂起期间未回
    private void ScheduleDeferredLock()
    {
        Volatile.Write(ref s_deferLock, 1);
        new Handler(Looper.MainLooper!).PostDelayed(() =>
        {
            if (Volatile.Read(ref s_deferLock) == 0) return;
            Volatile.Write(ref s_deferLock, 0);
            MainApplication.LogI(MainApplication.TagCore, "lifecycle: deferred lock timeout");
            VaultService.LockActive();
        }, DeferLockSec * 1000L);
    }

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        // 崩在 base
        MainApplication.LogI(MainApplication.TagCore, "startup: MainActivity.OnCreate begin");
        base.OnCreate(savedInstanceState);
        MainApplication.LogI(MainApplication.TagCore, "startup: MainActivity.OnCreate base done");
        // 默认开启
        ScreenSecurity.Apply(Window);
        BuildMask();
        // 冷启动不走这两
        // 清理丢后台线程
        // 通知权限
        _ = Task.Run(CacheJanitor.PurgeSensitive);
        Window?.DecorView?.Post(() => EnsureNotificationPermission(this));
        CaptureShareIntent(Intent);
        MainApplication.LogI(MainApplication.TagCore, "startup: MainActivity.OnCreate end");
    }

    // Android 13+ 通知运行时权限
    // 会误
    private static bool s_notifAsking;

    // 首帧
    // 不用「装机周期只
    public static void EnsureNotificationPermission(Activity? act = null)
    {
        act ??= global::Microsoft.Maui.ApplicationModel.Platform.CurrentActivity as Activity;
        if (act is null) return;
        if (Build.VERSION.SdkInt < BuildVersionCodes.Tiramisu) return;
        if (act.CheckSelfPermission(Android.Manifest.Permission.PostNotifications) == Permission.Granted) return;
        if (s_notifAsking) return;
        s_notifAsking = true;
        try
        {
            act.RequestPermissions(
                new[] { Android.Manifest.Permission.PostNotifications }, NotifyPermRequestCode);
        }
        catch { s_notifAsking = false; /* 个别机型抛异常：不影响其余功能 */ }
    }

    // 不透明全屏遮罩
    private void BuildMask()
    {
        _mask = new TextView(this)
        {
            Text = L10n.T("已锁定"),
            Gravity = GravityFlags.Center,
        };
        _mask.SetBackgroundColor(Android.Graphics.Color.Black);
        _mask.SetTextColor(Android.Graphics.Color.White);
        _mask.TextSize = 22;
        _mask.LayoutParameters = new ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.MatchParent);
        _mask.Clickable = true;
        // 验证
        _mask.Click += (s, e) => { if (AppLockEnabled() && !_promptShowing) RequestUnlock(); };
        (Window?.DecorView as ViewGroup)?.AddView(_mask);
        _mask.Visibility = ViewStates.Gone;
    }

    // 风险
    // PiP 小窗
    // 仅视频页打开
    protected override void OnUserLeaveHint()
    {
        base.OnUserLeaveHint();
        if (!VideoViewerPage.IsVideoOpen) return;
        if (Build.VERSION.SdkInt < BuildVersionCodes.O) return;
        try
        {
            int w = 16, h = 9;
            if (VideoPlayerHost.GetPipAspect(out int vw, out int vh) && vw > 0 && vh > 0)
            {
                w = vw;
                h = vh;
            }
            // 系统限制约 1
            float r = w / (float)h;
            if (r < 0.4184f) { w = 1; h = 2; }
            else if (r > 2.39f) { w = 2; h = 1; }
            var builder = new PictureInPictureParams.Builder();
            builder.SetAspectRatio(new global::Android.Util.Rational(w, h));
            var p = builder.Build();
            if (p is not null) EnterPictureInPictureMode(p);
        }
        catch (Exception ex) { MainApplication.LogCaught("pip-enter", ex); }
    }

    // PiP 状态变化
    public override void OnPictureInPictureModeChanged(bool isInPictureInPictureMode,
        global::Android.Content.Res.Configuration? newConfig)
    {
        base.OnPictureInPictureModeChanged(isInPictureInPictureMode, newConfig);
        VideoPlayerHost.OnPipModeChanged(isInPictureInPictureMode);
    }

    protected override void OnPause()
    {
        base.OnPause();
        _pipHold = false;
        // PiP 期间不锁库
        if (IsInPictureInPictureMode) { _pipHold = true; return; }
        // 验证界面
        // 此后每次 pause 只遮罩
        if (_promptShowing &&
            DateTime.UtcNow - _promptAtUtc > TimeSpan.FromSeconds(PromptTimeoutSec))
            _promptShowing = false;
        // 视频播放层挂
        // 与图片一样沿同
        VideoViewerPage.CloseIfOpen();
        // 退后台
        // 验证界面导致
        if (_promptShowing) { ShowMask(); ScheduleDeferredLock(); return; }
        // 主动拉起
        if (ConsumeExternalHold()) { ScheduleDeferredLock(); return; }
        ShowMask();
        AppInBackground = true;
        MainApplication.LogI(MainApplication.TagCore, "lifecycle: background -> lock vault + 清明文");
        // 音乐
        MusicPlayerHost.OnAppBackground();
        // 在加密库里
        // 长任务进行
        VaultService.LockActive();
        // 画廊开着退后台
        ImageViewerPage.CloseIfOpen();
        _bgPaused = true;
    }

    // PiP 补锁
    private void FinishPipLock()
    {
        if (!_pipHold) return;
        _pipHold = false;
        VideoViewerPage.CloseIfOpen();
        VaultService.LockActive();
        ImageViewerPage.CloseIfOpen();
        AppInBackground = true;
        _bgPaused = true;
        ShowMask();
    }

    protected override void OnStop()
    {
        base.OnStop();
        FinishPipLock();
    }

    // 销毁兜底
    protected override void OnDestroy()
    {
        base.OnDestroy();
        FinishPipLock();
    }

    protected override void OnResume()
    {
        base.OnResume();
        _pipHold = false;
        Volatile.Write(ref s_deferLock, 0);             // 正常回前台
        Interlocked.Exchange(ref s_externalHolds, 0);   // 清残留
        AppInBackground = false;
        // 从第三方查看器
        ExternalAppGuard.OnReturnedToApp();
        if (_promptShowing) return;   // 从验证界面返回
        if (AppLockEnabled())
        {
            if (_bgPaused) { _bgPaused = false; RequestUnlock(); }
            // 其余情况保持遮
            RaiseResumed();
            return;
        }
        _bgPaused = false;
        HideMask();
        RaiseResumed();
    }

    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);
        try
        {
            if (requestCode == VaultStorageHelper.PickDirRequestCode)
            {
                if (resultCode != Result.Ok || data?.Data is null)
                { VaultStorageHelper.RaiseDirectoryPicked(null); return; }
                // 空串表示非主存储
                VaultStorageHelper.RaiseDirectoryPicked(
                    VaultStorageHelper.ResolveTreePath(data.Data) ?? "");
            }
            else if (requestCode == VaultStorageHelper.PickCryptoDirRequestCode)
            {
                VaultStorageHelper.CompleteCryptoDirPick(resultCode, data?.Data);
            }
            else if (requestCode == AppLockRequestCode)
            {
                _promptShowing = false;
                // 验证成功才揭开
                if (resultCode == Result.Ok) { HideMask(); RaiseResumed(); }
            }
        }
        catch { /* 结果处理异常不致命 */ }
    }

    // 旧版运行时权限
    public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Permission[] grantResults)
    {
        base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == NotifyPermRequestCode)
            s_notifAsking = false;
        if (requestCode == NotifyPermRequestCode || requestCode == MusicPlayerView.NotifyPermRequestCode)
        {
            bool granted = grantResults.Length > 0 && grantResults[0] == Permission.Granted;
            MainApplication.LogD(MainApplication.TagMusic, $"permission: POST_NOTIFICATIONS granted={granted}");
            if (!granted)
                MainApplication.LogW(MainApplication.TagMusic, "permission: 通知被拒，后台播放没有通知栏/锁屏控制");
        }
        RaiseResumed();
    }

    // 关闭视频或锁库
    // PiP 期间 OnPause 早退不锁库
    public static void ExitPictureInPicture()
    {
        try
        {
            var a = global::Microsoft.Maui.ApplicationModel.Platform.CurrentActivity as MainActivity;
            if (a is null || a.IsFinishing || a.IsDestroyed) return;
            if (!a.IsInPictureInPictureMode) return;
            a.Finish();
        }
        catch (Exception ex) { MainApplication.LogCaught("pip-exit", ex); }
    }

    private static bool AppLockEnabled()
        => Preferences.Default.Get("app_lock", false);

    private static void RaiseResumed()
    {
        try { Resumed?.Invoke(); } catch { }
    }

    private void ShowMask()
    {
        if (_mask is not null) _mask.Visibility = ViewStates.Visible;
    }

    private void HideMask()
    {
        if (_mask is not null) _mask.Visibility = ViewStates.Gone;
    }

    // 入向分享
    // 只收 content
    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        CaptureShareIntent(intent);
    }

    private void CaptureShareIntent(Intent? intent)
    {
        try
        {
            if (intent is null) return;
            string? action = intent.Action;
            if (action != Intent.ActionSend && action != Intent.ActionSendMultiple &&
                action != Intent.ActionView) return;
            var uris = new List<string>();
            if (action == Intent.ActionView)
            {
                if (intent.Data is not null) uris.Add(intent.Data.ToString()!);
            }
            else
            {
                var single = intent.GetParcelableExtra(Intent.ExtraStream) as global::Android.Net.Uri;
                if (single is not null) uris.Add(single.ToString()!);
                var many = intent.GetParcelableArrayListExtra(Intent.ExtraStream);
                if (many is not null)
                    foreach (var o in many)
                        if (o is global::Android.Net.Uri u) uris.Add(u.ToString()!);
                var clip = intent.ClipData;
                if (clip is not null)
                    for (int i = 0; i < clip.ItemCount; i++)
                    {
                        var cu = clip.GetItemAt(i)?.Uri;
                        if (cu is not null) uris.Add(cu.ToString()!);
                    }
            }
            if (uris.Count == 0) return;
            ShareInbox.Add(uris);
            // 热启动直接切到
            if (Microsoft.Maui.Controls.Shell.Current is not null)
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(async () =>
                {
                    try { await Microsoft.Maui.Controls.Shell.Current.GoToAsync($"//{nameof(CryptoPage)}", true); }
                    catch { }
                });
        }
        catch { /* 分享数据异常不影响主界面 */ }
    }

    // 系统验证
    private void RequestUnlock()
    {
        ShowMask();
        var km = (KeyguardManager?)GetSystemService(KeyguardService);
        Intent? intent = null;
        try
        {
#pragma warning disable CA1422 // CreateConfirmDeviceCrede
            intent = km?.CreateConfirmDeviceCredentialIntent(
                L10n.T("验证以解锁"), L10n.T("使用设备锁屏验证后查看加密库"));
#pragma warning restore CA1422
        }
        catch { /* 个别机型抛异常：视为无可用验证 */ }
        if (intent is null) { HideMask(); return; }   // 无锁屏
        _promptShowing = true;
        _promptAtUtc = DateTime.UtcNow;   // 超时兜底起点
        try { StartActivityForResult(intent, AppLockRequestCode); }
        catch { _promptShowing = false; HideMask(); }
    }
}
