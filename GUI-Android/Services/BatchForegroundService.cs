// 批量任务前台服务：通知栏常驻进度（进度条 + 速率 + ETA + 计数），
// 任务不随应用切后台被回收。一个时刻只服务一个任务：新任务 Attach 即覆盖。
using System.Diagnostics;
using Android.App;
using Android.Content;
using Android.OS;
using Android.Content.PM;
using FileEncryptorMobile.Services;
namespace FileEncryptorMobile.Services;
[Service(ForegroundServiceType = global::Android.Content.PM.ForegroundService.TypeDataSync,
         Exported = false)]
public sealed class BatchForegroundService : Service
{
    public const string ChannelId = "fe_batch_progress";
    public const int NotifyId = 0x10CA;
    static BatchTracker? _tracker;
    static Func<bool>? _cancelHook;
    static string _title = L10n.T("处理中");
    static long _lastPushMs;
    NotificationManager? _nm;
    public override IBinder? OnBind(Intent? intent) => null;
    public override void OnCreate()
    {
        base.OnCreate();
        _nm = GetSystemService(NotificationService) as NotificationManager;
        EnsureChannel();
        Current = this;   // Push 是静态的，经此拿实例；Attach 先于实例创建完成时首帧会跳过
    }
    // 前台服务被系统回收后不会重建（任务态由调用方持有），直接停
    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (_tracker is null || _cancelHook is null)
        {
            StopSelf();
            return StartCommandResult.NotSticky;
        }
        StartForeground(NotifyId, Build());
        return StartCommandResult.NotSticky;
    }
    // 绑定任务：起前台 + 订阅进度。tracker/cancelHook 由调用方在任务结束时 Detach 解除
    public static void Attach(Context ctx, string title, BatchTracker tracker, Func<bool> cancelHook)
    {
        _title = title;
        _tracker = tracker;
        _cancelHook = cancelHook;
        _lastPushMs = 0;
        tracker.Updated -= Push;      // 防重复订阅
        tracker.Updated += Push;
        ctx.StartForegroundService(new Intent(ctx, typeof(BatchForegroundService)));
    }
    public static void Detach(Context ctx)
    {
        if (_tracker is not null) _tracker.Updated -= Push;
        _tracker = null;
        _cancelHook = null;
        try { ctx.StopService(new Intent(ctx, typeof(BatchForegroundService))); }
        catch { /* 服务已停 */ }
    }
    // 任务结束：仅应用在后台时补一条不常驻通知（应用内已有结果弹窗，无需重复）
    public static void ShowCompleted(Context ctx, string title, string text)
    {
        if (!FileEncryptorMobile.MainActivity.AppInBackground) return;
        var nm = ctx.GetSystemService(NotificationService) as NotificationManager;
        if (nm is null) return;
        var n = new Notification.Builder(ctx, ChannelId)
            .SetSmallIcon(Resource.Drawable.ic_stat_fe)
            .SetContentTitle(title)
            .SetContentText(text)
            .SetAutoCancel(true)
            .SetContentIntent(PendingIntent.GetActivity(
                ctx, 2,
                new Intent(ctx, typeof(FileEncryptorMobile.MainActivity)),
                PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent))
            .Build();
        try { nm.Notify(NotifyId + 1, n); }
        catch { /* 通知被禁用 */ }
    }
    // 进度推送：80ms 节流太快，通知栏 400ms 足够；终态强制推一次
    static void Push(BatchSnapshot s)
    {
        var svc = Current;
        if (svc?._nm is null) return;
        long now = Stopwatch.GetTimestamp() / TimeSpan.TicksPerMillisecond;
        bool final = s.Done + s.Failed + s.Skipped + s.Cancelled >= s.Count && s.Count > 0;
        if (!final && now - _lastPushMs < 400) return;
        _lastPushMs = now;
        try { svc._nm.Notify(NotifyId, svc.Build(s)); }
        catch { /* 通知被禁用/通道异常不影响任务 */ }
    }
    // 服务实例：Attach 先于实例创建完成时首帧推送会跳过，后续帧即正常
    public static BatchForegroundService? Current { get; private set; }
    public override void OnDestroy()
    {
        if (_tracker is not null) _tracker.Updated -= Push;
        _tracker = null;
        _cancelHook = null;
        Current = null;
        base.OnDestroy();
    }
    void EnsureChannel()
    {
        if (global::Android.OS.Build.VERSION.SdkInt < BuildVersionCodes.O) return;
        var ch = new NotificationChannel(ChannelId, L10n.T("任务进度"), NotificationImportance.Low)
        {
            Description = L10n.T("加密库批量任务的进度提醒"),
        };
        ch.SetShowBadge(false);
        ch.LockscreenVisibility = NotificationVisibility.Public;   // 锁屏也可见进度（内容不含文件名）
        _nm?.CreateNotificationChannel(ch);
    }
    Notification Build() => Build(_tracker?.Snapshot() ?? new BatchSnapshot());
    Notification Build(BatchSnapshot s)
    {
        string title = _title;
        int queued = ProgressPage.Queued;
        if (queued > 0) title += L10n.F("（排队 {0} 项）", queued);
        string text;
        if (s.Count > 0 && s.Total > 0)
        {
            string unit = s.CountMode ? L10n.T("个文件") : "";
            string amount = s.CountMode
                ? $"{s.Processed} / {s.Total} {unit}"
                : $"{Fmt.Bytes(s.Processed)} / {Fmt.Bytes(s.Total)}";
            string rate = s.CountMode || s.RateBps <= 0 ? "" : L10n.F("　{0}", Fmt.Rate(s.RateBps));
            string eta = s.CountMode || double.IsNaN(s.EtaSec) ? "" : L10n.F("　剩余 {0}", Fmt.Eta(s.EtaSec));
            string counts = L10n.F("完成 {0} · 失败 {1}", s.Done, s.Failed);
            if (s.Skipped > 0) counts += L10n.F(" · 跳过 {0}", s.Skipped);
            if (s.Cancelled > 0) counts += L10n.F(" · 取消 {0}", s.Cancelled);
            text = L10n.F("{0:F0}%　{1}{2}{3}\n{4}", s.OverallPct, amount, rate, eta, counts);
        }
        else
        {
            text = L10n.T("正在准备…");
        }
        var b = new Notification.Builder(this, ChannelId)
            .SetSmallIcon(Resource.Drawable.ic_stat_fe)
            .SetContentTitle(title)
            .SetContentText(text)
            .SetOngoing(true)
            .SetOnlyAlertOnce(true)
            .SetCategory(Notification.CategoryProgress)
            .SetProgress(100, (int)Math.Round(s.OverallPct), s.Total <= 0)
            .SetContentIntent(PendingIntent.GetActivity(
                this, 0,
                new Intent(this, typeof(FileEncryptorMobile.MainActivity)),
                PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent));
        // 锁屏只露标题与百分比，不露文件名（setPublic 需要一个简化通知）
        if (global::Android.OS.Build.VERSION.SdkInt >= BuildVersionCodes.Lollipop)
        {
            var pub = new Notification.Builder(this, ChannelId)
                .SetSmallIcon(Resource.Drawable.ic_stat_fe)
                .SetContentTitle(title)
                .SetContentText(s.Total > 0 ? L10n.F("{0:F0}%", s.OverallPct) : L10n.T("正在准备…"))
                .SetOngoing(true)
                .Build();
            b.SetPublicVersion(pub);
        }
        // 通知不带操作按钮：取消统一走进度页内按钮 / 返回键
        return b.Build();
    }
}
