// 应用外播放
// 播放内核仍是 MusicPlayerHost 里
// 通知
// 锁屏 / 蓝牙 / 耳机
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Runtime;
using AndroidX.Media3.Common;
using AndroidX.Media3.Session;
using AApplication = global::Android.App.Application;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

[Service(ForegroundServiceType = ForegroundService.TypeMediaPlayback, Exported = false)]
[IntentFilter(new[] { "androidx.media3.session.MediaSessionService" })]
public sealed class MusicPlaybackService : MediaSessionService
{
    // MediaSessionService.onBind 只在这个 action 下走
    // 那是「
    private const string BrowserAction = "android.media.browse.MediaBrowserService";

    private static bool s_running;
    private static IServiceConnection? s_connection;

    private MediaSession? _session;

    // 交给 session
    private SystemMediaPlayer? _mediaPlayer;

    // 启动
    public static void Start()
    {
        if (s_running) return;
        s_running = true;
        var ctx = AApplication.Context;
        try
        {
            // 用 startService
            // 播放态自己 startForeground；万一
            // ForegroundServiceDidNotS
            ctx.StartService(new Intent(ctx, typeof(MusicPlaybackService)));
            s_connection = new BindConnection();
            bool bound = ctx.BindService(
                new Intent(ctx, typeof(MusicPlaybackService)).SetAction(BrowserAction),
                s_connection, Bind.AutoCreate);
            MainApplication.LogD(MainApplication.TagMusic, $"service: start requested bound={bound}");
            if (!bound)
            {
                s_connection = null;
                s_running = false;
                MainApplication.LogW(MainApplication.TagMusic, L10n.T("service: bind failed, 仅应用内播放"));
                try { ctx.StopService(new Intent(ctx, typeof(MusicPlaybackService))); } catch { }
            }
        }
        catch (Exception ex)
        {
            s_running = false;
            MainApplication.LogCaught("music-service", ex);
        }
    }

    // 降级
    public static void Stop()
    {
        if (!s_running) return;
        s_running = false;
        var ctx = AApplication.Context;
        try
        {
            if (s_connection is not null) { ctx.UnbindService(s_connection); s_connection = null; }
        }
        catch (Exception ex) { MainApplication.LogCaught("music-service", ex); }
        try
        {
            ctx.StopService(new Intent(ctx, typeof(MusicPlaybackService)));
            MainApplication.LogD(MainApplication.TagMusic, "service: stop requested");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-service", ex); }
    }

    // 只为借 onBind
    // 服务本身是 start 起来
    private sealed class BindConnection : Java.Lang.Object, IServiceConnection
    {
        public void OnServiceConnected(ComponentName? name, IBinder? service)
        {
            MainApplication.LogD(MainApplication.TagMusic, "service: bound (session handed to notification manager)");
            try { AApplication.Context.UnbindService(this); } catch { }
            if (ReferenceEquals(s_connection, this)) s_connection = null;
        }

        public void OnServiceDisconnected(ComponentName? name) =>
            MainApplication.LogW(MainApplication.TagMusic, "service: disconnected");
    }

    public override IBinder? OnBind(Intent? intent)
    {
        if (intent is null)
        {
            MainApplication.LogW(MainApplication.TagMusic, "service: onBind with null intent");
            return null;
        }
        MainApplication.LogD(MainApplication.TagMusic, $"service: onBind action={intent.Action ?? "null"}");
        var binder = base.OnBind(intent);
        if (binder is null)
            MainApplication.LogW(MainApplication.TagMusic, L10n.T("service: onBind returned null (session 未注册到通知管理器)"));
        return binder;
    }

    public override void OnCreate()
    {
        base.OnCreate();
        MainApplication.LogD(MainApplication.TagMusic, "service: onCreate");

        var player = MusicPlayerHost.EnsurePlayer();
        if (player is null)
        {
            MainApplication.LogE(MainApplication.TagMusic, L10n.T("service: player 为空，停止服务"));
            StopSelf();
            return;
        }

        // session 必须挂到「已有播
        // 0:00/0:00
        // 打实例 hash
        MainApplication.LogD(MainApplication.TagMusic,
            $"service: player type={player.GetType().FullName}#{player.GetHashCode()}");
        MusicPlayerHost.ApplyPlaylist("service: before session");
        MusicPlayerHost.LogSnapshot("service: before session");

        // 进程
        // 空 Player 不建 session、不挂前台
        if (!MusicPlayerHost.HasTracks)
        {
            MainApplication.LogW(MainApplication.TagMusic,
                L10n.F("service: 播放列表为空（items={0}），停止服务且不建 session/通知", player.MediaItemCount));
            s_running = false;
            StopSelf();
            return;
        }

        var activity = PendingIntent.GetActivity(
            this, 0,
            new Intent(this, typeof(MainActivity)).SetFlags(ActivityFlags.SingleTop),
            PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent);

        // session 用一层外壳
        // 并把外部
        _mediaPlayer = new SystemMediaPlayer(player);
        MainApplication.LogD(MainApplication.TagMusic,
            $"session: player wrapper {_mediaPlayer.Describe()}");

        // 逐步打点 + 分段 try/catch
        // 实测每次
        // 用 LogFailure
        IList<CommandButton> prefs;
        try
        {
            MainApplication.LogD(MainApplication.TagMusic, "session: 1 prefs build begin");
            prefs = BuildMediaButtons();
            MainApplication.LogD(MainApplication.TagMusic,
                $"session: 1 prefs built count={prefs.Count}");
        }
        catch (Exception ex)
        {
            LogFailure("1 prefs build", ex);
            s_running = false;
            StopSelf();
            return;
        }

        try
        {
            MainApplication.LogD(MainApplication.TagMusic, "session: 2 builder begin");
            // 不自定 Id
            var sessionBuilder = new MediaSession.Builder(this, _mediaPlayer);
            MainApplication.LogD(MainApplication.TagMusic, "session: 2 builder created");
            sessionBuilder.SetSessionActivity(activity);
            MainApplication.LogD(MainApplication.TagMusic, "session: 2 activity set");
            // 通知
            // back =
            sessionBuilder.SetMediaButtonPreferences(prefs);
            MainApplication.LogD(MainApplication.TagMusic, "session: 2 prefs set");
            MainApplication.LogD(MainApplication.TagMusic, "session: 3 session build begin");
            _session = sessionBuilder.Build();
            MainApplication.LogD(MainApplication.TagMusic,
                $"session: 3 session built hash={_session?.GetHashCode()}");
        }
        catch (Exception ex)
        {
            LogFailure("2/3 builder-session", ex);
            s_running = false;
            StopSelf();
            return;
        }

        s_running = true;
        MainApplication.LogD(MainApplication.TagMusic, L10n.T("session: 4 post-build ok（前台通知由 Media3 内部启动）"));
        MainApplication.LogNote("music-service",
            $"created session with player state={player.PlaybackState} pwr={player.PlayWhenReady} items={player.MediaItemCount}");

        // 诊断
        // 快照用来确认「命
        // 打两次快照
        var handler = new Handler(Looper.MainLooper!);
        // 崩溃若发生
        // 这条 500ms 存活日志
        handler.PostDelayed(() =>
            MainApplication.LogD(MainApplication.TagMusic, "session: 5 alive t+500ms"), 500);
        handler.PostDelayed(() =>
        {
            LogSessionProbe("t+3s");
            LogNotificationActions("t+3s");
        }, 3000);
        handler.PostDelayed(() =>
        {
            LogSessionProbe("t+10s");
            LogNotificationActions("t+10s");
        }, 10000);
    }

    // 取证
    // logcat 单行有长度上限
    private static void LogFailure(string stage, Exception ex)
    {
        try { MainApplication.LogCaught("music-session", ex); } catch { }
        try
        {
            string text = ex.ToString() ?? "";
            const int chunk = 3000;
            int n = Math.Max(1, (text.Length + chunk - 1) / chunk);
            for (int i = 0; i < n; i++)
            {
                int start = i * chunk;
                int len = Math.Min(chunk, Math.Max(0, text.Length - start));
                string part = len > 0 ? text.Substring(start, len) : "";
                MainApplication.LogE(MainApplication.TagMusic,
                    $"session: {stage} FAILED [{i + 1}/{n}] {part}");
            }
        }
        catch { }
    }

    // 诊断
    private void LogSessionProbe(string stage)
    {
        var session = _session;
        if (session is null) return;
        try
        {
            var commands = session.Player?.AvailableCommands;
            var controllers = session.ConnectedControllers;
            string names = "";
            if (controllers is not null && controllers.Count > 0)
            {
                var parts = new List<string>();
                foreach (var controller in controllers)
                    parts.Add($"{controller?.PackageName}#{controller?.Uid}");
                names = $" [{string.Join(", ", parts)}]";
            }
            MainApplication.LogD(MainApplication.TagMusic,
                $"session: probe ({stage}) " +
                $"defaultPos={Contains(commands, BasePlayer.InterfaceConsts.CommandSeekToDefaultPosition)} " +
                $"prev={Contains(commands, BasePlayer.InterfaceConsts.CommandSeekToPreviousMediaItem)} " +
                $"next={Contains(commands, BasePlayer.InterfaceConsts.CommandSeekToNextMediaItem)} | " +
                $"controllers={controllers?.Count ?? 0}{names}");
        }
        catch (Exception ex) { MainApplication.LogCaught("music-session", ex); }
    }

    private static bool Contains(PlayerCommands? commands, int command)
    {
        try { return commands?.Contains(command) ?? false; }
        catch { return false; }
    }

    // 诊断用
    // 「通知里有没有
    private void LogNotificationActions(string stage)
    {
        try
        {
            if (GetSystemService(Context.NotificationService) is not NotificationManager nm)
            {
                MainApplication.LogW(MainApplication.TagMusic, L10n.F("notif: {0} 取不到 NotificationManager", stage));
                return;
            }
            var active = nm.GetActiveNotifications();
            if (active is null || active.Length == 0)
            {
                MainApplication.LogW(MainApplication.TagMusic, L10n.F("notif: {0} 当前没有活动通知", stage));
                return;
            }
            foreach (var sbn in active)
            {
                if (sbn is null) continue;
                var actions = sbn.Notification?.Actions;
                var parts = new List<string>();
                if (actions is not null)
                {
                    foreach (var action in actions)
                        parts.Add($"\"{action.Title}\"(icon={IconName(action.Icon?.ResId ?? 0)})");
                }
                MainApplication.LogD(MainApplication.TagMusic,
                    $"notif: {stage} id={sbn.Id} actions={parts.Count} [{string.Join(", ", parts)}]");
            }
        }
        catch (Exception ex) { MainApplication.LogCaught("music-notify", ex); }
    }

    // 日志用
    private static string IconName(int resId)
    {
        if (resId == Resource.Drawable.ic_fe_restart) return "ic_fe_restart";
        if (resId == Resource.Drawable.ic_fe_play) return "ic_fe_play";
        if (resId == Resource.Drawable.ic_fe_pause) return "ic_fe_pause";
        if (resId == Resource.Drawable.ic_fe_music_next) return "ic_fe_music_next";
        if (resId == Resource.Drawable.ic_fe_music_shuffle) return "ic_fe_music_shuffle";
        if (resId == Resource.Drawable.ic_fe_music_repeat_one) return "ic_fe_music_repeat_one";
        if (resId == Resource.Drawable.ic_fe_music_repeat_all) return "ic_fe_music_repeat_all";
        return resId.ToString();
    }

    // 通知栏三
    // back =
    // central = 播放 / 暂停
    //   forward = 下一首
    // 只声明这两个槽
    private static IList<CommandButton> BuildMediaButtons()
    {
        int restartIcon = Resource.Drawable.ic_fe_restart;
        int nextIcon = Resource.Drawable.ic_fe_music_next;
        // 两个通道分工
        // 构造参数 =
        // 自绘图标 =
        MainApplication.LogD(MainApplication.TagMusic,
            $"session: prefs icons restart=IconPrevious({CommandButton.IconPrevious})+res{restartIcon} " +
            $"next=IconNext({CommandButton.IconNext})+res{nextIcon}");

        // 「从头播放」用标准
        // seekToDefaultPosition
        var restart = new CommandButton.Builder(CommandButton.IconPrevious)
            .SetCustomIconResId(restartIcon)
            .SetDisplayName(L10n.T("从头播放"))
            .SetPlayerCommand(BasePlayer.InterfaceConsts.CommandSeekToPrevious)
            .SetSlots(CommandButton.SlotBack)
            .Build();
        var next = new CommandButton.Builder(CommandButton.IconNext)
            .SetCustomIconResId(nextIcon)
            .SetDisplayName(L10n.T("下一首"))
            .SetPlayerCommand(BasePlayer.InterfaceConsts.CommandSeekToNextMediaItem)
            .SetSlots(CommandButton.SlotForward)
            .Build();
        return new List<CommandButton> { restart!, next! };
    }

    public override MediaSession? OnGetSession(MediaSession.ControllerInfo? controllerInfo)
    {
        MainApplication.LogD(MainApplication.TagMusic,
            $"service: onGetSession package={controllerInfo?.PackageName} uid={controllerInfo?.Uid} session={( _session is null ? "null" : "ok")}");
        return _session;
    }

    // 用户
    public override void OnTaskRemoved(Intent? rootIntent)
    {
        MainApplication.LogD(MainApplication.TagMusic, "service: onTaskRemoved, stop");
        try { MusicPlayerHost.Pause(); } catch (Exception ex) { MainApplication.LogCaught("music-service", ex); }
        StopSelf();
        base.OnTaskRemoved(rootIntent);
    }

    public override void OnDestroy()
    {
        MainApplication.LogD(MainApplication.TagMusic, "service: onDestroy");
        s_running = false;
        try { _session?.Release(); } catch (Exception ex) { MainApplication.LogCaught("music-service", ex); }
        _session = null;
        _mediaPlayer = null;
        base.OnDestroy();
    }
}

// 只交给系统媒体
// 系统/耳机/通知
internal sealed class SystemMediaPlayer : ForwardingPlayer
{
    public SystemMediaPlayer(IPlayer player) : base(player) { }

    public override void SeekToPrevious() => SeekToDefaultPosition();

    public override void SeekToPreviousMediaItem() => SeekToDefaultPosition();

    public string Describe()
    {
        try
        {
            var commands = AvailableCommands;
            if (commands is null) return "commands=null";
            return "prev=" + (commands.Contains(BasePlayer.InterfaceConsts.CommandSeekToPreviousMediaItem)
                              || commands.Contains(BasePlayer.InterfaceConsts.CommandSeekToPrevious))
                   + " next=" + (commands.Contains(BasePlayer.InterfaceConsts.CommandSeekToNextMediaItem)
                              || commands.Contains(BasePlayer.InterfaceConsts.CommandSeekToNext))
                   + " defaultPos=" + commands.Contains(BasePlayer.InterfaceConsts.CommandSeekToDefaultPosition);
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("music-session", ex);
            return "commands=error";
        }
    }
}
