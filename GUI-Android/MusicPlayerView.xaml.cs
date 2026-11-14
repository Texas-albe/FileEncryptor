// 设置页内联
// 离开设置页只
// 「应用外播放」开关
using Android.Content.PM;
using Android.OS;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Dispatching;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class MusicPlayerView : ContentView
{
    internal const int NotifyPermRequestCode = 9912;

    private const string IconPlay = "ic_fe_play";
    private const string IconPause = "ic_fe_pause";
    private const string IconNext = "ic_fe_music_next";
    private const string IconRepeatOne = "ic_fe_music_repeat_one";
    private const string IconRepeatAll = "ic_fe_music_repeat_all";
    private const string IconShuffle = "ic_fe_music_shuffle";

    private IDispatcherTimer? _ticker;
    private bool _bound;
    private bool _empty = true;
    private bool _dragging;
    private bool _settingSwitch;
    private string _lastTime = "";
    private long _lastDurationMs = -1;   // 上一次打印
    private byte[]? _coverShown;

    private Android.Widget.SeekBar? _seekBar;
    private MusicProgressDrawable? _progress;

    public MusicPlayerView()
    {
        InitializeComponent();
        Seek.HandlerChanged += (_, _) => ApplySeekBarStyle();
        ApplyModeUi();
        ShowEmpty();
    }

    // 设置页 OnAppearing
    public void OnPageAppearing()
    {
        MusicPlayerHost.Changed -= OnHostChanged;
        MusicPlayerHost.Changed += OnHostChanged;
        _bound = true;
        MainApplication.LogD(MainApplication.TagMusic,
            $"ui: page enter bgPlay={MusicPlayerHost.BackgroundPlayEnabled} tracks={(MusicPlayerHost.HasTracks ? "ready" : "pending")}");

        _settingSwitch = true;
        SwBgPlay.IsToggled = MusicPlayerHost.BackgroundPlayEnabled;
        _settingSwitch = false;

        MusicPlayerHost.EnsureInitialized();
        _lastDurationMs = -1;   // 重新进页面
        ApplySeekBarStyle();
        Bind();
        StartTicker();
    }

    // 设置页 OnDisappearing：只解绑界
    public void OnPageDisappearing()
    {
        MainApplication.LogD(MainApplication.TagMusic, L10n.T("ui: page leave (播放不中断)"));
        MusicPlayerHost.Changed -= OnHostChanged;
        _bound = false;
        StopTicker();
    }

    private void OnHostChanged()
    {
        MainThread.BeginInvokeOnMainThread(() => { if (_bound) Bind(); });
    }

    private void Bind()
    {
        if (!MusicPlayerHost.HasTracks) { ShowEmpty(); return; }
        ShowTrack(MusicPlayerHost.Title, MusicPlayerHost.Artist, MusicPlayerHost.Cover);
        ApplyModeUi();
        UpdateProgress();
    }

    private void ShowEmpty()
    {
        _empty = true;
        _lastTime = "";
        _lastDurationMs = -1;
        _coverShown = null;
        CoverArt.Source = null;
        CoverArt.IsVisible = false;
        CoverFallback.IsVisible = true;
        LblTitle.Text = L10n.T("还没有放入音乐");
        LblTime.Text = "00:00/00:00";
        Seek.Value = 0;
        Seek.Maximum = 1;
        Seek.IsEnabled = false;
        BtnPlay.Source = IconPlay;
        SemanticProperties.SetDescription(BtnPlay, L10n.T("播放"));
        BtnPlay.IsEnabled = false;
        BtnNext.IsEnabled = false;
        BtnMode.IsEnabled = false;
        SetPlayedLevel(0);
    }

    private void ShowTrack(string title, string artist, byte[]? cover)
    {
        _empty = false;
        Seek.IsEnabled = true;
        BtnPlay.IsEnabled = true;
        BtnNext.IsEnabled = true;
        BtnMode.IsEnabled = true;

        string text = string.IsNullOrWhiteSpace(artist) ? title : $"{title} · {artist}";
        if (LblTitle.Text != text) LblTitle.Text = text;

        // 封面只
        if (!ReferenceEquals(_coverShown, cover))
        {
            _coverShown = cover;
            if (cover is { Length: > 0 })
            {
                var bytes = cover;
                CoverArt.Source = ImageSource.FromStream(() => new MemoryStream(bytes));
                CoverArt.IsVisible = true;
                CoverFallback.IsVisible = false;
            }
            else
            {
                CoverArt.Source = null;
                CoverArt.IsVisible = false;
                CoverFallback.IsVisible = true;
            }
        }
    }

    private void StartTicker()
    {
        StopTicker();
        try
        {
            _ticker = Dispatcher.CreateTimer();
            _ticker.Interval = TimeSpan.FromMilliseconds(500);
            _ticker.Tick += (_, _) => UpdateProgress();
            _ticker.Start();
        }
        catch (Exception ex) { MainApplication.LogCaught("music-ticker", ex); }
    }

    private void StopTicker()
    {
        try { _ticker?.Stop(); } catch { }
        _ticker = null;
    }

    private void UpdateProgress()
    {
        if (!_bound) return;
        if (!MusicPlayerHost.HasTracks) { if (!_empty) ShowEmpty(); return; }
        if (_empty) return;

        long duration = MusicPlayerHost.Duration;
        long position = MusicPlayerHost.Position;
        // 时长
        if (duration != _lastDurationMs)
        {
            _lastDurationMs = duration;
            MainApplication.LogD(MainApplication.TagMusic,
                $"ui: duration={duration}ms pos={position}ms failed={MusicPlayerHost.Failed}");
        }
        if (duration > 0)
        {
            if (Math.Abs(Seek.Maximum - duration) > 0.5) Seek.Maximum = duration;
            if (!_dragging) Seek.Value = Math.Clamp(position, 0, duration);
        }

        // 自定义进度条
        SetPlayedLevel(duration > 0 ? (int)Math.Clamp(position * 10000L / duration, 0, 10000) : 0);

        string time = MusicPlayerHost.Failed ? L10n.T("播放失败") : Fmt(position) + "/" + Fmt(duration);
        if (time != _lastTime) { _lastTime = time; LblTime.Text = time; }

        bool playing = MusicPlayerHost.WantsPlayback;
        string icon = playing ? IconPause : IconPlay;
        if (!(BtnPlay.Source is FileImageSource src && src.File == icon)) BtnPlay.Source = icon;
        SemanticProperties.SetDescription(BtnPlay, playing ? L10n.T("暂停") : L10n.T("播放"));
    }

    private void SetPlayedLevel(int level)
    {
        try { _progress?.SetLevel(Math.Clamp(level, 0, 10000)); } catch { }
    }

    // 循环三态
    private void ApplyModeUi()
    {
        switch (MusicPlayerHost.Mode)
        {
            case MusicPlayerHost.ModeSingle:
                BtnMode.Source = IconRepeatOne;
                SemanticProperties.SetDescription(BtnMode, L10n.T("单曲循环"));
                break;
            case MusicPlayerHost.ModeShuffle:
                BtnMode.Source = IconShuffle;
                SemanticProperties.SetDescription(BtnMode, L10n.T("随机播放"));
                break;
            default:
                BtnMode.Source = IconRepeatAll;
                SemanticProperties.SetDescription(BtnMode, L10n.T("列表循环"));
                break;
        }
    }

    // MAUI 的 Slider
    // LayerDrawable 不把 level 传给子层导
    private void ApplySeekBarStyle()
    {
        if (Seek.Handler?.PlatformView is not Android.Widget.SeekBar bar) return;
        if (ReferenceEquals(_seekBar, bar) && _progress is not null) return;
        try
        {
            int primary = PrimaryColor();
            int track = (primary & 0x00FFFFFF) | 0x4D000000;   // 主色 30% 透明度
            // 粗细
            float density = 1f;
            try { density = bar.Context?.Resources?.DisplayMetrics?.Density ?? 1f; } catch { }
            if (density <= 0) density = 1f;
            _progress = new MusicProgressDrawable(track, primary, 4f * density);
            bar.ProgressDrawable = _progress;
            bar.SplitTrack = false;
            _seekBar = bar;
            MainApplication.LogD(MainApplication.TagMusic,
                $"ui: seekbar drawable applied density={density:0.##} thickness={(4f * density):0.#}px");
            long duration = MusicPlayerHost.Duration;
            long position = MusicPlayerHost.Position;
            SetPlayedLevel(duration > 0
                ? (int)Math.Clamp(position * 10000L / duration, 0, 10000)
                : 0);
        }
        catch (Exception ex) { MainApplication.LogCaught("music-seekbar", ex); }
    }

    private static int PrimaryColor()
    {
        try
        {
            var act = Platform.CurrentActivity;
            if (act is null) return unchecked((int)0xFF4A72C8);
            return act.Resources!.GetColor(Resource.Color.colorPrimary, act.Theme!);
        }
        catch { return unchecked((int)0xFF4A72C8); }
    }

    private static string Fmt(long ms)
    {
        if (ms < 0) ms = 0;
        var t = TimeSpan.FromMilliseconds(ms);
        return t.TotalHours >= 1
            ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}"
            : $"{t.Minutes:00}:{t.Seconds:00}";
    }

    private void OnPlayPause(object? sender, EventArgs e)
    {
        MainApplication.LogD(MainApplication.TagMusic, "ui: play/pause tapped");
        MusicPlayerHost.TogglePlayPause();
        UpdateProgress();
    }

    private void OnNext(object? sender, EventArgs e)
    {
        MainApplication.LogD(MainApplication.TagMusic, "ui: next tapped");
        MusicPlayerHost.PlayNext();
        UpdateProgress();
    }

    private void OnCycleMode(object? sender, EventArgs e)
    {
        MainApplication.LogD(MainApplication.TagMusic, "ui: mode tapped");
        MusicPlayerHost.CycleMode();
        ApplyModeUi();
    }

    private void OnSeekDragStarted(object? sender, EventArgs e) => _dragging = true;

    private void OnSeekDragCompleted(object? sender, EventArgs e)
    {
        _dragging = false;
        MainApplication.LogD(MainApplication.TagMusic, $"ui: seek to {(long)Seek.Value}ms");
        MusicPlayerHost.SeekTo((long)Seek.Value);
        UpdateProgress();
    }

    // 开关
    private void OnBackgroundPlayToggled(object? sender, ToggledEventArgs e)
    {
        if (_settingSwitch) return;
        MainApplication.LogD(MainApplication.TagMusic, $"ui: bgPlay switch -> {e.Value}");
        MusicPlayerHost.SetBackgroundPlay(e.Value);
        if (e.Value) EnsureNotificationPermission();
    }

    private static void EnsureNotificationPermission()
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(33)) return;
        var act = Platform.CurrentActivity;
        if (act is null) return;
        try
        {
            if (act.CheckSelfPermission(Android.Manifest.Permission.PostNotifications) == Permission.Granted)
            {
                MainApplication.LogD(MainApplication.TagMusic, "permission: POST_NOTIFICATIONS already granted");
                return;
            }
            MainApplication.LogD(MainApplication.TagMusic, "permission: request POST_NOTIFICATIONS");
            act.RequestPermissions(
                new[] { Android.Manifest.Permission.PostNotifications }, NotifyPermRequestCode);
        }
        catch (Exception ex) { MainApplication.LogCaught("music-notify-perm", ex); }
    }
}

// 自绘进度条
// 不复用 LayerDrawable
internal sealed class MusicProgressDrawable : Android.Graphics.Drawables.Drawable
{
    private readonly Android.Graphics.Paint _trackPaint = new(Android.Graphics.PaintFlags.AntiAlias);
    private readonly Android.Graphics.Paint _playedPaint = new(Android.Graphics.PaintFlags.AntiAlias);
    private readonly float _thickness;

    public MusicProgressDrawable(int trackColor, int playedColor, float thickness)
    {
        _thickness = thickness;
        _trackPaint.Color = new Android.Graphics.Color(trackColor);
        _playedPaint.Color = new Android.Graphics.Color(playedColor);
    }

    public override int IntrinsicHeight => (int)Math.Ceiling(_thickness);

    public override int Opacity => (int)Android.Graphics.Format.Translucent;

    public override void Draw(Android.Graphics.Canvas canvas)
    {
        var bounds = Bounds;
        if (bounds.Width() <= 0 || bounds.Height() <= 0) return;

        float h = Math.Min(_thickness, bounds.Height());
        float top = bounds.Top + (bounds.Height() - h) / 2f;
        float radius = h / 2f;
        canvas.DrawRoundRect(bounds.Left, top, bounds.Right, top + h, radius, radius, _trackPaint);

        int level = Math.Clamp(Level, 0, 10000);
        if (level <= 0) return;
        float right = bounds.Left + bounds.Width() * level / 10000f;
        canvas.Save();
        canvas.ClipRect(bounds.Left, bounds.Top, right, bounds.Bottom);
        canvas.DrawRoundRect(bounds.Left, top, bounds.Right, top + h, radius, radius, _playedPaint);
        canvas.Restore();
    }

    public override void SetAlpha(int alpha) { }

    public override void SetColorFilter(Android.Graphics.ColorFilter? colorFilter) { }

    protected override bool OnLevelChange(int level)
    {
        InvalidateSelf();
        return true;
    }
}
