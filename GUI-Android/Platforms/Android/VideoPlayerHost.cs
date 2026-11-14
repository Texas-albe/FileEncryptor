// 视频播放原生层
// 播放内核双轨
// 容器尾部索引
// 顺序窗口解密兜
// 控制条全部是本
// 崩溃根因
// 再挂一
// MediaController.Show 抛 BadTokenException 正好发生
// 控制条全部作
// 并逐处 try/catch 落盘
// 版式对齐参考图
// 保证可读
// 。内边距
// 全部
using Android.Widget;
using Microsoft.Maui.Storage;
using GrowingFileDataSource = global::FileEncryptorMobile.Platforms.Android.GrowingFileDataSource;
using VaultMediaDataSource = global::FileEncryptorMobile.Platforms.Android.VaultMediaDataSource;
using IAbortableStream = global::FileEncryptorMobile.Platforms.Android.IAbortableStream;
using AActivity = global::Android.App.Activity;
using ACanvas = global::Android.Graphics.Canvas;
using AColor = global::Android.Graphics.Color;
using AColorFilter = global::Android.Graphics.ColorFilter;
using ADrawable = global::Android.Graphics.Drawables.Drawable;
using AFormat = global::Android.Graphics.Format;
using APaint = global::Android.Graphics.Paint;
using AGravity = global::Android.Views.GravityFlags;
using ATextUtils = global::Android.Text.TextUtils;
using AView = global::Android.Views.View;
using AViewGroup = global::Android.Views.ViewGroup;
using AWindowManagerFlags = global::Android.Views.WindowManagerFlags;
using AWindowManagerLayoutParams = global::Android.Views.WindowManagerLayoutParams;
using AWindowManagerTypes = global::Android.Views.WindowManagerTypes;
using FileEncryptorMobile.Services;
using AndroidX.Media3.Common;
// nextlib 工厂
using NextRenderersFactory = global::IO.Github.Anilbeesetti.Nextlib.Media3ext.Ffdecoder.NextRenderersFactory;
using FfmpegLibrary = global::IO.Github.Anilbeesetti.Nextlib.Media3ext.Ffdecoder.FfmpegLibrary;
using AndroidX.Media3.DataSource;
using AndroidX.Media3.ExoPlayer;
using AndroidX.Media3.ExoPlayer.Source;

namespace FileEncryptorMobile;

public static partial class VideoPlayerHost
{
    // 线性图标统一 tint
    private const int TintWhite = unchecked((int)0xFFFFFFFF);
    private const int TintDim = unchecked((int)0x8AFFFFFF);

    private static readonly float[] SpeedValues = { 0.5f, 1f, 1.25f, 1.5f, 2f, 3f };
    private static readonly int[] TimerValues = { 0, 5, 15, 30, 60 };

    private const int PlayerStateEnded = 4;

    // 会话代次
    // 一律作废
    private static int s_gen;
    private static AActivity? _activity;
    private static FrameLayout? _root;
    private static global::Android.Views.IWindowManager? _wm;
    private static global::Android.Views.TextureView? _video;
    private static RatioFrameLayout? _aspect;
    // 播放内核
    private static IVideoCore? _player;
    // 库内流式源引用
    private static global::Android.Media.MediaDataSource? _stream;
    private static long _wdExported = -1;   // 看门狗导出推进
    // 内核降级计数
    private static int _fallbackStage;
    // 内核记忆
    private static readonly System.Collections.Generic.Dictionary<string, int> s_coreHint = new();
    private static string? s_hintKey;
    private static Java.Lang.IRunnable? _watchdogRunnable;
    private static int _videoW;
    private static int _videoH;
    private static TextView? _message;
    private static ImageView? _playPause;
    private static TextView? _curTime;
    private static TextView? _totalTime;
    private static global::Android.Widget.SeekBar? _seek;
    private static ImageView? _lockBtn;
    private static ImageView? _rotateBtn;
    private static AView? _topBar;
    private static AView? _bottomBar;
    private static LinearLayout? _buttonRow;
    private static AView[]? _btnCells;
    private static TextView? _titleView;
    private static LinearLayout? _progressRow;
    // 手势中央提示
    private static TextView? _hint;
    // 音量手势走 STREAM_MUSIC；拿
    private static global::Android.Media.AudioManager? _audio;
    // 版式缓存
    private static int _chromeW = -1, _chromeH = -1, _chromeVw = -1, _chromeVh = -1, _chromeMode = -1;
    private static global::Android.OS.Handler? _handler;
    private static Java.Lang.IRunnable? _ticker;
    private static Java.Lang.IRunnable? _hideRunnable;
    private static Java.Lang.IRunnable? _timerRunnable;
    private static Action? _onExit;
    private static bool _seeking;
    private static bool _errorShown;
    private static bool _uiHidden;
    private static bool _locked;
    private static bool _prepared;
    // 正常播完 / 已释放
    // 不能当成解码失
    private static bool _ended;
    private static bool _released;
    private static bool _havePlayIcon;
    private static bool _lastPlaying;

    // 字幕
    // 字幕视图是同一
    private static SubtitleTrack? _subtitle;
    private static TextView? _subtitleView;
    private static global::Android.OS.Handler? _subtitleHandler;
    private static Java.Lang.IRunnable? _subtitleRunnable;
    private static string? _subtitleLastText;
    // PiP 小窗
    private static bool _pipMode;

    // 中心 loading
    private static global::Android.Widget.ProgressBar? _loadingView;
    private static global::Android.Widget.ImageView? _pulse;

    // 播放设置
    private static bool _fill;        // 强制铺满全屏
    private static bool _stretch;     // 拉伸
    private static bool _autoOrient;  // 自适应横竖屏
    private static bool _loop;        // 循环播放
    private static float _speed = 1f;
    private static int _timerMinutes; // 0 = 未设置
    private static float _density = 1f;

    // 返回 false 表示播放窗
    public static bool Open(AActivity act, string path, string title,
        Action onExit, Action onEnded, Action<string> onError,
        global::Android.Media.MediaDataSource? stream = null,
        System.Threading.Tasks.Task<bool>? exportGate = null)
    {
        try
        {
            Close();
            _released = false;
            _ended = false;
            if (act is null || act.IsFinishing || act.IsDestroyed)
            {
                onError(L10n.T("播放窗口不可用，请返回后重试。"));
                return false;
            }
            var wm = act.WindowManager;
            if (wm is null)
            {
                onError(L10n.T("播放窗口不可用，请返回后重试。"));
                return false;
            }
            // 库内随机读源
            if (stream is null && exportGate is null &&
                (!File.Exists(path) || new FileInfo(path).Length <= 0))
            {
                onError(L10n.T("临时文件不可用，请重新打开。"));
                return false;
            }

            int gen = s_gen;
            _wdExported = -1;
            s_hintKey = (stream as VaultMediaDataSource)?.RelPath ?? path;
            float density = act.Resources?.DisplayMetrics?.Density ?? 1f;
            _density = density;
            LoadSettings();
            int Dp(float v) => (int)(v * density + 0.5f);

            var root = new FrameLayout(act);
            root.SetBackgroundColor(AColor.Black);
            root.SetClipChildren(true);

            // 缩放容器
            var aspect = new RatioFrameLayout(act) { ResizeMode = ResizeModeValue() };
            var video = new global::Android.Views.TextureView(act);
            video.Clickable = false;
            video.Focusable = false;
            // TextureView 禁背景 drawable，用 Opaque 保黑
            video.SetOpaque(true);
            // 播放页常亮
            video.KeepScreenOn = true;
            aspect.AddView(video, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.MatchParent, AGravity.Center));
            root.AddView(aspect, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.MatchParent, AGravity.Center));

            // 中心 loading
            var loading = new global::Android.Widget.ProgressBar(act) { Indeterminate = true };
            try { loading.IndeterminateDrawable?.SetTint(AColor.White); } catch { }
            loading.Clickable = false;
            root.AddView(loading, new FrameLayout.LayoutParams(Dp(56), Dp(56), AGravity.Center));

            // 播放/暂停中心脉
            var pulse = new global::Android.Widget.ImageView(act);
            pulse.SetBackgroundColor(AColor.Transparent);
            pulse.Clickable = false;
            pulse.Focusable = false;
            pulse.Visibility = global::Android.Views.ViewStates.Gone;
            root.AddView(pulse, new FrameLayout.LayoutParams(Dp(88), Dp(88), AGravity.Center));

            // 顶栏
            var topBar = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Horizontal };
            topBar.SetGravity(AGravity.CenterVertical);
            topBar.SetBackgroundColor(AColor.Transparent);
            topBar.Clickable = true;   // 点栏本身不穿透

            var back = MakeIconButton(act, Resource.Drawable.ic_fe_back, 40, 24, TintWhite, density, true);
            back.Click += (_, _) => SafeInvoke(onExit);
            topBar.AddView(back, new LinearLayout.LayoutParams(Dp(40), Dp(40)));

            var titleView = new TextView(act) { Text = title, TextSize = 14, Gravity = AGravity.CenterVertical };
            titleView.SetTextColor(AColor.White);
            titleView.SetSingleLine(true);
            titleView.Ellipsize = ATextUtils.TruncateAt.End;
            AddTextShadow(titleView, density);
            topBar.AddView(titleView, new LinearLayout.LayoutParams(0, AViewGroup.LayoutParams.WrapContent, 1f) {
                LeftMargin = Dp(8), RightMargin = Dp(8),
            });

            var more = MakeIconButton(act, Resource.Drawable.ic_fe_more, 40, 24, TintWhite, density, true);
            more.Click += (_, _) => TogglePanel(gen);
            topBar.AddView(more, new LinearLayout.LayoutParams(Dp(40), Dp(40)));

            root.AddView(topBar, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent,
                AGravity.Top));

            // 底栏
            var bottomBar = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Vertical };
            bottomBar.SetBackgroundColor(AColor.Transparent);
            bottomBar.Clickable = true;

            var progressRow = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Horizontal };
            progressRow.SetGravity(AGravity.CenterVertical);

            var cur = new TextView(act) { Text = "00:00", TextSize = 12 };
            cur.SetTextColor(AColor.White);
            AddTextShadow(cur, density);
            progressRow.AddView(cur, new LinearLayout.LayoutParams(
                AViewGroup.LayoutParams.WrapContent, AViewGroup.LayoutParams.WrapContent));

            var seek = MakeSeekBar(act, density);
            progressRow.AddView(seek, new LinearLayout.LayoutParams(0, Dp(24), 1f) {
                LeftMargin = Dp(12), RightMargin = Dp(12),
            });

            var total = new TextView(act) { Text = "00:00", TextSize = 12 };
            total.SetTextColor(AColor.White);
            AddTextShadow(total, density);
            progressRow.AddView(total, new LinearLayout.LayoutParams(
                AViewGroup.LayoutParams.WrapContent, AViewGroup.LayoutParams.WrapContent));

            bottomBar.AddView(progressRow, new LinearLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent));

            // 按钮行放
            var buttonHost = new FrameLayout(act);
            var buttonRow = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Horizontal };
            buttonRow.SetGravity(AGravity.CenterVertical);
            buttonHost.AddView(buttonRow, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent, AGravity.CenterHorizontal));

            // 上一部 / 下一部
            var prev = MakeIconButton(act, Resource.Drawable.ic_fe_prev, 40, 24, TintWhite, density, true);
            prev.Click += (_, _) => { if (!_released) _onPrev?.Invoke(); };
            var next = MakeIconButton(act, Resource.Drawable.ic_fe_next, 40, 24, TintWhite, density, true);
            next.Click += (_, _) => { if (!_released) _onNext?.Invoke(); };
            _prevBtn = prev;
            _nextBtn = next;
            RefreshNavButtons();

            var rewind = MakeIconButton(act, Resource.Drawable.ic_fe_rewind10, 44, 28, TintWhite, density, true);
            rewind.Click += (_, _) => Skip(gen, -10_000);
            // 播放键
            var playPause = MakeIconButton(act, Resource.Drawable.ic_fe_play, 44, 28, TintWhite, density, true);
            var forward = MakeIconButton(act, Resource.Drawable.ic_fe_forward10, 44, 28, TintWhite, density, true);
            forward.Click += (_, _) => Skip(gen, 10_000);

            var cells = new AView[] { prev, rewind, playPause, forward, next };
            foreach (var cell in cells)
                buttonRow.AddView(cell, new LinearLayout.LayoutParams(0, Dp(52), 1f));

            bottomBar.AddView(buttonHost, new LinearLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent) { TopMargin = Dp(6) });

            root.AddView(bottomBar, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent,
                AGravity.Bottom));

            // 左悬浮
            // 位置
            var lockBtn = MakeIconButton(act, Resource.Drawable.ic_fe_unlock, 42, 20, TintWhite, density, true);
            lockBtn.Background = RoundBg("#59000000", 21, density);
            root.AddView(lockBtn, new FrameLayout.LayoutParams(Dp(42), Dp(42), AGravity.Top | AGravity.Left) {
                LeftMargin = Dp(18), TopMargin = Dp(100),
            });

            var rotateBtn = MakeIconButton(act, Resource.Drawable.ic_fe_rotate, 42, 20, TintWhite, density, true);
            rotateBtn.Background = RoundBg("#59000000", 21, density);
            rotateBtn.Click += (_, _) => ToggleOrientation(gen);
            root.AddView(rotateBtn, new FrameLayout.LayoutParams(Dp(42), Dp(42), AGravity.Top | AGravity.Left) {
                LeftMargin = Dp(18), TopMargin = Dp(100),
            });

            // 错误
            var message = new TextView(act)
            {
                TextSize = 14,
                Gravity = AGravity.Center,
            };
            message.Visibility = global::Android.Views.ViewStates.Gone;
            message.SetTextColor(AColor.White);
            message.Background = RoundBg("#CC000000", 10, density);
            message.SetPadding(Dp(18), Dp(12), Dp(18), Dp(12));
            root.AddView(message, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.WrapContent, AViewGroup.LayoutParams.WrapContent, AGravity.Center));

            // 手势提示
            // 免得拖进度
            var hint = new TextView(act) { TextSize = 16, Gravity = AGravity.Center };
            hint.SetTextColor(AColor.White);
            hint.Background = RoundBg("#CC000000", 10, density);
            hint.SetPadding(Dp(18), Dp(12), Dp(18), Dp(12));
            hint.Visibility = global::Android.Views.ViewStates.Gone;
            root.AddView(hint, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.WrapContent, AViewGroup.LayoutParams.WrapContent, AGravity.Center));

            // 字幕层
            var subtitleView = new TextView(act)
            {
                TextSize = 16,
                Gravity = AGravity.Center,
            };
            subtitleView.SetTextColor(AColor.White);
            subtitleView.SetShadowLayer(2f * density, 0f, 1f * density, AColor.ParseColor("#CC000000"));
            subtitleView.SetBackgroundColor(AColor.ParseColor("#66000000"));
            subtitleView.SetPadding(Dp(12), Dp(6), Dp(12), Dp(6));
            subtitleView.SetMaxLines(3);
            subtitleView.Ellipsize = ATextUtils.TruncateAt.End;
            subtitleView.Clickable = false;
            subtitleView.Focusable = false;
            subtitleView.Visibility = global::Android.Views.ViewStates.Gone;
            root.AddView(subtitleView, new FrameLayout.LayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent,
                AGravity.Bottom | AGravity.CenterHorizontal) {
                LeftMargin = Dp(24), RightMargin = Dp(24), BottomMargin = Dp(88),
            });

            // 先把视图状态保
            _activity = act;
            _wm = wm;
            _root = root;
            _video = video;
            _aspect = aspect;
            _message = message;
            _hint = hint;
            _subtitleView = subtitleView;
            _subtitle = SubtitleTrack.TryLoad(path);
            _subtitleLastText = null;
            _pipMode = false;
            // 音量手势用系统
            try
            {
                _audio = act.GetSystemService(global::Android.Content.Context.AudioService)
                    as global::Android.Media.AudioManager;
            }
            catch (Exception ex) { MainApplication.LogCaught("video-audio", ex); }
            _playPause = playPause;
            _curTime = cur;
            _totalTime = total;
            _seek = seek;
            _topBar = topBar;
            _bottomBar = bottomBar;
            _buttonRow = buttonRow;
            _btnCells = cells;
            _titleView = titleView;
            _progressRow = progressRow;
            _rotateBtn = rotateBtn;
            _lockBtn = lockBtn;
            _loadingView = loading;
            _pulse = pulse;
            _onExit = onExit;
            _prepared = false;
            _chromeW = _chromeH = _chromeVw = _chromeVh = -1;
            _chromeMode = -1;

            wm.AddView(root, new AWindowManagerLayoutParams(
                AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.MatchParent,
                AWindowManagerTypes.ApplicationPanel,
                // NotFocusable 与图片预览
                ScreenSecurity.OverlayFlags(
                    AWindowManagerFlags.LayoutNoLimits | AWindowManagerFlags.NotFocusable),
                AFormat.Transparent));

            // 横竖屏/窗口尺寸
            try
            {
                root.LayoutChange += (_, _) => ApplyChrome();
                root.Post(() => ApplyChrome());
            }
            catch (Exception ex) { MainApplication.LogCaught("video-chrome", ex); }

            // 画面手势
            // 无位移点击仍只
            // 控制层
            // 画面层万一自己
            try
            {
                var vc = global::Android.Views.ViewConfiguration.Get(act);
                float slop = vc?.ScaledTouchSlop ?? Dp(8);
                var gestures = new GestureTouchListener(gen, slop);
                root.SetOnTouchListener(gestures);
                video.SetOnTouchListener(gestures);
            }
            catch (Exception ex) { MainApplication.LogCaught("video-gesture", ex); }

            lockBtn.Click += (_, _) =>
            {
                if (gen != s_gen) return;
                _locked = !_locked;
                _uiHidden = _locked;
                if (_locked) CancelHide();
                ApplyUiVisibility();
                if (!_locked) ScheduleHide(gen);
            };

            // 播放回调
            void HandleReady()
            {
                if (gen != s_gen || _released) return;
                HideMessage();
                HideLoading(gen);
                _prepared = true;
                _ended = false;
                ReadVideoSize();
                MainApplication.LogNote("video-ready",
                    $"state={_player?.PlaybackState} size={_videoW}x{_videoH}"
                    + $" prepare={_player?.PrepareElapsedMs ?? 0}ms stage={_fallbackStage}");
                ApplySpeed(gen);
                ApplyAutoOrientation(gen);
                ApplyScale(gen, false);
                RefreshProgress(force: true);
                StartTicker(gen);
                StartSubtitleTimer(gen);
                RevealUi(gen, true);
                ScheduleNoVideoCheck(gen, onError);
            }

            void HandleEnded()
            {
                if (gen != s_gen || _released) return;
                if (_loop)
                {
                    _ended = false;
                    try { _player?.SeekTo(0); _player?.Play(); }
                    catch (Exception ex) { MainApplication.LogCaught("video-loop", ex); }
                    RefreshProgress(force: true);
                    StartSubtitleTimer(gen);
                    RevealUi(gen, true);
                    return;
                }
                // 播完停
                _ended = true;
                try { _player?.Pause(); } catch { }
                CancelHide();
                StopSubtitleTimer();
                HideSubtitleNow();
                HideMessage();
                HideLoading(gen);
                // 结束态只召唤控
                RevealUi(gen, false);
                SafeInvoke(onEnded);
            }

            void HandleCoreError(string detail)
            {
                if (gen != s_gen || _released) return;
                MainApplication.LogNote("video-error", detail);
                if (_ended) return;
                // 起播前失败
                if (!_prepared && _fallbackStage < 1)
                {
                    StartFallback(gen, detail, onError);
                    return;
                }
                Fail(L10n.F("无法播放：内核失败({0})。", detail), onError);
            }

            void HandleSize()
            {
                if (gen != s_gen || _released) return;
                ReadVideoSize();
                ApplyScale(gen, false);
            }

            void HandleBuffering(bool buffering)
            {
                if (gen != s_gen || _released) return;
                if (buffering) ShowLoading(gen);
                else if (_prepared) HideLoading(gen);
            }

            // 失败或超
            void StartFallback(int g, string reason, Action<string> fail)
            {
                if (g != s_gen || _fallbackStage >= 1 || _released) return;
                int stage = _fallbackStage + 1;
                _fallbackStage = stage;
                if (s_hintKey is not null) s_coreHint[s_hintKey] = stage;
                CancelWatchdog();
                long pos = 0;
                try { pos = _player?.CurrentPosition ?? 0; } catch { }
                var view = _video;
                var src = _stream;
                var act = _activity;
                if (view is null || act is null)
                {
                    Fail(L10n.F("无法播放：播放层已退出({0})。", reason), fail);
                    return;
                }
                ShowMessage(L10n.T("切换 Media3 内核…"));
                try { _player?.Release(); } catch { }
                _player = null;
                _prepared = false;
                try
                {
                    _player = new ExoCore(act, view, path, src, pos,
                        HandleReady, HandleEnded, HandleCoreError, HandleSize, HandleBuffering);
                    MainApplication.LogNote("video-fallback",
                        $"core={stage} reason={reason} pos={pos}");
                }
                catch (Exception ex)
                {
                    MainApplication.LogCaught("video-fallback", ex);
                    Fail(L10n.F("无法播放：兼容内核启动失败({0})。", reason), fail);
                    return;
                }
                // 降级后重挂看门
                Runnable? wd = null;
                wd = new Runnable(() =>
                {
                    if (gen != s_gen || _prepared || _released) return;
                    // 增长源导出未完
                    if (_stream is GrowingFileDataSource gfd && !gfd.ExportDone)
                    {
                        long e = gfd.ExportedBytes;
                        if (e != _wdExported)
                        {
                            _wdExported = e;
                            try { _root?.PostDelayed(wd!, 12000); } catch { }
                            return;
                        }
                    }
                    MainApplication.LogNote("video-watchdog", L10n.T("Media3 准备超时"));
                    Fail(L10n.T("无法播放：两级内核都未能准备此文件。"), fail);
                });
                _watchdogRunnable = wd;
                try { _root?.PostDelayed(wd, 12000); } catch { }
            }

            // 无画面检测
            void ScheduleNoVideoCheck(int g, Action<string> fail)
            {
                int stage0 = _fallbackStage;
                var nv = new Runnable(() =>
                {
                    if (g != s_gen || _released || _ended) return;
                    if (_fallbackStage != stage0) return;
                    var p = _player;
                    if (p is null) return;
                    bool playing = false;
                    try { playing = p.IsPlaying; } catch { }
                    MainApplication.LogNote("video-diag", $"novideo-check stage={_fallbackStage} w={p.VideoWidth} h={p.VideoHeight} playing={playing}");
                    if (!playing) { ScheduleNoVideoCheck(g, fail); return; }
                    if (p.VideoWidth > 0 && p.VideoHeight > 0) return;
                    if (_fallbackStage < 1)
                    {
                        MainApplication.LogNote("video-watchdog", L10n.T("内核1无画面，切换 Media3 内核"));
                        StartFallback(g, "no-video", fail);
                        return;
                    }
                    Fail(NoVideoDiag(p), fail);
                });
                try { root.PostDelayed(nv, 4500); } catch { }
            }

            // Media3 级仍无画面
            static string NoVideoDiag(IVideoCore p)
            {
                string ff = "?", vf = "?", trk = "?";
                try { ff = FfmpegLibrary.IsAvailable ? "y" : "n"; } catch { }
                if (p is ExoCore ec)
                {
                    try { vf = ec.VideoFmt != null ? "y" : "n"; } catch { }
                    try
                    {
                        var gs = ec.TracksNow?.Groups;
                        if (gs != null)
                            foreach (var g in gs)
                                if (g is Tracks.Group tg && tg.Type == C.TrackTypeVideo) { trk = "y"; break; }
                    }
                    catch { }
                }
                return L10n.F("无法播放：视频轨未能解码(ff={0},vf={1},trk={2})。", ff, vf, trk);
            }

            // 内核1
            void StartCore1()
            {
                if (gen != s_gen || _released) return;
                // 上次降级
                if (s_hintKey is not null && s_coreHint.TryGetValue(s_hintKey, out int hint) && hint >= 1)
                {
                    MainApplication.LogNote("video-diag", $"core-hint stage={hint}");
                    StartFallback(gen, "hint", onError);
                    return;
                }
                _player = new PlaybackCore(video, path, stream,
                    HandleReady, HandleEnded, HandleCoreError, HandleSize, HandleBuffering);
                _stream = stream;

                // 起播看门狗
                _watchdogRunnable = new Runnable(() =>
                {
                    if (gen != s_gen || _prepared || _fallbackStage >= 1 || _released) return;
                    // 增长源导出未完
                    if (_stream is GrowingFileDataSource gfd && !gfd.ExportDone)
                    {
                        long e = gfd.ExportedBytes;
                        if (e != _wdExported)
                        {
                            _wdExported = e;
                            try { root.PostDelayed(_watchdogRunnable!, 8000); } catch { }
                            return;
                        }
                    }
                    MainApplication.LogNote("video-watchdog", L10n.T("内核1准备超时，切换 Media3 内核"));
                    StartFallback(gen, "prepare-timeout", onError);
                });
                try { root.PostDelayed(_watchdogRunnable, 8000); } catch { }
            }

            if (exportGate is null)
            {
                StartCore1();
            }
            else
            {
                // 运行时解密
                _ = AwaitGateAsync();
            }

            async Task AwaitGateAsync()
            {
                var g = exportGate;
                if (g is null) return;
                bool ok = false;
                try { ok = await g.ConfigureAwait(true); }
                catch (Exception ex) { MainApplication.LogCaught("video-gate", ex); }
                if (gen != s_gen || _released) return;
                if (!ok) { Fail(L10n.T("解密导出失败，无法播放该文件。"), onError); return; }
                StartCore1();
            }

            playPause.Click += (_, _) =>
            {
                if (gen != s_gen) return;
                var p = _player;
                if (p is null) return;
                try
                {
                    if (p.IsPlaying)
                    {
                        p.Pause();
                        StopSubtitleTimer();
                        CancelHide();
                        RevealUi(gen, false);
                        Pulse(gen, Resource.Drawable.ic_fe_pause);
                    }
                    else
                    {
                        // 播放结束
                        if (p.PlaybackState == PlayerStateEnded)
                        {
                            _ended = false;
                            p.SeekTo(0);
                        }
                        p.Play();
                        StartSubtitleTimer(gen);
                        RevealUi(gen, true);
                        Pulse(gen, Resource.Drawable.ic_fe_play);
                    }
                    RefreshProgress(force: true);
                }
                catch (Exception ex) { MainApplication.LogCaught("video-toggle", ex); }
            };

            seek.SetOnSeekBarChangeListener(new SeekListener(
                () => { _seeking = true; CancelHide(); },
                () =>
                {
                    _seeking = false;
                    if (gen != s_gen) return;
                    try { _player?.SeekTo(seek.Progress); }
                    catch (Exception ex) { MainApplication.LogCaught("video-seek", ex); }
                    ScheduleHide(gen);
                },
                ms =>
                {
                    if (gen != s_gen) return;
                    var t = _curTime;
                    if (t is not null) t.Text = Fmt(ms);
                }));

            return true;
        }
        catch (Exception ex)
        {
            MainApplication.LogCaught("video-open", ex);
            Close();
            onError(L10n.T("无法播放此视频，请返回后重试。"));
            return false;
        }
    }

    // 上一部/下一部回
    private static Action? _onPrev;
    private static Action? _onNext;
    private static AView? _prevBtn;
    private static AView? _nextBtn;

    public static void SetNavHandlers(Action? onPrev, Action? onNext)
    {
        _onPrev = onPrev;
        _onNext = onNext;
        RefreshNavButtons();
    }

    private static void RefreshNavButtons()
    {
        if (_prevBtn is not null)
        {
            _prevBtn.Enabled = _onPrev is not null;
            _prevBtn.Alpha = _onPrev is not null ? 1f : 0.4f;
        }
        if (_nextBtn is not null)
        {
            _nextBtn.Enabled = _onNext is not null;
            _nextBtn.Alpha = _onNext is not null ? 1f : 0.4f;
        }
    }

    public static void Close()
    {
        Interlocked.Increment(ref s_gen);   // 旧回调
        _released = true;                   // 释放期间
        _ended = false;
        var player = _player;
        var root = _root;
        var wm = _wm;

        CancelHide();
        CancelTimer();
        CancelWatchdog();
        ClosePanelImmediate();
        StopTicker();
        StopSubtitleTimer();
        _video = null;
        _aspect = null;
        _loadingView = null;
        _pulse = null;
        _player = null;
        _stream = null;
        _fallbackStage = 0;
        _videoW = 0;
        _videoH = 0;
        _root = null;
        _wm = null;
        _activity = null;
        _message = null;
        _hint = null;
        _subtitleView = null;
        _subtitle = null;
        _subtitleLastText = null;
        _pipMode = false;
        _audio = null;
        _playPause = null;
        _curTime = null;
        _totalTime = null;
        _seek = null;
        _topBar = null;
        _bottomBar = null;
        _buttonRow = null;
        _btnCells = null;
        _onPrev = null;
        _onNext = null;
        _prevBtn = null;
        _nextBtn = null;
        _titleView = null;
        _progressRow = null;
        _chromeW = _chromeH = _chromeVw = _chromeVh = -1;
        _chromeMode = -1;
        _rotateBtn = null;
        _lockBtn = null;
        _onExit = null;
        _seeking = false;
        _errorShown = false;
        _uiHidden = false;
        _locked = false;
        _prepared = false;
        _havePlayIcon = false;
        _lastPlaying = false;
        _timerMinutes = 0;

        // 先让随机读数据
        if (player is not null)
        {
            try { player.Release(); } catch { }
        }
        if (root is not null)
        {
            try { if (root.IsAttachedToWindow && wm is not null) wm.RemoveView(root); } catch { }
            try { root.RemoveAllViews(); } catch { }
        }
    }

    // 退后台/切页
    public static void CloseIfOpen() => Close();

    // PiP 宽高比
    public static bool GetPipAspect(out int width, out int height)
    {
        width = _videoW;
        height = _videoH;
        return width > 0 && height > 0;
    }

    // PiP 进入或退出
    public static void OnPipModeChanged(bool inPip)
    {
        _pipMode = inPip;
        if (inPip)
        {
            CancelHide();
            StopSubtitleTimer();
            HideSubtitleNow();
            ClosePanelImmediate();
            SetVisible(_message, false);
            SetVisible(_hint, false);
            ApplyUiVisibility();
            return;
        }
        int gen = s_gen;
        RevealUi(gen, true);
        StartSubtitleTimer(gen);
    }

    // 字幕定时器
    private static void StartSubtitleTimer(int gen)
    {
        if (_subtitle is null || _subtitleView is null || _pipMode) return;
        StopSubtitleTimer();
        try
        {
            var h = new global::Android.OS.Handler(global::Android.OS.Looper.MainLooper!);
            Java.Lang.IRunnable? r = null;
            r = new Runnable(() =>
            {
                if (gen != s_gen || _pipMode) return;
                var p = _player;
                if (p is null) return;
                bool playing;
                try { playing = p.IsPlaying; } catch { playing = false; }
                if (!playing) { StopSubtitleTimer(); return; }
                long pos = 0;
                try { pos = p.CurrentPosition; } catch { }
                ApplySubtitleText(pos);
                try { h.PostDelayed(r!, 220); } catch { }
            });
            _subtitleHandler = h;
            _subtitleRunnable = r;
            h.PostDelayed(r, 220);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-subtitle", ex); }
    }

    private static void StopSubtitleTimer()
    {
        try
        {
            var h = _subtitleHandler;
            var r = _subtitleRunnable;
            if (h is not null && r is not null) h.RemoveCallbacks(r);
        }
        catch { }
        _subtitleHandler = null;
        _subtitleRunnable = null;
    }

    // 文本变化才重设
    private static void ApplySubtitleText(long positionMs)
    {
        var track = _subtitle;
        var view = _subtitleView;
        if (track is null || view is null) return;
        string? text = track.TextAt(positionMs);
        if (string.Equals(text, _subtitleLastText, StringComparison.Ordinal)) return;
        _subtitleLastText = text;
        try
        {
            if (string.IsNullOrEmpty(text))
            {
                view.Visibility = global::Android.Views.ViewStates.Gone;
            }
            else
            {
                view.Text = text.Length > SubtitleTrack.MaxCueChars
                    ? text.Substring(0, SubtitleTrack.MaxCueChars) : text;
                view.Visibility = global::Android.Views.ViewStates.Visible;
            }
        }
        catch (Exception ex) { MainApplication.LogCaught("video-subtitle", ex); }
    }

    private static void HideSubtitleNow()
    {
        try { if (_subtitleView is not null) _subtitleView.Visibility = global::Android.Views.ViewStates.Gone; }
        catch { }
        _subtitleLastText = null;
    }

    // 设置读写
    private static void LoadSettings()
    {
        try
        {
            var p = Preferences.Default;
            _fill = p.Get("video_fill", false);
            _stretch = p.Get("video_stretch", false);
            _autoOrient = p.Get("video_auto_orient", false);
            _loop = p.Get("video_loop", false);
            _speed = p.Get("video_speed", 1f);
            if (_speed < 0.25f || _speed > 4f) _speed = 1f;
            if (_fill) _stretch = false;   // 两者互斥
        }
        catch { _fill = _stretch = _autoOrient = _loop = false; _speed = 1f; }
    }

    private static int ScaleMode() => _fill ? 1 : (_stretch ? 2 : 0);

    // 缩放模式
    private static int ResizeModeValue() => ScaleMode();

    private static void ApplyScale(int gen, bool relayout)
    {
        if (gen != s_gen) return;
        var a = _aspect;
        if (a is null) return;
        try
        {
            a.ResizeMode = ResizeModeValue();
            if (_videoW > 0 && _videoH > 0)
                a.SetAspectRatio((float)_videoW / _videoH);
            if (relayout) a.RequestLayout();
            ApplyChrome();
        }
        catch (Exception ex) { MainApplication.LogCaught("video-scale", ex); }
    }

    // 尺寸回调
    private static void ReadVideoSize()
    {
        var p = _player;
        if (p is null) return;
        try
        {
            int w = p.VideoWidth, h = p.VideoHeight;
            var diag = p is ExoCore ec && ec.VideoFmt is global::AndroidX.Media3.Common.Format vf
                ? $" mime={vf.SampleMimeType} codecs={vf.Codecs}" : "";
            MainApplication.LogNote("video-diag", $"vsize core={_fallbackStage} w={w} h={h}{diag}");
            if (_video is not null)
                MainApplication.LogNote("video-diag",
                    $"view {_video.Width}x{_video.Height} shown={_video.IsShown} avail={_video.IsAvailable}");
            if (w > 0 && h > 0) { _videoW = w; _videoH = h; }
            if (_videoW > 0 && _videoH > 0)
                _aspect?.SetAspectRatio((float)_videoW / _videoH);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-size", ex); }
    }

    // 倍速
    private static void ApplySpeed(int gen)
    {
        if (gen != s_gen || !_prepared) return;
        var p = _player;
        if (p is null) return;
        try
        {
            bool playWhenReady = p.PlayWhenReady;
            p.SetPlaybackSpeed(_speed);
            // 兜底
            if (p.PlayWhenReady != playWhenReady) p.PlayWhenReady = playWhenReady;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-speed", ex); }
    }

    // 自适应横竖屏
    private static void ApplyAutoOrientation(int gen)
    {
        if (gen != s_gen || !_autoOrient) return;
        var act = _activity;
        if (act is null) return;
        try
        {
            if (_videoW <= 0 || _videoH <= 0) return;
            var target = _videoW >= _videoH
                ? global::Android.Content.PM.ScreenOrientation.SensorLandscape
                : global::Android.Content.PM.ScreenOrientation.Portrait;
            if (act.RequestedOrientation != target) act.RequestedOrientation = target;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-auto-orient", ex); }
    }

    // 定时关闭
    private static void SetTimerMinutes(int gen, int minutes)
    {
        _timerMinutes = minutes;
        CancelTimer();
        var label = _timerValue;
        if (label is not null) label.Text = minutes <= 0 ? L10n.T("未设置") : L10n.F("{0} 分钟", minutes);
        if (minutes <= 0) return;
        var root = _root;
        if (root is null) return;
        var r = new Runnable(() =>
        {
            if (gen != s_gen) return;
            try { _player?.Pause(); } catch { }
            SafeInvoke(_onExit);
        });
        _timerRunnable = r;
        try { root.PostDelayed(r, minutes * 60_000L); } catch { }
    }

    private static void CancelTimer()
    {
        try
        {
            var root = _root;
            var r = _timerRunnable;
            if (root is not null && r is not null) root.RemoveCallbacks(r);
        }
        catch { }
        _timerRunnable = null;
    }

    // 控件工厂
    // boxDp = 触摸区
    private static ImageView MakeIconButton(AActivity act, int resId, int boxDp, int iconDp,
        int tint, float density, bool shadow = false)
    {
        var iv = new ImageView(act);
        iv.SetScaleType(global::Android.Widget.ImageView.ScaleType.FitCenter);
        int box = (int)(boxDp * density + 0.5f);
        int icon = (int)(iconDp * density + 0.5f);
        int inset = Math.Max(0, (box - icon) / 2);
        iv.SetPadding(inset, inset, inset, inset);
        iv.Clickable = true;
        iv.Focusable = true;
        SetIcon(act, iv, resId, tint, density, shadow);
        iv.LayoutParameters = new FrameLayout.LayoutParams(box, box);
        return iv;
    }

    // 统一走 Drawable.SetTint：不依赖
    private static void SetIcon(AActivity? act, ImageView? view, int resId, int tint,
        float density = 1f, bool shadow = false)
    {
        if (act is null || view is null) return;
        try
        {
            var d = act.GetDrawable(resId);
            if (d is null) return;
            d.SetTint(tint);
            view.SetImageDrawable(shadow ? new ShadowDrawable(d, tint, density) : d);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-icon", ex); }
    }

    private static ImageView MakeRowIcon(AActivity act, int resId, int sizeDp, int tint, float density)
    {
        var iv = new ImageView(act);
        iv.SetScaleType(global::Android.Widget.ImageView.ScaleType.FitCenter);
        int size = (int)(sizeDp * density + 0.5f);
        SetIcon(act, iv, resId, tint);
        iv.LayoutParameters = new LinearLayout.LayoutParams(size, size);
        return iv;
    }

    // 顶栏标题 / 时间标
    private static void AddTextShadow(TextView view, float density)
    {
        try { view.SetShadowLayer(2f * density, 0f, 1f * density, AColor.ParseColor("#66000000")); }
        catch (Exception ex) { MainApplication.LogCaught("video-text-shadow", ex); }
    }

    // 已播放段颜色
    // 与 Resources/Styles
    private static AColor PrimaryColor(AActivity act)
    {
        try
        {
            var res = act.Resources;
            if (res is not null) return new AColor(res.GetColor(Resource.Color.colorPrimary, act.Theme));
        }
        catch (Exception ex) { MainApplication.LogCaught("video-primary", ex); }
        return AColor.White;
    }

    // 进度条
    // 已播放段
    // 拇指
    private static global::Android.Widget.SeekBar MakeSeekBar(AActivity act, float density)
    {
        var seek = new global::Android.Widget.SeekBar(act);
        try
        {
            float line = Math.Max(2f, 1.5f * density);

            // 不用 LayerDrawable +
            // 而 SeekBar 只有
            // 自己 new
            // 改成一个自绘 Drawable
            seek.ProgressDrawable = new PlayedBarDrawable(
                AColor.ParseColor("#99FFFFFF"), PrimaryColor(act), line);

            seek.SplitTrack = false;
            seek.SetThumb(new ThumbDrawable(11 * density, density));
            seek.ThumbOffset = (int)(5.5f * density + 0.5f);
            // 圆点投影需要软
            seek.SetLayerType(global::Android.Views.LayerType.Software, null);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-seek-style", ex); }
        return seek;
    }

    // 进度条本体
    // SeekBar 每次进度变化
    private sealed class PlayedBarDrawable : ADrawable
    {
        private const int LevelMax = 10000;
        private readonly AColor _trackColor;
        private readonly AColor _playedColor;
        private readonly float _line;
        private readonly float _radius;
        private readonly APaint _paint = new() { AntiAlias = true };
        private int _alpha = 255;

        public PlayedBarDrawable(AColor trackColor, AColor playedColor, float line)
        {
            _trackColor = trackColor;
            _playedColor = playedColor;
            _line = Math.Max(1f, line);
            _radius = _line / 2f;
        }

        public override int IntrinsicHeight => (int)Math.Ceiling(_line);
        public override int Opacity => (int)AFormat.Translucent;

        public override void Draw(ACanvas canvas)
        {
            var b = Bounds;
            if (b.Width() <= 0 || b.Height() <= 0) return;
            float cy = b.CenterY();
            float top = cy - _line / 2f;
            float bottom = cy + _line / 2f;

            // 底层
            _paint.Color = _trackColor;
            _paint.Alpha = _alpha;
            canvas.DrawRoundRect(b.Left, top, b.Right, bottom, _radius, _radius, _paint);

            // 上层
            int level = Level;
            if (level <= 0) return;
            float frac = Math.Min(1f, level / (float)LevelMax);
            float right = b.Left + b.Width() * frac;
            // 刚开始播放时至
            if (right - b.Left < _line) right = Math.Min(b.Right, b.Left + _line);
            _paint.Color = _playedColor;
            _paint.Alpha = _alpha;
            canvas.DrawRoundRect(b.Left, top, right, bottom, _radius, _radius, _paint);
        }

        // SeekBar 的 level 变化入口：不重
        protected override bool OnLevelChange(int level)
        {
            InvalidateSelf();
            return true;
        }

        public override void SetAlpha(int alpha)
        {
            _alpha = alpha;
            InvalidateSelf();
        }

        public override void SetColorFilter(AColorFilter? cf) => _paint.SetColorFilter(cf);
    }

    // 图标投影
    private sealed class ShadowDrawable : ADrawable
    {
        private readonly ADrawable _child;
        private readonly int _tint;
        private readonly int _dy;
        private int _alpha = 255;

        public override int IntrinsicWidth => _child.IntrinsicWidth;
        public override int IntrinsicHeight => _child.IntrinsicHeight;

        public ShadowDrawable(ADrawable child, int tint, float density)
        {
            _child = child;
            _tint = tint;
            _dy = Math.Max(1, (int)(1.5f * density + 0.5f));
        }

        public override int Opacity => (int)AFormat.Translucent;

        public override void Draw(ACanvas canvas)
        {
            var b = Bounds;
            try
            {
                _child.SetTint(unchecked((int)0x66000000));
                _child.SetBounds(b.Left, b.Top + _dy, b.Right, b.Bottom + _dy);
                _child.Draw(canvas);
                _child.SetTint(_tint);
                _child.Alpha = _alpha;
                _child.SetBounds(b.Left, b.Top, b.Right, b.Bottom);
                _child.Draw(canvas);
            }
            catch { }
        }

        public override void SetAlpha(int alpha)
        {
            _alpha = alpha;
            InvalidateSelf();
        }

        public override void SetColorFilter(AColorFilter? cf) => _child.SetColorFilter(cf);
    }

    private sealed class ThumbDrawable : ADrawable
    {
        private readonly int _size;
        private readonly APaint _paint = new() { AntiAlias = true };

        public ThumbDrawable(float size, float density)
        {
            _size = Math.Max(1, (int)(size + 0.5f));
            _paint.Color = AColor.White;
            _paint.SetShadowLayer(2f * density, 0f, 1f * density, unchecked((int)0x99000000));
        }

        public override int IntrinsicWidth => _size;
        public override int IntrinsicHeight => _size;
        public override int Opacity => (int)AFormat.Translucent;

        public override void Draw(ACanvas canvas)
        {
            var b = Bounds;
            canvas.DrawCircle(b.CenterX(), b.CenterY(),
                Math.Min(b.Width(), b.Height()) / 2f - Math.Max(1f, _size * 0.09f), _paint);
        }

        public override void SetAlpha(int alpha) => _paint.Alpha = alpha;
        public override void SetColorFilter(AColorFilter? cf) => _paint.SetColorFilter(cf);
    }

    // 横竖屏两套版式
    // 基准一律是屏幕
    // 底栏
    private static void ApplyChrome()
    {
        var root = _root;
        var top = _topBar;
        var bottom = _bottomBar;
        var act = _activity;
        if (root is null || top is null || bottom is null || act is null) return;
        try
        {
            int sw = root.Width, sh = root.Height;
            if (sw <= 0 || sh <= 0) return;
            int mode = ScaleMode();
            if (sw == _chromeW && sh == _chromeH && _videoW == _chromeVw &&
                _videoH == _chromeVh && mode == _chromeMode) return;
            _chromeW = sw; _chromeH = sh; _chromeVw = _videoW; _chromeVh = _videoH; _chromeMode = mode;

            float d = _density;
            int Dp(float v) => (int)(v * d + 0.5f);
            bool land = sw > sh;

            // 顶栏
            // 横竖屏同一套
            int topT = land ? Dp(6) : StatusBarHeight(act) + Dp(6);
            top.SetPadding(Dp(8), topT, Dp(8), 0);

            // 底栏
            int side = Dp(16);
            bottom.SetPadding(side, 0, side, land ? Dp(8) : NavBarHeight(act) + Dp(8));

            // 五键行
            // 横屏改成显式宽
            var row = _buttonRow;
            if (row is not null)
            {
                if (row.LayoutParameters is FrameLayout.LayoutParams lp)
                {
                    lp.Width = AViewGroup.LayoutParams.MatchParent;
                    lp.Gravity = AGravity.CenterHorizontal;
                    row.LayoutParameters = lp;
                }
                var cells = _btnCells;
                if (cells is not null)
                {
                    int cell = Math.Max(Dp(44), (sw - side * 2) / 5);
                    foreach (var c in cells)
                    {
                        if (c?.LayoutParameters is not LinearLayout.LayoutParams cp) continue;
                        cp.Width = land ? cell : 0;
                        cp.Weight = land ? 0f : 1f;
                        c.LayoutParameters = cp;
                    }
                }
            }

            // 悬浮锁/旋转
            int size = Dp(42);
            int centerY = sh / 2 - size / 2;
            PlaceSide(_lockBtn, Dp(18), centerY);
            PlaceSide(_rotateBtn, sw - Dp(18) - size, centerY);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-chrome", ex); }
    }

    private static void PlaceSide(AView? v, int left, int top)
    {
        if (v?.LayoutParameters is not FrameLayout.LayoutParams lp) return;
        lp.Gravity = AGravity.Top | AGravity.Left;
        lp.LeftMargin = Math.Max(0, left);
        lp.TopMargin = Math.Max(0, top);
        v.LayoutParameters = lp;
    }

    // 圆形半透明底
    private static global::Android.Graphics.Drawables.GradientDrawable RoundBg(string color, float radiusDp, float density)
    {
        var d = new global::Android.Graphics.Drawables.GradientDrawable();
        d.SetColor(AColor.ParseColor(color));
        d.SetCornerRadius(radiusDp * density);
        return d;
    }

    // 控制层显隐 / 自动
    private static void ApplyUiVisibility()
    {
        try
        {
            bool show = !_uiHidden && !_locked && !_pipMode;
            AnimateBar(_topBar, show, false);
            AnimateBar(_bottomBar, show, true);
            AnimateBar(_rotateBtn, show, null);
            var lockBtn = _lockBtn;
            if (lockBtn is not null)
            {
                // 锁定时显示闭合
                SetIcon(_activity, lockBtn,
                    _locked ? Resource.Drawable.ic_fe_lock : Resource.Drawable.ic_fe_unlock,
                    TintWhite, _density, true);
                // 锁按钮随显隐走
                AnimateBar(lockBtn, !_uiHidden, null);
            }
        }
        catch (Exception ex) { MainApplication.LogCaught("video-ui", ex); }
    }

    // 控制栏显隐动画
    // 隐藏动画结束
    private static void AnimateBar(AView? v, bool show, bool? isBottom)
    {
        if (v is null) return;
        int Dp(float x) => (int)(x * _density + 0.5f);
        // 顶栏负值上滑
        float off = isBottom == true ? Dp(64) : Dp(132);
        float dir = isBottom == false ? -1f : 1f;
        try
        {
            v.Animate()?.Cancel();
            if (show)
            {
                if (v.Visibility != global::Android.Views.ViewStates.Visible)
                {
                    v.Alpha = 0;
                    if (isBottom is not null) v.TranslationY = off * dir;
                    v.Visibility = global::Android.Views.ViewStates.Visible;
                }
                v.Animate()?.Alpha(1).TranslationY(0).SetDuration(220)
                    .SetInterpolator(new global::Android.Views.Animations.DecelerateInterpolator())
                    ?.Start();
            }
            else
            {
                if (v.Visibility == global::Android.Views.ViewStates.Gone) return;
                float toY = isBottom is null ? 0 : off * dir;
                v.Animate()?.Alpha(0).TranslationY(toY).SetDuration(200)
                    .SetInterpolator(new global::Android.Views.Animations.AccelerateInterpolator())
                    .WithEndAction(new Java.Lang.Runnable(() =>
                    {
                        try { v.TranslationY = 0; v.Visibility = global::Android.Views.ViewStates.Gone; }
                        catch { }
                    }))
                    ?.Start();
            }
        }
        catch (Exception ex) { MainApplication.LogCaught("video-bar-anim", ex); }
    }

    // 缓冲反馈
    private static void ShowLoading(int gen)
    {
        if (gen != s_gen) return;
        var v = _loadingView;
        if (v is null) return;
        try
        {
            if (v.Visibility == global::Android.Views.ViewStates.Visible) return;
            v.Alpha = 1;
            v.Visibility = global::Android.Views.ViewStates.Visible;
        }
        catch { }
    }

    private static void HideLoading(int gen)
    {
        if (gen != s_gen) return;
        var v = _loadingView;
        if (v is null) return;
        try
        {
            if (v.Visibility != global::Android.Views.ViewStates.Visible) return;
            v.Animate()?.Cancel();
            v.Animate()?.Alpha(0).SetDuration(180).WithEndAction(new Java.Lang.Runnable(() =>
            {
                try { v.Visibility = global::Android.Views.ViewStates.Gone; } catch { }
            }))?.Start();
        }
        catch { try { v.Visibility = global::Android.Views.ViewStates.Gone; } catch { } }
    }

    // 播放/暂停中心脉
    private static void Pulse(int gen, int iconRes)
    {
        if (gen != s_gen) return;
        var v = _pulse;
        if (v is null) return;
        try
        {
            SetIcon(_activity, v, iconRes, TintWhite, _density, false);
            v.Animate()?.Cancel();
            v.Alpha = 0;
            v.ScaleX = 1.35f;
            v.ScaleY = 1.35f;
            v.Visibility = global::Android.Views.ViewStates.Visible;
            v.Animate()?.Alpha(0.85f).ScaleX(1f).ScaleY(1f).SetDuration(150)
                .WithEndAction(new Java.Lang.Runnable(() =>
                {
                    try
                    {
                        v.Animate()?.Alpha(0f).SetDuration(280).WithEndAction(new Java.Lang.Runnable(() =>
                        {
                            try { v.Visibility = global::Android.Views.ViewStates.Gone; } catch { }
                        }))?.Start();
                    }
                    catch { }
                }))
                ?.Start();
        }
        catch (Exception ex) { MainApplication.LogCaught("video-pulse", ex); }
    }

    private static void SetVisible(AView? v, bool visible)
    {
        if (v is null) return;
        v.Visibility = visible
            ? global::Android.Views.ViewStates.Visible
            : global::Android.Views.ViewStates.Gone;
    }

    private static void RevealUi(int gen, bool schedule)
    {
        if (gen != s_gen) return;
        _uiHidden = false;
        ApplyUiVisibility();
        if (schedule) ScheduleHide(gen);
    }

    // 参考图
    // 锁定状态
    private static void ScheduleHide(int gen)
    {
        CancelHide();
        // 播放结束控制栏
        if (gen != s_gen || _panelOpen || _ended) return;
        bool playing = false;
        try { playing = _player?.IsPlaying ?? false; } catch { }
        if (!playing) return;
        var root = _root;
        if (root is null) return;
        var r = new Runnable(() =>
        {
            if (gen != s_gen || _seeking || _panelOpen) return;
            _uiHidden = true;
            ApplyUiVisibility();
        });
        _hideRunnable = r;
        try { root.PostDelayed(r, 3500); } catch { }
    }

    private static void CancelHide()
    {
        try
        {
            var root = _root;
            var r = _hideRunnable;
            if (root is not null && r is not null) root.RemoveCallbacks(r);
        }
        catch { }
        _hideRunnable = null;
    }

    // 快退/快进 10s
    private static void Skip(int gen, int deltaMs)
    {
        if (gen != s_gen) return;
        var p = _player;
        if (p is null) return;
        try
        {
            long dur = 0, pos = 0;
            try { dur = p.Duration; } catch { }
            try { pos = p.CurrentPosition; } catch { }
            long target = pos + deltaMs;
            if (target < 0) target = 0;
            if (dur > 0 && target > dur) target = dur;
            p.SeekTo(target);
            RefreshProgress(force: true);
            RevealUi(gen, true);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-skip", ex); }
    }

    // 横竖屏切换
    // overlay 窗口
    private static void ToggleOrientation(int gen)
    {
        if (gen != s_gen) return;
        var act = _activity;
        if (act is null) return;
        try
        {
            bool landscape =
                (act.Resources?.Configuration?.Orientation ?? global::Android.Content.Res.Orientation.Undefined)
                == global::Android.Content.Res.Orientation.Landscape;
            act.RequestedOrientation = landscape
                ? global::Android.Content.PM.ScreenOrientation.Portrait
                : global::Android.Content.PM.ScreenOrientation.SensorLandscape;
            RevealUi(gen, true);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-orientation", ex); }
    }

    private static void Fail(string text, Action<string> onError)
    {
        if (_errorShown) return;
        _errorShown = true;
        CancelWatchdog();
        CancelHide();
        _uiHidden = false;
        HideLoading(s_gen);
        ApplyUiVisibility();
        ShowMessage(text);
        StopTicker();
        StopSubtitleTimer();
        try { _player?.Pause(); } catch { }
        SafeInvoke(() => onError(text));
    }

    private static void SafeInvoke(Action? a)
    {
        try { a?.Invoke(); }
        catch (Exception ex) { MainApplication.LogCaught("video-callback", ex); }
    }

    private static void ShowMessage(string text)
    {
        if (_pipMode) return;
        try
        {
            var m = _message;
            if (m is null) return;
            m.Text = text;
            m.Visibility = global::Android.Views.ViewStates.Visible;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-message", ex); }
    }

    private static void HideMessage()
    {
        try
        {
            var m = _message;
            if (m is null) return;
            m.Visibility = global::Android.Views.ViewStates.Gone;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-message", ex); }
    }

    // 加载期进度说明
    public static void SetLoadingNote(string? text)
    {
        if (_pipMode) return;
        try
        {
            var m = _message;
            if (m is null) return;
            if (text is null) { m.Visibility = global::Android.Views.ViewStates.Gone; return; }
            m.Text = text;
            m.Visibility = global::Android.Views.ViewStates.Visible;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-message", ex); }
    }

    // 手势中央提示
    private static void ShowHint(string text)
    {
        if (_pipMode) return;
        try
        {
            var h = _hint;
            if (h is null) return;
            h.Text = text;
            h.Visibility = global::Android.Views.ViewStates.Visible;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-hint", ex); }
    }

    private static void HideHint()
    {
        try
        {
            var h = _hint;
            if (h is null) return;
            h.Visibility = global::Android.Views.ViewStates.Gone;
        }
        catch (Exception ex) { MainApplication.LogCaught("video-hint", ex); }
    }

    private static void StartTicker(int gen)
    {
        StopTicker();
        try
        {
            _handler = new global::Android.OS.Handler(global::Android.OS.Looper.MainLooper!);
            _ticker = new Ticker(() =>
            {
                if (gen != s_gen) return;
                RefreshProgress(force: false);
                try { _handler?.PostDelayed(_ticker!, 500); } catch { }
            });
            _handler.PostDelayed(_ticker, 500);
        }
        catch (Exception ex) { MainApplication.LogCaught("video-ticker", ex); }
    }

    private static void StopTicker()
    {
        try
        {
            if (_handler is not null && _ticker is not null) _handler.RemoveCallbacks(_ticker);
        }
        catch { }
        _handler = null;
        _ticker = null;
    }

    // 进度/时长/
    private static void RefreshProgress(bool force)
    {
        var p = _player;
        if (p is null) return;
        try
        {
            var seek = _seek;
            var cur = _curTime;
            var total = _totalTime;
            // Duration 在未知时返回 TIME_UNSET，统
            long durL = 0;
            try { durL = p.Duration; } catch { durL = 0; }
            if (durL < 0) durL = 0;
            long posL = 0;
            try { posL = p.CurrentPosition; } catch { posL = 0; }
            if (posL < 0) posL = 0;
            int dur = (int)Math.Min(durL, int.MaxValue);
            int pos = (int)Math.Min(posL, int.MaxValue);
            if (dur > 0)
            {
                if (seek is not null && (force || seek.Max != dur)) seek.Max = dur;
                if (total is not null && !_seeking) total.Text = Fmt(dur);
            }
            if (seek is not null && !_seeking)
            {
                seek.Progress = pos;
                // 双保险
                // 再按同一比例显
                if (dur > 0) seek.ProgressDrawable?.SetLevel((int)(pos * 10000L / dur));
            }
            if (cur is not null) cur.Text = Fmt(pos);
            bool playing = false;
            try { playing = p.IsPlaying; } catch { }
            // 图标只
            if (!_havePlayIcon || playing != _lastPlaying)
            {
                _havePlayIcon = true;
                _lastPlaying = playing;
                SetIcon(_activity, _playPause,
                    playing ? Resource.Drawable.ic_fe_pause : Resource.Drawable.ic_fe_play,
                    TintWhite, _density, true);
            }
        }
        catch (Exception ex) { MainApplication.LogCaught("video-progress", ex); }
    }

    private static string Fmt(int ms)
    {
        if (ms < 0) ms = 0;
        var t = TimeSpan.FromMilliseconds(ms);
        return t.TotalHours >= 1
            ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}"
            : $"{t.Minutes:00}:{t.Seconds:00}";
    }

    private static int StatusBarHeight(AActivity act)
    {
        try
        {
            int id = act.Resources?.GetIdentifier("status_bar_height", "dimen", "android") ?? 0;
            return id > 0 ? act.Resources!.GetDimensionPixelSize(id) : 0;
        }
        catch { return 0; }
    }

    // 手势条/三键导航
    private static int NavBarHeight(AActivity act)
    {
        try
        {
            int id = act.Resources?.GetIdentifier("navigation_bar_height", "dimen", "android") ?? 0;
            return id > 0 ? act.Resources!.GetDimensionPixelSize(id) : 0;
        }
        catch { return 0; }
    }

    // 画面手势
    // 方向锁定
    // 锁定
    // 无位移
    // 横向换算
    private sealed class GestureTouchListener : Java.Lang.Object, AView.IOnTouchListener
    {
        private const int ModeNone = 0;
        private const int ModeSeek = 1;
        private const int ModeVolume = 2;
        private const long MinSeekMs = 500;   // 松手时目标
        private const global::Android.Media.Stream StreamType = global::Android.Media.Stream.Music;

        private readonly int _gen;
        private readonly float _slop;
        private int _mode;
        private bool _moved;
        private float _downX, _downY;
        private int _width, _height;
        private long _startPos, _duration, _target;
        private int _startVolume, _maxVolume, _lastVolume = -1;

        public GestureTouchListener(int gen, float slop)
        {
            _gen = gen;
            _slop = Math.Max(4f, slop);
        }

        public bool OnTouch(AView? v, global::Android.Views.MotionEvent? e)
        {
            if (e is null) return false;
            try
            {
                switch (e.ActionMasked)
                {
                    case global::Android.Views.MotionEventActions.Down:
                        _mode = ModeNone;
                        _moved = false;
                        _downX = e.RawX;
                        _downY = e.RawY;
                        _target = 0;
                        _lastVolume = -1;
                        CancelHide();
                        return true;

                    case global::Android.Views.MotionEventActions.Move:
                    {
                        float dx = e.RawX - _downX;
                        float dy = e.RawY - _downY;
                        if (_mode == ModeNone)
                        {
                            if (Math.Abs(dx) < _slop && Math.Abs(dy) < _slop) return true;
                            _moved = true;
                            _mode = Math.Abs(dx) >= Math.Abs(dy) ? ModeSeek : ModeVolume;
                            if (!Begin()) { _mode = ModeNone; return true; }
                        }
                        if (_mode == ModeSeek) PreviewSeek(dx);
                        else if (_mode == ModeVolume) PreviewVolume(dy);
                        return true;
                    }

                    case global::Android.Views.MotionEventActions.Up:
                        if (_mode == ModeSeek) CommitSeek();
                        HideHint();
                        if (!_moved) ToggleChrome();
                        else if (!_uiHidden) ScheduleHide(_gen);
                        _mode = ModeNone;
                        return true;

                    case global::Android.Views.MotionEventActions.Cancel:
                        HideHint();
                        _mode = ModeNone;
                        return true;
                }
            }
            catch (Exception ex) { MainApplication.LogCaught("video-gesture", ex); }
            return false;
        }

        // 记录本次手势
        private bool Begin()
        {
            var root = _root;
            _width = root?.Width ?? 0;
            _height = root?.Height ?? 0;

            if (_mode == ModeSeek)
            {
                var p = _player;
                if (p is null || _width <= 0) return false;
                long dur = 0, pos = 0;
                try { dur = p.Duration; } catch { dur = 0; }
                try { pos = p.CurrentPosition; } catch { pos = 0; }
                if (dur <= 0) return false;
                _duration = dur;
                _startPos = pos < 0 ? 0 : Math.Min(pos, dur);
                _target = _startPos;
                return true;
            }

            var am = _audio;
            if (am is null || _height <= 0) return false;
            try
            {
                int max = am.GetStreamMaxVolume(StreamType);
                int cur = am.GetStreamVolume(StreamType);
                if (max <= 0) return false;
                _maxVolume = max;
                _startVolume = Math.Clamp(cur, 0, max);
                return true;
            }
            catch (Exception ex)
            {
                MainApplication.LogCaught("video-volume", ex);
                return false;
            }
        }

        private void PreviewSeek(float dx)
        {
            long delta = (long)Math.Round(dx / (double)_width * _duration);
            long target = _startPos + delta;
            if (target < 0) target = 0;
            if (target > _duration) target = _duration;
            _target = target;
            string icon = target < _startPos ? "↺ " : "↻ ";
            ShowHint(icon + Fmt((int)Math.Min(target, int.MaxValue)) + " / " +
                Fmt((int)Math.Min(_duration, int.MaxValue)));
        }

        private void CommitSeek()
        {
            if (_duration <= 0) return;
            if (Math.Abs(_target - _startPos) < MinSeekMs) return;
            try
            {
                _player?.SeekTo(_target);
                RefreshProgress(force: true);
            }
            catch (Exception ex) { MainApplication.LogCaught("video-gesture-seek", ex); }
        }

        private void PreviewVolume(float dy)
        {
            int max = _maxVolume;
            if (max <= 0) return;
            int vol = _startVolume + (int)Math.Round(-dy / (double)_height * max);
            if (vol < 0) vol = 0;
            if (vol > max) vol = max;
            if (vol != _lastVolume)
            {
                _lastVolume = vol;
                try { _audio?.SetStreamVolume(StreamType, vol, 0); }
                catch (Exception ex) { MainApplication.LogCaught("video-volume", ex); }
            }
            int pct = (int)Math.Round(vol * 100.0 / max);
            string suffix = vol <= 0 ? L10n.T("（最小）") : (vol >= max ? L10n.T("（最大）") : "");
            ShowHint(L10n.F("音量 {0}%{1}", pct, suffix));
        }

        // 无位移点击
        private void ToggleChrome()
        {
            if (_gen != s_gen) return;
            if (_uiHidden) RevealUi(_gen, true);
            else { CancelHide(); _uiHidden = true; ApplyUiVisibility(); }
        }
    }

    // 双内核统一成员
    private interface IVideoCore
    {
        int VideoWidth { get; }
        int VideoHeight { get; }
        int PlaybackState { get; }
        bool PlayWhenReady { get; set; }
        bool IsPlaying { get; }
        long Duration { get; }
        long CurrentPosition { get; }
        long PrepareElapsedMs { get; }
        void Play();
        void Pause();
        void SeekTo(long ms);
        void SetPlaybackSpeed(float speed);
        void Release();
    }

    // 起播看门狗取消
    private static void CancelWatchdog()
    {
        try
        {
            var root = _root;
            var r = _watchdogRunnable;
            if (root is not null && r is not null) root.RemoveCallbacks(r);
        }
        catch { }
        _watchdogRunnable = null;
    }

    // MediaPlayer 适配器
    // 承担
    private sealed class PlaybackCore : Java.Lang.Object,
        global::Android.Media.MediaPlayer.IOnPreparedListener,
        global::Android.Media.MediaPlayer.IOnCompletionListener,
        global::Android.Media.MediaPlayer.IOnErrorListener,
        global::Android.Media.MediaPlayer.IOnInfoListener,
        global::Android.Media.MediaPlayer.IOnVideoSizeChangedListener,
        global::Android.Views.TextureView.ISurfaceTextureListener,
        IVideoCore
    {
        private readonly global::Android.Media.MediaPlayer _mp;
        private readonly global::Android.Views.TextureView _view;
        private global::Android.Views.Surface? _surf;
        private readonly global::Android.Media.MediaDataSource? _stream;
        private readonly string _localPath;
        private readonly Action _onReady;
        private readonly Action _onEnded;
        private readonly Action<string> _onError;
        private readonly Action _onSize;
        private readonly Action<bool> _onBuffering;
        private bool _sourceSet;
        private bool _released;
        private long _t0;
        public long PrepareElapsedMs { get; private set; }

        public PlaybackCore(global::Android.Views.TextureView view, string localPath,
            global::Android.Media.MediaDataSource? stream,
            Action onReady, Action onEnded, Action<string> onError, Action onSize,
            Action<bool> onBuffering)
        {
            _localPath = localPath;
            _stream = stream;
            _onReady = onReady;
            _onEnded = onEnded;
            _onError = onError;
            _onSize = onSize;
            _onBuffering = onBuffering;
            PlayWhenReady = true;
            _mp = new global::Android.Media.MediaPlayer();
            _mp.SetOnPreparedListener(this);
            _mp.SetOnCompletionListener(this);
            _mp.SetOnErrorListener(this);
            _mp.SetOnVideoSizeChangedListener(this);
            _mp.SetOnInfoListener(this);
            _mp.SetScreenOnWhilePlaying(true);
            _view = view;
            view.SurfaceTextureListener = this;
            // attach 早于挂 listener 时系统
            if (view.IsAvailable && view.SurfaceTexture is global::Android.Graphics.SurfaceTexture st0)
                OnSurfaceTextureAvailable(st0, view.Width, view.Height);
        }

        public int VideoWidth { get; private set; }
        public int VideoHeight { get; private set; }
        public int PlaybackState { get; private set; } = 1;
        public bool PlayWhenReady { get; set; }
        public bool IsPlaying { get { try { return _mp.IsPlaying; } catch { return false; } } }
        public long Duration { get { try { return _mp.Duration; } catch { return 0; } } }
        public long CurrentPosition { get { try { return _mp.CurrentPosition; } catch { return 0; } } }

        public void Play()
        {
            try { _mp.Start(); PlayWhenReady = true; PlaybackState = 3; } catch { }
        }

        public void Pause()
        {
            try { _mp.Pause(); PlayWhenReady = false; } catch { }
        }

        public void SeekTo(long ms)
        {
            try { _mp.SeekTo((int)System.Math.Min(ms, int.MaxValue)); PlaybackState = 3; } catch { }
        }

        public void SetPlaybackSpeed(float speed)
        {
            try
            {
                var p = new global::Android.Media.PlaybackParams();
                p.AllowDefaults();
                p.SetSpeed(speed);
                _mp.PlaybackParams = p;
            }
            catch { }
        }

        public void OnPrepared(global::Android.Media.MediaPlayer? mp)
        {
            if (_released) return;
            PrepareElapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - _t0)
                * 1000 / System.Diagnostics.Stopwatch.Frequency;
            PlaybackState = 3;
            MainApplication.LogNote("video-diag", $"mp prepared w={VideoWidth} h={VideoHeight} t={PrepareElapsedMs}ms");
            try { if (PlayWhenReady) _mp.Start(); } catch { }
            try { _onReady(); } catch (Exception ex) { MainApplication.LogCaught("video-prepared", ex); }
        }

        public void OnCompletion(global::Android.Media.MediaPlayer? mp)
        {
            if (_released) return;
            PlaybackState = 4;
            PlayWhenReady = false;
            try { _onEnded(); } catch (Exception ex) { MainApplication.LogCaught("video-completion", ex); }
        }

        public bool OnError(global::Android.Media.MediaPlayer? mp,
            global::Android.Media.MediaError what, int extra)
        {
            if (!_released)
            {
                try { _onError($"what={what} extra={extra}"); }
                catch (Exception ex) { MainApplication.LogCaught("video-error", ex); }
            }
            return true;
        }

        public bool OnInfo(global::Android.Media.MediaPlayer? mp,
            global::Android.Media.MediaInfo what, int extra)
        {
            if (_released) return true;
            // what=3 首帧开始渲染
            if ((int)what == 3)
                MainApplication.LogNote("video-diag", "mp render-start");
            try { _onBuffering(what == global::Android.Media.MediaInfo.BufferingStart); }
            catch (Exception ex) { MainApplication.LogCaught("video-info", ex); }
            return true;
        }

        public void OnVideoSizeChanged(global::Android.Media.MediaPlayer? mp, int width, int height)
        {
            VideoWidth = width;
            VideoHeight = height;
            MainApplication.LogNote("video-diag", $"mp vsize w={width} h={height}");
            try { _onSize(); } catch (Exception ex) { MainApplication.LogCaught("video-size", ex); }
        }

        public void OnSurfaceTextureAvailable(global::Android.Graphics.SurfaceTexture st, int w, int h)
        {
            try { _surf?.Release(); } catch { }
            _surf = new global::Android.Views.Surface(st);
            try { _mp.SetSurface(_surf); } catch { }
            if (_sourceSet)
            {
                if (PlaybackState == 3 && PlayWhenReady) { try { _mp.Start(); } catch { } }
                return;
            }
            _sourceSet = true;
            try
            {
                _t0 = System.Diagnostics.Stopwatch.GetTimestamp();
                if (_stream is not null) _mp.SetDataSource(_stream);
                else _mp.SetDataSource(_localPath);
                _mp.PrepareAsync();
            }
            catch (Exception ex)
            {
                MainApplication.LogCaught("video-prepare", ex);
                try { _onError("prepare: " + ex.GetType().Name); } catch { }
            }
        }

        public void OnSurfaceTextureSizeChanged(global::Android.Graphics.SurfaceTexture st, int w, int h) { }

        public bool OnSurfaceTextureDestroyed(global::Android.Graphics.SurfaceTexture st)
        {
            // 旋转/PiP
            try { if (_mp.IsPlaying) _mp.Pause(); } catch { }
            try { _mp.SetSurface(null); } catch { }
            return true;
        }

        public void OnSurfaceTextureUpdated(global::Android.Graphics.SurfaceTexture st) { }

        public void Release()
        {
            if (_released) return;
            _released = true;
            try { _view.SurfaceTextureListener = null; } catch { }
            try { (_stream as IAbortableStream)?.Abort(); } catch { }
            var mp = _mp;
            var stream = _stream;
            // Abort 已
            // 释放移后台
            System.Threading.Tasks.Task.Run(() =>
            {
                try { _surf?.Release(); } catch { }
                try { mp.Reset(); } catch { }
                try { mp.Release(); } catch { }
                try { stream?.Close(); } catch { }
            });
        }
    }

    // Media3 兼容内核
    // 库内源走顺序解
    // Media3 分析监听
    private sealed class VideoDiagListener : Java.Lang.Object,
        global::AndroidX.Media3.ExoPlayer.Analytics.IAnalyticsListener
    {
        public void OnVideoDecoderInitialized(
            global::AndroidX.Media3.ExoPlayer.Analytics.AnalyticsListenerEventTime? t,
            string? decoderName, long initializedTimestampMs, long initializationDurationMs)
        {
            MainApplication.LogNote("video-diag", $"exo video-decoder={decoderName} init={initializationDurationMs}ms");
        }

        public void OnAudioDecoderInitialized(
            global::AndroidX.Media3.ExoPlayer.Analytics.AnalyticsListenerEventTime? t,
            string? decoderName, long initializedTimestampMs, long initializationDurationMs)
        {
            MainApplication.LogNote("video-diag", $"exo audio-decoder={decoderName} init={initializationDurationMs}ms");
        }

        public void OnRenderedFirstFrame(
            global::AndroidX.Media3.ExoPlayer.Analytics.AnalyticsListenerEventTime? t,
            global::Java.Lang.Object? output, long renderTimeMs)
        {
            MainApplication.LogNote("video-diag", "exo first-frame");
        }
    }

    private sealed class ExoCore : IVideoCore
    {
        private readonly IExoPlayer _p;
        private readonly PlayerEvents _events;
        private bool _released;
        private readonly long _t0;
        public long PrepareElapsedMs { get; private set; }

        // 无画面诊断透传
        public global::AndroidX.Media3.Common.Format? VideoFmt
        {
            get { try { return _p.VideoFormat; } catch { return null; } }
        }

        public global::AndroidX.Media3.Common.Tracks? TracksNow
        {
            get { try { return _p.CurrentTracks; } catch { return null; } }
        }

        public ExoCore(AActivity act, global::Android.Views.TextureView video,
            string localPath,
            global::Android.Media.MediaDataSource? stream,
            long startPosMs, Action onReady, Action onEnded, Action<string> onError,
            Action onSize, Action<bool> onBuffering)
        {
            _t0 = System.Diagnostics.Stopwatch.GetTimestamp();
            var factory = new NextRenderersFactory(act);
            // 扩展模式开
            if (FfmpegLibrary.IsAvailable)
                factory.SetExtensionRendererMode(DefaultRenderersFactory.ExtensionRendererModeOn);
            var builder = new ExoPlayerBuilder(act, factory);
            // 顺序解密源禁大
            var lc = new DefaultLoadControl.Builder()
                .SetBufferDurationsMs(1500, 3000, 500, 1000)!
                .SetTargetBufferBytes(8 * 1024 * 1024)!
                .SetPrioritizeTimeOverSizeThresholds(false)!
                .SetBackBuffer(0, false)!
                .Build();
            if (lc is not null) builder.SetLoadControl(lc);
            var player = builder.Build()!;
            _p = player;
            _p.AddAnalyticsListener(new VideoDiagListener());
            MainApplication.LogNote("video-diag", $"exo created ff={FfmpegLibrary.IsAvailable}");
            _events = new PlayerEvents(
                () =>
                {
                    PrepareElapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - _t0)
                        * 1000 / System.Diagnostics.Stopwatch.Frequency;
                    onReady();
                },
                onEnded, onError, onSize, onBuffering);
            player.AddListener(_events);
            if (stream is not null)
            {
                // 每 64KB 复检缓冲上限
                var msFactory = new ProgressiveMediaSource.Factory(new SeqFactory(stream));
                msFactory.SetContinueLoadingCheckIntervalBytes(64 * 1024);
                player.SetMediaSource(
                    msFactory.CreateMediaSource(MediaItem.FromUri("fevault://stream"))!);
            }
            else
            {
                player.SetMediaItem(MediaItem.FromUri(
                    global::Android.Net.Uri.FromFile(new Java.IO.File(localPath))));
            }
            player.SetVideoTextureView(video);
            if (startPosMs > 0) player.SeekTo(startPosMs);
            player.Prepare();
            player.PlayWhenReady = true;
        }

        public int VideoWidth { get { try { return _p.VideoSize?.Width ?? 0; } catch { return 0; } } }
        public int VideoHeight { get { try { return _p.VideoSize?.Height ?? 0; } catch { return 0; } } }
        public int PlaybackState { get { try { return _p.PlaybackState; } catch { return 1; } } }
        public bool PlayWhenReady
        {
            get { try { return _p.PlayWhenReady; } catch { return false; } }
            set { try { _p.PlayWhenReady = value; } catch { } }
        }
        public bool IsPlaying { get { try { return _p.IsPlaying; } catch { return false; } } }
        public long Duration { get { try { return _p.Duration; } catch { return 0; } } }
        public long CurrentPosition { get { try { return _p.CurrentPosition; } catch { return 0; } } }

        public void Play()
        {
            try { _p.Play(); } catch { }
        }

        public void Pause()
        {
            try { _p.Pause(); } catch { }
        }

        public void SeekTo(long ms)
        {
            try { _p.SeekTo(System.Math.Max(0, ms)); } catch { }
        }

        public void SetPlaybackSpeed(float speed)
        {
            try { _p.SetPlaybackSpeed(speed); } catch { }
        }

        public void Release()
        {
            if (_released) return;
            _released = true;
            var p = _p;
            var ev = _events;
            // release 内部 join 加载线程，移
            System.Threading.Tasks.Task.Run(() =>
            {
                try { p.SetVideoTextureView(null); } catch { }
                try { p.RemoveListener(ev); } catch { }
                try { p.Release(); } catch { }
            });
        }
    }

    // Media3 播放回调
    // 每个回调
    private sealed class PlayerEvents : Java.Lang.Object, IPlayerListener
    {
        private const int StateBuffering = 2;
        private const int StateReady = 3;
        private const int StateEnded = 4;

        private readonly Action _onReady;
        private readonly Action _onEnded;
        private readonly Action<string> _onError;
        private readonly Action _onSize;
        private readonly Action<bool> _onBuffering;

        public PlayerEvents(Action onReady, Action onEnded, Action<string> onError,
            Action onSize, Action<bool> onBuffering)
        {
            _onReady = onReady;
            _onEnded = onEnded;
            _onError = onError;
            _onSize = onSize;
            _onBuffering = onBuffering;
        }

        public void OnPlaybackStateChanged(int playbackState)
        {
            try
            {
                if (playbackState == StateReady) { _onBuffering(false); _onReady(); }
                else if (playbackState == StateEnded) _onEnded();
                else if (playbackState == StateBuffering) _onBuffering(true);
            }
            catch (Exception ex) { MainApplication.LogCaught("video-state", ex); }
        }

        public void OnVideoSizeChanged(VideoSize? videoSize)
        {
            try { _onSize(); }
            catch (Exception ex) { MainApplication.LogCaught("video-size", ex); }
        }

        public void OnPlayerError(PlaybackException? error)
        {
            try
            {
                string detail = $"{error?.ErrorCodeName}: {error?.Message}";
                // 播完 / 释放后数据
                if (_ended || _released)
                {
                    MainApplication.LogNote("video-error-ignored", detail);
                    return;
                }
                _onError(detail);
            }
            catch (Exception ex) { MainApplication.LogCaught("video-error", ex); }
        }
    }

    // 顺序解密数据源
    // 按数据源类型分
    private sealed class SeqFactory : Java.Lang.Object, IDataSourceFactory
    {
        private readonly global::Android.Media.MediaDataSource _stream;

        public SeqFactory(global::Android.Media.MediaDataSource stream)
        {
            _stream = stream;
        }

        public global::AndroidX.Media3.DataSource.IDataSource? CreateDataSource()
            => _stream switch
            {
                VaultMediaDataSource v => new VaultSeqSource(v),
                GrowingFileDataSource g => new GrowingSeqSource(g),
                _ => null,
            };
    }

    // 增长明文顺序源
    private sealed class GrowingSeqSource : BaseDataSource
    {
        private const int MaxChunk = 512 * 1024;

        private readonly GrowingFileDataSource _g;
        private long _pos;
        private long _remaining;
        private bool _started;
        private global::Android.Net.Uri? _uri;

        public GrowingSeqSource(GrowingFileDataSource g) : base(false) { _g = g; }

        public override long Open(DataSpec? dataSpec)
        {
            long pos = dataSpec?.Position ?? 0;
            if (pos < 0) pos = 0;
            long size = _g.Size;
            if (pos > size) pos = size;
            long len = dataSpec?.Length ?? -1;
            _pos = pos;
            _remaining = len < 0 ? size - pos : System.Math.Min(len, size - pos);
            try { _uri = global::Android.Net.Uri.Parse("fevault://growing"); }
            catch { _uri = null; }
            _started = true;
            TransferInitializing(dataSpec);
            TransferStarted(dataSpec);
            return _remaining;
        }

        public override int Read(byte[]? buffer, int offset, int length)
        {
            if (buffer is null || length <= 0 || _remaining <= 0) return -1;
            int want = (int)System.Math.Min(length, _remaining);
            if (want > MaxChunk) want = MaxChunk;
            int r = _g.ReadAt(_pos, buffer, offset, want);
            if (r <= 0) return -1;
            _pos += r;
            _remaining -= r;
            BytesTransferred(r);
            return r;
        }

        public override void Close()
        {
            try { if (_started) TransferEnded(); } catch { }
            _started = false;
            _remaining = 0;
        }

        public override global::Android.Net.Uri? Uri => _uri;
    }

    // 顺序解密数据源
    private sealed class VaultSeqSource : BaseDataSource
    {
        private const int MaxChunk = 512 * 1024;

        private readonly VaultService _vault;
        private readonly string _rel;
        private readonly long _size;
        private long _pos;
        private long _remaining;
        private bool _started;
        private global::Android.Net.Uri? _uri;

        public VaultSeqSource(global::FileEncryptorMobile.Platforms.Android.VaultMediaDataSource stream)
            : base(false)
        {
            _vault = stream.Vault;
            _rel = stream.RelPath;
            _size = stream.FileSize;
        }

        public override long Open(DataSpec? dataSpec)
        {
            long pos = dataSpec?.Position ?? 0;
            if (pos < 0) pos = 0;
            if (pos > _size) pos = _size;
            long len = dataSpec?.Length ?? -1;
            _pos = pos;
            _remaining = len < 0 ? _size - pos : System.Math.Min(len, _size - pos);
            try { _uri = global::Android.Net.Uri.Parse("fevault://stream/" + _rel); }
            catch { _uri = null; }
            _started = true;
            TransferInitializing(dataSpec);
            TransferStarted(dataSpec);
            return _remaining;
        }

        public override int Read(byte[]? buffer, int offset, int length)
        {
            if (buffer is null || length <= 0 || _remaining <= 0) return -1;
            int want = (int)System.Math.Min(length, _remaining);
            if (want > MaxChunk) want = MaxChunk;
            int got;
            try { got = _vault.ReadRangeTo(_rel, (ulong)_pos, buffer, offset, want); }
            catch (Exception ex)
            {
                MainApplication.LogCaught("video-seq-read", ex);
                throw new System.IO.IOException("seq read failed");
            }
            if (got <= 0) return -1;
            _pos += got;
            _remaining -= got;
            BytesTransferred(got);
            return got;
        }

        public override void Close()
        {
            try { if (_started) TransferEnded(); } catch { }
            _started = false;
            _remaining = 0;
        }

        public override global::Android.Net.Uri? Uri => _uri;
    }

    private sealed class Ticker : Java.Lang.Object, Java.Lang.IRunnable
    {
        private readonly Action _callback;
        public Ticker(Action callback) => _callback = callback;
        public void Run()
        {
            try { _callback(); }
            catch (Exception ex) { MainApplication.LogCaught("video-ticker", ex); }
        }
    }

    private sealed class Runnable : Java.Lang.Object, Java.Lang.IRunnable
    {
        private readonly Action _callback;
        public Runnable(Action callback) => _callback = callback;
        public void Run()
        {
            try { _callback(); }
            catch (Exception ex) { MainApplication.LogCaught("video-ui", ex); }
        }
    }

    private sealed class SeekListener : Java.Lang.Object, global::Android.Widget.SeekBar.IOnSeekBarChangeListener
    {
        private readonly Action _onStart;
        private readonly Action _onStop;
        private readonly Action<int> _onChange;

        public SeekListener(Action onStart, Action onStop, Action<int> onChange)
        {
            _onStart = onStart;
            _onStop = onStop;
            _onChange = onChange;
        }

        public void OnProgressChanged(global::Android.Widget.SeekBar? seekBar, int progress, bool fromUser)
        {
            if (!fromUser) return;
            try { _onChange(progress); }
            catch (Exception ex) { MainApplication.LogCaught("video-seek", ex); }
        }

        public void OnStartTrackingTouch(global::Android.Widget.SeekBar? seekBar)
        {
            try { _onStart(); } catch { }
        }

        public void OnStopTrackingTouch(global::Android.Widget.SeekBar? seekBar)
        {
            try { _onStop(); } catch { }
        }
    }
// 视频比例容器
// 未设比例或比例
public sealed class RatioFrameLayout : FrameLayout
{
    // 0 等比适配
    public int ResizeMode { get; set; }

    private float _ratio;

    public RatioFrameLayout(global::Android.Content.Context c) : base(c) { }

    public void SetAspectRatio(float ratio)
    {
        if (System.Math.Abs(_ratio - ratio) < 0.0001f) return;
        _ratio = ratio;
        RequestLayout();
    }

    protected override void OnMeasure(int wSpec, int hSpec)
    {
        if (_ratio <= 0f) { base.OnMeasure(wSpec, hSpec); return; }
        int width = GetDefaultSize(Width, wSpec);
        int height = GetDefaultSize(Height, hSpec);
        if (width >= (int)(height * _ratio))
        {
            int fitW = (int)(height * _ratio);
            if (ResizeMode == 0) width = fitW;
            else if (ResizeMode == 1)
            {
                width = System.Math.Max(width, fitW);
                height = System.Math.Max(height, (int)(width / _ratio));
            }
            // 2 拉伸
        }
        else
        {
            int fitH = (int)(width / _ratio);
            if (ResizeMode == 0) height = fitH;
            else if (ResizeMode == 1)
            {
                height = System.Math.Max(height, fitH);
                width = System.Math.Max(width, (int)(height * _ratio));
            }
        }
        SetMeasuredDimension(width, height);
        int cw = global::Android.Views.View.MeasureSpec.MakeMeasureSpec(width, global::Android.Views.MeasureSpecMode.Exactly);
        int ch = global::Android.Views.View.MeasureSpec.MakeMeasureSpec(height, global::Android.Views.MeasureSpecMode.Exactly);
        for (int i = 0; i < ChildCount; i++) GetChildAt(i)?.Measure(cw, ch);
    }
}

}
