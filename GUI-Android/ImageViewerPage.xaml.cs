// 图片画廊
// 交互
// 位移阈值 / 轻扫速
// pager 与 overlay 同帧
// 窗口化三单元回
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;

namespace FileEncryptorMobile;

// 画廊单页数据模
public sealed class GalleryImage : INotifyPropertyChanged
{
    public VaultItem Item { get; set; } = null!;
    public int Index { get; set; }

    private ImageSource? _src;
    public ImageSource? Source
    {
        get => _src;
        set { _src = value; OnPropertyChanged(); }
    }

    private bool _loading = true;
    public bool Loading
    {
        get => _loading;
        set { _loading = value; OnPropertyChanged(); }
    }

    // 解密/解码失败
    private bool _error;
    public bool Error
    {
        get => _error;
        set { _error = value; OnPropertyChanged(); }
    }

    // 缩略图缓存路径
    public string ThumbPath { get; set; } = "";

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}

public partial class ImageViewerPage : ContentPage, IPagerTouchSink
{
    private readonly VaultService _vault;
    private readonly List<VaultItem> _imgs;
    private readonly int _startIndex;
    private bool _active = true;
    // 三单元对应
    private readonly NativeImageHost[] _cellHosts = new NativeImageHost[3];
    // 每格代际计数
    private readonly int[] _slotGen = new int[3];
    // 各格当前显示
    private readonly bool[] _cellFull = new bool[3];
    // 每格已上屏
    private readonly int[] _cellStage = new int[3];
    // 逐带渲染进行
    private readonly bool[] _cellBandsPending = new bool[3];
    // 逐带进度
    private readonly int[] _bandNextY = { -1, -1, -1 };
    private readonly string?[] _bandPath = new string?[3];

    // 窗口化三单元
    private readonly GalleryImage[] _g = new GalleryImage[3];
    private readonly View[] _cellViews = new View[3];
    // 相邻格加载态控
    private readonly View[] _cellLoaders = new View[3];
    private readonly View[] _cellErrs = new View[3];

    private double _pageW, _pageH;
    private int _index;
    private bool _laidOut, _dragging, _animating;
    // px 状态源
    private float _txPx, _pageWpx;
    private float _density = 1f;
    private global::Android.Views.View? _pagerView;
    private global::Android.Animation.ValueAnimator? _anim;
    private float _dragBase;
    private bool _moveLogged;   // 拖动只记首帧 Move
    // 顶/底栏
    private global::Android.Widget.LinearLayout? _topBar, _bottomBar;
    private global::Android.Views.WindowManagerLayoutParams? _topLp, _bottomLp;
    private global::Android.Widget.TextView? _tvName, _tvMeta, _tvPage;
    private global::Android.Widget.ImageView? _ivBack, _ivCheck, _ivExport;
    private global::Android.Graphics.Bitmap? _iconBack, _iconExport, _iconCur;
    private global::Android.Animation.ValueAnimator? _barAnim;
    private bool _barsVisible = true, _exporting;
    private global::Android.Views.View? _warnView;
    private global::Android.Views.WindowManagerLayoutParams? _warnLp;
    private TaskCompletionSource<bool>? _warnTcs;
    private string _fileName = "", _metaBase = "", _metaRes = "", _exportHint = "", _pageText = "";
    private readonly Dictionary<string, string> _resByPath = new();   // 每张图已读到
    // 飞入/飞出动画
    private bool _flying, _closing, _purgedOnLeave;

    private const double SnapFraction = 0.38;   // 越过 38% 页宽才吸附
    private const double FlickVelDp = 900;      // dp/s
    private const double MinFlickDp = 36;       // 轻扫至少位移 36dp
    private const float SnapMs = 260;           // 吸附动画时长
    private const float BackMs = 160;           // 回弹动画时长
    private const float TapMovePx = 24;         // 位移小于此值
    private const long TapMs = 250;
    // ≤1.5MB 一次直出、跳过逐
    private const long DirectBytes = 1536L * 1024;

    public ImageViewerPage(VaultService vault, List<VaultItem> images, int startIndex)
    {
        InitializeComponent();
        NavigationPage.SetHasNavigationBar(this, false);
        // Shell 自带蓝色标题栏
        // 且与新顶栏叠成
        Microsoft.Maui.Controls.Shell.SetNavBarIsVisible(this, false);
        Microsoft.Maui.Controls.Shell.SetTabBarIsVisible(this, false);
        _vault = vault;
        _imgs = images;
        _startIndex = startIndex;
        _index = startIndex;
        try { _density = Android.App.Application.Context!.Resources!.DisplayMetrics!.Density; } catch { }
        BindingContext = this;
        BuildCells();
        NativeImageHost.OverlayMounted += OnOverlayMounted;   // 图片窗口上树
    }

    // 创建 3 个复用单元
    private void BuildCells()
    {
        for (int i = 0; i < 3; i++)
        {
            var g = new GalleryImage();
            _g[i] = g;
            // 原生 ImageView 宿主
            var host = new NativeImageHost
            {
                Slot = i,
                BackgroundColor = Colors.Black,
                HorizontalOptions = LayoutOptions.Fill,
                VerticalOptions = LayoutOptions.Fill,
            };
            _cellHosts[i] = host;
            var spin = new ActivityIndicator
            {
                Color = Colors.White, IsRunning = true, IsVisible = true,
                HorizontalOptions = LayoutOptions.Center
            };
            spin.SetBinding(ActivityIndicator.IsRunningProperty, new Binding(nameof(GalleryImage.Loading), source: g));
            spin.SetBinding(ActivityIndicator.IsVisibleProperty, new Binding(nameof(GalleryImage.Loading), source: g));
            // 文字兜底
            var lblLoad = new Label
            {
                Text = L10n.T("加载中…"), TextColor = Colors.White, FontSize = 12,
                HorizontalOptions = LayoutOptions.Center, Margin = new Thickness(0, 8, 0, 0)
            };
            lblLoad.SetBinding(Label.IsVisibleProperty, new Binding(nameof(GalleryImage.Loading), source: g));
            var loadStack = new VerticalStackLayout
            {
                HorizontalOptions = LayoutOptions.Center,
                VerticalOptions = LayoutOptions.Center,
                Children = { spin, lblLoad }
            };
            var err = new Label
            {
                Text = L10n.T("无法加载此图片"),
                TextColor = Colors.White,
                FontSize = 14,
                HorizontalOptions = LayoutOptions.Center,
                VerticalOptions = LayoutOptions.Center,
                IsVisible = false,
            };
            err.SetBinding(Label.IsVisibleProperty, new Binding(nameof(GalleryImage.Error), source: g));
            var cell = new Grid { BackgroundColor = Colors.Black, Children = { host, loadStack, err } };
            _cellViews[i] = cell;
            _cellLoaders[i] = loadStack;
            _cellErrs[i] = err;
            Pages.Children.Add(cell);
        }
    }

    protected override void OnSizeAllocated(double width, double height)
    {
        base.OnSizeAllocated(width, height);
        if (width <= 0 || height <= 0) return;
        ApplySafeInsets();   // 旋转/分屏/挖孔变
        bool first = !_laidOut;
        _pageW = width;
        _pageH = height;
        _pageWpx = (float)(width * _density);
        for (int i = 0; i < 3; i++)
            AbsoluteLayout.SetLayoutBounds(_cellViews[i], new Rect(i * _pageW, 0, _pageW, _pageH));
        // 非拖拽/动画时始
        if (!_dragging && !_animating && !_flying && !_closing)
            ApplyTx(-_pageWpx);
        if (first)
        {
            _laidOut = true;
            AssignSlot(0, _index - 1);
            AssignSlot(1, _index);
            AssignSlot(2, _index + 1);
            UpdateInfo(_g[1]);
            CreateBars();
            // 显示，不走淡入动
            Viewport.Opacity = 1;
            EntryFly();
        }
    }

    // 把第 slot 个单元指
    // carried
    // 是糊缩略图
    private void AssignSlot(int slot, int imgIndex, Android.Graphics.Bitmap? carried = null,
        bool carriedFull = false, bool skipLoad = false, bool carriedPartial = false,
        int carriedNextY = 0, string? carriedPath = null)
    {
        var g = _g[slot];
        if (imgIndex < 0 || imgIndex >= _imgs.Count)
        {
            g.Item = null!; g.Index = -1; g.Source = null; g.Loading = false; g.Error = false; g.ThumbPath = "";
            _slotGen[slot]++;
            _cellHosts[slot]?.Clear();
            _cellFull[slot] = false;
            _cellStage[slot] = 0;
            _cellBandsPending[slot] = false;
            _bandNextY[slot] = -1;
            _bandPath[slot] = null;
            return;
        }
        // 同图重复指派
        if (carried is null && g.Index == imgIndex &&
            ReferenceEquals(g.Item, _imgs[imgIndex]) && _cellFull[slot] &&
            !_cellBandsPending[slot])
            return;
        g.Item = _imgs[imgIndex];
        g.Index = imgIndex;
        g.Source = null;
        g.Error = false;
        g.ThumbPath = ThumbnailHelper.CachePath(g.Item);
        _slotGen[slot]++;
        _cellStage[slot] = 0;
        _cellBandsPending[slot] = false;
        if (carried is not null)
        {
            if (carriedPartial && carriedPath is not null && !carried.IsRecycled)
            {
                // 下一张已加载一
                g.Loading = false;
                _cellFull[slot] = false;
                _cellStage[slot] = 3;
                _cellBandsPending[slot] = true;
                _cellHosts[slot]?.Show(carried);
                ShowCellImage(slot, carriedPath, _slotGen[slot], full: true,
                    progressive: true, carried: carried, startY: carriedNextY);
                return;
            }
            if (carriedFull)
            {
                // 转移
                g.Loading = false;
                _cellHosts[slot]?.Show(carried);
                _cellFull[slot] = true;
                return;
            }
            // 转移
            try { carried.Recycle(); } catch { }
            g.Loading = !skipLoad;
            g.Error = false;
            _cellFull[slot] = false;
            _cellHosts[slot]?.Clear();
            if (!skipLoad) LoadOne(g, slot);
            return;
        }
        g.Loading = !skipLoad;
        _cellFull[slot] = false;
        _cellHosts[slot]?.Clear();
        if (!skipLoad) LoadOne(g, slot);
    }

    // 页码 / 文件名 / 元数
    private void UpdateInfo(GalleryImage g)
    {
        _fileName = g.Item?.Name ?? "";
        _pageText = $"{g.Index + 1}/{_imgs.Count}";
        string ext = "";
        try { ext = Path.GetExtension(_fileName).TrimStart('.').ToUpperInvariant(); } catch { }
        _metaBase = (g.Item?.SizeText ?? "") + (ext.Length > 0 ? " · " + ext : "");
        _metaRes = g.Item is not null && _resByPath.TryGetValue(g.Item.RelPath, out var r) ? r : "";
        ApplyBarText();
    }

    // 解密完成后补分
    private void SetMetaResolution(int w, int h)
    {
        _metaRes = $"{w}×{h}";
        ApplyBarText();
    }

    private void ApplyBarText()
    {
        try
        {
            if (_tvName is not null) _tvName.Text = _fileName;
            string meta = _exportHint.Length > 0 ? _exportHint : _metaBase;
            if (_metaRes.Length > 0) meta += " · " + _metaRes;
            if (_tvMeta is not null) _tvMeta.Text = meta;
            if (_tvPage is not null) _tvPage.Text = _pageText;
        }
        catch { }
    }

    // 取系统返回箭头
    private static int ResolveBackDrawable(global::Android.App.Activity act)
    {
        try
        {
            var res = act.Resources;
            string pkg = act.PackageName ?? "";
            var tv = new global::Android.Util.TypedValue();
            int attr = res?.GetIdentifier("homeAsUpIndicator", "attr", "android") ?? 0;
            if (attr != 0 && act.Theme?.ResolveAttribute(attr, tv, true) == true && tv.ResourceId != 0)
                return tv.ResourceId;
            foreach (var n in new[] { "abc_ic_ab_back_material", "abc_ic_ab_back_mtrl_am_alpha", "ic_arrow_back" })
            {
                int id = res?.GetIdentifier(n, "drawable", pkg) ?? 0;
                if (id != 0) return id;
            }
        }
        catch { }
        return 0;
    }

    // 图标自绘
    private static global::Android.Graphics.Bitmap MakeIcon(int dp, string kind)
    {
        var dm = global::Android.App.Application.Context!.Resources!.DisplayMetrics!;
        int s = global::System.Math.Max(24, (int)(dp * dm.Density));
        var bmp = global::Android.Graphics.Bitmap.CreateBitmap(
            s, s, global::Android.Graphics.Bitmap.Config.Argb8888!)!;
        using var c = new global::Android.Graphics.Canvas(bmp);
        using var p = new global::Android.Graphics.Paint(global::Android.Graphics.PaintFlags.AntiAlias);
        p.Color = global::Android.Graphics.Color.White;
        p.StrokeWidth = global::System.Math.Max(2f, s * 0.07f);
        float f = s;
        if (kind == "back")
        {
            c.DrawLine(0.62f * f, 0.50f * f, 0.32f * f, 0.50f * f, p);
            c.DrawLine(0.47f * f, 0.30f * f, 0.28f * f, 0.50f * f, p);
            c.DrawLine(0.28f * f, 0.50f * f, 0.47f * f, 0.70f * f, p);
        }
        else if (kind == "export")
        {
            c.DrawLine(0.50f * f, 0.72f * f, 0.50f * f, 0.26f * f, p);
            c.DrawLine(0.34f * f, 0.42f * f, 0.50f * f, 0.26f * f, p);
            c.DrawLine(0.50f * f, 0.26f * f, 0.66f * f, 0.42f * f, p);
            c.DrawLine(0.28f * f, 0.78f * f, 0.72f * f, 0.78f * f, p);
        }
        else
        {
            // 未选
            using var rect = new global::Android.Graphics.RectF(
                0.20f * f, 0.20f * f, 0.80f * f, 0.80f * f);
            float rad = 0.13f * f;
            if (kind == "check_on")
            {
                p.Color = global::Android.Graphics.Color.ParseColor("#4A72C8");
                p.SetStyle(global::Android.Graphics.Paint.Style.Fill);
                c.DrawRoundRect(rect, rad, rad, p);
                p.Color = global::Android.Graphics.Color.White;
                p.SetStyle(global::Android.Graphics.Paint.Style.Stroke);
                c.DrawLine(0.30f * f, 0.51f * f, 0.44f * f, 0.66f * f, p);
                c.DrawLine(0.44f * f, 0.66f * f, 0.71f * f, 0.33f * f, p);
            }
            else
            {
                p.SetStyle(global::Android.Graphics.Paint.Style.Stroke);
                c.DrawRoundRect(rect, rad, rad, p);
            }
        }
        return bmp;
    }

    private void ApplyCheckIcon()
    {
        var iv = _ivCheck;
        if (iv is null) return;
        try
        {
            bool on = _g[1]?.Item?.IsSelected ?? false;
            var bmp = MakeIcon(28, on ? "check_on" : "check_off");
            var old = _iconCur;
            iv.SetImageBitmap(bmp);
            _iconCur = bmp;
            if (old is not null && old.Handle != bmp.Handle)
            { try { if (!old.IsRecycled) old.Recycle(); } catch { } }
        }
        catch { }
    }

    // 栏窗口
    private static global::Android.Views.WindowManagerLayoutParams BarLp(
        global::Android.Views.GravityFlags gravity) =>
        new(global::Android.Views.ViewGroup.LayoutParams.MatchParent,
            global::Android.Views.ViewGroup.LayoutParams.WrapContent,
            global::Android.Views.WindowManagerTypes.ApplicationPanel,
            ScreenSecurity.OverlayFlags(
                global::Android.Views.WindowManagerFlags.NotFocusable
                | global::Android.Views.WindowManagerFlags.NotTouchModal
                | global::Android.Views.WindowManagerFlags.LayoutNoLimits),
            global::Android.Graphics.Format.Transparent)
        { Gravity = gravity, X = 0, Y = 0 };

    // 建顶/底栏
    private void CreateBars()
    {
        if (_topBar is not null) return;
        try
        {
            var act = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
            var wm = act?.WindowManager;
            if (act is null || wm is null) return;
            int hit = (int)(44 * _density);
            var bg = global::Android.Graphics.Color.ParseColor("#B3000000");
            var lpBtn = () => new global::Android.Widget.LinearLayout.LayoutParams(
                hit, hit, 0f) { Gravity = global::Android.Views.GravityFlags.CenterVertical };
            var lpFull = () => new global::Android.Widget.LinearLayout.LayoutParams(
                global::Android.Views.ViewGroup.LayoutParams.MatchParent,
                global::Android.Views.ViewGroup.LayoutParams.WrapContent);

            var top = new global::Android.Widget.LinearLayout(act)
            { Orientation = global::Android.Widget.Orientation.Horizontal };
            top.SetGravity(global::Android.Views.GravityFlags.CenterVertical);
            top.SetBackgroundColor(bg);
            _ivBack = new global::Android.Widget.ImageView(act);
            _ivBack.SetScaleType(global::Android.Widget.ImageView.ScaleType.CenterInside);
            int backRes = ResolveBackDrawable(act);
            if (backRes != 0)
            {
                _ivBack.SetImageResource(backRes);   // 系统箭头固有 24dp
                _ivBack.ImageTintList = global::Android.Content.Res.ColorStateList.ValueOf(
                    global::Android.Graphics.Color.White);
            }
            else
            {
                _iconBack = MakeIcon(24, "back");
                _ivBack.SetImageBitmap(_iconBack);
            }
            _ivBack.Click += OnBarBack;
            top.AddView(_ivBack, lpBtn());

            var center = new global::Android.Widget.LinearLayout(act)
            { Orientation = global::Android.Widget.Orientation.Vertical };
            center.SetGravity(global::Android.Views.GravityFlags.Center);
            _tvName = new global::Android.Widget.TextView(act) { TextSize = 16 };
            _tvName.SetTextColor(global::Android.Graphics.Color.White);
            _tvName.Gravity = global::Android.Views.GravityFlags.CenterHorizontal;
            _tvName.SetSingleLine(true);
            _tvName.Ellipsize = global::Android.Text.TextUtils.TruncateAt.End;
            _tvMeta = new global::Android.Widget.TextView(act) { TextSize = 12 };
            _tvMeta.SetTextColor(global::Android.Graphics.Color.ParseColor("#CCCCCC"));
            _tvMeta.Gravity = global::Android.Views.GravityFlags.CenterHorizontal;
            _tvMeta.SetSingleLine(true);
            _tvMeta.Ellipsize = global::Android.Text.TextUtils.TruncateAt.End;
            center.AddView(_tvName, lpFull());
            center.AddView(_tvMeta, lpFull());
            top.AddView(center, new global::Android.Widget.LinearLayout.LayoutParams(
                0, global::Android.Views.ViewGroup.LayoutParams.WrapContent, 1f));
            // 右侧等宽占位
            top.AddView(new global::Android.Views.View(act), lpBtn());

            var bottom = new global::Android.Widget.LinearLayout(act)
            { Orientation = global::Android.Widget.Orientation.Horizontal };
            bottom.SetGravity(global::Android.Views.GravityFlags.CenterVertical);
            bottom.SetBackgroundColor(bg);
            _ivCheck = new global::Android.Widget.ImageView(act);
            _ivCheck.SetScaleType(global::Android.Widget.ImageView.ScaleType.CenterInside);
            _ivCheck.Click += OnBarCheck;
            bottom.AddView(_ivCheck, lpBtn());
            _tvPage = new global::Android.Widget.TextView(act) { TextSize = 16 };
            _tvPage.SetTextColor(global::Android.Graphics.Color.White);
            _tvPage.Gravity = global::Android.Views.GravityFlags.Center;
            bottom.AddView(_tvPage, new global::Android.Widget.LinearLayout.LayoutParams(
                0, global::Android.Views.ViewGroup.LayoutParams.WrapContent, 1f)
            { Gravity = global::Android.Views.GravityFlags.CenterVertical });
            _ivExport = new global::Android.Widget.ImageView(act);
            _ivExport.SetScaleType(global::Android.Widget.ImageView.ScaleType.CenterInside);
            _iconExport = MakeIcon(28, "export");
            _ivExport.SetImageBitmap(_iconExport);
            _ivExport.Click += OnBarExport;
            bottom.AddView(_ivExport, lpBtn());

            _topLp = BarLp(global::Android.Views.GravityFlags.Top);
            _bottomLp = BarLp(global::Android.Views.GravityFlags.Bottom);
            wm.AddView(top, _topLp);
            wm.AddView(bottom, _bottomLp);
            _topBar = top;
            _bottomBar = bottom;
            ApplySafeInsets();
            ApplyBarText();
            ApplyCheckIcon();
            ApplyBarState();
            ApplyBarTouchFlags();
        }
        catch (Exception ex) { NativeImageHost.Log($"Bars fail {ex.Message}"); }
    }

    // 异形屏安全区
    private void ApplySafeInsets()
    {
        if (_topBar is null || _bottomBar is null) return;
        var (l0, t0, r0, b0) = ReadSafeInsets();
        int l = (int)(16 * _density) + l0;
        int r = (int)(16 * _density) + r0;
        try
        {
            _topBar.SetPadding(l, t0 + (int)(6 * _density), r, (int)(6 * _density));
            _bottomBar.SetPadding(l, (int)(6 * _density), r, b0 + (int)(10 * _density));
        }
        catch { }
    }

#pragma warning disable CA1416, CA1422   // SdkInt 已守卫
    private (int, int, int, int) ReadSafeInsets()
    {
        int l = 0, t = 0, r = 0, b = 0;
        try
        {
            var act = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
            global::Android.Views.WindowInsets? wi = null;
            if (global::Android.OS.Build.VERSION.SdkInt >= global::Android.OS.BuildVersionCodes.R)
                wi = act?.WindowManager?.CurrentWindowMetrics?.WindowInsets;
            wi ??= act?.Window?.DecorView?.RootWindowInsets;
            if (wi is not null)
            {
                l = wi.SystemWindowInsetLeft; t = wi.SystemWindowInsetTop;
                r = wi.SystemWindowInsetRight; b = wi.SystemWindowInsetBottom;
                if (global::Android.OS.Build.VERSION.SdkInt >= global::Android.OS.BuildVersionCodes.P)
                {
                    var cut = wi.DisplayCutout;
                    if (cut is not null)
                    {
                        l = Math.Max(l, cut.SafeInsetLeft); t = Math.Max(t, cut.SafeInsetTop);
                        r = Math.Max(r, cut.SafeInsetRight); b = Math.Max(b, cut.SafeInsetBottom);
                    }
                }
            }
        }
        catch { }
        t = Math.Max(t, (int)(24 * _density));   // ROM 不给 insets
        b = Math.Max(b, (int)(16 * _density));
        return (l, t, r, b);
    }
#pragma warning restore CA1416, CA1422

    private void SetBarAlpha(float a)
    {
        try
        {
            if (_topBar is not null) _topBar.Alpha = a;
            if (_bottomBar is not null) _bottomBar.Alpha = a;
        }
        catch { }
    }

    // 退出动画
    private void SetBarTx(float dx)
    {
        try
        {
            if (_topBar is not null) _topBar.TranslationX = dx;
            if (_bottomBar is not null) _bottomBar.TranslationX = dx;
        }
        catch { }
    }

    private void ApplyBarState()
    {
        float a = _barsVisible ? 1f : 0f;
        var st = _barsVisible
            ? global::Android.Views.ViewStates.Visible
            : global::Android.Views.ViewStates.Invisible;
        try
        {
            if (_topBar is not null) { _topBar.Alpha = a; _topBar.Visibility = st; }
            if (_bottomBar is not null) { _bottomBar.Alpha = a; _bottomBar.Visibility = st; }
        }
        catch { }
    }

    // 隐藏时窗口仍
    // 补 NotTouchable 让事件透传回
    private void ApplyBarTouchFlags()
    {
        try
        {
            var wm = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.WindowManager;
            if (wm is null) return;
            var bars = new global::Android.Views.View?[] { _topBar, _bottomBar };
            var lps = new global::Android.Views.WindowManagerLayoutParams?[] { _topLp, _bottomLp };
            for (int i = 0; i < 2; i++)
            {
                var v = bars[i];
                var lp = lps[i];
                if (v is null || lp is null) continue;
                var f = lp.Flags;
                var want = _barsVisible
                    ? f & ~global::Android.Views.WindowManagerFlags.NotTouchable
                    : f | global::Android.Views.WindowManagerFlags.NotTouchable;
                if (want == f) continue;
                lp.Flags = want;
                wm.UpdateViewLayout(v, lp);
            }
        }
        catch { }
    }

    // 沉浸式
    private void ShowBars(bool vis, bool animate = true)
    {
        var old = _barAnim;
        _barAnim = null;
        if (old is not null) { try { old.Cancel(); } catch { } }
        _barsVisible = vis;
        ApplyBarTouchFlags();
        if (_topBar is null) return;
        if (!animate) { ApplyBarState(); return; }
        float to = vis ? 1f : 0f;
        float from = -1f;
        try { from = _topBar.Alpha; } catch { }
        if (from < 0f) from = vis ? 0f : 1f;
        if (vis)
        {
            try
            {
                _topBar.Visibility = global::Android.Views.ViewStates.Visible;
                if (_bottomBar is not null) _bottomBar.Visibility = global::Android.Views.ViewStates.Visible;
            }
            catch { }
        }
        var a = global::Android.Animation.ValueAnimator.OfFloat(from, to);
        a.SetDuration(200);
        a.Update += (s, e) =>
        {
            if (!ReferenceEquals(_barAnim, a)) return;
            SetBarAlpha(from + (to - from) * a.AnimatedFraction);
        };
        a.AnimationEnd += (s, e) =>
        {
            if (!ReferenceEquals(_barAnim, a)) return;
            _barAnim = null;
            ApplyBarState();
        };
        _barAnim = a;
        a.Start();
    }

    private void ToggleBars() => ShowBars(!_barsVisible);

    private void RemoveBars()
    {
        if (_warnTcs is not null)
        {
            var w = _warnTcs;
            _warnTcs = null;
            try { Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.WindowManager?.RemoveView(_warnView); } catch { }
            _warnView = null; _warnLp = null;
            w.TrySetResult(false);
        }
        var old = _barAnim;
        _barAnim = null;
        if (old is not null) { try { old.Cancel(); } catch { } }
        var wm = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.WindowManager;
        foreach (var v in new global::Android.Views.View?[] { _topBar, _bottomBar })
        {
            if (v is null) continue;
            try { wm?.RemoveView(v); } catch { }
        }
        _topBar = _bottomBar = null;
        _topLp = _bottomLp = null;
        _tvName = _tvMeta = _tvPage = null;
        _ivBack = _ivCheck = _ivExport = null;
        foreach (var b in new[] { _iconBack, _iconExport, _iconCur })
            if (b is not null) { try { if (!b.IsRecycled) b.Recycle(); } catch { } }
        _iconBack = _iconExport = _iconCur = null;
    }

    // 图片窗口每次挂
    private void OnOverlayMounted()
    {
        var top = _topBar;
        var bottom = _bottomBar;
        if (top is null || bottom is null || _topLp is null || _bottomLp is null) return;
        try
        {
            var wm = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.WindowManager;
            if (wm is null) return;
            try { wm.RemoveView(top); } catch { }
            try { wm.RemoveView(bottom); } catch { }
            wm.AddView(top, _topLp);
            wm.AddView(bottom, _bottomLp);
            if (_warnView is not null && _warnLp is not null)
            {
                try { wm.RemoveView(_warnView); } catch { }
                wm.AddView(_warnView, _warnLp);
            }
            ApplyBarState();
        }
        catch (Exception ex) { NativeImageHost.Log($"BarsRe fail {ex.Message}"); }
    }

    private void OnBarBack(object? s, EventArgs e)
    {
        if (_closing || _flying) return;
        if (IsZoomed()) { ResetZoomForBack(); return; }
        _ = ExitWithUiAsync();
    }

    // 对接列表多选
    private void OnBarCheck(object? s, EventArgs e)
    {
        var item = _g[1]?.Item;
        if (item is null) return;
        Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
        {
            item.IsSelected = !item.IsSelected;
            ApplyCheckIcon();
        });
    }

    private void OnBarExport(object? s, EventArgs e) => _ = ExportCurrentAsync();

    // 导出安全警告
    private Task<bool> ConfirmExportAsync()
    {
        var tcs = new TaskCompletionSource<bool>();
        try
        {
            var act = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
            var wm = act?.WindowManager;
            if (act is null || wm is null) { tcs.SetResult(true); return tcs.Task; }
            int pad = (int)(18 * _density);
            var box = new global::Android.Widget.LinearLayout(act)
            { Orientation = global::Android.Widget.Orientation.Vertical };
            box.SetBackgroundColor(global::Android.Graphics.Color.ParseColor("#F01B2027"));
            box.SetPadding(pad, pad, pad, pad);
            var tv = new global::Android.Widget.TextView(act) { TextSize = 14 };
            tv.Text = L10n.T("将在公共目录生成明文副本，用完请删除。继续？");
            tv.SetTextColor(global::Android.Graphics.Color.White);
            box.AddView(tv, new global::Android.Widget.LinearLayout.LayoutParams(
                global::Android.Views.ViewGroup.LayoutParams.MatchParent,
                global::Android.Views.ViewGroup.LayoutParams.WrapContent));
            var row = new global::Android.Widget.LinearLayout(act)
            { Orientation = global::Android.Widget.Orientation.Horizontal };
            row.SetGravity(global::Android.Views.GravityFlags.End);
            var cancel = new global::Android.Widget.Button(act) { Text = L10n.T("取消") };
            var ok = new global::Android.Widget.Button(act) { Text = L10n.T("继续导出") };
            cancel.SetTextColor(global::Android.Graphics.Color.White);
            ok.SetTextColor(global::Android.Graphics.Color.White);
            void Finish(bool yes)
            {
                if (_warnTcs is null) return;
                _warnTcs = null;
                try { wm.RemoveView(box); } catch { }
                _warnView = null; _warnLp = null;
                tcs.TrySetResult(yes);
            }
            cancel.Click += (s2, e2) => Finish(false);
            ok.Click += (s2, e2) => Finish(true);
            var lpBtnW = () => new global::Android.Widget.LinearLayout.LayoutParams(
                global::Android.Views.ViewGroup.LayoutParams.WrapContent,
                global::Android.Views.ViewGroup.LayoutParams.WrapContent);
            row.AddView(cancel, lpBtnW());
            row.AddView(ok, lpBtnW());
            box.AddView(row, new global::Android.Widget.LinearLayout.LayoutParams(
                global::Android.Views.ViewGroup.LayoutParams.MatchParent,
                global::Android.Views.ViewGroup.LayoutParams.WrapContent));
            var lp = BarLp(global::Android.Views.GravityFlags.Center);
            lp.Width = (int)(310 * _density);
            wm.AddView(box, lp);
            _warnView = box; _warnLp = lp; _warnTcs = tcs;
        }
        catch { tcs.TrySetResult(true); }
        return tcs.Task;
    }

    // 导出当前图
    private async Task ExportCurrentAsync()
    {
        var item = _g[1]?.Item;
        if (item is null || _exporting) return;
        // 导出
        if (!await ConfirmExportAsync().ConfigureAwait(true)) return;
        _exporting = true;
        VaultService.BeginLongOp();
        try
        {
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
            Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(
                () => { _exportHint = L10n.T("导出中…"); ApplyBarText(); });
            try { await Task.Run(() => _vault.ExportFd(item.RelPath, fd, null)); }
            finally { LibcNative.close(fd); }
            ShowToast(L10n.F("已导出到：{0}\n结果是明文，用完请删除。", dst));
        }
        catch (Exception ex) { ShowToast(L10n.F("导出失败：{0}", ex.Message)); }
        finally
        {
            _exportHint = "";
            Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(ApplyBarText);
            VaultService.EndLongOp();
            _exporting = false;
        }
    }

    private static void ShowToast(string text)
    {
        try
        {
            global::Android.Widget.Toast.MakeText(
                Microsoft.Maui.ApplicationModel.Platform.CurrentActivity,
                text, global::Android.Widget.ToastLength.Long)?.Show();
        }
        catch { }
    }

    // 入场
    private void EntryFly()
    {
        try
        {
            var root = Handler?.PlatformView as global::Android.Views.View;
            if (root is null || _pageWpx <= 0) return;
            _flying = true;
            HideEntryNeighbors(true);
            var a = global::Android.Animation.ValueAnimator.OfFloat(0f, 1f);
            a.SetDuration(310);
            a.SetInterpolator(new global::Android.Views.Animations.DecelerateInterpolator(1.5f));
            a.Update += (s, e) =>
            {
                float dx = (1f - a.AnimatedFraction) * _pageWpx;
                root.TranslationX = dx;
                for (int i = 0; i < 3; i++) _cellHosts[i]?.NudgeTo(dx);
            };
            a.AnimationEnd += (s, e) =>
            {
                _flying = false;
                root.TranslationX = 0f;
                for (int i = 0; i < 3; i++) _cellHosts[i]?.NudgeTo(0f);
                HideEntryNeighbors(false);
                // 入场期间上树
                root.Post(() => { for (int i = 0; i < 3; i++) _cellHosts[i]?.Reposition(); });
            };
            a.Start();
        }
        catch { _flying = false; HideEntryNeighbors(false); }
    }

    // 入场只让当前格
    // 划入起点整屏
    private void HideEntryNeighbors(bool on)
    {
        if (_closing || _cellLoaders[0] is null) return;
        for (int i = 0; i < 3; i += 2)
        {
            _cellLoaders[i].Opacity = on ? 0 : 1;
            _cellErrs[i].Opacity = on ? 0 : 1;
            _cellHosts[i]?.SetEntryHidden(on);
        }
    }

    // pop 前抓整页 UI
    private void CaptureUiBackdrop()
    {
        try
        {
            var act = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
            var decor = act?.Window?.DecorView;
            if (decor is null || decor.Width <= 0 || decor.Height <= 0) return;
            global::Android.Graphics.Bitmap? bmp = null;
            try
            {
                bmp = global::Android.Graphics.Bitmap.CreateBitmap(
                    decor.Width, decor.Height, global::Android.Graphics.Bitmap.Config.Argb8888!);
            }
            catch { }
            if (bmp is null)
            {
                try
                {
                    bmp = global::Android.Graphics.Bitmap.CreateBitmap(
                        decor.Width, decor.Height, global::Android.Graphics.Bitmap.Config.Rgb565!);
                }
                catch { }
            }
            if (bmp is null) return;
            decor.Draw(new global::Android.Graphics.Canvas(bmp));
            _cellHosts[1]?.SetBackdrop(bmp);
        }
        catch (Exception ex) { NativeImageHost.Log($"UiSnap fail {ex.Message}"); }
    }

    // 退出
    // 动画期间背景
    public async Task ExitWithUiAsync()
    {
        if (_closing) return;
        _closing = true;
        _dragging = false;
        _anim?.Cancel();
        // 相邻两格清空
        DropSlotCache(0);
        DropSlotCache(2);
        CaptureUiBackdrop();
        // pop 会触发 OnDisappearing /
        // 三者
        foreach (var h in _cellHosts) h?.BeginExit();
        bool popped = false;
        try { await Navigation.PopAsync(false); popped = true; }
        catch { }
        if (!popped)
        {
            // 栈异常
            RemoveBars();
            foreach (var h in _cellHosts) h?.Disable();
            NativeImageHost.OverlayMounted -= OnOverlayMounted;
            return;
        }
        // 等一帧
        try { await Task.Delay(16); } catch { }
        try
        {
            if (_pageWpx > 0)
            {
                var tcs = new TaskCompletionSource();
                var a = global::Android.Animation.ValueAnimator.OfFloat(0f, 1f);
                a.SetDuration(300);
                a.SetInterpolator(new global::Android.Views.Animations.AccelerateInterpolator(1f));
                a.Update += (s, e) =>
                {
                    float dx = a.AnimatedFraction * _pageWpx;
                    // 视口
                    _cellHosts[1]?.ExitFrame(dx, 1f);
                    SetBarTx(dx);
                };
                a.AnimationEnd += (s, e) => tcs.TrySetResult();
                a.Start();
                await tcs.Task;
            }
        }
        catch { }
        RemoveBars();
        foreach (var h in _cellHosts) h?.Disable();
        NativeImageHost.OverlayMounted -= OnOverlayMounted;
    }

    // 一次只上屏高清
    // 大图
    // 小图一次合成即
    private void LoadOne(GalleryImage g, int slot)
    {
        if (g.Item is null) return;
        string resKey = g.Item.RelPath;
        int gen = _slotGen[slot];
        _ = Task.Run(async () =>
        {
            if (slot != 1) { try { await Task.Delay(60); } catch { } }   // 相邻格让路
            string? reason = null;
            string? path = ThumbnailHelper.BuildView(_vault, g.Item, out reason);
            bool fullPath = path is not null;
            bool small = (long)g.Item.Size <= DirectBytes;
            if (path is null) path = ThumbnailHelper.Build(_vault, g.Item);   // 解密失败退缩略
            try { global::Android.Util.Log.Warn(MainApplication.TagCore, $"FullPath slot={slot} gen={gen} f={NativeImageHost.Tag(path)} reason={reason}"); } catch { }
            if (fullPath && path is not null)
            {
                try
                {
                    var bo = new Android.Graphics.BitmapFactory.Options { InJustDecodeBounds = true };
                    Android.Graphics.BitmapFactory.DecodeFile(path, bo);
                    int w = bo.OutWidth, h = bo.OutHeight;
                    if (w > 0 && h > 0)
                    {
                        string res = $"{w}×{h}";
                        MainThread.BeginInvokeOnMainThread(() =>
                        {
                            _resByPath[resKey] = res;
                            // 预载格
                            var cur = _g[1]?.Item;
                            if (_active && !_closing && cur is not null && cur.RelPath == resKey)
                                SetMetaResolution(w, h);
                        });
                    }
                }
                catch { }
            }
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (!_active || _closing || _slotGen[slot] != gen) return;
                if (path is not null)
                    ShowCellImage(slot, path, gen, full: fullPath,
                        progressive: fullPath && !small);
                else { g.Error = true; g.Loading = false; }
            });
        });
    }

    // 解码文件并
    // 根因
    // 用原生 ImageView 宿主直接
    private void ShowCellImage(int slot, string path, int gen,
        bool full = false, bool final = true, int stage = 3, bool progressive = false,
        Android.Graphics.Bitmap? carried = null, int startY = 0)
    {
        if (progressive)
        {
            // 首带解码/大 Bitmap 分配
            _cellBandsPending[slot] = true;
            _bandPath[slot] = path;
            _bandNextY[slot] = startY;
            _ = Task.Run(async () => await RenderBands(slot, path, gen, carried, startY));
            return;
        }
        _ = Task.Run(() =>
        {
            Android.Graphics.Bitmap? bmp = DecodeFile(path, ViewMaxSide);
            if (bmp is null && full)
            {
                // 全图解码失败
                string? tp = _g[slot]?.ThumbPath;
                if (!string.IsNullOrEmpty(tp)) bmp = DecodeFile(tp, 0);
                if (bmp is not null) full = false;
            }
            if (bmp is null)
            {
                try { global::Android.Util.Log.Warn(MainApplication.TagCore, L10n.F("CustomImage: 解码空 slot={0} gen={1} f={2}", slot, gen, NativeImageHost.Tag(path))); } catch { }
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    if (_active && _slotGen[slot] == gen) { _g[slot].Error = true; _g[slot].Loading = false; }
                });
                return;
            }
            MainThread.BeginInvokeOnMainThread(() =>
            {
                // 代际守卫
                if (_closing || _slotGen[slot] != gen) { bmp.Recycle(); return; }
                // MT 风格保险
                // 强制重产出标准
                Android.Graphics.Bitmap? safe = null;
                try { safe = Android.Graphics.Bitmap.CreateScaledBitmap(bmp, bmp.Width, bmp.Height, false); } catch { }
                if (safe is not null && safe.Handle != bmp.Handle) { bmp.Recycle(); bmp = safe; }
                // 同格同代只允许
                if (_cellStage[slot] >= stage) { bmp.Recycle(); return; }
                _cellStage[slot] = stage;
                _cellFull[slot] = full;
                _cellHosts[slot]?.Show(bmp);
                if (final) _g[slot].Loading = false;   // 高清上屏才收转
            });
        });
    }

    // 大图逐带渲染
    // 首帧先画好第一
    // 同一个 mutable Bitmap 只
    // carried/startY
    private async Task RenderBands(int slot, string path, int gen,
        Android.Graphics.Bitmap? carried = null, int startY = 0)
    {
        Android.Graphics.Bitmap? owned = null;   // 本方法创建
        try
        {
            var b = new Android.Graphics.BitmapFactory.Options { InJustDecodeBounds = true };
            Android.Graphics.BitmapFactory.DecodeFile(path, b);
            int sw = b.OutWidth, sh = b.OutHeight;
            if (sw <= 0 || sh <= 0) { FallbackDecode(slot, path, gen); return; }

            double k = Math.Min(1.0, (double)ViewMaxSide / Math.Max(sw, sh));
            int tw = Math.Max(1, (int)Math.Round(sw * k));
            int th = Math.Max(1, (int)Math.Round(sh * k));
            Android.Graphics.Bitmap surface;
            if (carried is not null && !carried.IsRecycled)
            {
                surface = carried;   // 沿用已画好
            }
            else
            {
                surface = Android.Graphics.Bitmap.CreateBitmap(
                    tw, th, Android.Graphics.Bitmap.Config.Argb8888!);
                if (surface is null) { FallbackDecode(slot, path, gen); return; }
                owned = surface;
                using (var c0 = new Android.Graphics.Canvas(surface))
                    c0.DrawColor(global::Android.Graphics.Color.Black);
            }

            using var dec = global::Android.Graphics.BitmapRegionDecoder.NewInstance(path, false);
            if (dec is null) { FallbackDecode(slot, path, gen); return; }
            using var canvas = new Android.Graphics.Canvas(surface);
            using var paint = new global::Android.Graphics.Paint(
                global::Android.Graphics.PaintFlags.FilterBitmap);
            const int bands = 16;
            int srcBand = Math.Max(1, (sh + bands - 1) / bands);
            int sample = 1;
            while (sample < 8 && (long)(sw / sample) * (srcBand / sample) > 8L * 1024 * 1024)
                sample *= 2;

            int nextY;
            if (startY <= 0)
            {
                // 首带画完
                if (!await DrawBandAsync(slot, gen, canvas, paint, dec,
                        sw, sh, tw, th, 0, srcBand, sample)) return;
                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    if (!_active || _closing || _slotGen[slot] != gen || _cellStage[slot] >= 3) return;
                    _cellStage[slot] = 3;
                    _cellFull[slot] = true;
                    _cellHosts[slot]?.Show(surface);
                    _g[slot].Loading = false;
                    owned = null;   // 位图交
                });
                if (owned is not null) return;   // 代际变
                nextY = srcBand;
            }
            else nextY = startY;

            for (int y0 = nextY; y0 < sh; y0 += srcBand)
            {
                if (!_active || _closing || _slotGen[slot] != gen) return;
                if (!await DrawBandAsync(slot, gen, canvas, paint, dec,
                        sw, sh, tw, th, y0, srcBand, sample)) return;
                _bandNextY[slot] = y0 + srcBand;
                await Task.Delay(16);
            }
            _bandNextY[slot] = -1;
        }
        catch (Exception ex)
        {
            try { global::Android.Util.Log.Warn(MainApplication.TagCore, $"Bands fail slot={slot} {ex.Message}"); } catch { }
            if (_cellStage[slot] < 3) FallbackDecode(slot, path, gen);
        }
        finally
        {
            if (_slotGen[slot] == gen)
            {
                _cellBandsPending[slot] = false;
                _bandNextY[slot] = -1;
                _bandPath[slot] = null;
            }
            if (owned is not null)
                try { if (!owned.IsRecycled) owned.Recycle(); } catch { }
        }
    }

    private async Task<bool> DrawBandAsync(int slot, int gen,
        Android.Graphics.Canvas canvas, global::Android.Graphics.Paint paint,
        global::Android.Graphics.BitmapRegionDecoder dec,
        int sw, int sh, int tw, int th, int y0, int bandH, int sample)
    {
        int y1 = Math.Min(sh, y0 + bandH);
        if (y1 <= y0) return true;
        var rect = new global::Android.Graphics.Rect(0, y0, sw, y1);
        var opt = new Android.Graphics.BitmapFactory.Options { InSampleSize = sample };
        using var strip = dec.DecodeRegion(rect, opt);
        if (strip is null) return false;
        int dy0 = (int)Math.Round((double)y0 * th / sh);
        int dy1 = Math.Min(th, Math.Max(dy0 + 1, (int)Math.Round((double)y1 * th / sh)));
        var dst = new global::Android.Graphics.Rect(0, dy0, tw, dy1);
        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            if (_closing || _slotGen[slot] != gen || strip.IsRecycled) return;
            try
            {
                canvas.DrawBitmap(strip, null, dst, paint);
                _cellHosts[slot]?.PostInvalidateImage();
            }
            catch { }
        });
        return _slotGen[slot] == gen;
    }

    private void FallbackDecode(int slot, string path, int gen) =>
        ShowCellImage(slot, path, gen, full: true);

    // 全图解码上限
    // 超大图
    private static int ViewMaxSide
    {
        get
        {
            try
            {
                var dm = Android.App.Application.Context!.Resources!.DisplayMetrics!;
                return Math.Max(dm.WidthPixels, dm.HeightPixels);
            }
            catch { return 2728; }
        }
    }

    // BitmapFactory 直接解码
    private static Android.Graphics.Bitmap? DecodeFile(string path, int maxSide = 0)
    {
        try
        {
            var o = new Android.Graphics.BitmapFactory.Options { InJustDecodeBounds = true };
            Android.Graphics.BitmapFactory.DecodeFile(path, o);
            if (o.OutWidth <= 0 || o.OutHeight <= 0)
            {
                try { global::Android.Util.Log.Warn(MainApplication.TagCore, L10n.F("CustomImage: 头坏 f={0} {1}x{2}", NativeImageHost.Tag(path), o.OutWidth, o.OutHeight)); } catch { }
                return null;
            }
            // 目标采样率
            int s = 1, longest = Math.Max(o.OutWidth, o.OutHeight);
            if (maxSide > 0 && longest > maxSide)
                s = (int)System.Math.Ceiling((double)longest / maxSide);
            if (s < 1) s = 1;
            if (s > 32) s = 32;
            var bmp = Android.Graphics.BitmapFactory.DecodeFile(path,
                new Android.Graphics.BitmapFactory.Options { InSampleSize = s });
            if (bmp is null)
                try { global::Android.Util.Log.Warn(MainApplication.TagCore, L10n.F("CustomImage: DecodeFile 空 f={0}", NativeImageHost.Tag(path))); } catch { }
            return bmp;
        }
        catch (Exception ex)
        {
            try { global::Android.Util.Log.Warn(MainApplication.TagCore, L10n.F("CustomImage: DecodeFile 异常 f={0} → {1}", NativeImageHost.Tag(path), ex.Message)); } catch { }
            return null;
        }
    }

    // 程序退到后台
    public static void CloseIfOpen()
    {
        try
        {
            var nav = Shell.Current?.CurrentPage?.Navigation;
            var stack = nav?.NavigationStack;
            if (stack is null || stack.Count == 0) return;
            if (stack[^1] is not ImageViewerPage) return;
            MainThread.BeginInvokeOnMainThread(() =>
            {
                try { _ = nav!.PopAsync(false); } catch { }
            });
        }
        catch { }
    }

    // 全局平移
    private void ApplyTx(double txPx)
    {
        _txPx = (float)txPx;
        if (_pagerView is null)
        {
            try { _pagerView = Pages.Handler?.PlatformView as global::Android.Views.View; } catch { }
            NativeImageHost.Log($"PagerView {( _pagerView is not null ? "OK" : "兜底MAUI" )}");
            if (_pagerView is not null) AttachProbes(_pagerView);
        }
        if (_pagerView is not null)
            _pagerView.TranslationX = _txPx;
        else
            Pages.TranslationX = txPx / _density;   // 平台视图未
        for (int i = 0; i < 3; i++)
            _cellHosts[i]?.FollowPanTo(_txPx);
    }

    // 手势接管挂载
    // 探针定位结论
    // PagerTouchListener 必须字段强引用
    private PagerTouchListener? _pagerTouch;

    private void AttachProbes(global::Android.Views.View pagerView)
    {
        try
        {
            var clip = pagerView.Parent as global::Android.Views.View;
            if (clip is not null)
            {
                _pagerTouch = new PagerTouchListener(this);
                clip.SetOnTouchListener(_pagerTouch);
            }
        }
        catch { }
    }

    // 吸附动画
    private void StartSnap(double toTx, float ms, int? landing = null)
    {
        _anim?.Cancel();
        _animating = true;
        float from = _txPx, to = (float)toTx;
        var a = global::Android.Animation.ValueAnimator.OfFloat(from, to);
        a.SetDuration((long)ms);
        a.SetInterpolator(new global::Android.Views.Animations.DecelerateInterpolator(2f));
        // cancel 也会触发 AnimationEnd：置标志
        bool cancelled = false;
        a.AnimationCancel += (s, e) => cancelled = true;
        // AnimatedFraction 是插值后进度，避
        a.Update += (s, e) => ApplyTx(from + (to - from) * a.AnimatedFraction);
        a.AnimationEnd += (s, e) =>
        {
            if (cancelled) return;
            _animating = false;
            _anim = null;
            if (landing is int t && t != _index)
            {
                AdvanceTo(t);
                return;
            }
            ApplyTx(-_pageWpx);   // 回弹/未翻页
        };
        _anim = a;
        a.Start();
    }

    // 翻页转移
    private void AdvanceTo(int target)
    {
        for (int i = 0; i < 3; i++) _cellHosts[i]?.ResetZoom();
        bool left = target > _index;
        int[] map = left ? new[] { 1, 2, -1 } : new[] { -1, 0, 1 };
        var carried = new Android.Graphics.Bitmap?[3];
        var carriedFull = new bool[3];
        var carriedPartial = new bool[3];
        var carriedNextY = new int[3];
        var carriedPath = new string?[3];
        for (int ns = 0; ns < 3; ns++)
        {
            int os = map[ns];
            if (os >= 0)
            {
                var bmp = _cellHosts[os]?.DetachBitmap();
                // 逐带未画完
                bool pending = _cellBandsPending[os] && bmp is not null;
                carried[ns] = bmp;
                carriedPartial[ns] = pending;
                carriedNextY[ns] = pending ? Math.Max(0, _bandNextY[os]) : 0;
                carriedPath[ns] = pending ? _bandPath[os] : null;
                carriedFull[ns] = !_cellBandsPending[os] && _cellFull[os];
                _cellFull[os] = false;
            }
        }
        // 被划走那张落
        int goneSlot = left ? 0 : 2;
        if (carried[goneSlot] is not null)
        {
            try { carried[goneSlot]!.Recycle(); } catch { }
            carried[goneSlot] = null;
        }
        carriedFull[goneSlot] = false;
        carriedPartial[goneSlot] = false;
        // skipLoad
        AssignSlot(0, target - 1, carried[0], carriedFull[0], goneSlot == 0,
            carriedPartial[0], carriedNextY[0], carriedPath[0]);
        AssignSlot(1, target, carried[1], carriedFull[1], false,
            carriedPartial[1], carriedNextY[1], carriedPath[1]);
        AssignSlot(2, target + 1, carried[2], carriedFull[2], goneSlot == 2,
            carriedPartial[2], carriedNextY[2], carriedPath[2]);
        DropSlotCache(goneSlot);
        _index = target;
        // 复位窗口 + overlay 归位
        ApplyTx(-_pageWpx);
        UpdateInfo(_g[1]);
        ApplyCheckIcon();        // 换图后同步外面
        // 隐藏态翻页不自
    }

    // 原生手势回调
    public bool OnPagerDown()
    {
        if (_animating || _flying || _closing || IsZoomed() || _pageWpx <= 0)
        {
            NativeImageHost.Log(L10n.F("PagerDn 拒绝 anim={0} fly={1} close={2} n={3} pw={4:F0}", _animating, _flying, _closing, _imgs.Count, _pageWpx));
            return false;
        }
        _dragging = true;
        _dragBase = _txPx;
        _moveLogged = false;
        _anim?.Cancel();
        return true;
    }

    public void OnPagerMove(float dxPx)
    {
        if (!_dragging) return;
        if (_imgs.Count <= 1) return;   // 单图仍可点
        if (!_moveLogged)
        {
            _moveLogged = true;
            NativeImageHost.Log($"Move1 dx={dxPx:F0} base={_dragBase:F0}");
        }
        double nx = _dragBase + dxPx;
        double minX = -(double)(_imgs.Count - 1) * _pageWpx;
        if (nx > 0) nx = 0;                 // 首页不能
        if (nx < minX) nx = minX;           // 末页不能
        ApplyTx(nx);
    }

    public void OnPagerUp(float velPx, long dtMs, float downX, float upX)
    {
        if (!_dragging) return;
        _dragging = false;
        // 边缘返回手势二
        if (NativeImageHost.InEdgeGestureZone(downX))
        {
            NativeImageHost.Log($"Up edge guard down={downX:F0} up={upX:F0}");
            StartSnap(-_pageWpx, BackMs);
            return;
        }
        double disp = _txPx + _pageWpx;     // 距居
        if (Math.Abs(disp) < TapMovePx && dtMs < TapMs)
        {
            // 视为点
            OnImageTapped(this, EventArgs.Empty);
            StartSnap(-_pageWpx, BackMs);
            return;
        }
        double threshold = _pageWpx * SnapFraction;
        double flick = FlickVelDp * _density;
        int target = _index;
        if (disp <= -threshold) target = _index + 1;          // 左拖 → 下一张
        else if (disp >= threshold) target = _index - 1;      // 右拖 → 上一张
        else if (Math.Abs(disp) >= MinFlickDp * _density && velPx <= -flick) target = _index + 1;
        else if (Math.Abs(disp) >= MinFlickDp * _density && velPx >= flick) target = _index - 1;
        target = Math.Clamp(target, 0, _imgs.Count - 1);
        NativeImageHost.Log($"Up disp={disp:F0} vel={velPx:F0} target={target}");
        double targetTx = -_pageWpx;
        if (target == _index + 1) targetTx = -2 * _pageWpx;
        else if (target == _index - 1) targetTx = 0;
        StartSnap(targetTx, SnapMs, landing: target != _index ? target : null);
    }

    public void OnPagerCancel()
    {
        if (!_dragging) return;
        _dragging = false;
        StartSnap(-_pageWpx, BackMs);
    }

    // 缩放只作用当
    public bool IsZoomed() => _cellHosts[1]?.Zoomed == true;
    public void OnZoomBy(float f, float x, float y) => _cellHosts[1]?.ZoomBy(f, x, y);
    public float OnZoomPan(float dx, float dy) => _cellHosts[1]?.PanBy(dx, dy) ?? 0f;

    // 放大态拖到边界
    public void OnZoomEdgePage(int dir)
    {
        if (_animating || _flying || _closing || _imgs.Count <= 1 || _pageWpx <= 0) return;
        int target = Math.Clamp(_index + dir, 0, _imgs.Count - 1);
        if (target == _index) return;
        StartSnap(target > _index ? -2 * _pageWpx : 0, SnapMs, landing: target);
    }

    // 放大态返回键
    public void ResetZoomForBack() => _cellHosts[1]?.ResetZoomAnimated();

    private void OnImageTapped(object? sender, EventArgs e) => ToggleBars();

    // 纯点
    public void OnPagerTap()
    {
        OnPagerCancel();   // 复位 _dragging 并回弹
        ToggleBars();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        Microsoft.Maui.Controls.Shell.SetNavBarIsVisible(this, false);
        Microsoft.Maui.Controls.Shell.SetTabBarIsVisible(this, false);
        if (!_purgedOnLeave || !_laidOut || _closing) return;
        _active = true;
        _purgedOnLeave = false;
        AssignSlot(0, _index - 1);
        AssignSlot(1, _index);
        AssignSlot(2, _index + 1);
        UpdateInfo(_g[1]);
        CreateBars();
        ApplyCheckIcon();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        // 退出流程
        if (_closing) return;
        _active = false;          // 页面已分离
        _anim?.Cancel();
        NativeImageHost.OverlayMounted -= OnOverlayMounted;
        RemoveBars();
        PurgeAllOnLeave();
    }

    // 作废
    private void DropSlotCache(int slot)
    {
        _slotGen[slot]++;
        _cellBandsPending[slot] = false;
        _bandNextY[slot] = -1;
        _bandPath[slot] = null;
        _cellStage[slot] = 0;
        _cellFull[slot] = false;
        _cellHosts[slot]?.Clear();
        _g[slot].Loading = false;
    }

    // 退出 / 切 Tab / 退后台
    private void PurgeAllOnLeave()
    {
        for (int i = 0; i < 3; i++) DropSlotCache(i);
        _purgedOnLeave = true;
    }
}
