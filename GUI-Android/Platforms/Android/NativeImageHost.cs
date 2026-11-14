// 画廊单图宿主
// 根因
// R28
// 混用导致 overlay 位移只
// pager 与 overlay 同帧
// 注意
using Android.Graphics;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Handlers;

namespace FileEncryptorMobile.Platforms.Android;

// 原生手势回调
public interface IPagerTouchSink
{
    // 返回 false 表示不接管
    bool OnPagerDown();
    void OnPagerMove(float dxPx);
    void OnPagerUp(float velPxPerSec, long dtMs, float downX, float upX);
    void OnPagerCancel();
    // 纯点
    void OnPagerTap();
    // 缩放
    bool IsZoomed();
    void OnZoomBy(float factor, float focusX, float focusY);
    // 返回水平方向未
    float OnZoomPan(float dxPx, float dyPx);
    void OnZoomEdgePage(int dir);
}

// 画廊触摸接管器
// R29 定位
// ClipBox/Viewport 层且无人消费即
// 。此处返回 true 即接管
// 并请求父容器禁
public sealed class PagerTouchListener : Java.Lang.Object, global::Android.Views.View.IOnTouchListener
{
    private readonly IPagerTouchSink _sink;
    private global::Android.Views.VelocityTracker? _vt;
    private float _downX, _downY;
    private long _downAt;
    private bool _taken;
    // 缩放序列
    private bool _zooming, _zoomPan;
    private float _span, _cx, _cy, _panX, _panY;
    private bool _activated, _edgePaged, _edgeBlocked, _seqDown;
    private float _edgeDx;

    public PagerTouchListener(IPagerTouchSink sink) { _sink = sink; }
    public PagerTouchListener(IntPtr h, global::Android.Runtime.JniHandleOwnership o) : base(h, o) { }

    private static float Span(global::Android.Views.MotionEvent e)
    {
        float dx = e.GetX(0) - e.GetX(1), dy = e.GetY(0) - e.GetY(1);
        return (float)global::System.Math.Sqrt(dx * dx + dy * dy);
    }
    private static float Cx(global::Android.Views.MotionEvent e) => (e.GetX(0) + e.GetX(1)) * 0.5f;
    private static float Cy(global::Android.Views.MotionEvent e) => (e.GetY(0) + e.GetY(1)) * 0.5f;
    // 视图相对坐标转
    private static float Sx(global::Android.Views.MotionEvent e, float x) => x + e.RawX - e.GetX(0);
    private static float Sy(global::Android.Views.MotionEvent e, float y) => y + e.RawY - e.GetY(0);

    // 放弃本次拖动
    private void ReleasePager(global::Android.Views.View? v)
    {
        if (_taken) _sink.OnPagerCancel();
        _taken = false;
        _vt?.Recycle(); _vt = null;
        v?.Parent?.RequestDisallowInterceptTouchEvent(false);
    }

    public bool OnTouch(global::Android.Views.View? v, global::Android.Views.MotionEvent? e)
    {
        if (e is null) return false;
        switch (e.ActionMasked)
        {
            case global::Android.Views.MotionEventActions.Down:
                // 系统边缘手势
                _taken = _zooming = _zoomPan = _activated = _edgePaged = false;
                _edgeBlocked = _seqDown = false;
                _edgeDx = 0;
                _vt?.Recycle(); _vt = null;
                // 归属只
                if (NativeImageHost.InEdgeGestureZone(e.RawX, v))
                {
                    _edgeBlocked = true;
                    NativeImageHost.Log("TouchDn edge skip");
                    return false;
                }
                _seqDown = true;   // 本序列确已收到 DOWN
                if (_sink.IsZoomed())
                {
                    _zoomPan = true;
                    _panX = e.GetX(0); _panY = e.GetY(0);
                    return true;   // 不提前禁止拦截
                }
                _taken = _sink.OnPagerDown();
                NativeImageHost.Log($"TouchDn take={_taken}");
                if (!_taken) return false;
                _vt = global::Android.Views.VelocityTracker.Obtain();
                _vt.AddMovement(e);
                _downX = e.RawX;
                _downY = e.RawY;
                _downAt = e.EventTime;
                return true;

            case global::Android.Views.MotionEventActions.PointerDown:
                if (!_seqDown || _edgeBlocked) return false;
                if (e.PointerCount == 2)
                {
                    if (_taken || _zoomPan)
                    {
                        _sink.OnPagerCancel();
                        _taken = false;
                        _vt?.Recycle(); _vt = null;
                    }
                    _zoomPan = false;
                    _zooming = true;
                    _span = Span(e); _cx = Cx(e); _cy = Cy(e);
                    v?.Parent?.RequestDisallowInterceptTouchEvent(true);
                    return true;
                }
                return _taken || _zooming || _zoomPan;

            case global::Android.Views.MotionEventActions.Move:
                if (!_seqDown || _edgeBlocked) return false;
                // 起点
                if (NativeImageHost.InEdgeGestureZone(_downX)) { ReleasePager(v); return false; }
                if (_zooming && e.PointerCount >= 2)
                {
                    float sp = Span(e);
                    float ratio = (sp > 1f && _span > 1f) ? sp / _span : 1f;
                    if (sp > 1f && _span > 1f)
                        _sink.OnZoomBy(ratio, Sx(e, Cx(e)), Sy(e, Cy(e)));
                    _span = sp;
                    float cx = Cx(e), cy = Cy(e);
                    // 捏合时中心自然
                    if (global::System.Math.Abs(ratio - 1f) < 0.008f)
                        _sink.OnZoomPan(cx - _cx, cy - _cy);
                    _cx = cx; _cy = cy;
                    return true;
                }
                if (_zoomPan && e.PointerCount == 1)
                {
                    float px = e.GetX(0), py = e.GetY(0);
                    float ddx = float.IsNaN(_panX) ? 0f : px - _panX;
                    float ddy = float.IsNaN(_panY) ? 0f : py - _panY;
                    _panX = px; _panY = py;
                    // 图片已到边界
                    float rest = _edgePaged ? 0f : _sink.OnZoomPan(ddx, ddy);
                    if (!_edgePaged && rest != 0f)
                    {
                        _edgeDx += rest;
                        if (global::System.Math.Abs(_edgeDx) >= NativeImageHost.EdgePagePx)
                        {
                            _edgePaged = true;
                            v?.Parent?.RequestDisallowInterceptTouchEvent(true);
                            _sink.OnZoomEdgePage(_edgeDx < 0 ? 1 : -1);
                        }
                    }
                    return true;
                }
                if (!_taken || _vt is null) return false;
                _vt.AddMovement(e);
                float dx = e.RawX - _downX, dy = e.RawY - _downY;
                float ax = global::System.Math.Abs(dx), ay = global::System.Math.Abs(dy);
                // 检查当前点是否
                // 旧逻辑
                if (!_activated)
                {
                    if (ax < NativeImageHost.ActivatePx && ay < NativeImageHost.ActivatePx) return true;
                    if (ay > ax * 1.2f) { ReleasePager(v); return false; }
                    _activated = true;
                    // DOWN 不禁止拦截
                    v?.Parent?.RequestDisallowInterceptTouchEvent(true);
                }
                _sink.OnPagerMove(dx);
                return true;

            case global::Android.Views.MotionEventActions.PointerUp:
                if (!_seqDown || _edgeBlocked) return false;
                if (_zooming)
                {
                    _zooming = false;
                    _zoomPan = true;
                    // 双轴失效
                    _panX = _panY = float.NaN;
                }
                return _taken || _zoomPan;

            case global::Android.Views.MotionEventActions.Up:
                // 系统边缘手势吃
                if (!_seqDown || _edgeBlocked)
                {
                    _seqDown = _edgeBlocked = false;
                    return false;
                }
                _seqDown = false;
                if (_zooming || _zoomPan)
                {
                    _zooming = _zoomPan = false;
                    _edgeDx = 0; _edgePaged = false;
                    v?.Parent?.RequestDisallowInterceptTouchEvent(false);
                    return true;
                }
                if (!_taken) return false;
                float velUp = 0f;
                long dtUp = e.EventTime - _downAt;
                if (_vt is not null)
                {
                    _vt.AddMovement(e);
                    _vt.ComputeCurrentVelocity(1000);
                    velUp = _vt.XVelocity;
                    _vt.Recycle();
                    _vt = null;
                }
                bool didActivate = _activated;
                v?.Parent?.RequestDisallowInterceptTouchEvent(false);
                _taken = _activated = false;
                // 未激活说明这次
                if (!didActivate)
                {
                    // 纯点
                    if (dtUp <= 300 &&
                        global::System.Math.Abs(e.RawX - _downX) < 24f &&
                        global::System.Math.Abs(e.RawY - _downY) < 24f)
                    {
                        NativeImageHost.Log("TouchUp tap");
                        _sink.OnPagerTap();
                        return true;
                    }
                    NativeImageHost.Log("TouchUp no-activate");
                    _sink.OnPagerCancel();
                    return true;
                }
                NativeImageHost.Log($"TouchUp vel={velUp:F0} dt={dtUp} dx={e.RawX - _downX:F0}");
                _sink.OnPagerUp(velUp, dtUp, _downX, e.RawX);
                return true;

            case global::Android.Views.MotionEventActions.Cancel:
                _seqDown = _edgeBlocked = false;
                bool any = _taken || _zooming || _zoomPan;
                if (any)
                {
                    NativeImageHost.Log("TouchCx");
                    _vt?.Recycle();
                    _vt = null;
                    if (_taken) _sink.OnPagerCancel();
                    v?.Parent?.RequestDisallowInterceptTouchEvent(false);
                    _taken = _zooming = _zoomPan = _activated = false;
                    _edgeBlocked = false;
                    _edgeDx = 0; _edgePaged = false;
                }
                return any;
            default:
                return _taken || _zooming || _zoomPan;
        }
    }
}

// 占位容器
public sealed class HostBox : global::Android.Widget.FrameLayout
{
    internal Action? OnDetach;

    public HostBox(global::Android.Content.Context c) : base(c) { }

    protected override void OnDetachedFromWindow()
    {
        base.OnDetachedFromWindow();
        OnDetach?.Invoke();
    }
}

// 容器布局变化监
public sealed class BoxListener : Java.Lang.Object, global::Android.Views.View.IOnLayoutChangeListener
{
    private readonly NativeImageHost _h;
    public BoxListener(NativeImageHost h) { _h = h; }
    public BoxListener(IntPtr handle, global::Android.Runtime.JniHandleOwnership o) : base(handle, o) { }
    public void OnLayoutChange(global::Android.Views.View? v, int l, int t, int r, int b,
        int ol, int ot, int orr, int ob) => _h.Reposition();
}

public sealed class NativeImageHost : View
{
    public int Slot { get; set; }
    internal HostBox? PlatformBox { get; private set; }

    private global::Android.Widget.ImageView? _iv;
    private global::Android.Widget.FrameLayout? _overlay;
    // 视口裁剪层
    private global::Android.Widget.FrameLayout? _clip;
    private BoxListener? _listener;
    private Bitmap? _curBmp;
    // 最近一次全局平
    internal float LastTx;
    // 页面级飞入/飞出
    internal float Nudge;
    // 关闭流程置位
    internal bool Disabled;
    // 退出动画期间 pop 已
    private bool _exiting;
    // 入场动画期间相
    private bool _entryHidden;
    // 缩放状态
    private float _zoom = 1f, _panX, _panY;
    // 返回键复位 1x
    private global::Android.Animation.ValueAnimator? _zoomAnim;
    private bool _zoomAnimating;
    // 退出快照层
    private global::Android.Widget.ImageView? _backdrop;
    private Bitmap? _backdropBmp;
    internal bool Zoomed => _zoom > 1.02f;
    // 任一 overlay 窗口挂到
    internal static event Action? OverlayMounted;

    // overlay 状态日志
    internal static void Log(string m)
    {
        try { global::Android.Util.Log.Warn(MainApplication.TagCore, m); } catch { }
    }

    // 日志脱敏
    internal static string Tag(string? name)
    {
        if (string.IsNullOrEmpty(name)) return "-";
        ulong h = 14695981039346656037UL;
        foreach (char c in name) { h ^= c; h *= 1099511628211UL; }
        return "f" + (h & 0xFFFFFFFFUL).ToString("x8");
    }

    // 系统返回手势区
    internal static bool InEdgeGestureZone(float rawX, global::Android.Views.View? v = null)
    {
        try
        {
            var dm = global::Android.App.Application.Context!.Resources!.DisplayMetrics;
            if (dm is null) return false;
            float left = 0f, right = dm.WidthPixels;
            try
            {
                var dec = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.Window?.DecorView;
                if (dec is not null && dec.Width > 0)
                {
                    int[] loc = new int[2];
                    dec.GetLocationOnScreen(loc);
                    left = loc[0];
                    right = loc[0] + dec.Width;
                }
            }
            catch { }
            float w = right - left;
            if (w <= 0) { left = 0f; right = dm.WidthPixels; w = right; }
            float edge = global::System.Math.Max(72f * dm.Density, w * 0.12f);
            return rawX < left + edge || rawX > right - edge;
        }
        catch { return false; }
    }

    // 拖动激活门槛
    internal static float ActivatePx
    {
        get
        {
            try { return 12f * global::Android.App.Application.Context!.Resources!.DisplayMetrics!.Density; }
            catch { return 24f; }
        }
    }

    // 放大态拖到图片
    internal static float EdgePagePx
    {
        get
        {
            try
            {
                var dm = global::Android.App.Application.Context!.Resources!.DisplayMetrics!;
                return global::System.Math.Max(88f * dm.Density, dm.WidthPixels * 0.16f);
            }
            catch { return 240f; }
        }
    }

    internal void Attach(HostBox box)
    {
        PlatformBox = box;
        box.OnDetach = RemoveOverlay;
        Log($"Attach slot={Slot}");
        _listener = new BoxListener(this);
        box.AddOnLayoutChangeListener(_listener);
    }

    // pop 提前到退出动画
    internal void BeginExit()
    {
        _exiting = true;
        var box = PlatformBox;
        if (box is null) return;
        box.OnDetach = null;
        try
        {
            if (_listener is not null) box.RemoveOnLayoutChangeListener(_listener);
        }
        catch { }
        _listener = null;
    }

    // 入场
    internal void SetEntryHidden(bool on)
    {
        _entryHidden = on;
        var root = _overlay;
        if (root is null) return;
        try
        {
            root.Alpha = on ? 0f : 1f;
            root.Visibility = on
                ? global::Android.Views.ViewStates.Invisible
                : global::Android.Views.ViewStates.Visible;
        }
        catch { }
    }

    // 入场期间相邻格
    private void ApplyEntryHidden()
    {
        var root = _overlay;
        if (root is null) return;
        try
        {
            root.Alpha = 0f;
            root.Visibility = global::Android.Views.ViewStates.Invisible;
        }
        catch { }
    }

    internal void Show(Bitmap? bmp)
    {
        if (Disabled) return;
        var box = PlatformBox;
        if (box is null) return;
        // 换图复用已上树
        // RemoveView+AddView 会重分配大窗口
        if (_overlay is not null && _iv is not null)
        {
            var curIv = _iv;
            var old = _curBmp;
            curIv.SetImageBitmap(bmp);
            _curBmp = bmp;
            if (_entryHidden) ApplyEntryHidden();
            if (old is not null && (bmp is null || old.Handle != bmp.Handle))
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                { try { if (!old.IsRecycled) old.Recycle(); } catch { } });
            Log($"OvSwap slot={Slot} bmp={bmp?.Width}x{bmp?.Height}");
            return;
        }
        var act = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
        if (act?.Window is null) { Log($"OvAdd slot={Slot} no-activity"); return; }
        // 全新 IV 先设图
        var iv = NativeImageHostHandler.NewIv();
        if (bmp is not null) iv.SetImageBitmap(bmp);
        var root = new global::Android.Widget.FrameLayout(act);
        root.SetClipChildren(true);
        var clip = new global::Android.Widget.FrameLayout(act);
        clip.SetClipChildren(true);
        clip.SetClipToPadding(true);
        clip.AddView(iv, InnerLp());
        root.AddView(clip, InnerLp());   // 先装配
        act.WindowManager?.AddView(root, OverlayLp());
        _overlay = root;
        _clip = clip;
        _iv = iv;
        _curBmp = bmp;
        // 入场期间才上树
        if (_entryHidden) ApplyEntryHidden();
        // 新图复位缩放
        _zoom = 1f; _panX = _panY = 0f;
        ApplyTransform();
        Reposition();
        Log($"OvAdd slot={Slot} bmp={bmp?.Width}x{bmp?.Height} box={box.Width}x{box.Height}");
        OverlayMounted?.Invoke();
    }

    internal void Clear()
    {
        // 退出动画仍
        if (_exiting) return;
        // 换图不重建窗口
        // RemoveView+AddView 会重分配大 surface，是「出
        var old = _curBmp;
        _curBmp = null;
        try { _iv?.SetImageBitmap(null); } catch { }
        if (old is not null && !old.IsRecycled) { try { old.Recycle(); } catch { } }
    }

    // 逐带渲染
    internal void PostInvalidateImage()
    {
        try { _iv?.PostInvalidate(); } catch { }
    }

    // 关闭流程
    internal void Disable() { _exiting = false; Disabled = true; Destroy(); }

    internal void Destroy()
    {
        Clear();
        RemoveOverlay();
    }

    // 翻页转移
    internal Bitmap? DetachBitmap()
    {
        var b = _curBmp;
        _curBmp = null;
        try { _iv?.SetImageBitmap(null); } catch { }
        return b;
    }

    private bool _warnedNoIv;

    // 全局平移
    internal void FollowPanTo(float txPx)
    {
        LastTx = txPx;
        if (_iv is null)
        {
            // 只告警一次
            if (!_warnedNoIv) { _warnedNoIv = true; Log($"PanSkip slot={Slot} iv=null"); }
            return;
        }
        ApplyTransform();
    }

    // 页面飞入/飞出动
    internal void NudgeTo(float dx)
    {
        Nudge = dx;
        ApplyTransform();
    }

    // 退出动画
    // 只动 iv
    internal void ExitFrame(float dx, float alpha)
    {
        try
        {
            if (_clip is not null) _clip.TranslationX = dx;
            if (_backdrop is not null) _backdrop.TranslationX = dx;
            if (_overlay is not null) _overlay.Alpha = alpha;
        }
        catch { }
    }

    // 挂整页 UI 快照
    internal void SetBackdrop(Bitmap bmp)
    {
        var root = _overlay;
        if (root is null) { try { bmp.Recycle(); } catch { } return; }
        try
        {
            var iv = new global::Android.Widget.ImageView(global::Android.App.Application.Context!);
            iv.SetImageBitmap(bmp);
            var lp = new global::Android.Widget.FrameLayout.LayoutParams(
                bmp.Width, bmp.Height,
                global::Android.Views.GravityFlags.Top | global::Android.Views.GravityFlags.Left);
            root.AddView(iv, 0, lp);
            _backdrop = iv;
            _backdropBmp = bmp;
            Log($"UiSnap slot={Slot} {bmp.Width}x{bmp.Height}");
        }
        catch (Exception ex)
        {
            Log($"UiSnap fail {ex.Message}");
            try { bmp.Recycle(); } catch { }
        }
    }

    internal void Reposition()
    {
        var box = PlatformBox;
        var root = _overlay;
        var clip = _clip;
        var iv = _iv;
        if (box is null || root is null || clip is null || iv is null) return;
        if (box.Width <= 0 || box.Height <= 0) { root.Post(Reposition); return; }
        int[] p = new int[2];
        box.GetLocationOnScreen(p);
        // 扣掉平移
        int mx = p[0] - (int)(LastTx + Nudge);
        // 水平固定
        // （蓝色 Shell 标题栏曾占
        int screenH = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.Window?.DecorView?.Height ?? 0;
        if (screenH <= 0) screenH = root.Height;
        int vx = 0, vy = screenH >= box.Height ? (screenH - box.Height) / 2 : p[1];
        if (clip.LayoutParameters is global::Android.Widget.FrameLayout.LayoutParams clp &&
            (clp.Width != box.Width || clp.Height != box.Height ||
             clp.LeftMargin != vx || clp.TopMargin != vy))
        {
            clp.Width = box.Width;
            clp.Height = box.Height;
            clp.LeftMargin = vx;
            clp.TopMargin = vy;
            clip.LayoutParameters = clp;
        }
        if (iv.LayoutParameters is not global::Android.Widget.FrameLayout.LayoutParams lp) return;
        int ix = mx - vx, iy = 0;
        if (lp.Width != box.Width || lp.Height != box.Height ||
            lp.LeftMargin != ix || lp.TopMargin != iy)
        {
            lp.Width = box.Width;
            lp.Height = box.Height;
            lp.LeftMargin = ix;
            lp.TopMargin = iy;
            iv.LayoutParameters = lp;
            Log($"OvPos slot={Slot} clip={vx},{vy} iv={ix} {box.Width}x{box.Height}");
        }
    }

    // 缩放
    internal void ZoomBy(float factor, float focusX, float focusY)
    {
        var box = PlatformBox;
        if (_iv is null || box is null || box.Width <= 0) return;
        // 重新捏合打断复
        if (_zoomAnimating) CancelZoomAnim();
        float old = _zoom;
        float next = global::System.Math.Clamp(old * factor, 1f, 5f);
        if (next <= 1.001f)
        {
            _zoom = 1f; _panX = _panY = 0f;
            ApplyTransform();
            return;
        }
        float ratio = next / old;
        int[] p = new int[2];
        box.GetLocationOnScreen(p);   // 已含 pager 平移
        float fx = focusX - (p[0] + box.Width * 0.5f);
        float fy = focusY - (p[1] + box.Height * 0.5f);
        _panX = fx * (1f - ratio) + _panX * ratio;
        _panY = fy * (1f - ratio) + _panY * ratio;
        _zoom = next;
        ClampPan();
        ApplyTransform();
    }

    internal float PanBy(float dx, float dy)
    {
        if (_zoomAnimating || !Zoomed || _iv is null) return 0f;
        float before = _panX;
        _panX += dx; _panY += dy;
        ClampPan();
        ApplyTransform();
        return dx - (_panX - before);
    }

    internal void ResetZoom()
    {
        CancelZoomAnim();
        _zoom = 1f; _panX = _panY = 0f;
        ApplyTransform();
    }

    // 返回键
    internal void ResetZoomAnimated()
    {
        if (_zoomAnimating) return;
        if (!Zoomed) { ResetZoom(); return; }
        float z0 = _zoom, x0 = _panX, y0 = _panY;
        var a = global::Android.Animation.ValueAnimator.OfFloat(0f, 1f);
        a.SetDuration(220);
        a.SetInterpolator(new global::Android.Views.Animations.DecelerateInterpolator(1.6f));
        _zoomAnimating = true;
        a.Update += (s, e) =>
        {
            if (!ReferenceEquals(_zoomAnim, a)) return;
            float t = a.AnimatedFraction;
            _zoom = z0 + (1f - z0) * t;
            _panX = x0 * (1f - t);
            _panY = y0 * (1f - t);
            ApplyTransform();
        };
        a.AnimationEnd += (s, e) =>
        {
            if (!ReferenceEquals(_zoomAnim, a)) return;
            _zoom = 1f; _panX = _panY = 0f;
            _zoomAnimating = false;
            _zoomAnim = null;
            ApplyTransform();
        };
        _zoomAnim = a;
        a.Start();
    }

    private void CancelZoomAnim()
    {
        var a = _zoomAnim;
        _zoomAnim = null;
        _zoomAnimating = false;
        if (a is null) return;
        try { a.Cancel(); } catch { }
    }

    private void ClampPan()
    {
        var box = PlatformBox;
        if (box is null) return;
        float lx = box.Width * (_zoom - 1f) * 0.5f;
        float ly = box.Height * (_zoom - 1f) * 0.5f;
        _panX = global::System.Math.Clamp(_panX, -lx, lx);
        _panY = global::System.Math.Clamp(_panY, -ly, ly);
    }

    private void ApplyTransform()
    {
        var iv = _iv;
        if (iv is null) return;
        iv.ScaleX = _zoom;
        iv.ScaleY = _zoom;
        iv.TranslationX = LastTx + Nudge + _panX;
        iv.TranslationY = _panY;
    }

    private void RemoveOverlay()
    {
        var root = _overlay;
        _overlay = null;
        // 先解绑 drawable
        try { _iv?.SetImageBitmap(null); } catch { }
        _iv = null;
        _clip = null;
        try { _backdrop?.SetImageBitmap(null); } catch { }
        _backdrop = null;
        var snap = _backdropBmp;
        _backdropBmp = null;
        if (snap is not null && !snap.IsRecycled) { try { snap.Recycle(); } catch { } }
        CancelZoomAnim();
        _zoom = 1f; _panX = _panY = 0f;
        _entryHidden = false;
        if (root is null) return;
        try
        {
            var act = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
            act?.WindowManager?.RemoveView(root);
            Log($"OvRm slot={Slot}");
        }
        catch (Exception ex) { Log($"OvRm slot={Slot} fail {ex.Message}"); }
    }

    private static global::Android.Views.WindowManagerLayoutParams OverlayLp() =>
        new(global::Android.Views.ViewGroup.LayoutParams.MatchParent,
            global::Android.Views.ViewGroup.LayoutParams.MatchParent,
            global::Android.Views.WindowManagerTypes.ApplicationPanel,
            FileEncryptorMobile.Services.ScreenSecurity.OverlayFlags(
                global::Android.Views.WindowManagerFlags.NotFocusable
                | global::Android.Views.WindowManagerFlags.NotTouchable
                | global::Android.Views.WindowManagerFlags.LayoutNoLimits),
            global::Android.Graphics.Format.Transparent);

    private static global::Android.Widget.FrameLayout.LayoutParams InnerLp() =>
        new(1, 1, global::Android.Views.GravityFlags.Top | global::Android.Views.GravityFlags.Left);
}

public sealed class NativeImageHostHandler : ViewHandler<NativeImageHost, HostBox>
{
    public NativeImageHostHandler() : base(ViewHandler.ViewMapper, ViewHandler.ViewCommandMapper) { }

    internal static global::Android.Widget.ImageView NewIv()
    {
        var iv = new global::Android.Widget.ImageView(global::Android.App.Application.Context!);
        iv.SetScaleType(global::Android.Widget.ImageView.ScaleType.FitCenter);
        // 透明底
        iv.SetBackgroundColor(global::Android.Graphics.Color.Transparent);
        return iv;
    }

    protected override HostBox CreatePlatformView()
    {
        var box = new HostBox(global::Android.App.Application.Context!)
        {
            LayoutParameters = new global::Android.Views.ViewGroup.LayoutParams(
                global::Android.Views.ViewGroup.LayoutParams.MatchParent,
                global::Android.Views.ViewGroup.LayoutParams.MatchParent),
        };
        box.SetBackgroundColor(global::Android.Graphics.Color.Black);
        return box;
    }

    protected override void ConnectHandler(HostBox box)
    {
        base.ConnectHandler(box);
        VirtualView.Attach(box);
    }

    protected override void DisconnectHandler(HostBox box)
    {
        VirtualView.Clear();
        box.RemoveAllViews();
        base.DisconnectHandler(box);
    }
}
