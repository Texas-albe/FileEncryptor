// 「更多」面板
// 行左侧线性图标 +
// 面板本身半透明
// 单文件播放没有
using Android.Widget;
using Microsoft.Maui.Storage;
using AActivity = global::Android.App.Activity;
using AColor = global::Android.Graphics.Color;
using AGravity = global::Android.Views.GravityFlags;
using ASwitch = global::Android.Widget.Switch;
using AScrollView = global::Android.Widget.ScrollView;
using AView = global::Android.Views.View;
using AViewGroup = global::Android.Views.ViewGroup;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public static partial class VideoPlayerHost
{
    private const int TintRow = unchecked((int)0xE6FFFFFF);

    private static LinearLayout? _panel;
    private static AView? _panelScrim;
    private static TextView? _timerValue;
    private static LinearLayout? _speedRow;
    private static bool _panelOpen;

    private static void TogglePanel(int gen)
    {
        if (gen != s_gen) return;
        if (_panelOpen) ClosePanel(gen);
        else BuildPanel(gen);
    }

    private static void BuildPanel(int gen)
    {
        var act = _activity;
        var root = _root;
        if (act is null || root is null) return;

        CancelHide();
        _panelOpen = true;
        float d = _density;
        int Dp(float v) => Dpx(d, v);

        var scrim = new AView(act);
        // 整屏压暗
        scrim.SetBackgroundColor(AColor.ParseColor("#59000000"));
        scrim.Clickable = true;
        scrim.Click += (_, _) => ClosePanel(gen);
        root.AddView(scrim, new FrameLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.MatchParent));
        _panelScrim = scrim;

        var panel = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Vertical };
        panel.SetBackgroundColor(AColor.ParseColor("#8C000000"));
        panel.Clickable = true;

        var scroll = new AScrollView(act);
        var content = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Vertical };
        scroll.AddView(content, new AScrollView.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent));
        panel.AddView(scroll, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, 0, 1f));

        AddSection(act, content, L10n.T("显示"), d);

        ASwitch? stretchSw = null;
        ASwitch? fullSw = null;
        // 强制铺满 = 等比放
        fullSw = AddSwitchRow(act, content, Resource.Drawable.ic_fe_fullscreen, L10n.T("强制铺满全屏"), _fill, d, on =>
        {
            _fill = on;
            try { Preferences.Default.Set("video_fill", on); } catch { }
            if (on && _stretch)
            {
                _stretch = false;
                try { Preferences.Default.Set("video_stretch", false); } catch { }
                if (stretchSw is not null) stretchSw.Checked = false;
            }
            ApplyScale(gen, true);
        });
        // 拉伸 = 忽略宽高比
        stretchSw = AddSwitchRow(act, content, Resource.Drawable.ic_fe_stretch, L10n.T("拉伸以铺满全屏"), _stretch, d, on =>
        {
            _stretch = on;
            try { Preferences.Default.Set("video_stretch", on); } catch { }
            if (on && _fill)
            {
                _fill = false;
                try { Preferences.Default.Set("video_fill", false); } catch { }
                if (fullSw is not null) fullSw.Checked = false;
            }
            ApplyScale(gen, true);
        });
        AddSwitchRow(act, content, Resource.Drawable.ic_fe_rotate, L10n.T("自适应横竖屏"), _autoOrient, d, on =>
        {
            _autoOrient = on;
            try { Preferences.Default.Set("video_auto_orient", on); } catch { }
            if (on) ApplyAutoOrientation(gen);
        });

        AddSection(act, content, L10n.T("播放"), d);
        AddSwitchRow(act, content, Resource.Drawable.ic_fe_loop, L10n.T("开启循环播放"), _loop, d, on =>
        {
            _loop = on;
            try { Preferences.Default.Set("video_loop", on); } catch { }
        });
        _timerValue = AddValueRow(act, content, Resource.Drawable.ic_fe_timer, L10n.T("定时关闭"),
            TimerText(_timerMinutes), d, () => CycleTimer(gen));

        AddSection(act, content, L10n.T("播放速度"), d);
        AddSpeedRow(act, content, d, gen);

        var spacer = new AView(act);
        content.AddView(spacer, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, Dp(16)));

        int screenH = act.Resources?.DisplayMetrics?.HeightPixels ?? Dp(720);
        // 参考图
        int panelH = (int)(screenH * 0.73f);
        root.AddView(panel, new FrameLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, panelH, AGravity.Bottom));
        _panel = panel;

        // 从底部滑入
        panel.TranslationY = panelH;
        try { panel.Animate().TranslationY(0f).SetDuration(200).Start(); } catch { }
    }

    private static void ClosePanel(int gen)
    {
        if (!_panelOpen) return;
        _panelOpen = false;

        var root = _root;
        var panel = _panel;
        var scrim = _panelScrim;
        _panel = null;
        _panelScrim = null;
        _timerValue = null;
        _speedRow = null;

        if (root is not null)
        {
            if (scrim is not null)
            {
                try { root.RemoveView(scrim); } catch { }
            }
            if (panel is not null)
            {
                try { panel.Animate().TranslationY(panel.Height).SetDuration(160).Start(); } catch { }
                var r = root;
                try
                {
                    r.PostDelayed(new Runnable(() => { try { r.RemoveView(panel); } catch { } }), 180);
                }
                catch { }
            }
        }
        if (gen == s_gen && !_locked) ScheduleHide(gen);
    }

    // Close 用
    private static void ClosePanelImmediate()
    {
        _panelOpen = false;
        var root = _root;
        var panel = _panel;
        var scrim = _panelScrim;
        _panel = null;
        _panelScrim = null;
        _timerValue = null;
        _speedRow = null;
        if (root is null) return;
        try { if (scrim is not null) root.RemoveView(scrim); } catch { }
        try { if (panel is not null) root.RemoveView(panel); } catch { }
    }

    // 分组标题
    private static void AddSection(AActivity act, LinearLayout parent, string title, float d)
    {
        AddDivider(act, parent, d, 0, 0);

        var head = new TextView(act) { Text = title, Gravity = AGravity.CenterVertical };
        head.TextSize = 14;
        head.SetTextColor(AColor.ParseColor("#999999"));
        head.SetPadding(Dpx(d, 60), 0, Dpx(d, 40), 0);
        parent.AddView(head, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, Dpx(d, 46)));

        AddDivider(act, parent, d, 0, 0);
    }

    private static ASwitch AddSwitchRow(AActivity act, LinearLayout parent, int iconRes, string label,
        bool value, float d, Action<bool> onChange)
    {
        var row = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Horizontal };
        row.SetGravity(AGravity.CenterVertical);
        row.SetPadding(Dpx(d, 60), 0, Dpx(d, 40), 0);
        row.Clickable = true;

        var icon = MakeRowIcon(act, iconRes, 24, TintRow, d);
        row.AddView(icon, new LinearLayout.LayoutParams(Dpx(d, 24), Dpx(d, 24)) {
            RightMargin = Dpx(d, 14),
        });

        var text = new TextView(act) { Text = label };
        text.TextSize = 15;
        text.SetTextColor(AColor.ParseColor("#F2FFFFFF"));
        row.AddView(text, new LinearLayout.LayoutParams(0, AViewGroup.LayoutParams.WrapContent, 1f));

        var sw = new ASwitch(act) { Checked = value };
        sw.CheckedChange += (_, e) =>
        {
            try { onChange(e.IsChecked); }
            catch (Exception ex) { MainApplication.LogCaught("video-switch", ex); }
        };
        row.AddView(sw, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.WrapContent, AViewGroup.LayoutParams.WrapContent));

        // 整行可点
        row.Click += (_, _) => { sw.Checked = !sw.Checked; };

        parent.AddView(row, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, Dpx(d, 52)));
        AddDivider(act, parent, d, 60, 40);
        return sw;
    }

    private static TextView AddValueRow(AActivity act, LinearLayout parent, int iconRes, string label,
        string value, float d, Action onClick)
    {
        var row = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Horizontal };
        row.SetGravity(AGravity.CenterVertical);
        row.SetPadding(Dpx(d, 60), 0, Dpx(d, 40), 0);
        row.Clickable = true;

        var icon = MakeRowIcon(act, iconRes, 24, TintRow, d);
        row.AddView(icon, new LinearLayout.LayoutParams(Dpx(d, 24), Dpx(d, 24)) {
            RightMargin = Dpx(d, 14),
        });

        var text = new TextView(act) { Text = label };
        text.TextSize = 15;
        text.SetTextColor(AColor.ParseColor("#F2FFFFFF"));
        row.AddView(text, new LinearLayout.LayoutParams(0, AViewGroup.LayoutParams.WrapContent, 1f));

        var val = new TextView(act) { Text = value };
        val.TextSize = 14;
        val.SetTextColor(AColor.ParseColor("#999999"));
        row.AddView(val, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.WrapContent, AViewGroup.LayoutParams.WrapContent));

        row.Click += (_, _) =>
        {
            try { onClick(); }
            catch (Exception ex) { MainApplication.LogCaught("video-row", ex); }
        };

        parent.AddView(row, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, Dpx(d, 52)));
        AddDivider(act, parent, d, 60, 40);
        return val;
    }

    private static void AddSpeedRow(AActivity act, LinearLayout parent, float d, int gen)
    {
        var row = new LinearLayout(act) { Orientation = global::Android.Widget.Orientation.Horizontal };
        row.SetPadding(Dpx(d, 60), 0, Dpx(d, 40), Dpx(d, 10));

        foreach (var speed in SpeedValues)
        {
            var tv = new TextView(act)
            {
                Text = speed.ToString("0.0#", System.Globalization.CultureInfo.InvariantCulture),
                Gravity = AGravity.Center,
            };
            tv.TextSize = 15;
            tv.Clickable = true;
            tv.SetPadding(0, Dpx(d, 10), 0, Dpx(d, 10));
            tv.Click += (_, _) =>
            {
                _speed = speed;
                try { Preferences.Default.Set("video_speed", speed); } catch { }
                ApplySpeed(gen);
                RefreshSpeedRow();
            };
            row.AddView(tv, new LinearLayout.LayoutParams(
                0, AViewGroup.LayoutParams.WrapContent, 1f));
        }

        parent.AddView(row, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, AViewGroup.LayoutParams.WrapContent));
        _speedRow = row;
        RefreshSpeedRow();
    }

    private static void RefreshSpeedRow()
    {
        var row = _speedRow;
        if (row is null) return;
        try
        {
            for (int i = 0; i < row.ChildCount && i < SpeedValues.Length; i++)
            {
                if (row.GetChildAt(i) is not TextView tv) continue;
                tv.SetTextColor(Math.Abs(SpeedValues[i] - _speed) < 0.001f
                    ? AColor.ParseColor("#4C8DF6")
                    : AColor.ParseColor("#C7CBD1"));
            }
        }
        catch (Exception ex) { MainApplication.LogCaught("video-speed-ui", ex); }
    }

    // 1px 细分隔线
    private static void AddDivider(AActivity act, LinearLayout parent, float d, float leftDp, float rightDp)
    {
        var line = new AView(act);
        line.SetBackgroundColor(AColor.ParseColor("#1AFFFFFF"));
        parent.AddView(line, new LinearLayout.LayoutParams(
            AViewGroup.LayoutParams.MatchParent, Math.Max(1, (int)(0.6f * d))) {
            LeftMargin = Dpx(d, leftDp),
            RightMargin = Dpx(d, rightDp),
        });
    }

    private static string TimerText(int minutes) => minutes <= 0 ? L10n.T("未设置") : L10n.F("{0} 分钟", minutes);

    // 单文件播放没有
    // 再开 Dialog 窗口带来层
    private static void CycleTimer(int gen)
    {
        int idx = Array.IndexOf(TimerValues, _timerMinutes);
        if (idx < 0) idx = 0;
        int next = TimerValues[(idx + 1) % TimerValues.Length];
        SetTimerMinutes(gen, next);
    }

    private static int Dpx(float density, float v) => (int)(v * density + 0.5f);
}
