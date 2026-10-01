using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using System;

namespace FileEncryptorGUI.Services;

// 国庆节主题
public static class NationalDayTheme
{
    // 中国国旗红
    public static Windows.UI.Color ChinaRed => RGB(0xDE, 0x29, 0x10);

    // 是否国庆窗口
    public static bool IsActive(DateTime? when = null)
    {
        var d = when ?? DateTime.Today;
        return d.Month == 10 && d.Day >= 1 && d.Day <= 7;
    }

    // 祖国年龄
    public static int MotherlandAge(DateTime? when = null)
    {
        var d = when ?? DateTime.Today;
        return d.Year - 1949;
    }

    // 关于页祝福语
    public static string BirthdayMessage(DateTime? when = null)
        => string.Format(L10n.T("祝祖国{0}岁生日快乐！永远繁荣昌盛！"), MotherlandAge(when));

    // ===== 节日配色 =====
    private static Windows.UI.Color RGB(byte r, byte g, byte b) => Windows.UI.Color.FromArgb(255, r, g, b);

    private static bool Dark => App.Settings.Current.Theme != AppTheme.Light;

    // 主窗口底色
    public static Windows.UI.Color WindowBg => Dark ? RGB(0x3A, 0x12, 0x10) : RGB(0xF7, 0xDD, 0xD9);
    // 卡片/区块底色
    public static Windows.UI.Color CardBg => Dark ? RGB(0x4A, 0x1A, 0x16) : RGB(0xF0, 0xC4, 0xBE);
    // 次级底色（输入区、列表）
    public static Windows.UI.Color CardBgAlt => Dark ? RGB(0x35, 0x13, 0x0F) : RGB(0xF6, 0xC9, 0xC4);
    // 控件底色（按钮、下拉）
    public static Windows.UI.Color ControlBg => Dark ? RGB(0x5C, 0x22, 0x22) : RGB(0xF2, 0xBD, 0xB5);
    // 边框
    public static Windows.UI.Color Stroke => Dark ? RGB(0x7A, 0x32, 0x2B) : RGB(0xD9, 0x9A, 0x92);
    // 正文/次要文字
    public static Windows.UI.Color TextPrimary => Dark ? RGB(0xF2, 0xDA, 0xD6) : RGB(0x3A, 0x15, 0x12);
    public static Windows.UI.Color TextSecondary => Dark ? RGB(0xC9, 0x9A, 0x94) : RGB(0x7A, 0x4A, 0x44);

    // 运行/取消按钮：节日窗口统一红系，靠深浅区分
    public static Windows.UI.Color RunBg => Dark ? RGB(0xDE, 0x29, 0x10) : RGB(0xC0, 0x39, 0x2B);
    public static Windows.UI.Color RunBgPointer => Dark ? RGB(0xF0, 0x4A, 0x30) : RGB(0xA9, 0x32, 0x26);
    public static Windows.UI.Color RunBgPressed => Dark ? RGB(0xC0, 0x22, 0x0B) : RGB(0x8E, 0x2B, 0x20);
    public static Windows.UI.Color CancelBg => Dark ? RGB(0x7A, 0x1A, 0x12) : RGB(0x8A, 0x1E, 0x13);
    public static Windows.UI.Color CancelBgPointer => Dark ? RGB(0x9A, 0x24, 0x1A) : RGB(0x6E, 0x18, 0x0F);
    public static Windows.UI.Color CancelBgPressed => Dark ? RGB(0x5C, 0x12, 0x0C) : RGB(0x54, 0x12, 0x0B);

    // 覆盖按钮配色（含 PointerOver / Pressed 资源，避免露出系统绿/红）
    public static void ApplyButtonColors(Microsoft.UI.Xaml.Controls.Button run,
                                         Microsoft.UI.Xaml.Controls.Button cancel)
    {
        if (!IsActive()) return;
        run.Background = new SolidColorBrush(RunBg);
        SetBrush(run, "ButtonBackgroundPointerOver", RunBgPointer);
        SetBrush(run, "ButtonBackgroundPressed", RunBgPressed);
        cancel.Background = new SolidColorBrush(CancelBg);
        SetBrush(cancel, "ButtonBackgroundPointerOver", CancelBgPointer);
        SetBrush(cancel, "ButtonBackgroundPressed", CancelBgPressed);
        SetBrush(cancel, "ButtonBackgroundDisabled", Stroke);
    }

    private static void SetBrush(Microsoft.UI.Xaml.FrameworkElement e, string key, Windows.UI.Color c)
    {
        try { e.Resources[key] = new SolidColorBrush(c); } catch {  }
    }

    // 节日窗口把系统主题色整体换成国旗红
    public static void ApplyThemeOverrides()
    {
        if (!IsActive()) return;
        ApplyAccentOverrides();
        var app = Application.Current;
        if (app == null) return;

        var res = app.Resources;
        var window = new SolidColorBrush(WindowBg);
        var card = new SolidColorBrush(CardBg);
        var cardAlt = new SolidColorBrush(CardBgAlt);
        var ctrl = new SolidColorBrush(ControlBg);
        var stroke = new SolidColorBrush(Stroke);
        var text = new SolidColorBrush(TextPrimary);
        var text2 = new SolidColorBrush(TextSecondary);

        Set(res, "ApplicationPageBackgroundThemeBrush", window);
        Set(res, "SolidBackgroundFillColorBaseBrush", window);
        Set(res, "LayerFillColorDefaultBrush", card);
        Set(res, "LayerFillColorAltBrush", cardAlt);
        Set(res, "CardBackgroundFillColorDefaultBrush", card);
        Set(res, "CardBackgroundFillColorSecondaryBrush", cardAlt);
        Set(res, "CardStrokeColorDefaultBrush", stroke);
        Set(res, "ControlFillColorDefaultBrush", ctrl);
        Set(res, "ControlFillColorSecondaryBrush", ctrl);
        Set(res, "ControlStrokeColorDefaultBrush", stroke);
        Set(res, "ControlStrokeColorSecondaryBrush", stroke);
        Set(res, "TextFillColorPrimaryBrush", text);
        Set(res, "TextFillColorSecondaryBrush", text2);
        Set(res, "TextFillColorTertiaryBrush", text2);
        Set(res, "TextFillColorDisabledBrush", text2);
    }

    // 覆盖强调色为中国红
    public static void ApplyAccentOverrides()
    {
        if (!IsActive()) return;
        var app = Application.Current;
        if (app == null) return;
        var res = app.Resources;
        var red = new SolidColorBrush(ChinaRed);

        // WinUI 3 强调色
        Set(res, "AccentFillColorDefaultBrush", red);
        Set(res, "AccentFillColorSecondaryBrush", red);
        Set(res, "AccentFillColorTertiaryBrush", red);
        Set(res, "AccentFillColorDisabledBrush", red);
        Set(res, "AccentFillColorSelectedTextBackgroundBrush", red);
        Set(res, "AccentTextFillColorPrimaryBrush", red);
        Set(res, "AccentTextFillColorSecondaryBrush", red);
        Set(res, "AccentTextFillColorTertiaryBrush", red);
        Set(res, "AccentTextFillColorDisabledBrush", red);

        // 兼容旧版 SystemControl 键
        Set(res, "SystemControlHighlightAccentBrush", red);
        Set(res, "SystemControlForegroundAccentBrush", red);
        Set(res, "SystemControlHighlightAltAccentBrush", red);
        Set(res, "SystemControlHyperlinkTextBrush", red);
        Set(res, "SystemControlHighlightListAccentLowBrush",
            new SolidColorBrush(Windows.UI.Color.FromArgb(0x33, 0xDE, 0x29, 0x10)));
        Set(res, "SystemControlHighlightListAccentMediumBrush",
            new SolidColorBrush(Windows.UI.Color.FromArgb(0x59, 0xDE, 0x29, 0x10)));
        Set(res, "SystemControlHighlightListAccentHighBrush", red);
    }

    private static void Set(ResourceDictionary res, string key, Brush brush)
    {
        try { res[key] = brush; } catch {  }
    }
}
