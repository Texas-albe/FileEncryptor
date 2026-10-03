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

    // System 档要看系统当前是深是浅，否则浅色系统下会拿到深色配色
    private static bool Dark => App.Settings.Current.Theme switch
    {
        AppTheme.Light => false,
        AppTheme.Dark => true,
        _ => ThemeService.IsSystemDark(),
    };

    // 主窗口底色
    public static Windows.UI.Color WindowBg => Dark ? RGB(0x12, 0x11, 0x11) : RGB(0xF7, 0xF5, 0xF4);
    // 卡片/区块底色：比窗口底亮一档，靠明度差拉开层级而不是靠色相
    public static Windows.UI.Color CardBg => Dark ? RGB(0x1E, 0x1C, 0x1C) : RGB(0xFF, 0xFF, 0xFF);
    // 次级底色（输入区、列表）：压在卡片底之下，形成凹陷感
    public static Windows.UI.Color CardBgAlt => Dark ? RGB(0x17, 0x16, 0x16) : RGB(0xF1, 0xEF, 0xEE);
    // 控件底色（按钮、下拉）：比卡片底再亮一档
    public static Windows.UI.Color ControlBg => Dark ? RGB(0x2C, 0x29, 0x29) : RGB(0xF0, 0xEE, 0xED);
    // 控件底（带透度）：按钮/输入框密集，不透明会把面板遮死。
    // 按钮保持较实（要看得出可点），输入框类更透。
    // alpha 跟着窗口档位走：窗口越透，控件也得跟着透，否则控件像贴纸。
    public static Windows.UI.Color ControlBgOverlay => Dark
        ? WithAlpha(RGB(0x2C, 0x29, 0x29), AlphaWindowDark + 0.27)
        : WithAlpha(RGB(0xF0, 0xEE, 0xED), 1.0);
    // 输入框 / 下拉 / 列表：比按钮更实一点，输入文字才清楚
    public static Windows.UI.Color FieldBgOverlay => Dark
        ? WithAlpha(RGB(0x17, 0x16, 0x16), AlphaWindowDark + 0.07)
        : WithAlpha(RGB(0xFF, 0xFF, 0xFF), 1.0);
    // 边框：浅色下要够深才看得见按钮轮廓，深色下够浅
    public static Windows.UI.Color Stroke => Dark ? RGB(0x40, 0x3C, 0x3C) : RGB(0xC4, 0xBD, 0xBB);
    // 正文/次要文字
    public static Windows.UI.Color TextPrimary => Dark ? RGB(0xF5, 0xF2, 0xF1) : RGB(0x1C, 0x18, 0x17);
    public static Windows.UI.Color TextSecondary => Dark ? RGB(0xAD, 0xA3, 0xA1) : RGB(0x6B, 0x60, 0x5E);

    // 运行/取消按钮：红只落在按钮上，底子保持中性，红才不褪成粉
    public static Windows.UI.Color RunBg => ChinaRed;
    // 深色底上国旗红偏暗，悬停往亮里走才看得清
    public static Windows.UI.Color RunBgPointer => Dark ? RGB(0xF0, 0x4A, 0x30) : RGB(0xF2, 0x3C, 0x22);
    public static Windows.UI.Color RunBgPressed => RGB(0xA8, 0x1F, 0x0A);
    // 取消键同样是红但明显加深，与运行键拉开层级（不靠色相，用明度）
    public static Windows.UI.Color CancelBg => Dark ? RGB(0x8E, 0x22, 0x14) : RGB(0x9E, 0x2A, 0x1B);
    public static Windows.UI.Color CancelBgPointer => Dark ? RGB(0xA8, 0x2C, 0x1B) : RGB(0xB8, 0x36, 0x24);
    public static Windows.UI.Color CancelBgPressed => Dark ? RGB(0x6E, 0x18, 0x0E) : RGB(0x7C, 0x20, 0x14);
    // 标题左侧的装饰红条：深色档同样靠它点出节日氛围
    public static Windows.UI.Color AccentBar => ChinaRed;

    // 主窗口底色（带透度）。深色档走 Mica，这层只是节日染色；
    // 浅色档没有模糊（Mica 跟随系统深浅，深色系统下会黑白不一），
    // 遮罩必须给足 alpha，否则底下什么都没有、控件全是白的糊一片。
    public static Windows.UI.Color WindowBgOverlay => Dark
        ? WithAlpha(RGB(0x1A, 0x18, 0x18), AlphaWindowDark)
        : WithAlpha(RGB(0xF7, 0xF5, 0xF4), AlphaWindowLight);
    // 卡片底同样留透，层次靠 alpha 叠出来
    public static Windows.UI.Color CardBgOverlay => Dark
        ? WithAlpha(RGB(0x1E, 0x1C, 0x1C), AlphaPanelDark)
        : WithAlpha(RGB(0xFF, 0xFF, 0xFF), 1.0);
    // 面板底（功能区 / 文件选择区）：比窗口底实一档，比卡片透，
    // 用自身 Mica 让面板和窗口两层采样叠出层次。
    // 这是 Mica 不生效时的退化色，alpha 要跟下面的 TintOpacity 对齐，
    // 否则真Mica 与退化色之间会跳一次亮度。
    public static Windows.UI.Color PanelBgOverlay => Dark
        ? WithAlpha(RGB(0x1E, 0x1C, 0x1C), AlphaPanelDark)
        : WithAlpha(RGB(0xFF, 0xFF, 0xFF), AlphaPanelLight);

    // 窗口底染色层：用 MicaBrush，tint 完全自己掌握。
    // 为什么不用 Acrylic：系统的 DesktopAcrylicBackdrop 在深色档自带很重的暗 tint
    // （实测吃掉约 73% 光，透过率只剩 22%），且 WinUI 3.1 的 SystemBackdrop 没有
    // Tint* 属性可调。Mica 的系统材质本身通透度高，叠这层只做节日染色。
    // 为什么不用 SolidColorBrush：那会把 Mica 完全盖死，模糊就没了。
    public static Brush WindowBackdropBrush()
    {
        if (App.Settings.Current.BackgroundMode == BackgroundMode.Flat)
            return new SolidColorBrush(WindowBgOverlay);
        // 纯薄染色：模糊由窗口级Mica 提供，这层只调色调与通透度。
        // 不能用 AcrylicBrush/MicaBrush：WinAppSDK 1.5 没有元素级 MicaBrush，
        // 而 AcrylicBrush 是用户明确不要的。
        return new SolidColorBrush(WindowBgOverlay);
    }

    // 窗口底 alpha 档位（越低越透）。菜单里可现场调。
    // 用 alpha 而不是 Mica 的 TintOpacity：WinAppSDK 1.5 没有元素级 MicaBrush，
    // tint 无处可设，改 alpha 是等效且可控的旋钮。
    public static double AlphaWindowDark { get; set; } = 0.45;
    public static double AlphaWindowLight { get; set; } = 0.85;
    // 面板 alpha。面板要略实于窗口，层次才分得开。
    public static double AlphaPanelDark { get; set; } = 0.62;
    public static double AlphaPanelLight { get; set; } = 0.92;

    private static Windows.UI.Color WithAlpha(Windows.UI.Color c, double a)
        => Windows.UI.Color.FromArgb(
            (byte)Math.Clamp(a * 255, 0, 255), c.R, c.G, c.B);

    // 面板底（功能区 / 文件选择区）：这层用自己的 MicaBrush 采样，
    // TintOpacity 就是面板的"通透度"旋钮，越低越透。
    // 面板要略实于窗口底，两个 Mica 采样区叠出来的层次才分得开；
    // 描边再补一道边界，避免浅色下两块面板糊成一片。
    public static Brush PanelBackdropBrush()
    {
        // 面板没有元素级 Mica 可用（WinAppSDK 1.5 只提供窗口级 MicaBackdrop），
        // 用半透明纯色：窗口级 Mica 的模糊从底下透上来，两个半透明层叠出层次。
        // alpha 必须给足，否则浅色下面板比窗口底还浅，糊成一片。
        return new SolidColorBrush(PanelBgOverlay);
    }

    // 覆盖按钮配色（含 PointerOver / Pressed 资源，避免露出系统绿/红）
    public static void ApplyButtonColors(Microsoft.UI.Xaml.Controls.Button run,
                                         Microsoft.UI.Xaml.Controls.Button cancel)
    {
        if (!IsActive()) return;
        var onAccent = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0xFF, 0xFF, 0xFF));
        run.Background = new SolidColorBrush(RunBg);
        run.Foreground = onAccent;
        SetBrush(run, "ButtonBackgroundPointerOver", RunBgPointer);
        SetBrush(run, "ButtonBackgroundPressed", RunBgPressed);
        SetBrush(run, "ButtonForeground", onAccent);
        SetBrush(run, "ButtonForegroundPointerOver", onAccent);
        SetBrush(run, "ButtonForegroundPressed", onAccent);
        cancel.Background = new SolidColorBrush(CancelBg);
        cancel.Foreground = onAccent;
        SetBrush(cancel, "ButtonBackgroundPointerOver", CancelBgPointer);
        SetBrush(cancel, "ButtonBackgroundPressed", CancelBgPressed);
        SetBrush(cancel, "ButtonBackgroundDisabled", Stroke);
        SetBrush(cancel, "ButtonForeground", onAccent);
        SetBrush(cancel, "ButtonForegroundPointerOver", onAccent);
        SetBrush(cancel, "ButtonForegroundPressed", onAccent);
    }

    // 切主题后重算并重刷：配色依赖深浅档，资源只覆盖一次不够
    public static void Refresh()
    {
        ApplyThemeOverrides();
        ApplyAccentOverrides();
    }

    // 按钮底/文字/描边：这些是控件模板级资源，写进 Application.Resources 不生效，
    // 必须逐个下到控件自身的 Resources 里。浅色下不给会继承系统浅灰，叠在浅底上等于隐形。
    public static void ApplyControlColors(Microsoft.UI.Xaml.FrameworkElement root)
    {
        if (!IsActive()) return;
        var text = new SolidColorBrush(TextPrimary);
        var text2 = new SolidColorBrush(TextSecondary);
        var stroke = new SolidColorBrush(Stroke);
        var normal = new SolidColorBrush(ControlBgOverlay);
        // 输入框类用更透的底，否则面板的 Acrylic 到不了控件这一层
        var field = new SolidColorBrush(FieldBgOverlay);
        var hover = new SolidColorBrush(Dark ? RGB(0x3A, 0x36, 0x36) : RGB(0xE6, 0xE3, 0xE2));
        var pressed = new SolidColorBrush(Dark ? RGB(0x22, 0x20, 0x20) : RGB(0xDC, 0xD8, 0xD7));
        var disabled = new SolidColorBrush(Dark ? RGB(0x24, 0x21, 0x21) : RGB(0xEC, 0xEA, 0xE9));

        var count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            if (VisualTreeHelper.GetChild(root, i) is FrameworkElement fe)
                ApplyOne(fe, text, text2, stroke, normal, field, hover, pressed, disabled);
        }
    }

    private static void ApplyOne(Microsoft.UI.Xaml.FrameworkElement fe,
        Brush text, Brush text2, Brush stroke, Brush normal, Brush field,
        Brush hover, Brush pressed, Brush disabled)
    {
        switch (fe)
        {
            case Microsoft.UI.Xaml.Controls.Button b:
                // 运行/取消键有自己的红/灰配色，不要被这层覆盖掉
                if (b.Name != "BtnRun" && b.Name != "BtnCancel")
                {
                    b.Background = normal;
                    b.BorderBrush = stroke;
                    b.Foreground = text;
                    SetBrush(b, "ButtonBackgroundPointerOver", hover);
                    SetBrush(b, "ButtonBackgroundPressed", pressed);
                    SetBrush(b, "ButtonBackgroundDisabled", disabled);
                    SetBrush(b, "ButtonForegroundPointerOver", text);
                    SetBrush(b, "ButtonForegroundPressed", text);
                    SetBrush(b, "ButtonForegroundDisabled", text2);
                    SetBrush(b, "ButtonBorderBrushPointerOver", stroke);
                }
                break;
            case Microsoft.UI.Xaml.Controls.ComboBox cb:
                cb.Background = field;
                cb.BorderBrush = stroke;
                cb.Foreground = text;
                break;
            case Microsoft.UI.Xaml.Controls.TextBox tb:
                tb.Background = field;
                tb.BorderBrush = stroke;
                tb.Foreground = text;
                break;
            case Microsoft.UI.Xaml.Controls.PasswordBox pb:
                pb.Background = field;
                pb.BorderBrush = stroke;
                pb.Foreground = text;
                break;
            case Microsoft.UI.Xaml.Controls.ListView lv:
                lv.Background = field;
                lv.BorderBrush = stroke;
                break;
        }
        var n = VisualTreeHelper.GetChildrenCount(fe);
        for (int i = 0; i < n; i++)
            if (VisualTreeHelper.GetChild(fe, i) is FrameworkElement child)
                ApplyOne(child, text, text2, stroke, normal, field, hover, pressed, disabled);
    }


    private static void SetBrush(Microsoft.UI.Xaml.FrameworkElement e, string key, Windows.UI.Color c)
    {
        try { e.Resources[key] = new SolidColorBrush(c); } catch {  }
    }

    // 资源键赋值：颜色与画刷都能传，省得为两种形态各写一个方法
    private static void SetBrush(Microsoft.UI.Xaml.FrameworkElement e, string key, Brush b)
    {
        try { e.Resources[key] = b; } catch {  }
    }

    // 节日窗口把系统主题色整体换成国旗红
    public static void ApplyThemeOverrides()
    {
        if (!IsActive()) return;
        ApplyAccentOverrides();
        var app = Application.Current;
        if (app == null) return;

        var res = app.Resources;
        var card = new SolidColorBrush(CardBg);
        var cardAlt = new SolidColorBrush(CardBgAlt);
        var ctrl = new SolidColorBrush(ControlBg);
        var stroke = new SolidColorBrush(Stroke);
        var text = new SolidColorBrush(TextPrimary);
        var text2 = new SolidColorBrush(TextSecondary);
        var red = new SolidColorBrush(ChinaRed);
        // 卡片与控件都留 alpha，否则大面积不透明块会把窗口 Acrylic 遮死
        var cardOverlay = new SolidColorBrush(CardBgOverlay);
        var ctrlOverlay = new SolidColorBrush(ControlBgOverlay);
        var fieldOverlay = new SolidColorBrush(FieldBgOverlay);

        Set(res, "ApplicationPageBackgroundThemeBrush",
            new SolidColorBrush(WindowBgOverlay));
        Set(res, "SolidBackgroundFillColorBaseBrush",
            new SolidColorBrush(WindowBgOverlay));
        Set(res, "LayerFillColorDefaultBrush", cardOverlay);
        Set(res, "LayerFillColorAltBrush", cardAlt);
        Set(res, "CardBackgroundFillColorDefaultBrush", cardOverlay);
        Set(res, "CardBackgroundFillColorSecondaryBrush",
            new SolidColorBrush(Dark ? CardBgAlt : Windows.UI.Color.FromArgb(0xFF, 0xF1, 0xEF, 0xEE)));
        Set(res, "CardBackgroundFillColorTertiaryBrush", fieldOverlay);
        Set(res, "CardStrokeColorDefaultBrush", stroke);
        Set(res, "ControlFillColorDefaultBrush", ctrlOverlay);
        Set(res, "ControlFillColorSecondaryBrush", ctrlOverlay);
        Set(res, "ControlStrokeColorDefaultBrush", stroke);
        Set(res, "ControlStrokeColorSecondaryBrush", stroke);
        // 按钮文字与描边：模板级资源写这里无效，改由 ApplyControlColors 逐控件下压
        Set(res, "TextOnAccentFillColorSecondaryBrush", text);
        Set(res, "TextOnAccentFillColorDisabledBrush", text2);
        Set(res, "TextFillColorPrimaryBrush", text);
        Set(res, "TextFillColorSecondaryBrush", text2);
        Set(res, "TextFillColorTertiaryBrush", text2);
        Set(res, "TextFillColorDisabledBrush", text2);
        // 控件内文字：浅色下不给会继承系统黑，深色下不给就压不出层次
        var white = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0xFF, 0xFF, 0xFF));
        Set(res, "TextOnAccentFillColorPrimaryBrush", white);
        // TextFillColorPrimaryInverse 不覆盖：它的语义是"反色底上的文字"，
        // 浅色档覆盖它容易出白字白底（黑白不一的典型来源），交给系统按主题解析
        // 强调色上的文字（运行/取消键、勾选框）在红底上必须够亮
        Set(res, "AccentTextFillColorPrimaryBrush", white);
        Set(res, "AccentTextFillColorSecondaryBrush", white);
        Set(res, "AccentTextFillColorTertiaryBrush", white);
        // 复选框勾选标记、文本选择高亮
        Set(res, "TextSelectionHighlightColorPrimaryBrush", red);
        Set(res, "TextSelectionHighlightColorSecondaryBrush", red);
        // 下拉/输入框的占位提示（截图里「留空 = 写到源文件目录」那类）
        Set(res, "TextFillColorPlaceholderBrush",
            new SolidColorBrush(Dark ? RGB(0x8A, 0x80, 0x7E) : RGB(0x8A, 0x81, 0x7F)));
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
        // 强调色上的文字必须保持白：这里若也刷成国旗红，
        // 单选项与勾选框的标签就变成「红底红字」，直接看不见。
        var onAccent = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0xFF, 0xFF, 0xFF));
        Set(res, "AccentTextFillColorPrimaryBrush", onAccent);
        Set(res, "AccentTextFillColorSecondaryBrush", onAccent);
        Set(res, "AccentTextFillColorTertiaryBrush", onAccent);
        Set(res, "AccentTextFillColorDisabledBrush", onAccent);

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
