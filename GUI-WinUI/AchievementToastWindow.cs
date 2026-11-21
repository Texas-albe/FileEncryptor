using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using System;
using System.Numerics;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 成就Toast 纯代码 XAML编译器去死
public sealed class AchievementToastWindow : Window
{
    private const int CardW = 312;
    private const int CardH = 76;
    private const int Margin = 16;
    private const int HoldMs = 2400;

    private readonly int _slot;
    private readonly DispatcherTimer _timer;
    private readonly Visual _rootVisual;
    private bool _out;

    public event Action<AchievementToastWindow>? Expired;

    public AchievementToastWindow(AdvDef def, string lang, int slot)
    {
        _slot = slot;
        var disp = def.Display;
        var title = disp?.Title.Of(lang) ?? def.Id;
        // 过冲14 回弹5 谁写对了谁上
        var desc = disp?.Description.Of(lang) ?? "";

        var icon = new FontIcon { Glyph = IconFor(disp?.Icon ?? ""), FontSize = 22,
            Foreground = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 224, 200, 120)) };
        var iconBox = new Grid { Width = 44, Height = 44, CornerRadius = new CornerRadius(8),
            Background = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(18, 255, 255, 255)) };
        iconBox.Children.Add(icon);

        var bar = new Microsoft.UI.Xaml.Shapes.Rectangle {
            Width = 3, RadiusX = 1.5, RadiusY = 1.5, Margin = new Thickness(0, 6, 12, 6),
            VerticalAlignment = VerticalAlignment.Stretch, Fill = FrameBrush(disp?.Frame ?? "task") };

        var badge = new TextBlock { Text = "成就已解锁", FontSize = 11,
            Foreground = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 154, 154, 154)) };
        var titleText = new TextBlock { Text = title, FontSize = 14,
            Foreground = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 255, 255, 255)) };
        var descText = new TextBlock { Text = desc, FontSize = 12, TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 181, 181, 181)) };
        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 2 };
        texts.Children.Add(badge);
        texts.Children.Add(titleText);
        texts.Children.Add(descText);

        var cols = new Grid();
        cols.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        cols.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        cols.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(iconBox, 0);
        Grid.SetColumn(bar, 1);
        Grid.SetColumn(texts, 2);
        cols.Children.Add(iconBox);
        cols.Children.Add(bar);
        cols.Children.Add(texts);

        var border = new Border { CornerRadius = new CornerRadius(10),
            Background = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(232, 16, 16, 20)),
            BorderBrush = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(42, 255, 255, 255)),
            BorderThickness = new Thickness(1), Padding = new Thickness(14, 12, 14, 12) };
        border.Child = cols;

        var root = new Grid { Background = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(0, 0, 0, 0)) };
        root.Children.Add(border);
        Content = root;

        _rootVisual = ElementCompositionPreview.GetElementVisual(root);
        SetupWindow();
        Activate();
        PlaceWindow(slot);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(HoldMs) };
        _timer.Tick += (_, _) => { _timer.Stop(); AnimateOut(); };
        root.PointerEntered += (_, _) => _timer.Stop();
        root.PointerExited += (_, _) => { if (!_out) _timer.Start(); };
    }

    private static Brush FrameBrush(string frame) => frame switch
    {
        "goal" => new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 128, 200, 96)),
        "challenge" => new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 184, 120, 208)),
        _ => new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 104, 168, 200))
    };

    // 这堆图标码 他妈的试了半天
    private static string IconFor(string name) => name switch
    {
        "lock" => "\uE72E",
        "unlock" => "\uE785",
        "drive" => "\uE7C9",
        "vault" => "\uE1F6",
        _ => "\uE734"
    };

    private void SetupWindow()
    {
        if (AppWindow.Presenter is OverlappedPresenter p)
        {
            p.SetBorderAndTitleBar(false, false);
            p.IsAlwaysOnTop = true;
            p.IsMinimizable = false;
            p.IsMaximizable = false;
            p.IsResizable = false;
        }
    }

    private void PlaceWindow(int slot)
    {
        var area = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Nearest);
        var work = area?.WorkArea ?? new Windows.Graphics.RectInt32(0, 0, 1920, 1080);
        // 贴左边 别动
        int x = work.X + work.Width - CardW - Margin;
        int y = work.Y + Margin + slot * (CardH + 8);
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(x, y, CardW, CardH));
    }

    public void SetSlot(int slot) { if (!_out) PlaceWindow(slot); }

    public void Play() { Activate(); AnimateIn(); }

    private void AnimateIn()
    {
        var compositor = _rootVisual.Compositor;
        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.Target = "Translation";
        anim.InsertKeyFrame(0f, new Vector3(CardW + 34, -12, 0));
        anim.InsertKeyFrame(0.55f, Vector3.Zero);
        anim.InsertKeyFrame(0.71f, new Vector3(-14, 0, 0));
        anim.InsertKeyFrame(0.82f, new Vector3(4, 0, 0));
        anim.InsertKeyFrame(0.92f, Vector3.Zero);
        anim.InsertKeyFrame(1f, Vector3.Zero);
        // 650 别改 改了就抖
        anim.Duration = TimeSpan.FromMilliseconds(650);

        var opacity = compositor.CreateScalarKeyFrameAnimation();
        opacity.Target = "Opacity";
        opacity.InsertKeyFrame(0f, 0f);
        opacity.InsertKeyFrame(0.2f, 1f);
        opacity.Duration = TimeSpan.FromMilliseconds(200);

        var batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        _rootVisual.StartAnimation("Translation", anim);
        _rootVisual.StartAnimation("Opacity", opacity);
        batch.End();
        batch.Completed += (_, _) => _timer.Start();
    }

    private void AnimateOut()
    {
        if (_out) return;
        _out = true;
        var compositor = _rootVisual.Compositor;
        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.Target = "Translation";
        anim.InsertKeyFrame(0f, Vector3.Zero);
        anim.InsertKeyFrame(0.1f, Vector3.Zero);
        anim.InsertKeyFrame(1f, new Vector3(CardW + 44, 0, 0));
        // 立刻收 不等动画
        anim.Duration = TimeSpan.FromMilliseconds(420);

        var opacity = compositor.CreateScalarKeyFrameAnimation();
        opacity.Target = "Opacity";
        opacity.InsertKeyFrame(0f, 1f);
        opacity.InsertKeyFrame(1f, 0f);
        opacity.Duration = TimeSpan.FromMilliseconds(420);

        var batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        _rootVisual.StartAnimation("Translation", anim);
        _rootVisual.StartAnimation("Opacity", opacity);
        batch.End();
        batch.Completed += (_, _) => Expired?.Invoke(this);
    }

    public void CloseNow()
    {
        _timer.Stop();
        Close();
    }
}
