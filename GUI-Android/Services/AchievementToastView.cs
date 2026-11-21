using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;

namespace FileEncryptorMobile.Services;

// 通知卡 又他妈来一遍
public sealed class AchievementToastView : ContentView
{
    private const int CardW = 288;
    private const int HoldMs = 2400;
    private readonly CancellationTokenSource _cts = new();

    public event Action<AchievementToastView>? Expired;

    public AchievementToastView(AdvDef def, string lang)
    {
        var disp = def.Display;
        WidthRequest = CardW;
        HeightRequest = 72; // 目测60就够 多了浪费
        InputTransparent = true;

        var icon = new Label
        {
            Text = IconFor(disp?.Icon ?? ""),
            FontSize = 24,
            TextColor = Color.FromArgb("#E0C878"),
            WidthRequest = 44,
            HeightRequest = 44,
            HorizontalTextAlignment = TextAlignment.Center,
            VerticalTextAlignment = TextAlignment.Center,
            BackgroundColor = Color.FromArgb("#12FFFFFF")
        };

        var bar = new Rectangle
        {
            WidthRequest = 3,
            Margin = new Thickness(0, 6, 12, 6),
            VerticalOptions = LayoutOptions.Fill,
            Fill = FrameBrush(disp?.Frame ?? "task")
        };

        var badge = new Label { Text = "成就已解锁", FontSize = 11, TextColor = Color.FromArgb("#9A9A9A") };
        var title = new Label
        {
            Text = disp?.Title.Of(lang) ?? def.Id,
            FontSize = 14, TextColor = Colors.White, LineBreakMode = LineBreakMode.TailTruncation
        };
        var desc = new Label
        {
            Text = disp?.Description.Of(lang) ?? "",
            FontSize = 12, TextColor = Color.FromArgb("#B5B5B5"), MaxLines = 2
        };
        var texts = new VerticalStackLayout { Spacing = 2, VerticalOptions = LayoutOptions.Center };
        texts.Children.Add(badge);
        texts.Children.Add(title);
        texts.Children.Add(desc);

        var row = new HorizontalStackLayout { Spacing = 12, Padding = new Thickness(14, 10, 12, 10) };
        row.Children.Add(icon);
        row.Children.Add(bar);
        row.Children.Add(texts);

        Content = new Border
        {
            StrokeShape = new RoundRectangle { CornerRadius = 10 },
            BackgroundColor = Color.FromArgb("#E8141418"),
            Stroke = Color.FromArgb("#2AFFFFFF"),
            StrokeThickness = 1,
            Content = row
        };

        TranslationX = CardW + 34;
        Opacity = 0;
    }

    // 三种颜色 鬼知道哪抄的
    private static Brush FrameBrush(string frame)
    {
        var c = frame switch
        {
            "goal" => "#80C860",
            "challenge" => "#B878D0",
            _ => "#68A8C8"
        };
        return new SolidColorBrush(Color.FromArgb(c));
    }

    private static string IconFor(string name) => name switch
    {
        "lock" or "unlock" => "\u25A3",
        "drive" => "\u25A4",
        "vault" => "\u25C6",
        _ => "\u25C6"
    };

    public void Play() => _ = Run();

    private async Task Run()
    {
        await this.FadeTo(1, 200);
        // 滑入过冲回弹 妈的调了八百遍
        await this.TranslateTo(0, 0, 360, Easing.CubicOut);
        await this.TranslateTo(-14, 0, 103);
        await this.TranslateTo(4, 0, 72);
        await this.TranslateTo(0, 0, 115);
        try { await Task.Delay(HoldMs, _cts.Token); }
        catch (TaskCanceledException) { return; }
        await this.TranslateTo(CardW + 44, 0, 420, Easing.CubicIn);
        // 淡入 慢一点
        await this.FadeTo(0, 300);
        Expired?.Invoke(this);
    }

    public void Cancel() => _cts.Cancel();
}
