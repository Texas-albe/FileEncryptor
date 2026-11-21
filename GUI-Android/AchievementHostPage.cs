using Microsoft.Maui.Controls;

namespace FileEncryptorMobile;

// 覆盖层宿主 承载外壳与成就通知
public sealed class AchievementHostPage : ContentPage
{
    public VerticalStackLayout ToastStack { get; }

    public AchievementHostPage(Page shell)
    {
        // 点击穿透 别挡操作 妈的
        ToastStack = new VerticalStackLayout
        {
            Spacing = 8,
            Margin = new Thickness(0, 16, 16, 0),
            HorizontalOptions = LayoutOptions.End,
            VerticalOptions = LayoutOptions.Start,
            InputTransparent = true
        };
        var toastArea = new Grid { InputTransparent = true };
        toastArea.Children.Add(ToastStack);
        Content = new Grid { Children = { shell, toastArea } };
    }
}
