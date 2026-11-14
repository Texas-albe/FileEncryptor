using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 可滚动
// 内容超出可视区
public sealed partial class ScrollOutputDialog : ContentDialog
{
    public ScrollOutputDialog(string title, string body, bool monospace = true)
    {
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };

        var tb = new TextBlock
        {
            Text = string.IsNullOrEmpty(body) ? L10n.T("（无输出）") : body,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
        };
        if (monospace)
            tb.FontFamily = new FontFamily("Consolas, Cascadia Mono, Microsoft YaHei Mono, monospace");

        var scroller = new ScrollViewer
        {
            Content = tb,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            MaxHeight = 480,
            // 横向滚动条是浮
            Padding = new Thickness(0, 4, 0, 16),
        };

        Content = scroller;
        Title = title;
        CloseButtonText = L10n.T("关闭");
        XamlRoot = ((MainWindow)App.MainWindow!).Content.XamlRoot;
    }
}
