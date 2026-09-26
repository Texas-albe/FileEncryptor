using Microsoft.UI.Xaml;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using System;
using System.IO;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

public sealed partial class ViewSettingsDialog : ContentDialog
{
    private readonly TextBox _bgPath;
    private readonly ImageBrush? _backgroundBrush;

    public ViewSettingsDialog(ImageBrush? backgroundBrush = null)
    {
        // 跟随主程序主题
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };
        Title = "视图设置";
        PrimaryButtonText = "保存";
        SecondaryButtonText = "取消";
        _backgroundBrush = backgroundBrush;

        var panel = new StackPanel { Spacing = 12, Width = 380 };

        // 背景图
        var bgLabel = new TextBlock { Text = "自定义背景图", FontWeight = FontWeights.Bold };
        _bgPath = new TextBox { PlaceholderText = "图片路径", Text = App.Settings.Current.CustomBackgroundPath ?? "" };
        var browseBtn = new Button { Content = "浏览..." };
        browseBtn.Click += async (_, _) =>
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow!);
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
            picker.FileTypeFilter.Add(".png");
            picker.FileTypeFilter.Add(".jpg");
            picker.FileTypeFilter.Add(".jpeg");
            picker.FileTypeFilter.Add(".bmp");
            picker.FileTypeFilter.Add(".webp");
            var file = await picker.PickSingleFileAsync();
            if (file != null) _bgPath.Text = file.Path;
        };
        var clearBtn = new Button { Content = "清除背景" };
        clearBtn.Click += (_, _) => { _bgPath.Text = ""; };
        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        btnPanel.Children.Add(browseBtn);
        btnPanel.Children.Add(clearBtn);
        var bgPanel = new StackPanel { Spacing = 4 };
        bgPanel.Children.Add(bgLabel);
        bgPanel.Children.Add(_bgPath);
        bgPanel.Children.Add(btnPanel);
        panel.Children.Add(bgPanel);

        // 提示
        var hint = new TextBlock
        {
            Text = "支持 PNG / JPG / BMP / WebP 格式。",
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray)
        };
        panel.Children.Add(hint);

        Content = panel;

        PrimaryButtonClick += (_, _) =>
        {
            var path = string.IsNullOrEmpty(_bgPath.Text) ? null : _bgPath.Text.Trim();
            App.Settings.Current.CustomBackgroundPath = path;
            App.Settings.Save();
            ApplyBackground(path);
        };
    }

    private void ApplyBackground(string? path)
    {
        if (_backgroundBrush == null) return;
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            _backgroundBrush.ImageSource = null;
            return;
        }
        try
        {
            var bitmap = new BitmapImage();
            bitmap.UriSource = new Uri(path);
            _backgroundBrush.ImageSource = bitmap;
            _backgroundBrush.Stretch = Stretch.UniformToFill;
            _backgroundBrush.Opacity = 1.0;
        }
        catch { /* 图片加载失败忽略 */ }
    }
}
