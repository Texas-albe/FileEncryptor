using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace FileEncryptorGUI.Services;

public class ThemeService
{
    public event Action<AppTheme>? ThemeChanged;

    public void ApplyTheme(AppTheme theme)
    {
        if (App.MainWindow?.Content is FrameworkElement fe)
        {
            fe.RequestedTheme = theme switch
            {
                AppTheme.Light => ElementTheme.Light,
                AppTheme.Dark => ElementTheme.Dark,
                _ => ElementTheme.Default
            };
        }
        ThemeChanged?.Invoke(theme);
    }

    public static bool IsSystemDark()
    {
        var appsUseLightTheme = Microsoft.Win32.Registry.CurrentUser
            .OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            ?.GetValue("AppsUseLightTheme");
        return appsUseLightTheme is 0;
    }

    // 代码创建
    public static Brush BrushFor(string key, ElementTheme requested)
    {
        var theme = requested switch
        {
            ElementTheme.Light => "Light",
            ElementTheme.Dark => "Dark",
            _ => IsSystemDark() ? "Dark" : "Light",
        };
        var app = Application.Current;
        if (app != null &&
            app.Resources.ThemeDictionaries.TryGetValue(theme, out var value) &&
            value is ResourceDictionary dict &&
            dict.TryGetValue(key, out var brush) &&
            brush is Brush b)
            return b;
        return new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    // 代码创建
    public static Style? StyleFor(string key)
    {
        var app = Application.Current;
        if (app != null && app.Resources.TryGetValue(key, out var value) && value is Style style)
            return style;
        return null;
    }
}
