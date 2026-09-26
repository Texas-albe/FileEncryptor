using Microsoft.UI.Xaml;

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
}
