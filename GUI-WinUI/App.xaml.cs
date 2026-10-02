using Microsoft.UI.Xaml;
using System;
using System.IO;

namespace FileEncryptorGUI;

public partial class App : Application
{
    public static Window? MainWindow { get; private set; }
    public static Services.SettingsService Settings { get; } = new();
    public static Services.ThemeService Theme { get; } = new();

    private static readonly string CrashLogDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "FileEncryptor", "GUI");
    private static readonly string CrashLogPath = Path.Combine(CrashLogDir, "crash.log");

    private static void WriteCrashLog(string message)
    {
        try
        {
            Directory.CreateDirectory(CrashLogDir);
            File.WriteAllText(CrashLogPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n{message}\n");
        }
        catch {  }
    }

    public App()
    {
        InitializeComponent();
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            // 仅记录异常类型与消息
            if (e.ExceptionObject is Exception ex)
                WriteCrashLog($"UnhandledException: {ex.GetType().Name}: {ex.Message}");
            else
                WriteCrashLog("UnhandledException: non-Exception payload");
        };
        UnhandledException += (s, e) =>
        {
            // XAML 解析失败只给一行消息时没法定位，这里连 inner exception 与栈一起落盘。
            WriteCrashLog("XamlUnhandledException: " + (e.Exception?.ToString() ?? "null"));
            e.Handled = true;
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            // 固定深色主题
            Settings.Current.Theme = Services.AppTheme.Dark;
            // 国庆节主题（节日窗口生效）
            Services.NationalDayTheme.ApplyThemeOverrides();
            MainWindow = new MainWindow();
            MainWindow.Activate();
            Theme.ApplyTheme(Services.AppTheme.Dark);
        }
        catch (Exception ex)
        {
            WriteCrashLog($"OnLaunched Exception: {ex.GetType().Name}: {ex.Message}");
            throw;
        }
    }
}
