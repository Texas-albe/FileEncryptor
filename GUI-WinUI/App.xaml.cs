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
        catch { /* 日志写入失败不能阻塞崩溃处理 */ }
    }

    public App()
    {
        InitializeComponent();
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            WriteCrashLog($"UnhandledException: {e.ExceptionObject}");
        };
        UnhandledException += (s, e) =>
        {
            WriteCrashLog($"XamlUnhandledException: {e.Exception}\nMessage: {e.Message}");
            e.Handled = true;
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            Settings.Current.Theme = Services.AppTheme.Dark;
            MainWindow = new MainWindow();
            MainWindow.Activate();
            Theme.ApplyTheme(Services.AppTheme.Dark);
        }
        catch (Exception ex)
        {
            WriteCrashLog($"OnLaunched Exception: {ex}");
            throw;
        }
    }
}
