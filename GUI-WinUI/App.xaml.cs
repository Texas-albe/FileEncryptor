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
            // 顺序要紧：资源覆盖必须在控件加载之前做完。
            // 控件模板里的 {ThemeResource} 只在解析那一刻取一次值，
            // 放到 MainWindow 构造之后覆盖资源字典，界面会一半深一半浅。
            Services.NationalDayTheme.ApplyThemeOverrides();
            MainWindow = new FileEncryptorGUI.MainWindow();
            MainWindow.Activate();
            // SystemBackdrop 必须在窗口激活之后再设：
            // 构造函数阶段 DWM 还没拿到窗口句柄，会被静默丢弃（表现为设了却完全不透明）
            if (MainWindow is FileEncryptorGUI.MainWindow mw) mw.ApplyBackdrop();
            // 主题取用户在「视图」菜单里的选择，不再每次启动强制覆写
            Theme.ApplyTheme(Settings.Current.Theme);
        }
        catch (Exception ex)
        {
            WriteCrashLog($"OnLaunched Exception: {ex.GetType().Name}: {ex.Message}");
            throw;
        }
    }
}
