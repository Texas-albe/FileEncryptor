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
        // 进程加固
        Services.ProcessHardening.HardenImageLoad();   // P1-2 禁远程/低 IL 镜像
        Services.ProcessHardening.Harden();            // P0-1 收紧进程对象 DACL
        Services.ProcessHardening.DisableCrashDump();  // P1-3 排除出 WER
        InitializeComponent();
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            // 仅记录异常类型
            if (e.ExceptionObject is Exception ex)
                WriteCrashLog($"UnhandledException: {ex.GetType().Name}: {ex.Message}");
            else
                WriteCrashLog("UnhandledException: non-Exception payload");
        };
        UnhandledException += (s, e) =>
        {
            // 只记异常类型名
            WriteCrashLog("XamlUnhandledException: " + (e.Exception != null
                ? $"{e.Exception.GetType().Name}: {e.Exception.Message}"
                : "null"));
            e.Handled = true;
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            // 顺序要紧
            // 控件模板里
            // 放到 MainWindow 构造
            Services.NationalDayTheme.ApplyThemeOverrides();
            // 成就加载与解锁弹窗
            Services.AchievementService.Instance.Load();
            Services.AchievementService.Instance.Unlocked += def =>
            {
                var lang = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
                Services.AchievementToastManager.Instance.Show(def, lang);
            };
            MainWindow = new FileEncryptorGUI.MainWindow();
            MainWindow.Activate();
            // SystemBackdrop 必须
            // 构造函数阶段 DWM
            // 文件关联
            if (MainWindow is FileEncryptorGUI.MainWindow mw)
            {
                mw.ApplyBackdrop();
                mw.AddFilesFromCommandLine(Environment.GetCommandLineArgs().Skip(1));
            }
            // 主题取用户
            Theme.ApplyTheme(Settings.Current.Theme);

            // P2 调试检测
            if (Services.ProcessHardening.IsDebuggerAttached())
                _ = ShowDebuggerWarningAsync();
        }
        catch (Exception ex)
        {
            WriteCrashLog($"OnLaunched Exception: {ex.GetType().Name}: {ex.Message}");
            throw;
        }
    }

    // P2 调试器告警
    private async System.Threading.Tasks.Task ShowDebuggerWarningAsync()
    {
        try
        {
            await System.Threading.Tasks.Task.Delay(800);   // 等主窗口稳定
            var dlg = new Microsoft.UI.Xaml.Controls.ContentDialog
            {
                Title = Services.L10n.T("检测到调试器"),
                Content = new Microsoft.UI.Xaml.Controls.TextBlock
                {
                    Text = Services.L10n.T("检测到有调试器附加到本程序。若非你本人操作，请立即退出并检查系统安全；程序功能不受影响。"),
                    TextWrapping = Microsoft.UI.Xaml.TextWrapping.Wrap,
                },
                CloseButtonText = Services.L10n.T("关闭"),
                XamlRoot = MainWindow?.Content?.XamlRoot,
            };
            await dlg.ShowAsync();
        }
        catch { }
    }
}
