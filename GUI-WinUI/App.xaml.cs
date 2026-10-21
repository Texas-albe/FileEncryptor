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
        // 进程加固（顺序要紧：加载策略须早于任何非系统 DLL 加载）
        Services.ProcessHardening.HardenImageLoad();   // P1-2 禁远程/低 IL 镜像
        Services.ProcessHardening.Harden();            // P0-1 收紧进程对象 DACL
        Services.ProcessHardening.DisableCrashDump();  // P1-3 排除出 WER，不产生崩溃转储
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
            // 只记异常类型名与消息：完整 ToString() 含调用栈与本地路径，落入 crash.log 反而造成信息泄漏
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

            // P2 调试检测：仅告警，不阻断使用（Attach 调试属正常开发行为，不能拦）
            if (Services.ProcessHardening.IsDebuggerAttached())
                _ = ShowDebuggerWarningAsync();
        }
        catch (Exception ex)
        {
            WriteCrashLog($"OnLaunched Exception: {ex.GetType().Name}: {ex.Message}");
            throw;
        }
    }

    // P2 调试器告警：非阻塞提示，用户关掉即可继续使用
    private async System.Threading.Tasks.Task ShowDebuggerWarningAsync()
    {
        try
        {
            await System.Threading.Tasks.Task.Delay(800);   // 等主窗口稳定，避免抢焦点
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
