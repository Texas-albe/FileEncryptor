using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using System;

namespace FileEncryptorGUI;

public sealed partial class TaskNotificationWindow : Window
{
    private const int Margin = 24;
    private const int AutoCloseMs = 3000;

    public TaskNotificationWindow(string message)
    {
        InitializeComponent();
        MessageText.Text = message;

        // Acrylic 背景
        SystemBackdrop = new DesktopAcrylicBackdrop();

        // 完全移除标题栏和边框（无系统按钮、无边框）
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.SetBorderAndTitleBar(hasBorder: false, hasTitleBar: false);
            presenter.IsAlwaysOnTop = true;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
            presenter.IsResizable = false;
        }

        // 定位到屏幕右下角
        var displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Nearest);
        var work = displayArea.WorkArea;
        int x = work.X + work.Width - 300 - Margin;
        int y = work.Y + work.Height - 75 - Margin;
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(x, y, 300, 75));

        // 退出动画结束后关闭
        ExitStoryboard.Completed += (_, _) => Close();

        // 进入动画
        EnterStoryboard.Begin();

        // 3 秒后退出
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(AutoCloseMs) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            ExitStoryboard.Begin();
        };
        timer.Start();
    }
}
