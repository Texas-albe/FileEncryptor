using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using FileEncryptorGUI.Services;
using FileEncryptorGUI.Models;
using FileEncryptorGUI.ViewModels;

namespace FileEncryptorGUI;

public sealed partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; } = new();
    private readonly ImageBrush _backgroundBrush = new();

    private ElementTheme CurrentTheme => App.Settings.Current.Theme switch
    {
        Services.AppTheme.Light => ElementTheme.Light,
        Services.AppTheme.Dark => ElementTheme.Dark,
        _ => ElementTheme.Default
    };
    public MainWindow()
    {
        InitializeComponent();

        // 主题要在控件加载前定死：控件模板里的 {ThemeResource} 只在解析那一刻取值，
        // 事后再改 RequestedTheme 只影响之后创建的控件，
        // 表现就是「一部分控件换了配色，另一部分还是旧的」。
        RootGrid.RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ThemeService.IsSystemDark() ? ElementTheme.Dark : ElementTheme.Light
        };

        // 先初始化语言再翻译界面
        L10n.Init();
        ApplyLocalization();

        Title = $"FileEncryptorGUI {FileEncryptorLocator.GuiVersion}";
        TitleText.Text = Title;

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(DragRegion);
        var tb = AppWindow.TitleBar;
        // 标题栏必须整体透明，否则 SystemBackdrop 的Acrylic 只在内容区生效，
        // 顶部会留一条不透明带，看起来就像「没生效」
        tb.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
        tb.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        tb.ButtonHoverBackgroundColor = Windows.UI.Color.FromArgb(0x20, 0, 0, 0);
        tb.ButtonPressedBackgroundColor = Windows.UI.Color.FromArgb(0x30, 0, 0, 0);
        UpdateTitleBarButtonColors();

        // 16:9 窗口比例。横向加宽给功能区更多余量，英文/俄文选项不再挤成滚动条
        const int kWinW = 1440;
        const int kWinH = kWinW * 9 / 16;
        AppWindow.Resize(new Windows.Graphics.SizeInt32(kWinW, kWinH));

        // 勾选框初值一律在代码里设：XAML 里写 IsChecked="..." 会让 XamlCompiler 生成
        // 对 Primitives.ToggleButton.IsChecked 的赋值，运行时对 CheckBox 赋值抛
        // XamlParseException，InitializeComponent 阶段直接把进程干掉（0xC000027B）。
        ChkForce.IsChecked = true;
        ChkPqc.IsChecked = true;
        RbEncrypt.IsChecked = true;
        FileCipherCombo.SelectedIndex = 0;

        // 背景优先级：图片 > Acrylic
        RootGrid.Background = _backgroundBrush;
        ApplySavedBackground();

        // 国庆配色不在这里刷：面板 Acrylic 依赖窗口 backdrop，
        // 构造函数阶段还没就绪，交给 ApplyBackdrop() 在 Activate() 之后统一做。
        ModeCombo.SelectedIndex = 0;
        SourceCombo.SelectedIndex = 0;
        WrapAlgCombo.SelectedIndex = 0;

        // 加密盘目录默认填上次用的那块盘：挂载/锁定/解锁菜单与「入加密盘」都指向它
        var lastVault = (App.Settings.Current.LastVaultDir ?? "").Trim();
        if (lastVault.Length > 0 && Directory.Exists(lastVault)) VaultDirEdit.Text = lastVault;

        try {
            var iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
            if (System.IO.File.Exists(iconPath))
                this.AppWindow.SetIcon(iconPath);
        } catch {  }

        RootGrid.Loaded += OnFirstLoaded;

        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ViewModel.IsRunning))
            {
                BtnRun.IsEnabled = !ViewModel.IsRunning;
                BtnCancel.IsEnabled = ViewModel.IsRunning;
            }
            else if (e.PropertyName == nameof(ViewModel.ActionIndex))
            {
                RbEncrypt.IsChecked = ViewModel.ActionIndex == 0;
                RbDecrypt.IsChecked = ViewModel.ActionIndex == 1;
                RbBatchEncrypt.IsChecked = ViewModel.ActionIndex == 2;
                RbBatchDecrypt.IsChecked = ViewModel.ActionIndex == 3;
                RbKeyGen.IsChecked = ViewModel.ActionIndex == 4;
                RbDerive.IsChecked = ViewModel.ActionIndex == 5;
                RbPubKey.IsChecked = ViewModel.ActionIndex == 6;
                RbWrapKey.IsChecked = ViewModel.ActionIndex == 7;
                RbUnwrapKey.IsChecked = ViewModel.ActionIndex == 8;
            }
        };

        // 加密盘能力探测完成（VaultAvailable 变化）后重算可见性，免得入加密盘选项要切模式才出现
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ViewModel.VaultAvailable) ||
                e.PropertyName == nameof(ViewModel.VaultRwAvailable))
                UpdateVisibility();
        };

        // 旧 CLI 不支持包装动作时禁用两个单选，并把停用原因写进提示
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(ViewModel.KeywrapAvailable)) return;
            RbWrapKey.IsEnabled = ViewModel.KeywrapAvailable;
            RbUnwrapKey.IsEnabled = ViewModel.KeywrapAvailable;
            if (ViewModel.KeywrapAvailable)
            {
                // 可用时保留说明性提示（随语言切换由 LocalizeTree 翻译）
                ToolTipService.SetToolTip(RbWrapKey, L10n.T("把一份 32 字节的数据密钥单独包进 .fekw 文件，用密码或收件人公钥保护"));
                ToolTipService.SetToolTip(RbUnwrapKey, L10n.T("把 .fekw 里的数据密钥还原成 32 字节文件"));
            }
            else
            {
                var tip = L10n.T("配套的命令行程序没有密钥包装能力，请更换带 OpenSSL 的 CLI");
                ToolTipService.SetToolTip(RbWrapKey, tip);
                ToolTipService.SetToolTip(RbUnwrapKey, tip);
            }
            // 勾中的那个要主动切走，否则界面停用却仍能点运行
            if (!ViewModel.KeywrapAvailable && (RbWrapKey.IsChecked == true || RbUnwrapKey.IsChecked == true))
            {
                RbWrapKey.IsChecked = false;
                RbUnwrapKey.IsChecked = false;
                RbEncrypt.IsChecked = true;
            }
        };

        ViewModel.PasswordRequested += OnPasswordRequested;
        ViewModel.ConfirmPromptRequested += OnConfirmPromptRequested;
        ViewModel.TaskCompleted += OnTaskCompleted;
        ViewModel.TaskSummary += OnTaskSummary;
        this.Closed += (_, _) => App.Settings.Save();
    }

    // ===== 多语言 =====

    private void ApplyLocalization()
    {
        ApplyMenuLocalization();
        // 中文时 T() 原样返回，遍历无害；保证从英文切回也能还原
        LocalizeTree(RootGrid);
        ApplyRowOrientation();
        RefreshBirthdayText();
        ViewModel.RefreshRuntimeTexts();
    }

    // 祝福语带 {0} 年龄占位，LocalizeTree 只能翻译出模板，
    // 这里在遍历之后再把年龄填回去，否则界面会露出 {0}
    private void RefreshBirthdayText()
    {
        BirthdayText.Text = NationalDayTheme.BirthdayMessage();
    }

    // 同一行控件在英/俄文下比中文长得多，横排时给容器开横向滚动而不是改成竖排：
// 竖排会把选项挤成一条长列，比被裁更难看。中文窄文本下不会有滚动条。
    private void ApplyRowOrientation()
    {
        var h = Microsoft.UI.Xaml.Controls.Orientation.Horizontal;
        ActionRow.Orientation = h;
        KeyMgmtRow.Orientation = h;
        WrapRow.Orientation = h;
        OptionsRow.Orientation = h;
    }

    private void ApplyMenuLocalization()
    {
        MenuEdit.Title = L10n.T("编辑");
        MenuView.Title = L10n.T("视图");
        MenuTools.Title = L10n.T("工具");
        MenuAbout.Title = L10n.T("关于");
        MenuEditConfig.Text = L10n.T("编辑 CLI 配置");
        MenuViewSettings.Text = L10n.T("背景设置...");
        MenuRetryCli.Text = L10n.T("重新检测 CLI 程序");
        MenuCheckUpdate.Text = L10n.T("检查更新...");
        MenuCredits.Text = L10n.T("鸣谢...");
        MenuReadme.Text = L10n.T("README 摘要...");
        MenuLangZh.IsChecked = L10n.Current == L10n.Zh;
        MenuLangEn.IsChecked = L10n.Current == L10n.En;
        MenuLangRu.IsChecked = L10n.Current == L10n.Ru;
        MenuTheme.Text = L10n.T("主题");
        MenuThemeLight.Text = L10n.T("浅色");
        MenuThemeDark.Text = L10n.T("深色");
        MenuThemeSystem.Text = L10n.T("跟随系统");
        MenuVault.Text = L10n.T("加密盘");
        MenuVaultInit.Text = L10n.T("新建加密盘...");
        MenuVaultList.Text = L10n.T("查看盘内文件...");
        MenuVaultRekey.Text = L10n.T("修改加密盘密码...");
        MenuVaultRecoveryCreate.Text = L10n.T("生成恢复码...");
        MenuVaultRecoveryOpen.Text = L10n.T("用恢复码找回密码...");
        MenuVaultMount.Text = L10n.T("挂载为磁盘...");
        MenuVaultLock.Text = L10n.T("暂时锁定");
        MenuVaultUnlock.Text = L10n.T("重新解锁...");
        SyncThemeMenuState();
    }

    // 视觉树走不到折叠元素，需按逻辑树下钻，否则英文下重启会中英混杂
    private static void LocalizeTree(Microsoft.UI.Xaml.DependencyObject root)
    {
        LocalizeElement(root);
        switch (root)
        {
            case Microsoft.UI.Xaml.Controls.Panel p:
                foreach (var c in p.Children) LocalizeTree(c);
                return;
            case Microsoft.UI.Xaml.Controls.Border b when b.Child != null:
                LocalizeTree(b.Child);
                return;
            case Microsoft.UI.Xaml.Controls.ContentControl cc when cc.Content is Microsoft.UI.Xaml.DependencyObject cd:
                LocalizeTree(cd);
                return;
            case Microsoft.UI.Xaml.Controls.ItemsControl ic:
                foreach (var it in ic.Items)
                    if (it is Microsoft.UI.Xaml.DependencyObject id) LocalizeTree(id);
                return;
        }
        var count = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < count; i++)
            LocalizeTree(Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(root, i));
    }

    private static void LocalizeElement(Microsoft.UI.Xaml.DependencyObject child)
    {
        switch (child)
        {
                case Microsoft.UI.Xaml.Controls.MenuBarItem mb:
                    mb.Title = L10n.T(mb.Title ?? "");
                    break;
                case Microsoft.UI.Xaml.Controls.MenuFlyoutItem mi:
                    mi.Text = L10n.T(mi.Text ?? "");
                    break;
                case Microsoft.UI.Xaml.Controls.TextBlock tb:
                    tb.Text = L10n.T(tb.Text ?? "");
                    break;
                case Microsoft.UI.Xaml.Controls.TextBox box:
                    box.PlaceholderText = L10n.T(box.PlaceholderText ?? "");
                    break;
                case Microsoft.UI.Xaml.Controls.PasswordBox pwb:
                    pwb.PlaceholderText = L10n.T(pwb.PlaceholderText ?? "");
                    break;
                case Microsoft.UI.Xaml.Controls.ContentControl cc when cc.Content is string s:
                    cc.Content = L10n.T(s);
                    break;
                // 下拉项未展开时不在视觉树中，需单独遍历 Items
                case Microsoft.UI.Xaml.Controls.ComboBox cb:
                    foreach (var item in cb.Items)
                    {
                        if (item is Microsoft.UI.Xaml.Controls.ComboBoxItem cbi && cbi.Content is string cs)
                            cbi.Content = L10n.T(cs);
                    }
                    break;
        }
        // 悬停提示是附加属性，所有 FrameworkElement 统一兜底翻译。
        // 不能放进上面 switch —— ComboBox/ContentControl 等命中自己的 case 后 break，
        // 会跳过最后的 FrameworkElement 分支，导致它们的 tooltip 一直漏翻。
        if (child is Microsoft.UI.Xaml.FrameworkElement fe)
        {
            var tip = fe.GetValue(Microsoft.UI.Xaml.Controls.ToolTipService.ToolTipProperty);
            if (tip is string ts)
                fe.SetValue(Microsoft.UI.Xaml.Controls.ToolTipService.ToolTipProperty, L10n.T(ts));
        }
    }

    private void OnLangZh(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.Zh);
    private void OnLangEn(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.En);
    private void OnLangRu(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.Ru);

    // 两个面板用 AcrylicBrush 做底：TintOpacity 比窗口底高，
    // 面板之间与窗口之间才有层次，但整体仍然通透。
    // 两个面板必须各拿一个独立实例：共用同一个 Brush 会被资源系统按共享引用处理，
    // 第二个面板拿不到自己的 Acrylic 采样，看起来就是「只有左panel 生效」。
    private void ApplyPanelBackdrops()
    {
        LeftPanel.Background = NationalDayTheme.PanelBackdropBrush();
        CenterPanel.Background = NationalDayTheme.PanelBackdropBrush();
    }

    // 标题红条：节日窗口上国旗红，平时透明
    private void ApplyTitleAccent()
    {
        TitleAccentBar.Background = NationalDayTheme.IsActive()
            ? new Microsoft.UI.Xaml.Media.SolidColorBrush(NationalDayTheme.AccentBar)
            : new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Transparent);
    }

    // ===== 主题 =====
    private void OnThemeLight(object sender, RoutedEventArgs e) => ChangeTheme(Services.AppTheme.Light);
    private void OnThemeDark(object sender, RoutedEventArgs e) => ChangeTheme(Services.AppTheme.Dark);
    private void OnThemeSystem(object sender, RoutedEventArgs e) => ChangeTheme(Services.AppTheme.System);

    private void ChangeTheme(Services.AppTheme theme)
    {
        if (App.Settings.Current.Theme == theme) { SyncThemeMenuState(); return; }
        App.Settings.Current.Theme = theme;
        App.Settings.Save();
        // 国庆配色按深浅档取值，切主题要重新覆盖资源并重刷按钮
        NationalDayTheme.Refresh();
        if (NationalDayTheme.IsActive())
        {
            NationalDayTheme.ApplyButtonColors(BtnRun, BtnCancel);
            ApplyTitleAccent();
            NationalDayTheme.ApplyControlColors(RootGrid);
        }
        // 面板与窗口底都随深浅档换tint
        ApplyPanelBackdrops();
        if (_backgroundBrush.ImageSource == null)
            RootGrid.Background = NationalDayTheme.WindowBackdropBrush();
        App.Theme.ApplyTheme(theme);
        // 预览窗是独立 Window，得单独跟着换（对话框都是新建时传 RequestedTheme，不受影响）
        _previewWindow?.ApplyTheme(CurrentTheme);
        SyncThemeMenuState();
        UpdateTitleBarButtonColors();
    }

    private void SyncThemeMenuState()
    {
        var cur = App.Settings.Current.Theme;
        MenuThemeLight.IsChecked = cur == Services.AppTheme.Light;
        MenuThemeDark.IsChecked = cur == Services.AppTheme.Dark;
        MenuThemeSystem.IsChecked = cur == Services.AppTheme.System;
    }

    private async void ChangeLanguage(string lang)
    {
        if (lang == L10n.Current) { ApplyMenuLocalization(); return; }
        L10n.Set(lang);
        ApplyLocalization();

        var dlg = new ContentDialog
        {
            Title = L10n.T("语言 / Language"),
            Content = L10n.T("语言已切换，界面已立即刷新。\nLanguage switched; the UI has been refreshed."),
            CloseButtonText = L10n.T("确定 / OK"),
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        await dlg.ShowAsync();
    }

    private void OnFirstLoaded(object sender, RoutedEventArgs e)
    {
        RootGrid.Loaded -= OnFirstLoaded;
        if (!ViewModel.DetectCli(out _))
            ShowCliNotFoundDialog();
        else
            ViewModel.RefreshCommandPreview();
        // 能力探测是异步的（--features 子进程），其结果决定「入加密盘」等选项的可见性。
        // 除 PropertyChanged 订阅外，窗口激活后再兜底刷几次可见性：
        // 探测完成时刻可能早于/晚于 XAML 初始布局，只靠事件容易漏一次重算。
        _ = RefreshVisibilityAfterProbeAsync();
    }

    // 启动后按固定间隔重算几次可见性，探测出 vault 能力后即收工。
    private async Task RefreshVisibilityAfterProbeAsync()
    {
        var dq = this.DispatcherQueue;
        if (dq == null) return;
        for (int i = 0; i < 5; ++i)
        {
            await Task.Delay(i == 4 ? 800 : 400);
            bool ran = false;
            dq.TryEnqueue(() => { UpdateVisibility(); ran = true; });
            await Task.Delay(50);
            if (ran && ViewModel.VaultAvailable) return;
        }
    }

    // ===== 动作 / 密钥管理 =====
    // 三组单选的 GroupName 各不相同，WinUI 只在同组内互斥，跨组要手工取消。
    // 被点亮的那组绝不能碰，否则调用方刚勾上的会被这里清掉。
    private const int GroupAction = 0;
    private const int GroupKeyMgmt = 1;
    private const int GroupWrap = 2;

    private void ExclusiveGroup(int keep)
    {
        if (keep != GroupAction)
        {
            RbEncrypt.IsChecked = false; RbDecrypt.IsChecked = false;
            RbBatchEncrypt.IsChecked = false; RbBatchDecrypt.IsChecked = false;
        }
        if (keep != GroupKeyMgmt)
        {
            RbKeyGen.IsChecked = false; RbDerive.IsChecked = false; RbPubKey.IsChecked = false;
        }
        if (keep != GroupWrap)
        {
            RbWrapKey.IsChecked = false; RbUnwrapKey.IsChecked = false;
        }
    }

    private void OnKeyMgmtRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbKeyGen.IsChecked != true && RbDerive.IsChecked != true && RbPubKey.IsChecked != true) return;
        ExclusiveGroup(GroupKeyMgmt);
        if (RbKeyGen.IsChecked == true) ViewModel.ActionIndex = 4;
        else if (RbDerive.IsChecked == true) ViewModel.ActionIndex = 5;
        else if (RbPubKey.IsChecked == true) ViewModel.ActionIndex = 6;
        UpdateVisibility();
    }

    private void OnWrapRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbWrapKey.IsChecked != true && RbUnwrapKey.IsChecked != true) return;
        ExclusiveGroup(GroupWrap);
        ViewModel.ActionIndex = RbWrapKey.IsChecked == true ? 7 : 8;
        UpdateVisibility();
    }

    private void OnWrapAlgChanged(object sender, SelectionChangedEventArgs e)
    {
        if (WrapAlgCombo.SelectedIndex >= 0) ViewModel.WrapAlgIndex = WrapAlgCombo.SelectedIndex;
        UpdateVisibility();
    }

    private void OnWrapInputChanged(object sender, TextChangedEventArgs e) => ViewModel.WrapInput = WrapFileEdit.Text;
    private void OnWrapOutputChanged(object sender, TextChangedEventArgs e) => ViewModel.WrapOutput = WrapOutEdit.Text;

    private void UpdateTitleBarButtonColors()
    {
        var tb = AppWindow.TitleBar;
        tb.ButtonForegroundColor = Microsoft.UI.Colors.White;
        tb.ButtonInactiveForegroundColor = Microsoft.UI.Colors.LightGray;
        tb.ButtonHoverForegroundColor = Microsoft.UI.Colors.White;
        tb.ButtonPressedForegroundColor = Microsoft.UI.Colors.White;
    }

    // ===== 任务完成通知 =====
    private void OnTaskCompleted(string message)
    {
        var notif = new TaskNotificationWindow(message);
        notif.Activate();
    }

    // ===== 任务汇总弹窗 =====
    private void OnTaskSummary(TaskSummaryInfo summary)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            var dlg = new TaskSummaryDialog(summary.Title, summary.Duration, summary.AvgSpeed, summary.EncryptedSize, summary.Done, summary.Skip, summary.Fail)
            {
                XamlRoot = Content.XamlRoot
            };
            _ = dlg.ShowAsync();
        });
    }


    // ===== CLI 未找到 =====
    private int _cliNotFoundRetries;
    private async void ShowCliNotFoundDialog()
    {
        if (Content?.XamlRoot == null)
        {
            if (++_cliNotFoundRetries > 5) return;
            DispatcherQueue.TryEnqueue(ShowCliNotFoundDialog);
            return;
        }
        _cliNotFoundRetries = 0;
        var names = FileEncryptorLocator.GetExpectedNames();
        var nameList = string.Join("\n", names.Select(n => "  • " + n));
        var panel = new StackPanel();
        var infoText = new TextBlock { Text = L10n.F("无法找到 FileEncryptor CLI 可执行文件\n\n程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。\n\n预期文件名：\n{0}\n\n当前程序目录：{1}", nameList, AppContext.BaseDirectory), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
        var statusText = new TextBlock { Text = "", Margin = new Thickness(0,8,0,0), Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray) };
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Margin = new Thickness(0,4,0,0) };
        panel.Children.Add(infoText); panel.Children.Add(statusText); panel.Children.Add(progress);
        // 三键：重试 / 下载 CLI / 关闭。ContentDialog 的排列固定是
        // Primary → Secondary → Close，所以下载键自然落在重试与关闭中间。
        var dlg = new ContentDialog { Title = L10n.T("FileEncryptor CLI 未找到"), Content = panel, PrimaryButtonText = L10n.T("重试"), SecondaryButtonText = L10n.T("下载 CLI"), CloseButtonText = L10n.T("关闭"), XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        var result = await dlg.ShowAsync();
        if (result == ContentDialogResult.Primary) { if (ViewModel.DetectCli(out _)) ViewModel.RefreshCommandPreview(); else ShowCliNotFoundDialog(); }
        else if (result == ContentDialogResult.Secondary) { await ShowDownloadCliDialog(); }
    }

    // 下载对话框：下载中不给任何按钮，装完自己关。
    private async System.Threading.Tasks.Task ShowDownloadCliDialog()
    {
        var statusText = new TextBlock { Text = L10n.T("准备下载…"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray) };
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Margin = new Thickness(0, 4, 0, 0) };
        var panel = new StackPanel();
        panel.Children.Add(statusText); panel.Children.Add(progress);
        var dlg = new ContentDialog
        {
            Title = L10n.T("下载 CLI"),
            Content = panel,
            CloseButtonText = L10n.T("关闭"),
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme
        };
        var downloading = DownloadCliFromGithub(statusText, progress);
        await dlg.ShowAsync();
        // 关窗往往早于下载完成，这里只顺手补一次检测：
        // 赶上了就刷新命令预览，没赶上用户再点一次「重新检测 CLI 程序」
        if (ViewModel.DetectCli(out var path))
        {
            ViewModel.SetStatus("已检测到 CLI: {0}", path);
            ViewModel.RefreshCommandPreview();
        }
        _ = downloading;
    }

    // 在tag 列表中定位精确 tag：命中返回索引，未找到返回 -1
    private static int IndexOfTag(System.Text.Json.JsonElement tags, string want)
    {
        var i = 0;
        foreach (var t in tags.EnumerateArray())
        {
            if (string.Equals(t.GetProperty("name").GetString(), want, StringComparison.Ordinal))
                return i;
            i++;
        }
        return -1;
    }

    // 从 GitHub 拉取配套 CLI 并落到程序目录：
    // 精确 tag → 平台匹配 → 域名白名单 → 文件名净化 → SHA256 → 落盘
    private async System.Threading.Tasks.Task DownloadCliFromGithub(TextBlock statusText, ProgressBar progress)
    {
        string? tempPath = null;
        try
        {
            statusText.Text = L10n.T("正在从 GitHub 检索可用版本…");
            using var http = new System.Net.Http.HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("FileEncryptorGUI");
            var tagsJson = await http.GetStringAsync("https://api.github.com/repos/Texas-albe/FileEncryptor/tags");
            using var tagsDoc = System.Text.Json.JsonDocument.Parse(tagsJson);
            // 只接受与预期版本精确配套的 tag；取「最大版本」会下到不匹配的 CLI
            var guiVer = FileEncryptorLocator.GuiVersion;
            var cliVer = FileEncryptorLocator.ExpectedCliVersion;
            var want = $"GUI{guiVer}_CLI{cliVer}";
            if (IndexOfTag(tagsDoc.RootElement, want) < 0)
            {
                statusText.Text = L10n.F("未找到预期的 CLI {0}（要求 tag GUI{1}_CLI{0}），已中止下载", cliVer, guiVer);
                return;
            }
            statusText.Text = L10n.F("找到 {0}，正在获取下载链接…", want);
            var relJson = await http.GetStringAsync($"https://api.github.com/repos/Texas-albe/FileEncryptor/releases/tags/{want}");
            using var relDoc = System.Text.Json.JsonDocument.Parse(relJson);
            string? downloadUrl = null;
            string? fileName = null;
            foreach (var a in relDoc.RootElement.GetProperty("assets").EnumerateArray())
            {
                var an = a.GetProperty("name").GetString();
                if (an != null && an.StartsWith("FileEncryptorCLI-", StringComparison.Ordinal)
                    && an.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                { downloadUrl = a.GetProperty("browser_download_url").GetString(); fileName = an; break; }
            }
            if (downloadUrl == null || fileName == null) { statusText.Text = L10n.T("未找到当前平台的 CLI 包"); return; }
            if (!IsAllowedDownloadHost(downloadUrl))
            {
                statusText.Text = L10n.T("下载链接域名不在白名单内，已中止");
                return;
            }

            // URL 不可信，文件名只取末段并查非法字符
            var safeName = Path.GetFileName(fileName.Trim());
            if (string.IsNullOrEmpty(safeName) || safeName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                statusText.Text = L10n.T("下载文件名非法，已中止");
                return;
            }
            fileName = safeName;

            statusText.Text = L10n.F("下载中：{0}", fileName);
            progress.Visibility = Visibility.Visible;
            tempPath = Path.Combine(Path.GetTempPath(), $"fe_cli_{Guid.NewGuid():N}.tmp");
            // 边下边写盘：几百 MB 的 CLI 全塞内存没必要，
            // 顺带让进度条是真的而不是先跳到 60% 再一次性到 100%
            using (var resp = await http.GetAsync(downloadUrl, System.Net.Http.HttpCompletionOption.ResponseHeadersRead))
            {
                resp.EnsureSuccessStatusCode();
                var total = resp.Content.Headers.ContentLength ?? 0L;
                if (total <= 0) progress.IsIndeterminate = true;
                using var src = await resp.Content.ReadAsStreamAsync();
                using var dst = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None);
                var buf = new byte[131072];
                long got = 0;
                var shownPct = -1;
                int n;
                while ((n = await src.ReadAsync(buf)) > 0)
                {
                    await dst.WriteAsync(buf.AsMemory(0, n));
                    got += n;
                    if (total <= 0) continue;
                    var pct = (int)(got * 100 / total);
                    if (pct != shownPct) { shownPct = pct; progress.Value = pct; }
                }
            }

            var expectedHash = await TryFetchSha256(http, downloadUrl);
            if (expectedHash != null)
            {
                using var sha = System.Security.Cryptography.SHA256.Create();
                using var fs = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var actualHash = Convert.ToHexString(await sha.ComputeHashAsync(fs)).ToLowerInvariant();
                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(tempPath); tempPath = null;
                    statusText.Text = L10n.T("SHA256 校验失败，下载内容已被丢弃");
                    return;
                }
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("CLI release 未提供 .sha256 清单，跳过完整性校验");
            }

            var savePath = Path.Combine(AppContext.BaseDirectory, fileName);
            try
            {
                File.Move(tempPath, savePath, overwrite: true);
            }
            catch (UnauthorizedAccessException)
            {
                // 装在 Program Files 下时没管理员权限就是这个异常
                statusText.Text = L10n.F("安装失败：程序目录不可写，请以管理员身份运行，或手动把文件放到：{0}", savePath);
                return;
            }
            tempPath = null;
            progress.IsIndeterminate = false;
            progress.Value = 100;
            statusText.Text = L10n.F("下载完成：{0}", fileName);
        }
        catch (Exception ex) { statusText.Text = L10n.F("下载失败：{0}", ex.Message); }
        finally
        {
            try { if (tempPath != null && File.Exists(tempPath)) File.Delete(tempPath); } catch { }
        }
    }

    // ===== 密码请求 =====
    private async void OnPasswordRequested()
    {
        var dlg = new PasswordDialog
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            NeedConfirm = ViewModel.PasswordNeedsConfirm
        };
        var result = await dlg.ShowAsync();
        if (result == ContentDialogResult.Primary && !string.IsNullOrEmpty(dlg.Password))
        {
            ViewModel.RunWithPassword(dlg.Password);
        }
    }

    // ===== 文件操作 =====
    private async void OnAddFiles(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var files = await picker.PickMultipleFilesAsync();
            if (files != null) ViewModel.AddInputPaths(files.Select(f => f.Path));
        }
        catch (Exception ex)
        {
            ViewModel.SetStatus("[添加文件] 错误: {0}", ex.Message);
        }
    }

    private async void OnAddDir(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FolderPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var folder = await picker.PickSingleFolderAsync();
            if (folder != null) ViewModel.AddInputPaths(new[] { folder.Path });
        }
        catch (Exception ex)
        {
            ViewModel.SetStatus("[添加目录] 错误: {0}", ex.Message);
        }
    }

    private void OnClearFiles(object sender, RoutedEventArgs e) => ViewModel.ClearInputPaths();

    private PreviewWindow? _previewWindow;

    private async void OnPreviewClicked(object sender, RoutedEventArgs e)
    {
        if (FileList.SelectedItem is null)
        {
            await new ContentDialog
            {
                Title = L10n.T("未选择文件"),
                Content = L10n.T("请先在列表里选中一个要预览的密文文件。"),
                CloseButtonText = L10n.T("关闭"),
                XamlRoot = Content.XamlRoot,
                RequestedTheme = CurrentTheme,
            }.ShowAsync();
            return;
        }

        var path = FileList.SelectedItem as string ?? FileList.SelectedItem.ToString();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            await new ContentDialog
            {
                Title = L10n.T("文件不存在"),
                Content = L10n.F("找不到该文件：\n{0}", path),
                CloseButtonText = L10n.T("关闭"),
                XamlRoot = Content.XamlRoot,
                RequestedTheme = CurrentTheme,
            }.ShowAsync();
            return;
        }

        // 预览是解密行为：加密/密钥动作下没有预览语义
        if (ViewModel.ActionIndex is not (1 or 3))
        {
            await new ContentDialog
            {
                Title = L10n.T("无法预览"),
                Content = L10n.T("预览仅适用于解密。请先将动作切换到「解密」或「批量解密」。"),
                CloseButtonText = L10n.T("关闭"),
                XamlRoot = Content.XamlRoot,
                RequestedTheme = CurrentTheme,
            }.ShowAsync();
            return;
        }

        // 与 Qt 侧同一判据：解密时填了私钥文件即非对称，不需要密码
        var identity = ViewModel.Identity?.Trim();
        byte[] password = Array.Empty<byte>();
        if (string.IsNullOrEmpty(identity))
        {
            var pwd = new PasswordDialog
            {
                XamlRoot = Content.XamlRoot,
                RequestedTheme = CurrentTheme,
                NeedConfirm = false   // 预览恒为解密
            };
            if (await pwd.ShowAsync() != ContentDialogResult.Primary) return;
            password = Encoding.UTF8.GetBytes(pwd.Password);
        }

        if (_previewWindow == null)
        {
            _previewWindow = new PreviewWindow();
            _previewWindow.NextRequested += () => PreviewNextFile();
        }
        _previewWindow.ShowFor(
            ViewModel.CliPath ?? "",
            path,
            password,
            System.IO.Path.GetFileName(path));
    }

    private void PreviewNextFile()
    {
        // 选中下一项再预览，让列表高亮跟着走
        var idx = FileList.SelectedIndex;
        if (idx < 0 || idx + 1 >= FileList.Items.Count) return;
        FileList.SelectedIndex = idx + 1;
        OnPreviewClicked(this, new RoutedEventArgs());
    }

    private void OnFileListDragOver(object sender, DragEventArgs e)
    {
        e.AcceptedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
    }

    private async void OnFileListDrop(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems))
        {
            var items = await e.DataView.GetStorageItemsAsync();
            ViewModel.AddInputPaths(items.Select(i => i.Path));
        }
    }

    // ===== 选项变更 =====
    private void OnActionRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbEncrypt.IsChecked != true && RbDecrypt.IsChecked != true
            && RbBatchEncrypt.IsChecked != true && RbBatchDecrypt.IsChecked != true) return;
        // 互斥只取消另外两组，本组的勾选状态由本次 Checked 决定，不受影响
        ExclusiveGroup(GroupAction);
        if (RbEncrypt.IsChecked == true) ViewModel.ActionIndex = 0;
        else if (RbDecrypt.IsChecked == true) ViewModel.ActionIndex = 1;
        else if (RbBatchEncrypt.IsChecked == true) ViewModel.ActionIndex = 2;
        else if (RbBatchDecrypt.IsChecked == true) ViewModel.ActionIndex = 3;
        UpdateVisibility();
    }

    private void OnModeChanged(object sender, SelectionChangedEventArgs e)
    {
        ViewModel.ModeIndex = ModeCombo.SelectedIndex;
        UpdateVisibility();
    }

    private void OnFileCipherChanged(object sender, SelectionChangedEventArgs e)
    {
        ViewModel.FileCipherIndex = FileCipherCombo.SelectedIndex;
        UpdateVisibility();
    }

    private void OnSourceChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SourceCombo.SelectedIndex >= 0) ViewModel.SourceIndex = SourceCombo.SelectedIndex;
    }

    private bool _optionSyncing;

    private void OnOptionChanged(object sender, RoutedEventArgs e)
    {
        // 下面的可见性同步会改勾选状态，会再次触发本回调
        if (_optionSyncing) return;
        _optionSyncing = true;
        try
        {
            ViewModel.Force = ChkForce.IsChecked == true;
            ViewModel.Pack = ChkPack.IsChecked == true;
            ViewModel.Split = ChkSplit.IsChecked == true;
            ViewModel.Sha256 = ChkSha256.IsChecked == true;
            ViewModel.Compress = ChkCompress.IsChecked == true;
            ViewModel.RestoreName = ChkRestoreName.IsChecked == true;
            ViewModel.UseX448 = ChkX448.IsChecked == true;
            ViewModel.Pqc = ChkPqc.IsChecked == true;
            ViewModel.Watermark = ChkWatermark.IsChecked == true;
            ViewModel.WatermarkKey = WatermarkKeyEdit.Password;
            UpdateVisibility();
        }
        finally { _optionSyncing = false; }
    }

    // 文件列表勾选框：DataContext 即 SelectablePath 项，不走 {x:Bind} 以免触发附加属性赋值崩溃
    private void OnItemCheckedChanged(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox cb && cb.DataContext is Models.SelectablePath sp)
            sp.IsSelected = cb.IsChecked == true;
    }

    // 列表项加载时把视觉勾选态同步到数据（IsSelected 默认 true，但 CheckBox 未绑 IsChecked，需手动对齐）
    private void OnItemLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox cb && cb.DataContext is Models.SelectablePath sp)
            cb.IsChecked = sp.IsSelected;
    }

    private void OnCompressLevelChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        ViewModel.CompressLevel = (int)sender.Value;
    }

    private void OnSplitSizeChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_optionSyncing) return;
        ViewModel.SplitSize = sender.Value;
    }

    private void OnSplitUnitChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_optionSyncing) return;
        if (sender is ComboBox cb) ViewModel.SplitUnitIndex = cb.SelectedIndex < 0 ? 0 : cb.SelectedIndex;
    }

    private void OnOutDirChanged(object sender, TextChangedEventArgs e) => ViewModel.OutputDir = OutDirEdit.Text;
    private void OnKeyfileChanged(object sender, TextChangedEventArgs e) => ViewModel.Keyfile = KeyfileEdit.Text;
    private void OnRecipientChanged(object sender, TextChangedEventArgs e) => ViewModel.Recipient = RecipientEdit.Text;
    private void OnIdentityChanged(object sender, TextChangedEventArgs e) => ViewModel.Identity = IdentityEdit.Text;

    private async void OnBrowseOutDir(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FolderPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var folder = await picker.PickSingleFolderAsync();
            if (folder != null) OutDirEdit.Text = folder.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[输出目录] 错误: {0}", ex.Message); }
    }

    // 加密盘：勾选才启用目录输入，取消勾选要把路径一起清掉，否则残留值仍会被下发
    private void OnIntoVaultChanged(object sender, RoutedEventArgs e)
    {
        bool on = ChkIntoVault.IsChecked == true;
        VaultDirEdit.IsEnabled = on;
        BtnVaultBrowse.IsEnabled = on;
        if (!on) { VaultDirEdit.Text = ""; ViewModel.IntoVault = ""; }
        else ViewModel.IntoVault = VaultDirEdit.Text;
    }
    private void OnVaultDirChanged(object sender, TextChangedEventArgs e)
        => ViewModel.IntoVault = ChkIntoVault.IsChecked == true ? VaultDirEdit.Text : "";
    private async void OnBrowseVaultDir(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FolderPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var folder = await picker.PickSingleFolderAsync();
            if (folder != null) VaultDirEdit.Text = folder.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[加密盘] 错误: {0}", ex.Message); }
    }

    // ===== 加密盘库管理：与 Qt 前端同源，砍掉普通用户用不到的重建索引/库内重加密 =====

    // 新建：vault.meta 只是个带随机盐的明文文件，密码到第一次往盘里放文件时才生效，
    // 所以这里不问密码，只在成功后告诉用户「以后放文件时用的密码就是盘密码」
    private async void OnVaultInit(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var dir = await PickVaultPathAsync(L10n.T("新建加密盘"), false);
        if (dir == null) return;
        if (File.Exists(Path.Combine(dir, "vault.meta")))
        {
            await ShowMessageAsync(L10n.T("新建加密盘"), L10n.F("该文件夹已是加密盘：{0}", dir));
            return;
        }
        await RunVaultCliAsync(L10n.T("新建加密盘"),
            new List<string> { "--vault-init", dir }, null,
            L10n.T("加密盘已创建。此后向该盘存入文件时使用的密码即为该盘密码，请妥善保管。"));
    }

    // 查看盘内文件：解密索引后列出条目
    private async void OnVaultList(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var dir = await PickVaultPathAsync(L10n.T("查看盘内文件"), true);
        if (dir == null) return;
        var pw = await AskPasswordAsync(L10n.T("加密盘密码"), false);
        if (pw == null) return;
        await RunVaultCliAsync(L10n.T("查看盘内文件"),
            new List<string> { "--vault-list", dir, "--key-stdin" }, ToStdin(pw));
    }

    // 修改盘密码：旧密码走 -k 临时文件，新密码走 stdin（stdin 只能被一个来源占用）
    private async void OnVaultRekey(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var dir = await PickVaultPathAsync(L10n.T("修改加密盘密码"), true);
        if (dir == null) return;
        var oldPw = await AskPasswordAsync(L10n.T("请输入当前加密盘密码"), false);
        if (oldPw == null) return;

        var tmp = WriteTempPass(oldPw);
        if (tmp == null)
        {
            await ShowMessageAsync(L10n.T("修改加密盘密码"), L10n.T("无法写入临时密码文件。"));
            return;
        }
        var newPw = await AskPasswordAsync(L10n.T("再输入新密码（需输入两遍）"), true);
        if (newPw == null) { try { File.Delete(tmp); } catch { } return; }

        await RunVaultCliAsync(L10n.T("修改加密盘密码"),
            new List<string> { "--vault-rekey", dir, "-k", tmp, "--new-key-stdin" },
            ToStdin(newPw),
            L10n.T("盘中所有文件均已使用新密码重新加密。原恢复码失效，请重新生成。"),
            tmp);
    }

    // 生成恢复码：忘密码时的第二把钥匙，泄露恢复码 = 泄露整块盘
    private async void OnVaultRecoveryCreate(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var dir = await PickVaultPathAsync(L10n.T("生成恢复码"), true);
        if (dir == null) return;
        var pw = await AskPasswordAsync(L10n.T("加密盘密码"), false);
        if (pw == null) return;
        await RunVaultCliAsync(L10n.T("生成恢复码"),
            new List<string> { "--vault-recovery", dir, "--recovery-arg", "create", "--key-stdin" },
            ToStdin(pw),
            L10n.T("请将上方恢复码抄录至纸张并离线保存；持有该恢复码即可打开此加密盘。"));
    }

    // 用恢复码找回密码
    private async void OnVaultRecoveryOpen(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var dir = await PickVaultPathAsync(L10n.T("用恢复码找回密码"), true);
        if (dir == null) return;
        var code = await PromptTextAsync(L10n.T("用恢复码找回密码"),
            L10n.T("请输入此前抄录的 48 位恢复码（仅限数字）："), L10n.T("恢复码"));
        if (code == null) return;
        await RunVaultCliAsync(L10n.T("用恢复码找回密码"),
            new List<string> { "--vault-recovery", dir, "--recovery-arg", "open " + code }, null,
            L10n.T("上行为原密码。找回后请尽快修改密码并重新生成恢复码。"));
    }

    // 选加密盘目录：默认填上次用的那块盘，可直接改路径，也可点「浏览…」用系统选择器。
    // FolderPicker 不支持自定义起始目录，所以做成小对话框；requireVault 为真时不是盘就拒掉。
    private async Task<string?> PickVaultPathAsync(string title, bool requireVault)
    {
        var box = new TextBox
        {
            Text = (App.Settings.Current.LastVaultDir ?? "").Trim(),
            PlaceholderText = L10n.T("加密盘目录"),
            Width = 360,
        };
        var browse = new Button { Content = L10n.T("浏览...") };
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(new TextBlock
        {
            Text = L10n.T("该加密盘位于哪个文件夹？"),
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(box);
        panel.Children.Add(browse);
        var dlg = new ContentDialog
        {
            Title = title,
            Content = panel,
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            PrimaryButtonText = L10n.T("确定"),
            CloseButtonText = L10n.T("取消"),
            DefaultButton = ContentDialogButton.Primary,
        };
        browse.Click += async (_, _) =>
        {
            try
            {
                var picker = new FolderPicker();
                WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
                picker.FileTypeFilter.Add("*");
                var f = await picker.PickSingleFolderAsync();
                if (f != null) box.Text = f.Path;
            }
            catch { }
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return null;

        var dir = box.Text.Trim();
        if (dir.Length == 0) return null;
        if (!Directory.Exists(dir))
        {
            await ShowMessageAsync(title, L10n.F("找不到这个文件夹：{0}", dir));
            return null;
        }
        if (requireVault && !File.Exists(Path.Combine(dir, "vault.meta")))
        {
            await ShowMessageAsync(title,
                L10n.F("该文件夹尚未成为加密盘：{0}\n请先用「加密盘 → 新建加密盘」创建。", dir));
            return null;
        }
        // 记住这块盘：下次各菜单项默认就是它
        App.Settings.Current.LastVaultDir = dir;
        App.Settings.Save();
        return dir;
    }

    // 密码弹窗；取消或空密码返回 null
    private async Task<string?> AskPasswordAsync(string purpose, bool needConfirm)
    {
        var dlg = new PasswordDialog
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            NeedConfirm = needConfirm,
            Title = purpose,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return null;
        return string.IsNullOrEmpty(dlg.Password) ? null : dlg.Password;
    }

    // 单行文本输入弹窗（恢复码）；取消返回 null
    private async Task<string?> PromptTextAsync(string title, string desc, string placeholder)
    {
        var box = new TextBox { PlaceholderText = placeholder, Width = 360 };
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(new TextBlock { Text = desc, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(box);
        var dlg = new ContentDialog
        {
            Title = title,
            Content = panel,
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            PrimaryButtonText = L10n.T("确定"),
            CloseButtonText = L10n.T("取消"),
            DefaultButton = ContentDialogButton.Primary,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return null;
        var t = box.Text.Trim();
        return t.Length == 0 ? null : t;
    }

    // 密码转 stdin 字节：CLI 按原始字节当密钥材料，不做编码转换
    private static byte[] ToStdin(string pw) => Encoding.UTF8.GetBytes(pw);

    // 跑一次 CLI 加密盘命令并回显结果；hint 为追加的中文说明，deleteAfter 为用完即删的临时密码文件
    private async Task RunVaultCliAsync(string title, List<string> args, byte[]? stdin,
                                        string? hint = null, string? deleteAfter = null)
    {
        var cli = ViewModel.CliPath;
        if (string.IsNullOrEmpty(cli))
        {
            await ShowMessageAsync(title, L10n.T("尚未找到命令行程序，请先用「重新检测 CLI 程序」定位。"));
            return;
        }
        var svc = new CliProcessService();
        var sb = new StringBuilder();
        svc.OutputLine += line => { lock (sb) { sb.AppendLine(line); } };
        var tcs = new TaskCompletionSource<CommandResult>();
        svc.Finished += r => tcs.TrySetResult(r);

        svc.Execute(new CommandRequest
        {
            ProgramPath = cli,
            Arguments = args,
            StdinData = stdin ?? Array.Empty<byte>(),
        });
        var result = await tcs.Task;

        if (deleteAfter != null)
            _ = Task.Run(async () => { await Task.Delay(1500); try { File.Delete(deleteAfter); } catch { } });

        string detail = sb.ToString().Trim();
        if (result.ExitCode == 0)
        {
            ViewModel.SetStatus("{0}：成功", title);
            var body = detail;
            if (!string.IsNullOrEmpty(hint)) body = (body + "\n\n" + hint).Trim();
            await ShowMessageAsync(title, string.IsNullOrEmpty(body) ? L10n.T("完成。") : body);
        }
        else
        {
            ViewModel.SetStatus("{0}：失败 (exit {1})", title, result.ExitCode);
            await ShowMessageAsync(title,
                string.IsNullOrEmpty(detail)
                    ? L10n.F("命令失败（exit {0}）。", result.ExitCode)
                    : L10n.F("命令失败（exit {0}）：\n{1}", result.ExitCode, detail));
        }
    }

    // ===== 加密盘控制端（M3/M4 未完项）：挂载由 FE-Mounter 常驻持有，锁定/解锁经受限 IPC =====
    private async void OnVaultMount(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.T("未找到挂载组件 FE-Mounter。请重新安装并勾选「加密盘挂载」，或将 FE-Mounter 放在本程序同目录。"));
            return;
        }
        // WinFSP 用户态 DLL 必须与 FE-Mounter 同目录（静态导入，缺了进程都起不来）。
        // 先自查一遍，否则用户只看到「盘没挂上」，没有任何线索。
        var wfsp = Path.Combine(Path.GetDirectoryName(mounter) ?? "", "winfsp-x64.dll");
        if (!File.Exists(wfsp))
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.T("挂载组件缺少 WinFSP 运行时（winfsp-x64.dll），无法挂载。\n请重新安装本程序（安装时勾选「加密盘挂载」）。"));
            return;
        }
        var dir = await PickVaultPathAsync(L10n.T("挂载为磁盘"), true);
        if (dir == null) return;

        var dlg = new VaultMountDialog(ViewModel.VaultRwAvailable, App.Settings.Current.LastMountPoint ?? "")
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return;
        var point = dlg.MountPoint;
        if (string.IsNullOrEmpty(point)) return;
        var pw = dlg.Password;

        // 记住这次的盘：下次挂载/锁定/解锁默认就是它
        App.Settings.Current.LastVaultDir = dir;
        App.Settings.Current.LastMountPoint = point;
        App.Settings.Save();

        // 记录挂载点进 vault.meta（fire-and-forget，失败不阻断挂载）
        var cli = ViewModel.CliPath;
        if (!string.IsNullOrEmpty(cli))
        {
            try
            {
                Process.Start(new ProcessStartInfo(cli,
                    $"--vault-mount \"{dir}\" --mount-point \"{point}\"")
                { UseShellExecute = false, CreateNoWindow = true });
            }
            catch { }
        }

        var tmp = WriteTempPass(pw);
        if (tmp == null)
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"), L10n.T("无法写入临时密码文件。"));
            return;
        }

        // winmount <挂载点> --vault <dir> [--rw] --idle-timeout 60 --pass-file <临时密码>
        var args = new List<string> { "winmount", point, "--vault", dir };
        if (dlg.ReadWrite) args.Add("--rw");
        args.Add("--idle-timeout");
        args.Add("60");
        args.Add("--pass-file");
        args.Add(tmp);

        bool ok = LaunchMounterDetached(mounter, args);
        // FE-Mounter 启动时即读取并关闭密码文件，稍后删除临时件
        _ = Task.Run(async () => { await Task.Delay(2000); try { File.Delete(tmp); } catch { } });

        if (ok)
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.F("正在挂载，盘符由后台进程持有。稍后可在「此电脑」中看到：{0}", point));
        else
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.T("无法启动挂载组件。请确认 FE-Mounter 存在，且未被安全软件拦截。"));
    }

    private async void OnVaultLock(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("暂时锁定"),
                L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }
        var dir = await PickVaultPathAsync(L10n.T("暂时锁定"), true);
        if (dir == null) return;
        await RunVaultIpcAsync(mounter, dir, new List<string> { "lock" }, null, L10n.T("暂时锁定"));
    }

    private async void OnVaultUnlock(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.VaultAvailable) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("重新解锁"),
                L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }
        var dir = await PickVaultPathAsync(L10n.T("重新解锁"), true);
        if (dir == null) return;

        var pwd = new PasswordDialog { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme, NeedConfirm = false };
        if (await pwd.ShowAsync() != ContentDialogResult.Primary) return;
        if (string.IsNullOrEmpty(pwd.Password)) return;

        var tmp = WriteTempPass(pwd.Password);
        if (tmp == null)
        {
            await ShowMessageAsync(L10n.T("重新解锁"), L10n.T("无法写入临时密码文件。"));
            return;
        }
        await RunVaultIpcAsync(mounter, dir,
            new List<string> { "unlock", "--pass-file", tmp }, tmp, L10n.T("重新解锁"));
    }

    // 写临时密码文件（收紧为仅当前用户读写），用完即删；失败返回 null
    private string? WriteTempPass(string pw)
    {
        try
        {
            var tmp = Path.Combine(Path.GetTempPath(),
                $"fe_mountpw_{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}.tmp");
            File.WriteAllText(tmp, pw, new UTF8Encoding(false));
            try
            {
                var fi = new FileInfo(tmp);
                fi.Attributes &= ~System.IO.FileAttributes.ReadOnly;
                // 仅当前用户：清掉继承的 Everyone/Users 读取权限
                var sid = WindowsIdentity.GetCurrent().User;
                if (sid != null)
                {
                    var sec = fi.GetAccessControl();
                    sec.SetAccessRuleProtection(true, false);
                    sec.PurgeAccessRules(sid);
                    sec.AddAccessRule(new FileSystemAccessRule(
                        sid, FileSystemRights.FullControl, AccessControlType.Allow));
                    fi.SetAccessControl(sec);
                }
            }
            catch { }
            return tmp;
        }
        catch { return null; }
    }

    // detached 启动 FE-Mounter（长驻，不随 GUI 退出而结束）
    private bool LaunchMounterDetached(string mounter, List<string> args)
    {
        try
        {
            var psi = new ProcessStartInfo(mounter)
            {
                UseShellExecute = false,
                RedirectStandardInput = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            Process.Start(psi);
            return true;
        }
        catch { return false; }
    }

    // 经 FE-Mounter ipc-call 执行短命令（lock/unlock），回显结果
    private async Task RunVaultIpcAsync(string mounter, string dir, List<string> extraArgs, string? passFile, string title)
    {
        var cli = new CliProcessService();
        var sb = new StringBuilder();
        cli.OutputLine += line => { lock (sb) { sb.AppendLine(line); } };
        var tcs = new TaskCompletionSource<CommandResult>();
        cli.Finished += r => tcs.TrySetResult(r);

        var req = new CommandRequest
        {
            ProgramPath = mounter,
            Arguments = new List<string> { "ipc-call", "--vault", dir }.Concat(extraArgs).ToList(),
        };
        cli.Execute(req);

        var result = await tcs.Task;
        if (passFile != null)
            _ = Task.Run(async () => { await Task.Delay(2000); try { File.Delete(passFile); } catch { } });

        string detail = sb.ToString().Trim();
        if (result.ExitCode == 0)
        {
            ViewModel.SetStatus("{0}：成功", title);
            if (!string.IsNullOrEmpty(detail)) await ShowMessageAsync(title, detail);
        }
        else
        {
            ViewModel.SetStatus("{0}：失败 (exit {1})", title, result.ExitCode);
            await ShowMessageAsync(title,
                string.IsNullOrEmpty(detail)
                    ? L10n.F("命令失败（exit {0}）。", result.ExitCode)
                    : L10n.F("命令失败（exit {0}）：\n{1}", result.ExitCode, detail));
        }
    }

    private async void OnBrowseKeyfile(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) KeyfileEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[密钥文件] 错误: {0}", ex.Message); }
    }

    private async void OnBrowseRecipient(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) RecipientEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[收件人] 错误: {0}", ex.Message); }
    }

    private async void OnBrowseIdentity(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) IdentityEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[身份文件] 错误: {0}", ex.Message); }
    }

    private async void OnBrowseWrapFile(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            if (ViewModel.IsWrapKeyMode) picker.FileTypeFilter.Add("*");
            else { picker.FileTypeFilter.Add(".fekw"); picker.FileTypeFilter.Add("*"); }
            var file = await picker.PickSingleFileAsync();
            if (file != null) WrapFileEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[密钥文件] 错误: {0}", ex.Message); }
    }

    private async void OnBrowseWrapOut(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileSavePicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeChoices.Add(ViewModel.IsWrapKeyMode ? "包装文件" : "数据密钥",
                new List<string> { ViewModel.IsWrapKeyMode ? ".fekw" : ".dek" });
            var file = await picker.PickSaveFileAsync();
            if (file != null) WrapOutEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[输出路径] 错误: {0}", ex.Message); }
    }

    private async void OnBrowseWatermarkKey(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add(".pem");
            var file = await picker.PickSingleFileAsync();
            if (file == null) return;
            // 密钥内容直接进密码框，界面不回显明文
            WatermarkKeyEdit.Password = await FileIO.ReadTextAsync(file);
            ViewModel.SetStatus("[水印私钥] 已载入: {0}", file.Name);
        } catch (Exception ex) { ViewModel.SetStatus("[水印私钥] 错误: {0}", ex.Message); }
    }

    private void UpdateVisibility()
    {
        bool isEncrypt = ViewModel.IsEncryptMode;
        bool isAsym = ViewModel.IsAsymmetric;
        bool isKeyGen = ViewModel.IsKeyGenMode;
        bool isWrap = ViewModel.IsWrapMode;
        bool isWrapKey = ViewModel.IsWrapKeyMode;
        bool wrapPubkey = isWrap && ViewModel.WrapUsesPublicKey;

        // 非对称（X25519 / X448）模式下「文件算法」与曲线开关才有意义
        bool asymMode = ModeCombo.SelectedIndex == 4;
        bool isKeyGenOnly = ViewModel.ActionIndex == 4;   // -x448 只对「生成密钥对」有意义

        // 加密模式整行只服务加密动作，其余动作连左侧标签一起收起
        EncryptModeRow.Visibility = (isEncrypt && !isKeyGen) ? Visibility.Visible : Visibility.Collapsed;
        // 文件算法只在非对称模式露出；露出时模式下拉退回半宽，两个选择框等分同一行
        var fileCipherVisible = asymMode && isEncrypt && !isKeyGen;
        FileCipherCell.Visibility = fileCipherVisible ? Visibility.Visible : Visibility.Collapsed;
        FileCipherLabel.Visibility = fileCipherVisible ? Visibility.Visible : Visibility.Collapsed;
        ModeCombo.SetValue(Microsoft.UI.Xaml.Controls.Grid.ColumnSpanProperty, fileCipherVisible ? 1 : 2);
        // 曲线开关：非对称模式下控制封装曲线；生成密钥对时控制 -x448（CLI 只认这条）
        ChkX448.Visibility = (asymMode || isKeyGenOnly) ? Visibility.Visible : Visibility.Collapsed;

        // 加密专属选项：密钥管理与密钥包装动作下一律不出现
        bool encOptionVisible = isEncrypt && !isKeyGen && !isWrap;
        // 藏起来的开关先取消勾选，免得 CLI 收到对当前动作无意义的开关
        if (!encOptionVisible)
        {
            if (ChkCompress.IsChecked == true) ChkCompress.IsChecked = false;
            if (ChkWatermark.IsChecked == true) ChkWatermark.IsChecked = false;
            if (ChkPack.IsChecked == true) ChkPack.IsChecked = false;
            if (ChkSplit.IsChecked == true) ChkSplit.IsChecked = false;
            // PQC 只影响载荷封装与水印签名，包装路线不经过这两步
            if (ChkPqc.IsChecked == true) ChkPqc.IsChecked = false;
        }
        SourceCombo.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkPack.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkSplit.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 分卷大小行只在「加密动作 + 勾选分卷」时露出
        SplitSizeRow.Visibility = (encOptionVisible && ChkSplit.IsChecked == true)
            ? Visibility.Visible : Visibility.Collapsed;
        // 压缩整行（含标签与级别输入）同样只在加密动作出现，解密 / 批量解密 / 密钥管理下连行一起收起
        CompressionRow.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkSha256.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 签名水印只服务于加密动作
        ChkWatermark.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 后量子开关同样只在加密动作出现，包装路线用不上
        ChkPqc.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 公钥路线没有 KEK，密钥文件行对它无意义
        KeyfileEdit.Visibility = (!isAsym && !isKeyGen && !wrapPubkey) ? Visibility.Visible : Visibility.Collapsed;
        // 产物路径由包装区块的输出行决定
        OutDirRow.Visibility = isWrap ? Visibility.Collapsed : Visibility.Visible;
        // 加密盘：只有加密动作 + CLI 报了 vault=1 才露出（旧 CLI 不认 --into-vault）
        var vaultVisible = encOptionVisible && ViewModel.VaultAvailable;
        VaultRow.Visibility = vaultVisible ? Visibility.Visible : Visibility.Collapsed;
        if (!vaultVisible) ChkIntoVault.IsChecked = false;
        // 包装动作复用收件人 / 身份这两组输入框
        RecipientPanel.Visibility = (isAsym && isEncrypt) || (isWrapKey && wrapPubkey)
            ? Visibility.Visible : Visibility.Collapsed;
        IdentityPanel.Visibility = (isAsym && !isEncrypt) || (ViewModel.IsUnwrapMode && wrapPubkey)
            ? Visibility.Visible : Visibility.Collapsed;
        // 同一面板在包装动作下装的是另一种密钥，标签跟着改
        RecipientLabel.Text = L10n.T(isWrapKey ? "收件人公钥:" : "收件人:");
        RecipientEdit.PlaceholderText = L10n.T(isWrapKey ? "公钥或公钥文件路径（--wrap-to）" : "公钥或公钥文件路径");
        IdentityLabel.Text = L10n.T(ViewModel.IsUnwrapMode ? "身份私钥:" : "身份文件:");
        ChkRestoreName.Visibility = ViewModel.ActionIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
        // PQC 在密钥生成时仍有意义（CLI 的 -g 读 --no-pqc），X448 由上一行单独控制；
        // 签名水印只在加密动作下露出（见上）。
        UpdateWatermarkKeyRow();
        BtnRewrap.Visibility = isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        UpdateWrapPanel();

        // 切动作会成批改子控件 Visibility，ScrollViewer 有时不立刻重算滚动区，
        // 表现是滚动条莫名消失（再切一次又好了）。强制走一次布局把它算回来。
        MainScroll.UpdateLayout();
    }

    // 包装区块的措辞随动作与算法切换
    private void UpdateWrapPanel()
    {
        bool isWrap = ViewModel.IsWrapMode;
        WrapPanel.Visibility = isWrap ? Visibility.Visible : Visibility.Collapsed;
        if (!isWrap) return;
        bool wrapKey = ViewModel.IsWrapKeyMode;
        bool pubkey = ViewModel.WrapUsesPublicKey;
        WrapFileLabel.Text = L10n.T(wrapKey ? "32 字节密钥文件" : "包装文件");
        WrapFileEdit.PlaceholderText = L10n.T(wrapKey
            ? "恰好 32 字节的数据密钥（DEK）文件"
            : ".fekw 包装文件");
        WrapOutLabel.Text = L10n.T(wrapKey ? "包装输出" : "解包输出");
        WrapOutEdit.PlaceholderText = L10n.T(wrapKey
            ? "留空则用 <密钥文件>.fekw"
            : "留空则用 <包装文件>.dek");
        // 解包时算法写在 blob 头里，下拉只决定「密码还是私钥」，标题随之改口
        WrapAlgLabel.Text = L10n.T(wrapKey ? "包装算法" : "解密方式");
        WrapIntroText.Text = L10n.T(wrapKey
            ? (pubkey
                ? "把 32 字节数据密钥用收件人公钥封装，不需要密码。"
                : "用密码派生出的密钥包装 32 字节数据密钥。")
            : (pubkey
                ? "从 .fekw 中取回 32 字节数据密钥，需要当初收件人的身份私钥。"
                : "从 .fekw 中取回 32 字节数据密钥，需要包装时使用的密码。"));
    }

    // 水印私钥行：勾选「签名水印」后才显示（该行不改变动作语义，任何加密模式都可用）
    private void UpdateWatermarkKeyRow()
        => WatermarkKeyRow.Visibility =
            (ChkWatermark.IsChecked == true && ViewModel.IsEncryptMode) ? Visibility.Visible : Visibility.Collapsed;

    // ===== 运行 =====
    private async void OnRunClicked(object sender, RoutedEventArgs e)
    {
        if (ViewModel.CliPath == null)
        {
            ShowCliNotFoundDialog();
            return;
        }
        // 目录 + 删除类源处置：整棵树都会被清掉，动手前必须确认一次。
        // 确认通过后下发 --source-delete-ok，免得 CLI 再问一遍（问第二遍用户会懵）。
        if (ViewModel.IsEncryptMode && !ViewModel.Pack && ViewModel.SourceIndex != 0)
        {
            var dirs = ViewModel.InputPaths.Where(p => p.IsSelected && Directory.Exists(p.Path)).ToList();
            if (dirs.Count > 0)
            {
                // ContentDialog 不在 XAML 视觉树里，L10n.T 不会覆盖，手工翻译
                string how = ViewModel.SourceIndex switch
                {
                    2 => L10n.T("安全擦除（多次覆写）"),
                    3 => L10n.T("移至回收站"),
                    _ => L10n.T("删除"),
                };
                var show = dirs.Take(5).Select(d => d.Path).ToList();
                // 与 CLI 行为对齐：-de 只逐个删除目录树里的文件，空目录壳保留
                string msg = L10n.F("加密完成后，以下源目录中的文件将被{0}（目录本身保留），此操作不可撤销：\n\n{1}",
                                    how, string.Join("\n", show));
                if (dirs.Count > show.Count)
                    msg += "\n\n" + L10n.F("... 另有 {0} 个目录", dirs.Count - show.Count);
                var warn = new ContentDialog
                {
                    XamlRoot = Content.XamlRoot,
                    RequestedTheme = CurrentTheme,
                    Title = L10n.T("确认删除源目录"),
                    Content = msg,
                    PrimaryButtonText = L10n.T("继续"),
                    CloseButtonText = L10n.T("取消"),
                    DefaultButton = ContentDialogButton.Close,
                };
                if (await warn.ShowAsync() != ContentDialogResult.Primary)
                    return;
                ViewModel.SourceDeleteOk = true;
            }
        }
        // 入盘：支持直接指定已有盘，或指定一个目录由 CLI 自动初始化为新盘
        if (ViewModel.IsEncryptMode && ChkIntoVault.IsChecked == true)
        {
            var vd = (ViewModel.IntoVault ?? "").Trim();
            if (vd.Length == 0)
            {
                await ShowMessageAsync(L10n.T("缺少加密盘目录"), L10n.T("勾选「入加密盘」后请选择加密盘的存储目录，例如 E:\\Disks。"));
                VaultDirEdit.Focus(FocusState.Programmatic);
                return;
            }
            // 盘符根（Z / Z: / Z:\）已移除支持：CLI 会拒盘符根，这里提前拦并说清要填什么。
            // 仅「去掉尾部斜杠后长度为 1 或 2 的 X / X:」算盘符根；E:\Disks 这类真实目录不能误判。
            string vdNoSlash = vd.TrimEnd('\\', '/');
            bool isDrive = vdNoSlash.Length >= 1 && char.IsLetter(vdNoSlash[0])
                && (vdNoSlash.Length == 1 || (vdNoSlash.Length == 2 && vdNoSlash[1] == ':'));
            if (isDrive)
            {
                await ShowMessageAsync(L10n.T("不支持填盘符"),
                    L10n.T("「入加密盘」需要填写加密盘的存储目录，而不是挂载盘符。\n\n盘符（如 Z:）只是加密盘挂载后的访问视图，数据并不存放在那里。请填写数据实际所在的目录，例如 E:\\Disks。"));
                VaultDirEdit.Focus(FocusState.Programmatic);
                return;
            }
            if (!Directory.Exists(vd))
            {
                await ShowMessageAsync(L10n.T("加密盘目录无效"), L10n.F("找不到该目录：{0}\n请重新选择，或取消「入加密盘」改用普通加密。", vd));
                VaultDirEdit.Focus(FocusState.Programmatic);
                return;
            }
            // 非空且无 vault.meta：多半选错目录，先问一句再让 CLI 自动初始化
            if (!isDrive && !File.Exists(Path.Combine(vd, "vault.meta"))
                && Directory.EnumerateFileSystemEntries(vd).Any())
            {
                var ask = new ContentDialog
                {
                    XamlRoot = Content.XamlRoot,
                    RequestedTheme = CurrentTheme,
                    Title = L10n.T("初始化为新加密盘"),
                    Content = L10n.F("这个文件夹还不是加密盘：{0}\n是否把它初始化为新的加密盘并写入文件？", vd),
                    PrimaryButtonText = L10n.T("继续"),
                    CloseButtonText = L10n.T("取消"),
                    DefaultButton = ContentDialogButton.Close,
                };
                if (await ask.ShowAsync() != ContentDialogResult.Primary)
                {
                    VaultDirEdit.Focus(FocusState.Programmatic);
                    return;
                }
            }
        }
        // 包装动作的前置校验：CLI 能力、输入路径、公钥材料三样缺一不可
        if (ViewModel.IsWrapMode)
        {
            if (!ViewModel.KeywrapAvailable)
            {
                await ShowMessageAsync(L10n.T("密钥包装不可用"),
                    L10n.T("配套的命令行程序没有密钥包装能力，无法包装或解开密钥。\n请更换带 OpenSSL 的 CLI。"));
                return;
            }
            // 包装输入是单个文件，不走文件清单；缺路径或路径不存在在这里拦下
            var wrapIn = ViewModel.WrapInput ?? "";
            if (string.IsNullOrEmpty(wrapIn))
            {
                await ShowMessageAsync(L10n.T("缺少密钥文件"),
                    L10n.T(ViewModel.IsWrapKeyMode
                        ? "请先选择要包装的 32 字节数据密钥文件。"
                        : "请先选择要解开的 .fekw 包装文件。"));
                WrapFileEdit.Focus(FocusState.Programmatic);
                return;
            }
            if (!File.Exists(wrapIn))
            {
                await ShowMessageAsync(L10n.T("文件不存在"), L10n.F("找不到：{0}", wrapIn));
                WrapFileEdit.Focus(FocusState.Programmatic);
                return;
            }
            if (ViewModel.WrapUsesPublicKey)
            {
                string material = ViewModel.IsWrapKeyMode ? (ViewModel.Recipient ?? "") : (ViewModel.Identity ?? "");
                if (string.IsNullOrEmpty(material))
                {
                    await ShowMessageAsync(L10n.T("缺少密钥材料"),
                        L10n.T(ViewModel.IsWrapKeyMode
                            ? "公钥包装需要收件人公钥：粘贴公钥串或选择一个含公钥的文件。"
                            : "公钥解包需要当初收件人的身份私钥文件。"));
                    (ViewModel.IsWrapKeyMode ? RecipientEdit : IdentityEdit).Focus(FocusState.Programmatic);
                    return;
                }
            }
        }
        ViewModel.Run();
    }

    // ===== CLI 确认询问 =====
    // CLI 遇到 y/n 询问时把问题写进握手文件，这里弹窗询问，答完写回让 CLI 继续
    private async void OnConfirmPromptRequested(string text)
    {
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            // 问题文本来自 CLI（英文），标题与按钮走三语
            Title = L10n.T("需要确认"),
            Content = text,
            PrimaryButtonText = L10n.T("是"),
            CloseButtonText = L10n.T("否"),
            DefaultButton = ContentDialogButton.Close,
        };
        bool yes = await dlg.ShowAsync() == ContentDialogResult.Primary;
        ViewModel.AnswerConfirm(yes);
    }
    private void OnCancelClicked(object sender, RoutedEventArgs e) => ViewModel.Cancel();

    private async void OnRewrapClicked(object sender, RoutedEventArgs e)
    {
        var dlg = new ContentDialog
        {
            Title = L10n.T("密钥轮换（v6 容器）"),
            Content = L10n.T("选择一个已加密的 .ptd 文件，用旧密码解密后用新密码重新包裹 DEK。\n文件内容不变，仅更换密码。"),
            PrimaryButtonText = L10n.T("选择文件"),
            SecondaryButtonText = L10n.T("取消"),
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme
        };
        if (await dlg.ShowAsync() == ContentDialogResult.Primary)
        {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add(".ptd");
            var file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                ViewModel.SetStatus("密钥轮换功能实现中");
            }
        }
    }

    // ===== 菜单 =====
    private void OnEditConfig(object sender, RoutedEventArgs e)
    {
        var configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "FileEncryptor", "config.yaml");
        if (File.Exists(configPath))
            Process.Start(new ProcessStartInfo(configPath) { UseShellExecute = true });
        else
            ViewModel.SetStatus("配置文件不存在（首次运行 CLI 后生成）");
    }

    private void OnExit(object sender, RoutedEventArgs e) => Close();

    // 自动更新
    private string LocateUpdater()
    {
        string dir = AppContext.BaseDirectory;
        string[] cands = {
            Path.Combine(dir, "updater", "Updater.exe"),
            Path.Combine(dir, "Updater.exe"),
        };
        foreach (var c in cands) if (File.Exists(c)) return c;
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var p in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var c = Path.Combine(p, "Updater.exe");
            if (File.Exists(c)) return c;
        }
        return null;
    }

    private async void OnCheckForUpdate(object sender, RoutedEventArgs e)
    {
        var updater = LocateUpdater();
        if (updater == null)
        {
            await ShowMessageAsync(L10n.T("检查更新"), L10n.T("未找到更新器 (Updater.exe)。请确认程序安装完整，或前往 GitHub 手动获取新版本。"));
            return;
        }
        try
        {
            var curVer = $"GUI {FileEncryptorLocator.GuiVersion} / CLI {FileEncryptorLocator.ExpectedCliVersion}";
            // 参数逐项传，避免拼字符串时空格/引号把命令行截断
            var start = new ProcessStartInfo(updater)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("--check");
            start.ArgumentList.Add("--current");
            start.ArgumentList.Add(FileEncryptorLocator.GuiVersion);
            start.ArgumentList.Add("--type");
            start.ArgumentList.Add("winui");
            start.ArgumentList.Add("--platform");
            start.ArgumentList.Add("windows");
            using var proc = Process.Start(start);
            if (proc == null)
            {
                await ShowMessageAsync(L10n.T("检查更新"), L10n.T("无法启动更新器，请确认程序安装完整。"));
                return;
            }
            var readTask = proc.StandardOutput.ReadToEndAsync();
            var doneTask = proc.WaitForExitAsync();
            var finished = await System.Threading.Tasks.Task.WhenAny(readTask, doneTask, Task.Delay(TimeSpan.FromSeconds(60)));
            if (finished != readTask)
            {
                // 超时或更新器起不来：读不到 JSON 就别拿空串去解析
                try { proc.Kill(); } catch { }
                try { await doneTask; } catch { }
                await ShowMessageAsync(L10n.T("检查更新"), L10n.T("检查更新未返回结果（可能已超时）。请稍后再试。"));
                return;
            }
            var outJson = await readTask;
            await doneTask;
            using var doc = System.Text.Json.JsonDocument.Parse(outJson);
            var root = doc.RootElement;
            if (!root.GetProperty("ok").GetBoolean())
            {
                await ShowMessageAsync(L10n.T("检查更新"), L10n.F("检查失败：{0}", root.GetProperty("error").GetString()));
                return;
            }
            if (root.GetProperty("has_update").GetBoolean())
            {
                var latest = root.GetProperty("latest_version").GetString();
                var notes = root.TryGetProperty("notes", out var n) ? n.GetString() : "";
                var dlg = new ContentDialog
                {
                    Title = L10n.T("发现新版本"),
                    Content = L10n.F("发现新版本 {0}。\n\n{1}\n\n{2}\n\n是否现在下载并安装？", latest, notes, L10n.F("当前版本：{0}", curVer)),
                    PrimaryButtonText = L10n.T("下载并安装"),
                    CloseButtonText = L10n.T("关闭"),
                    XamlRoot = Content.XamlRoot,
                    RequestedTheme = CurrentTheme,
                };
                var r = await dlg.ShowAsync();
                if (r == ContentDialogResult.Primary)
                {
                    var url = root.GetProperty("download_url").GetString();
                    var sha = root.TryGetProperty("sha256", out var s) ? s.GetString() : "";
                    var sig = root.TryGetProperty("sig_url", out var g) ? g.GetString() : "";
                    long size = root.TryGetProperty("size", out var sz) && sz.TryGetInt64(out long szv) ? szv : 0;
                    await RunUpdaterUpdate(updater, url, sha, sig, size);
                }
            }
            else
            {
                await ShowMessageAsync("检查更新", L10n.F("已是最新版本（{0}）。", curVer));
            }
        }
        catch (Exception ex)
        {
            await ShowMessageAsync("检查更新", L10n.F("检查更新时出错：{0}", ex.Message));
        }
    }

    private async System.Threading.Tasks.Task RunUpdaterUpdate(string updater, string url, string sha, string sig, long size)
    {
        if (string.IsNullOrEmpty(url))
        {
            await ShowMessageAsync(L10n.T("更新"), L10n.T("未找到适用于本平台的安装包，请前往 GitHub 手动下载。"));
            return;
        }
        var staging = Path.Combine(AppContext.BaseDirectory, "update_staging");
        Directory.CreateDirectory(staging);
        var args = new List<string> { "--update", "--url", url, "--install-dir", staging };
        if (!string.IsNullOrEmpty(sha)) args.AddRange(new[] { "--sha256", sha });
        if (size > 0) args.AddRange(new[] { "--size", size.ToString() });
        if (!string.IsNullOrEmpty(sig)) args.AddRange(new[] { "--sig-url", sig });

        var statusText = new TextBlock { Text = L10n.T("准备下载…"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray) };
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Margin = new Thickness(0, 4, 0, 0) };
        var panel = new StackPanel(); panel.Children.Add(statusText); panel.Children.Add(progress);
        var dlg = new ContentDialog
        {
            Title = L10n.T("更新"),
            Content = panel,
            CloseButtonText = L10n.T("关闭"),
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        _ = UpdateWorker(updater, args, statusText, progress);
        await dlg.ShowAsync();
    }

    private async System.Threading.Tasks.Task UpdateWorker(string updater, List<string> args, TextBlock statusText, ProgressBar progress)
    {
        try
        {
            statusText.Text = L10n.T("正在下载并校验…");
            var start = new ProcessStartInfo(updater) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in args) start.ArgumentList.Add(a);
            using var proc = Process.Start(start);
            if (proc == null) { statusText.Text = L10n.T("无法启动更新器。"); return; }
            var exited = System.Threading.Tasks.Task.Run(async () =>
            {
                var done = proc.WaitForExitAsync();
                var timeout = Task.Delay(TimeSpan.FromMinutes(5));
                return await Task.WhenAny(done, timeout) == done;
            });
            if (!await exited) { try { proc.Kill(); } catch { } statusText.Text = L10n.T("下载超时，请稍后再试。"); return; }
            while (!proc.StandardOutput.EndOfStream)
            {
                var line = await proc.StandardOutput.ReadLineAsync();
                if (line == null) break;
                try
                {
                    using var d = System.Text.Json.JsonDocument.Parse(line);
                    var o = d.RootElement;
                    if (o.TryGetProperty("progress", out var p) && p.ValueKind == System.Text.Json.JsonValueKind.Number)
                    {
                        int v = p.GetInt32();
                        if (v >= 0) progress.Value = v;
                    }
                    if (o.TryGetProperty("stage", out var st))
                    {
                        var s = st.GetString();
                        if (s == "downloading") statusText.Text = L10n.T("正在下载…");
                        else if (s == "verifying") statusText.Text = L10n.T("正在校验完整性…");
                        else if (s == "done") statusText.Text = L10n.T("更新包已下载并校验完成。");
                        else if (s == "error") statusText.Text = L10n.T("更新失败：") + (o.TryGetProperty("error", out var er) ? er.GetString() : L10n.T("未知错误"));
                    }
                }
                catch {  }
            }
            if (!proc.HasExited) { await proc.WaitForExitAsync(); }
            if (proc.ExitCode == 0)
                statusText.Text = L10n.F("更新包已就绪，存放于：\n{0}\n请关闭程序后以该文件替换当前程序并重新启动。", Path.Combine(AppContext.BaseDirectory, "update_staging"));
            else
                statusText.Text = L10n.T("更新失败（退出码 ") + proc.ExitCode + L10n.T("）。可前往 GitHub 手动下载。");
        }
        catch (Exception ex)
        {
            statusText.Text = L10n.T("更新出错：") + ex.Message;
        }
    }

    private async System.Threading.Tasks.Task ShowMessageAsync(string title, string msg)
    {
        var dlg = new ContentDialog { Title = title, Content = msg, CloseButtonText = L10n.T("关闭"), XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
    }

    private async void OnCredits(object sender, RoutedEventArgs e)
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "FileEncryptor v" + FileEncryptorLocator.GuiVersion + " — " + L10n.T("鸣谢"), FontWeight = Microsoft.UI.Text.FontWeights.Bold, FontSize = 18, Margin = new Thickness(0,0,0,12) });
        panel.Children.Add(new TextBlock { Text = L10n.T("感谢以下贡献者的付出："), Margin = new Thickness(0,0,0,8) });

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());
        grid.RowDefinitions.Add(new RowDefinition());

        void AddRow(int row, string role, string name, string? link) {
            var tb1 = new TextBlock { Text = role, FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,0,16,4) };
            Grid.SetColumn(tb1, 0); Grid.SetRow(tb1, row); grid.Children.Add(tb1);
            var tb2 = new TextBlock { Text = name, Margin = new Thickness(0,0,16,4) };
            Grid.SetColumn(tb2, 1); Grid.SetRow(tb2, row); grid.Children.Add(tb2);
            if (link != null) {
                var hl = new HyperlinkButton { Content = L10n.T("个人主页"), NavigateUri = new Uri(link), Padding = new Thickness(0) };
                Grid.SetColumn(hl, 2); Grid.SetRow(hl, row); grid.Children.Add(hl);
            }
        }
        AddRow(0, L10n.T("代码开发"), L10n.T("瑶璎珞"), "https://space.bilibili.com/3546692557212318");
        // 瑶璎珞额外加赞助链接
        var sponsorLink = new HyperlinkButton { Content = L10n.T("赞助支持"), NavigateUri = new Uri("https://afdian.com/a/yaoyingluo"), Padding = new Thickness(0), Margin = new Thickness(16,0,0,0) };
        Grid.SetColumn(sponsorLink, 3); Grid.SetRow(sponsorLink, 0); grid.Children.Add(sponsorLink);
        AddRow(1, L10n.T("测试"), L10n.T("就不错了我"), "https://space.bilibili.com/1705671238");
        AddRow(2, L10n.T("宣传"), L10n.T("Twilight飞友"), "https://space.bilibili.com/3546728261224829");
        panel.Children.Add(grid);

        panel.Children.Add(new TextBlock { Text = L10n.T("\n本项目基于 libsodium 实现文件加密（XChaCha20-Poly1305 / AEGIS-256），采用 C++17 编写，跨平台运行于 Windows / Linux / macOS。"), TextWrapping = TextWrapping.Wrap, Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray), FontSize = 12 });

        // 国庆节窗口内追加祝福语（主窗功能区底部也有一处常驻展示）
        if (NationalDayTheme.IsActive())
        {
            panel.Children.Add(new TextBlock
            {
                Text = NationalDayTheme.BirthdayMessage(),
                TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                FontSize = 15,
                Margin = new Thickness(0, 14, 0, 0),
                Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(NationalDayTheme.ChinaRed)
            });
        }

        var dlg = new ContentDialog { Title = L10n.T("鸣谢"), Content = new ScrollViewer { Content = panel, MaxHeight = 400, VerticalScrollBarVisibility = ScrollBarVisibility.Hidden }, CloseButtonText = L10n.T("关闭"), XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
    }

    private async void OnReadme(object sender, RoutedEventArgs e)
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "FileEncryptor v" + FileEncryptorLocator.GuiVersion + " " + L10n.T("— 项目摘要"), FontWeight = Microsoft.UI.Text.FontWeights.Bold, FontSize = 18, Margin = new Thickness(0,0,0,12) });
        panel.Children.Add(new TextBlock { Text = L10n.T("简介：跨平台（Windows / Linux / macOS）文件加密工具，基于 libsodium 实现 XChaCha20-Poly1305 与 AEGIS-256 加密。"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = L10n.T("核心特性"), FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
        panel.Children.Add(new TextBlock { Text = L10n.T("• 加密算法：XChaCha20-Poly1305（默认）/ AEGIS-256，密钥经 Argon2id 派生") });
        panel.Children.Add(new TextBlock { Text = L10n.T("• 单文件与批量：支持单文件加/解密，及目录批量加/解密（递归）") });
        panel.Children.Add(new TextBlock { Text = L10n.T("• 断点续传：加密中断后可从上次进度继续，防静默数据丢失") });
        panel.Children.Add(new TextBlock { Text = L10n.T("• 路径安全：拒绝目录穿越（..），白名单前缀校验") });
        panel.Children.Add(new TextBlock { Text = L10n.T("• 限速：进程级令牌桶限速（YAML max_speed 配置）") });
        panel.Children.Add(new TextBlock { Text = L10n.T("• 配置化：日志/并发/路径策略等运维参数经 YAML 配置"), Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = L10n.T("命令行用法"), FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
        panel.Children.Add(new TextBlock { Text = "FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256|aes-gcm|sm4] [-y]\nFileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256|aes-gcm|sm4] [-y]", FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"), Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = L10n.T("密钥来源优先级"), FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
        panel.Children.Add(new TextBlock { Text = L10n.T("-k <keyfile>（密钥文件） > --key-stdin（stdin 管道） > ENCRYPTOR_KEY（环境变量） > 交互式输入；非对称模式用 X25519 身份私钥 > 交互式输入"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = L10n.T("许可证：GPLv3"), Margin = new Thickness(0,8,0,0) });
        panel.Children.Add(new TextBlock { Text = L10n.T("本窗口为 README 摘要，完整文档请见项目根目录 README.md"), Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray), FontSize = 12, Margin = new Thickness(0,8,0,0) });

        var dlg = new ContentDialog { Title = L10n.T("README 摘要"), Content = new ScrollViewer { Content = panel, MaxHeight = 480, VerticalScrollBarVisibility = ScrollBarVisibility.Hidden }, CloseButtonText = L10n.T("关闭"), XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
    }

    private async void OnOpenTaskHistory(object sender, RoutedEventArgs e)
    {
        var records = TaskHistoryService.Load(out _);
        var dlg = new TaskHistoryDialog(records) { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
        if (dlg.SelectedTask is { } rec)
            RestoreTask(rec);
    }

    private void RestoreTask(Models.TaskRecord rec)
    {
        ViewModel.ActionIndex = rec.Action switch
        {
            "encrypt" => 0,
            "decrypt" => 1,
            "batch-encrypt" => 2,
            "batch-decrypt" => 3,
            "keygen" => 4,
            "derive" => 5,
            "pubkey" => 6,
            "wrap" => 7,
            "unwrap" => 8,
            _ => ViewModel.ActionIndex
        };
        ViewModel.ModeIndex = rec.Mode switch
        {
            "xchacha20" => 0,
            "aegis256" => 1,
            "aes-gcm" => 2,
            "sm4" => 3,
            "x25519" => 4,
            "x448" => 4,
            "asymmetric" => 4,
            _ => ViewModel.ModeIndex
        };
        // 非对称模式的文件算法一并回填，否则下拉会停在默认项却回放出对应的 -m
        ModeCombo.SelectedIndex = ViewModel.ModeIndex;
        FileCipherCombo.SelectedIndex = rec.FileCipher switch
        {
            "aegis256" => 1,
            "aes-gcm" => 2,
            "sm4" => 3,
            _ => 0
        };
        ViewModel.FileCipherIndex = FileCipherCombo.SelectedIndex;
        ChkX448.IsChecked = rec.Mode == "x448";
        ViewModel.UseX448 = rec.Mode == "x448";
        if (!string.IsNullOrEmpty(rec.OutputDir))
            OutDirEdit.Text = rec.OutputDir;
        ViewModel.ClearInputPaths();
        ViewModel.AddInputPaths(rec.InputPaths);
        ViewModel.SourceIndex = rec.SourceIndex;
        ViewModel.Force = rec.Force;
        ViewModel.Sha256 = rec.Sha256;
        ViewModel.Compress = rec.Compress;
        ViewModel.CompressLevel = rec.CompressionLevel;
        ViewModel.Pqc = rec.Pqc;
        ViewModel.Watermark = rec.Watermark;
        ViewModel.WatermarkKey = rec.WatermarkKey ?? "";
        ChkPqc.IsChecked = rec.Pqc;
        ChkWatermark.IsChecked = rec.Watermark;
        if (!string.IsNullOrEmpty(rec.Keyfile)) KeyfileEdit.Text = rec.Keyfile;
        if (!string.IsNullOrEmpty(rec.Recipient)) RecipientEdit.Text = rec.Recipient;
        if (!string.IsNullOrEmpty(rec.Identity)) IdentityEdit.Text = rec.Identity;
        ChkRestoreName.IsChecked = rec.RestoreName;
        // 算法下拉先设，动作切过去时 PropertyChanged 会顺带刷可见性
        if (!string.IsNullOrEmpty(rec.WrapAlg))
            WrapAlgCombo.SelectedIndex = rec.WrapAlg switch { "kwp" => 0, "aes-kw" => 1, "pubkey" => 2, _ => WrapAlgCombo.SelectedIndex };
        if (!string.IsNullOrEmpty(rec.WrapInput)) WrapFileEdit.Text = rec.WrapInput;
        if (!string.IsNullOrEmpty(rec.WrapOutput)) WrapOutEdit.Text = rec.WrapOutput;
        ChkForce.IsChecked = rec.Force;
        ChkSha256.IsChecked = rec.Sha256;
        ChkCompress.IsChecked = rec.Compress;
        CompressLevel.Value = rec.CompressionLevel;
        SourceCombo.SelectedIndex = rec.SourceIndex;
        // 历史里只存占位符，私钥需重新输入
        var wmKey = rec.WatermarkKey ?? "";
        WatermarkKeyEdit.Password = wmKey.StartsWith("<") ? "" : wmKey;
        ViewModel.WatermarkKey = WatermarkKeyEdit.Password;
        // 打包为一个文件 / 入加密盘：控件可用时才回填，否则 UpdateVisibility 会把它清掉
        ChkPack.IsChecked = rec.Pack;
        ViewModel.Pack = rec.Pack;
        if (!string.IsNullOrEmpty(rec.IntoVault))
        {
            ChkIntoVault.IsChecked = true;
            VaultDirEdit.Text = rec.IntoVault;
            ViewModel.IntoVault = rec.IntoVault;
        }
        else
        {
            ChkIntoVault.IsChecked = false;
            ViewModel.IntoVault = "";
        }
        UpdateVisibility();
        ViewModel.SetStatus("已恢复任务: {0}", rec.ActionLabel);
    }

    private void OnRetryCliDetection(object sender, RoutedEventArgs e)
    {
        if (ViewModel.DetectCli(out var path))
        {
            ViewModel.SetStatus("已检测到 CLI: {0}", path);
            ViewModel.RefreshCommandPreview();
        }
        else
        {
            ViewModel.SetStatus("未检测到 FileEncryptor CLI");
            ShowCliNotFoundDialog();
        }
    }

    // 窗口背景：Mica。
    // 注意两处都要动：
    // 1) 只设托管属性 SystemBackdrop 时DWM 侧读出来仍是 0(NONE)，
    //    WinUI 的 setter 没递交到 DWM，窗口会全不透明，必须 P/Invoke 补一刀；
    // 2) DWM 的 Mica tint 跟随**系统**深浅，不跟随应用主题。
    //    深色系统 + 浅色应用时，系统给的是暗 Mica，叠上浅色遮罩就成了
    //    「黑白不一」。所以浅色档干脆不用系统 Mica，改纯色底。
    public void ApplyBackdrop()
    {
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var mode = App.Settings.Current.BackgroundMode;
        // 应用实际生效的深浅（System 档看注册表）
        var dark = CurrentTheme != ElementTheme.Light;

        if (_backgroundBrush.ImageSource != null)
        {
            // 有背景图就不开系统背景，图片自己铺满
            SystemBackdrop = null;
        }
        else if (mode == BackgroundMode.Flat)
        {
            SystemBackdrop = null;
        }
        else
        {
            // MicaBackdrop.Kind 只读且跟随系统深浅：Dark 用默认档，
            // Light 强制 MicaKind.Base（浅色 Mica），这样浅色应用不会拿到暗 Mica。
            var mica = new MicaBackdrop();
            if (!dark) mica.Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.Base;
            SystemBackdrop = mica;
            int hr = DwmBackdrop.SetMica(hwnd);
            Debug.WriteLine($"DwmSetWindowAttribute(Mica) hr={hr} readback={DwmBackdrop.Query(hwnd)}");
        }

        // 背景就绪后再上节日配色：面板的 Mica 依赖窗口底这层采样源已就绪
        ApplyNationalDayVisuals();
    }

    // 国庆主题的界面配色：底色染色、面板 Mica、按钮、控件、祝福语
    private void ApplyNationalDayVisuals()
    {
        // 窗口底：非国庆也走同一套，按背景模式分派
        if (_backgroundBrush.ImageSource == null)
            RootGrid.Background = NationalDayTheme.WindowBackdropBrush();
        else
            _backgroundBrush.Opacity = 0.88;

        if (!NationalDayTheme.IsActive())
        {
            // 非国庆：面板跟着窗口走同样那层 Mica，保证整体一致
            ApplyPanelBackdrops();
            return;
        }
        // 运行/取消按钮也走红系，否则绿色运行键是杂色
        NationalDayTheme.ApplyButtonColors(BtnRun, BtnCancel);
        ApplyTitleAccent();
        // 浅色下按钮/输入框沿用系统浅灰会看不见，逐个下压配色
        NationalDayTheme.ApplyControlColors(RootGrid);
        // 功能区 / 文件选择区：换成自身的 Mica 底，与窗口底两层采样叠出层次
        ApplyPanelBackdrops();
        // 祝福语常驻功能区底部
        BirthdayBar.Visibility = Visibility.Visible;
        RefreshBirthdayText();
    }

    private async void OnViewSettings(object sender, RoutedEventArgs e)
    {
        var dlg = new ViewSettingsDialog(_backgroundBrush) { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
        // 换过背景后要重刷：ApplyBackdrop 内部按有无图片决定开不开系统背景
        ApplyBackdrop();
        if (_backgroundBrush.ImageSource == null && NationalDayTheme.IsActive())
            RootGrid.Background = NationalDayTheme.WindowBackdropBrush();
        else if (_backgroundBrush.ImageSource != null)
            RootGrid.Background = _backgroundBrush;
    }

    private void ApplySavedBackground()
    {
        var path = App.Settings.Current.CustomBackgroundPath;
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        try
        {
            var uri = new Uri(path);
            if (!uri.IsFile) return;
            var bitmap = new BitmapImage();
            bitmap.UriSource = uri;
            _backgroundBrush.ImageSource = bitmap;
            _backgroundBrush.Stretch = Stretch.UniformToFill;
            _backgroundBrush.Opacity = 1.0;
        }
        catch {  }
    }

    // 更新源白名单，与 Updater/src/updater.cpp 的 kGitHubHosts 保持一致
    private static readonly string[] s_allowedHosts = {
        "github.com", "api.github.com",
        "objects.githubusercontent.com", "codeload.github.com"
    };

    // 仅 GitHub 官方域名（精确匹配，不做后缀模糊）
    private static bool IsAllowedDownloadHost(string url)
    {
        try
        {
            var host = new Uri(url).Host;
            return s_allowedHosts.Any(h => string.Equals(host, h, StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private static async System.Threading.Tasks.Task<string?> TryFetchSha256(System.Net.Http.HttpClient http, string assetUrl)
    {
        try
        {
            var shaUrl = assetUrl + ".sha256";
            if (!IsAllowedDownloadHost(shaUrl)) return null;
            var text = await http.GetStringAsync(shaUrl);
            var token = text.Trim().Split(new[] { ' ', '\t', '\r', '\n' }, 2)[0];
            if (token.Length == 64) return token.ToLowerInvariant();
            return null;
        }
        catch { return null; }
    }
}
