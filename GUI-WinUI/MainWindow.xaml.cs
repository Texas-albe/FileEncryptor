using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Dispatching;
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
using WinRT.Interop;
using System.Runtime.InteropServices;

namespace FileEncryptorGUI;

public sealed partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; } = new();
    private readonly ImageBrush _backgroundBrush = new();
    // 锁定盘访问事件
    private DispatcherQueueTimer? _lockTimer;
    private bool _unlockPromptActive;   // 解锁框重复弹出
    // 同 vault 解锁弹窗节流
    private readonly Dictionary<string, DateTime> _unlockPromptTimes = new();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    private ElementTheme CurrentTheme => App.Settings.Current.Theme switch
    {
        Services.AppTheme.Light => ElementTheme.Light,
        Services.AppTheme.Dark => ElementTheme.Dark,
        _ => ElementTheme.Default
    };
    // 设置/加密盘标签
    private readonly List<SettingsTabView> _settingsTabs = new();
    private readonly List<VaultTabView> _vaultTabs = new();
    private readonly List<HomeTabView> _homeTabs = new();
    private readonly List<TerminalTabView> _terminalTabs = new();

    // 主页工作区初值
    internal void InitHomeView(HomeTabView v)
    {
        v.ChkForce.IsChecked = true;
        v.ChkPqc.IsChecked = true;
        v.RbEncrypt.IsChecked = true;
        v.FileCipherCombo.SelectedIndex = 0;
        v.ModeCombo.SelectedIndex = 0;
        v.SourceCombo.SelectedIndex = 0;
        v.WrapAlgCombo.SelectedIndex = 0;
        // 加密盘目录默认
        var lastVault = (App.Settings.Current.LastVaultDir ?? "").Trim();
        if (lastVault.Length > 0 && Directory.Exists(lastVault)) v.VaultDirEdit.Text = lastVault;
    }


    // 主页工作区
    // 既有代码
    public HomeTabView ActiveHome { get; private set; } = null!;

    private Border LeftPanel => ActiveHome.LeftPanel;
    private ListView FileList => ActiveHome.FileList;
    private Border CenterPanel => ActiveHome.CenterPanel;
    private ScrollViewer MainScroll => ActiveHome.MainScroll;
    private StackPanel ActionRow => ActiveHome.ActionRow;
    private RadioButton RbEncrypt => ActiveHome.RbEncrypt;
    private RadioButton RbDecrypt => ActiveHome.RbDecrypt;
    private RadioButton RbBatchEncrypt => ActiveHome.RbBatchEncrypt;
    private RadioButton RbBatchDecrypt => ActiveHome.RbBatchDecrypt;
    private StackPanel KeyMgmtRow => ActiveHome.KeyMgmtRow;
    private RadioButton RbKeyGen => ActiveHome.RbKeyGen;
    private RadioButton RbDerive => ActiveHome.RbDerive;
    private RadioButton RbPubKey => ActiveHome.RbPubKey;
    private StackPanel WrapRow => ActiveHome.WrapRow;
    private RadioButton RbWrapKey => ActiveHome.RbWrapKey;
    private RadioButton RbUnwrapKey => ActiveHome.RbUnwrapKey;
    private StackPanel WrapPanel => ActiveHome.WrapPanel;
    private TextBlock WrapFileLabel => ActiveHome.WrapFileLabel;
    private TextBox WrapFileEdit => ActiveHome.WrapFileEdit;
    private TextBlock WrapOutLabel => ActiveHome.WrapOutLabel;
    private TextBox WrapOutEdit => ActiveHome.WrapOutEdit;
    private TextBlock WrapAlgLabel => ActiveHome.WrapAlgLabel;
    private ComboBox WrapAlgCombo => ActiveHome.WrapAlgCombo;
    private TextBlock WrapIntroText => ActiveHome.WrapIntroText;
    private Grid EncryptModeRow => ActiveHome.EncryptModeRow;
    private ComboBox ModeCombo => ActiveHome.ModeCombo;
    private Grid FileCipherCell => ActiveHome.FileCipherCell;
    private TextBlock FileCipherLabel => ActiveHome.FileCipherLabel;
    private ComboBox FileCipherCombo => ActiveHome.FileCipherCombo;
    private Grid CompressionRow => ActiveHome.CompressionRow;
    private CheckBox ChkCompress => ActiveHome.ChkCompress;
    private NumberBox CompressLevel => ActiveHome.CompressLevel;
    private Grid OutDirRow => ActiveHome.OutDirRow;
    private TextBox OutDirEdit => ActiveHome.OutDirEdit;
    private Grid VaultRow => ActiveHome.VaultRow;
    private CheckBox ChkIntoVault => ActiveHome.ChkIntoVault;
    private TextBox VaultDirEdit => ActiveHome.VaultDirEdit;
    private Button BtnVaultBrowse => ActiveHome.BtnVaultBrowse;
    private TextBox KeyfileEdit => ActiveHome.KeyfileEdit;
    private StackPanel OptionsRow => ActiveHome.OptionsRow;
    private ComboBox SourceCombo => ActiveHome.SourceCombo;
    private CheckBox ChkForce => ActiveHome.ChkForce;
    private CheckBox ChkPack => ActiveHome.ChkPack;
    private CheckBox ChkSplit => ActiveHome.ChkSplit;
    private CheckBox ChkSha256 => ActiveHome.ChkSha256;
    private CheckBox ChkPqc => ActiveHome.ChkPqc;
    private CheckBox ChkX448 => ActiveHome.ChkX448;
    private CheckBox ChkWatermark => ActiveHome.ChkWatermark;
    private Grid SplitSizeRow => ActiveHome.SplitSizeRow;
    private NumberBox SplitSizeBox => ActiveHome.SplitSizeBox;
    private ComboBox SplitUnitCombo => ActiveHome.SplitUnitCombo;
    private Grid WatermarkKeyRow => ActiveHome.WatermarkKeyRow;
    private PasswordBox WatermarkKeyEdit => ActiveHome.WatermarkKeyEdit;
    private Button BtnRewrap => ActiveHome.BtnRewrap;
    private Button BtnRun => ActiveHome.BtnRun;
    private Button BtnCancel => ActiveHome.BtnCancel;
    private StackPanel RecipientPanel => ActiveHome.RecipientPanel;
    private TextBlock RecipientLabel => ActiveHome.RecipientLabel;
    private TextBox RecipientEdit => ActiveHome.RecipientEdit;
    private StackPanel IdentityPanel => ActiveHome.IdentityPanel;
    private TextBlock IdentityLabel => ActiveHome.IdentityLabel;
    private TextBox IdentityEdit => ActiveHome.IdentityEdit;
    private CheckBox ChkRestoreName => ActiveHome.ChkRestoreName;
    private Border BirthdayBar => ActiveHome.BirthdayBar;
    private TextBlock BirthdayText => ActiveHome.BirthdayText;

    // 设置/加密盘标签
    internal static MainWindow? Instance { get; private set; }

    public MainWindow()
    {
        // UserControl 标签页通过它拿
        Instance = this;
        InitializeComponent();
        // 代理属性要指
        ActiveHome = HomeView;

        // M41
        CleanupStaleTempPasses();

        // 主题要
        // 表现
        RootGrid.RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ThemeService.IsSystemDark() ? ElementTheme.Dark : ElementTheme.Light
        };

        // 先初始化语言
        L10n.Init();
        ApplyLocalization();

        Title = $"FileEncryptorGUI {FileEncryptorLocator.GuiVersion}";

        ExtendsContentIntoTitleBar = true;
        // 标题栏
        // SetTitleBar 只指定「标签条右
        // 精确拖拽区
        // 默认整条标题栏
        SetTitleBar(TitleBarDragRegion);
        var tb = AppWindow.TitleBar;
        // 标题栏必须整体
        // 顶部
        tb.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
        tb.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        UpdateTitleBarButtonColors();

        // 轮询锁定盘访问
        _lockTimer = DispatcherQueue.CreateTimer();
        _lockTimer.Interval = TimeSpan.FromSeconds(2);
        _lockTimer.Tick += PollLockedAccess;
        _lockTimer.Start();
        // 启动即处理一次
        PollLockedAccess(_lockTimer, null);

        // 16
        const int kWinW = 1440;
        const int kWinH = kWinW * 9 / 16;
        AppWindow.Resize(new Windows.Graphics.SizeInt32(kWinW, kWinH));

        // 勾选框初值一律
        // 对 Primitives.ToggleButto
        // XamlParseException，Initi
        InitHomeView(ActiveHome);

        // 背景优先级
        RootGrid.Background = _backgroundBrush;
        ApplySavedBackground();
        // 终端观察器
        CliProcessService.GlobalOutput += OnCliGlobalOutput;
        CliProcessService.RunStarted += OnCliRunStarted;
        CliProcessService.RunEnded += OnCliRunEnded;
        // 启动只登记主页
        _homeTabs.Add(HomeView);
        // 标签条尺寸变
        MainTabView.SizeChanged += OnTabViewSizeChanged;

        // 国庆配色
        // 构造函数阶段

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

        // 加密盘能力探测
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ViewModel.VaultAvailable) ||
                e.PropertyName == nameof(ViewModel.VaultRwAvailable))
            {
                UpdateVisibility();
                RefreshVaultHint();
            }
        };

        // 旧 CLI 不支持包装动
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(ViewModel.KeywrapAvailable)) return;
            RbWrapKey.IsEnabled = ViewModel.KeywrapAvailable;
            RbUnwrapKey.IsEnabled = ViewModel.KeywrapAvailable;
            if (ViewModel.KeywrapAvailable)
            {
                // 可用时保留说明
                ToolTipService.SetToolTip(RbWrapKey, L10n.T("将一份 32 字节数据密钥单独封装进 .fekw 文件，用密码或收件人公钥保护"));
                ToolTipService.SetToolTip(RbUnwrapKey, L10n.T("将 .fekw 中的数据密钥还原为 32 字节文件"));
            }
            else
            {
                var tip = L10n.T("当前 CLI 不支持密钥包装，请使用带 OpenSSL 的 CLI");
                ToolTipService.SetToolTip(RbWrapKey, tip);
                ToolTipService.SetToolTip(RbUnwrapKey, tip);
            }
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
        this.Closed += (_, _) =>
        {
            CliProcessService.GlobalOutput -= OnCliGlobalOutput;
            CliProcessService.RunStarted -= OnCliRunStarted;
            CliProcessService.RunEnded -= OnCliRunEnded;
            App.Settings.Save();
        };
    }

    // 多语言

    private void ApplyLocalization()
    {
        ApplyMenuLocalization();
        // 中文时 T 原样返回
        LocalizeTree(RootGrid);
        ApplyRowOrientation();
        RefreshBirthdayText();
        ViewModel.RefreshRuntimeTexts();
    }

    // 祝福语带 {0} 年龄占
    // 在遍历
    private void RefreshBirthdayText()
    {
        BirthdayText.Text = NationalDayTheme.BirthdayMessage();
    }

    // 同一行控件
// 竖排
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
        // 标签
        foreach (var it in MainTabView.TabItems)
        {
            if (it is not TabViewItem tvi) continue;
            if (tvi.Content is SettingsTabView) tvi.Header = L10n.T("设置");
            else if (tvi.Content is VaultTabView) tvi.Header = L10n.T("加密盘管理");
            else if (tvi.Content is HomeTabView) tvi.Header = L10n.T("主页");
            else if (tvi.Content is TerminalTabView) tvi.Header = L10n.T("终端");
        }
        SyncThemeMenuState();
        SyncLangRadioState();
    }

    // 视觉树走不到折
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
                // 下拉项未展开
                case Microsoft.UI.Xaml.Controls.ComboBox cb:
                    foreach (var item in cb.Items)
                    {
                        if (item is Microsoft.UI.Xaml.Controls.ComboBoxItem cbi && cbi.Content is string cs)
                            cbi.Content = L10n.T(cs);
                    }
                    break;
        }
        // 悬停提示是附加
        // 不能放进上面 switch  ComboBox/
        // 会跳
        if (child is Microsoft.UI.Xaml.FrameworkElement fe)
        {
            var tip = fe.GetValue(Microsoft.UI.Xaml.Controls.ToolTipService.ToolTipProperty);
            if (tip is string ts)
                fe.SetValue(Microsoft.UI.Xaml.Controls.ToolTipService.ToolTipProperty, L10n.T(ts));
        }
    }

    internal void OnLangZh(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.Zh);
    internal void OnLangEn(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.En);
    internal void OnLangRu(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.Ru);

    // 两个面板用 AcrylicBrush
    // 面板
    // 两个面板必须各
    // 第二个面板拿
    private void ApplyPanelBackdrops()
    {
        if (NationalDayTheme.IsActive())
        {
            LeftPanel.Background = NationalDayTheme.PanelBackdropBrush();
            CenterPanel.Background = NationalDayTheme.PanelBackdropBrush();
        }
        else
        {
            // 平时交给 Fluent 卡片样
            LeftPanel.ClearValue(Microsoft.UI.Xaml.Controls.Border.BackgroundProperty);
            CenterPanel.ClearValue(Microsoft.UI.Xaml.Controls.Border.BackgroundProperty);
        }
    }

    // 标题红条
    private void ApplyTitleAccent()
    {
    }

    // 主题
    internal void OnThemeLight(object sender, RoutedEventArgs e) => ChangeTheme(Services.AppTheme.Light);
    internal void OnThemeDark(object sender, RoutedEventArgs e) => ChangeTheme(Services.AppTheme.Dark);
    internal void OnThemeSystem(object sender, RoutedEventArgs e) => ChangeTheme(Services.AppTheme.System);

    private void ChangeTheme(Services.AppTheme theme)
    {
        if (App.Settings.Current.Theme == theme) { SyncThemeMenuState(); return; }
        App.Settings.Current.Theme = theme;
        App.Settings.Save();
        // 国庆配色
        NationalDayTheme.Refresh();
        if (NationalDayTheme.IsActive())
        {
            NationalDayTheme.ApplyButtonColors(BtnRun, BtnCancel);
            ApplyTitleAccent();
            NationalDayTheme.ApplyControlColors(RootGrid);
        }
        // 面板
        ApplyPanelBackdrops();
        if (_backgroundBrush.ImageSource == null)
            RootGrid.Background = NationalDayTheme.WindowBackdropBrush();
        App.Theme.ApplyTheme(theme);
        // 预览窗是独立 Window
        _previewWindow?.ApplyTheme(CurrentTheme);
        SyncThemeMenuState();
        UpdateTitleBarButtonColors();
    }

    private void SyncThemeMenuState()
    {
        PruneTabInstances();
        var cur = App.Settings.Current.Theme;
        foreach (var s in _settingsTabs) s.SyncTheme(cur);
    }

    private void SyncLangRadioState()
    {
        PruneTabInstances();
        foreach (var s in _settingsTabs) s.SyncLang(L10n.Current);
    }

    // 终端
    // 终端不进「+」菜单
    // 只在执行期间存
    private TabViewItem? _terminalTab;

    private void OpenTerminal()
    {
        if (_terminalTab != null && MainTabView.TabItems.IndexOf(_terminalTab) >= 0)
        {
            MainTabView.SelectedItem = _terminalTab;
            return;
        }
        var view = new TerminalTabView();
        _terminalTabs.Add(view);
        var item = NewTabItem(L10n.T("终端"), view, closable: false);
        _terminalTab = item;
        MainTabView.TabItems.Add(item);
        MainTabView.SelectedItem = item;
        LocalizeTree(view);
        UpdateTitleBarDragRegion();
    }

    private void CloseTerminal()
    {
        if (_terminalTab == null) return;
        int idx = MainTabView.TabItems.IndexOf(_terminalTab);
        if (idx >= 0) MainTabView.TabItems.RemoveAt(idx);
        if (_terminalTab.Content is TerminalTabView v) _terminalTabs.Remove(v);
        _terminalTab = null;
        UpdateTitleBarDragRegion();
    }

    // 收起前留一拍
    private async void CloseTerminalSoon()
    {
        await Task.Delay(1200);
        DispatcherQueue?.TryEnqueue(CloseTerminal);
    }

    // 有 CLI 开跑
    private void OnCliRunStarted() => DispatcherQueue?.TryEnqueue(() =>
    {
        foreach (var t in _terminalTabs) t.Clear();
        OpenTerminal();
    });

    // 最后一个 CLI 退完
    private void OnCliRunEnded() => DispatcherQueue?.TryEnqueue(CloseTerminalSoon);

    private void OnCliGlobalOutput(string text)
    {
        DispatcherQueue?.TryEnqueue(() =>
        {
            foreach (var t in _terminalTabs) t.Append(text + "\n");
        });
    }

    private void OnTermClear(object sender, RoutedEventArgs e)
    {
        foreach (var t in _terminalTabs) t.Clear();
    }

    // 设置
    // 供设置标签页
    internal async Task<string?> PickBackgroundImageAsync()
    {
        var picker = new FileOpenPicker();
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        picker.FileTypeFilter.Add(".png");
        picker.FileTypeFilter.Add(".jpg");
        picker.FileTypeFilter.Add(".jpeg");
        picker.FileTypeFilter.Add(".bmp");
        picker.FileTypeFilter.Add(".webp");
        var file = await picker.PickSingleFileAsync();
        return file?.Path;
    }

    internal void ApplyCustomBackground(string? path)
    {
        path = string.IsNullOrWhiteSpace(path) ? null : path.Trim();
        App.Settings.Current.CustomBackgroundPath = path;
        App.Settings.Save();
        if (path == null || !File.Exists(path))
        {
            _backgroundBrush.ImageSource = null;
        }
        else
        {
            try
            {
                var uri = new Uri(path);
                if (uri.IsFile)
                {
                    var bitmap = new BitmapImage();
                    bitmap.UriSource = uri;
                    _backgroundBrush.ImageSource = bitmap;
                    _backgroundBrush.Stretch = Stretch.UniformToFill;
                    _backgroundBrush.Opacity = 1.0;
                }
            }
            catch { }
        }
        ApplyBackdrop();
        if (_backgroundBrush.ImageSource == null && NationalDayTheme.IsActive())
            RootGrid.Background = NationalDayTheme.WindowBackdropBrush();
        else if (_backgroundBrush.ImageSource != null)
            RootGrid.Background = _backgroundBrush;
    }

    // 加密盘管理
    private void OnTabSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // 全部标签
        if (MainTabView.TabItems.Count == 0)
        {
            var view = new HomeTabView();
            ActiveHome = view;
            InitHomeView(view);
            _homeTabs.Add(view);
            var item = NewTabItem(L10n.T("主页"), view);
            MainTabView.TabItems.Add(item);
            MainTabView.SelectedItem = item;
            LocalizeTree(view);
            UpdateTitleBarDragRegion();
            return;
        }
        // 切到主页标签
        if (MainTabView.SelectedItem is TabViewItem tvi && tvi.Content is HomeTabView h)
        {
            ActiveHome = h;
        }
        // 淡入淡出
        // 用户看到
        var outgoing = e.RemovedItems.Count > 0
            ? (e.RemovedItems[0] as TabViewItem)?.Content as FrameworkElement
            : null;
        FadeContent(outgoing, 0);
        FadeContent((MainTabView.SelectedItem as TabViewItem)?.Content as FrameworkElement, 1);

        if ((MainTabView.SelectedItem as TabViewItem)?.Content is VaultTabView)
            RefreshMountedVaults();
    }

    // 标签切换动画
    // 下次切回来
    private static void FadeContent(FrameworkElement? el, double to)
    {
        if (el == null) return;
        if (to >= 1) el.Opacity = 0;
        var anim = new DoubleAnimation
        {
            From = el.Opacity,
            To = to,
            Duration = new Duration(TimeSpan.FromMilliseconds(150)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
            EnableDependentAnimation = true,
        };
        var sb = new Storyboard();
        Storyboard.SetTarget(anim, el);
        Storyboard.SetTargetProperty(anim, "Opacity");
        sb.Children.Add(anim);
        if (to < 1) sb.Completed += (_, _) => el.Opacity = 1;
        sb.Begin();
    }

    private void OnRefreshMounted(object sender, RoutedEventArgs e) => RefreshMountedVaults();

    // 加密盘能力
    private async Task<bool> EnsureVaultAvailableAsync()
    {
        if (ViewModel.VaultAvailable) return true;
        await ShowMessageAsync(L10n.T("加密盘管理"), VaultUnavailableReason());
        return false;
    }

    internal string VaultUnavailableReason()
    {
        return string.IsNullOrEmpty(ViewModel.CliPath)
            ? L10n.T("未检测到 FileEncryptor CLI，请先在「设置 → 程序」中重新检测 CLI 程序。")
            : L10n.T("当前 CLI 不支持加密盘功能，需要 FileEncryptor CLI 3.0.1 或更高版本。");
    }

    // 加密盘页顶部
    private void RefreshVaultHint()
    {
        foreach (var v in _vaultTabs) v.RefreshHint();
    }

    private void RefreshMountedVaults()
    {
        PruneTabInstances();
        foreach (var v in _vaultTabs) v.RefreshList();
    }

    // 标签页

    // Explorer 式标题栏
    // WinUI 开启
    // 输入命中全
    // 用 SetDragRectangles
    // 其余区域
    private void UpdateTitleBarDragRegion()
    {
        if (AppWindow == null) return;
        if (TitleBarDragRegion == null || TitleBarDragRegion.ActualWidth <= 0) return;

        var t = TitleBarDragRegion.TransformToVisual(null);
        var origin = t.TransformPoint(new Windows.Foundation.Point(0, 0));
        int x = (int)Math.Round(origin.X);
        int y = (int)Math.Round(origin.Y);
        int w = (int)Math.Round(TitleBarDragRegion.ActualWidth);
        int h = (int)Math.Round(TitleBarDragRegion.ActualHeight);
        if (w <= 0 || h <= 0) return;

        // 系统
        const int captionW = 140;
        int maxW = Math.Max(0, (int)AppWindow.Size.Width - captionW - x);
        w = Math.Min(w, maxW);
        if (w <= 0) return;

        AppWindow.TitleBar.SetDragRectangles(new[] { new Windows.Graphics.RectInt32(x, y, w, h) });
    }

    // 标签条宽度随标
    private void OnTabViewSizeChanged(object sender, SizeChangedEventArgs e) => UpdateTitleBarDragRegion();

    // 内置「+」
    private void OnAddTabButtonClick(TabView sender, object args)
    {
        // 某些版本
        for (int i = MainTabView.TabItems.Count - 1; i >= 0; i--)
        {
            if (MainTabView.TabItems[i] is TabViewItem t &&
                string.IsNullOrEmpty(t.Header as string) && t.Content == null)
                MainTabView.TabItems.RemoveAt(i);
            else break;
        }
        ShowNewTabMenu();
    }

    private void ShowNewTabMenu()
    {
        var menu = new MenuFlyout();
        menu.Placement = Microsoft.UI.Xaml.Controls.Primitives.FlyoutPlacementMode.BottomEdgeAlignedLeft;
        // 终端是全局唯一
        menu.Items.Add(NewTabMenuItem(L10n.T("主页"), "\uE80F", OnNewHomeTab));
        menu.Items.Add(NewTabMenuItem(L10n.T("设置"), "\uE713", OnNewSettingsTab));
        menu.Items.Add(NewTabMenuItem(L10n.T("加密盘管理"), "\uE8B7", OnNewVaultTab));

        // 锚点优先用内置
        // 绝不能退到整
        FrameworkElement? anchor = FindAddTabButton();
        if (anchor == null && MainTabView.TabItems.Count > 0)
            anchor = MainTabView.TabItems[MainTabView.TabItems.Count - 1] as FrameworkElement;
        if (anchor == null) anchor = MainTabView;
        menu.ShowAt(anchor);
    }

    private static MenuFlyoutItem NewTabMenuItem(string text, string glyph, Action action)
    {
        var item = new MenuFlyoutItem { Text = text, Icon = new FontIcon { Glyph = glyph } };
        item.Click += (_, _) => action();
        return item;
    }

    // 内置加号
    // 取「标签条高度内
    private Button? FindAddTabButton()
    {
        var buttons = new List<Button>();
        CollectButtons(MainTabView, buttons);
        if (buttons.Count == 0) return null;

        // 最后一个标签
        double bandTop = 0, bandBottom = 0, lastRight = 0;
        bool any = false;
        for (int i = 0; i < MainTabView.TabItems.Count; i++)
        {
            if (MainTabView.TabItems[i] is not TabViewItem t) continue;
            var o = t.TransformToVisual(MainTabView).TransformPoint(new Windows.Foundation.Point(0, 0));
            var e = t.TransformToVisual(MainTabView).TransformPoint(new Windows.Foundation.Point(t.ActualWidth, t.ActualHeight));
            bandTop = any ? Math.Min(bandTop, o.Y) : o.Y;
            bandBottom = any ? Math.Max(bandBottom, e.Y) : e.Y;
            lastRight = Math.Max(lastRight, e.X);
            any = true;
        }
        if (!any) return null;

        // 取最靠左
        Button? best = null;
        double bestX = double.MaxValue;
        foreach (var b in buttons)
        {
            if (b.ActualWidth <= 0) continue;
            var p = b.TransformToVisual(MainTabView).TransformPoint(new Windows.Foundation.Point(0, 0));
            if (p.Y < bandTop - 2 || p.Y > bandBottom + 2) continue;   // 不在标签条高度
            if (p.X < lastRight - 2) continue;                          
            if (p.X < bestX) { bestX = p.X; best = b; }
        }
        return best;
    }

    private static void CollectButtons(DependencyObject root, List<Button> acc)
    {
        int n = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < n; i++)
        {
            var child = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(root, i);
            if (child is Button b) acc.Add(b);
            CollectButtons(child, acc);
        }
    }

    // 标签「×」
    // 统一兜底
    private void OnTabCloseRequested(TabView sender, TabViewTabCloseRequestedEventArgs args)
    {
        if (args.Tab is not TabViewItem item) return;
        if (item.Content is SettingsTabView s) _settingsTabs.Remove(s);
        if (item.Content is VaultTabView v) _vaultTabs.Remove(v);
        if (item.Content is HomeTabView h) _homeTabs.Remove(h);
        if (item.Content is TerminalTabView t) _terminalTabs.Remove(t);
        int idx = MainTabView.TabItems.IndexOf(item);
        if (idx >= 0) MainTabView.TabItems.RemoveAt(idx);
        UpdateTitleBarDragRegion();
    }

    // 新建标签
    private TabViewItem NewTabItem(string header, object content, bool closable = true)
        => new()
        {
            Header = header,
            Content = content,
            IsClosable = closable,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            VerticalContentAlignment = VerticalAlignment.Stretch,
        };

    // 主页
    private void OnNewHomeTab(object sender, RoutedEventArgs e) => OnNewHomeTab();
    private void OnNewHomeTab()
    {
        var view = new HomeTabView();
        // 先把代理指向新
        ActiveHome = view;
        InitHomeView(view);
        _homeTabs.Add(view);
        var item = NewTabItem(L10n.T("主页"), view);
        MainTabView.TabItems.Add(item);
        MainTabView.SelectedItem = item;
        LocalizeTree(view);
        UpdateTitleBarDragRegion();
    }

    private void OnNewSettingsTab(object sender, RoutedEventArgs e) => OnNewSettingsTab();
    private void OnNewSettingsTab()
    {
        var view = new SettingsTabView();
        _settingsTabs.Add(view);
        var item = NewTabItem(L10n.T("设置"), view);
        MainTabView.TabItems.Add(item);
        MainTabView.SelectedItem = item;
        // 按需新开
        view.SyncTheme(App.Settings.Current.Theme);
        view.SyncLang(L10n.Current);
        LocalizeTree(view);
        UpdateTitleBarDragRegion();
    }

    private void OnNewVaultTab(object sender, RoutedEventArgs e) => OnNewVaultTab();
    private void OnNewVaultTab()
    {
        var view = new VaultTabView();
        _vaultTabs.Add(view);
        var item = NewTabItem(L10n.T("加密盘管理"), view);
        MainTabView.TabItems.Add(item);
        MainTabView.SelectedItem = item;
        view.RefreshHint();   // 能力提示不依赖
        LocalizeTree(view);
        UpdateTitleBarDragRegion();
    }

    // 标签
    // 不依赖 TabClosed 事件
    private void PruneTabInstances()
    {
        var alive = new HashSet<object>();
        foreach (var t in MainTabView.TabItems)
            if (t is TabViewItem tvi && tvi.Content != null) alive.Add(tvi.Content);
        _settingsTabs.RemoveAll(v => !alive.Contains(v));
        _vaultTabs.RemoveAll(v => !alive.Contains(v));
        _homeTabs.RemoveAll(v => !alive.Contains(v));
        _terminalTabs.RemoveAll(v => !alive.Contains(v));
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
            CloseButtonText = L10n.T("确定"),
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        await dlg.ShowAsync();
    }

    private void OnFirstLoaded(object sender, RoutedEventArgs e)
    {
        RootGrid.Loaded -= OnFirstLoaded;
        // 首帧布局完成
        UpdateTitleBarDragRegion();
        if (!ViewModel.DetectCli(out _))
            ShowCliNotFoundDialog();
        else
            ViewModel.RefreshCommandPreview();
        // 能力探测是异步
        // 除 PropertyChanged 订阅外，窗口
        // 探测完成时刻
        _ = RefreshVisibilityAfterProbeAsync();
    }

    // 启动
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

    // 动作 / 密钥管理
    // 三组单选
    // 被点亮
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

    internal void OnKeyMgmtRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbKeyGen.IsChecked != true && RbDerive.IsChecked != true && RbPubKey.IsChecked != true) return;
        ExclusiveGroup(GroupKeyMgmt);
        if (RbKeyGen.IsChecked == true) ViewModel.ActionIndex = 4;
        else if (RbDerive.IsChecked == true) ViewModel.ActionIndex = 5;
        else if (RbPubKey.IsChecked == true) ViewModel.ActionIndex = 6;
        UpdateVisibility();
    }

    internal void OnWrapRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbWrapKey.IsChecked != true && RbUnwrapKey.IsChecked != true) return;
        ExclusiveGroup(GroupWrap);
        ViewModel.ActionIndex = RbWrapKey.IsChecked == true ? 7 : 8;
        UpdateVisibility();
    }

    internal void OnWrapAlgChanged(object sender, SelectionChangedEventArgs e)
    {
        if (WrapAlgCombo.SelectedIndex >= 0) ViewModel.WrapAlgIndex = WrapAlgCombo.SelectedIndex;
        UpdateVisibility();
    }

    internal void OnWrapInputChanged(object sender, TextChangedEventArgs e) => ViewModel.WrapInput = WrapFileEdit.Text;
    internal void OnWrapOutputChanged(object sender, TextChangedEventArgs e) => ViewModel.WrapOutput = WrapOutEdit.Text;

    private void UpdateTitleBarButtonColors()
    {
        // 标题栏叠
        var tb = AppWindow.TitleBar;
        var dark = CurrentTheme != ElementTheme.Light;
        var fg = dark ? Microsoft.UI.Colors.White : Microsoft.UI.Colors.Black;
        var fgInactive = dark
            ? Windows.UI.Color.FromArgb(255, 0xC8, 0xC8, 0xC8)
            : Windows.UI.Color.FromArgb(255, 0x5D, 0x5D, 0x5D);
        tb.ButtonForegroundColor = fg;
        tb.ButtonInactiveForegroundColor = fgInactive;
        tb.ButtonHoverForegroundColor = fg;
        tb.ButtonPressedForegroundColor = fg;
        var hover = dark
            ? Windows.UI.Color.FromArgb(0x20, 0xFF, 0xFF, 0xFF)
            : Windows.UI.Color.FromArgb(0x20, 0, 0, 0);
        var pressed = dark
            ? Windows.UI.Color.FromArgb(0x30, 0xFF, 0xFF, 0xFF)
            : Windows.UI.Color.FromArgb(0x30, 0, 0, 0);
        tb.ButtonHoverBackgroundColor = hover;
        tb.ButtonPressedBackgroundColor = pressed;
    }

    // 任务完成通知
    private void OnTaskCompleted(string message)
    {
        var notif = new TaskNotificationWindow(message);
        notif.Activate();
    }

    // 任务汇总弹窗
    private void OnTaskSummary(TaskSummaryInfo summary)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            var dlg = new TaskSummaryDialog(summary.Title, summary.Duration, summary.AvgSpeed, summary.EncryptedSize, summary.Done, summary.Skip, summary.Fail)
            {
                XamlRoot = Content.XamlRoot
            };
            // 观测 ShowAsync 返回
            _ = dlg.ShowAsync().AsTask().ContinueWith(static t => { _ = t.Exception; },
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        });
    }


    // CLI 未找到
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
        var statusText = new TextBlock { Text = "", Margin = new Thickness(0,8,0,0), Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", CurrentTheme) };
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Margin = new Thickness(0,4,0,0) };
        panel.Children.Add(infoText); panel.Children.Add(statusText); panel.Children.Add(progress);
        // 三键
        // Primary → Secondary → Close
        var dlg = new ContentDialog { Title = L10n.T("FileEncryptor CLI 未找到"), Content = panel, PrimaryButtonText = L10n.T("重试"), SecondaryButtonText = L10n.T("下载 CLI"), CloseButtonText = L10n.T("关闭"), XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        var result = await dlg.ShowAsync();
        if (result == ContentDialogResult.Primary) { if (ViewModel.DetectCli(out _)) ViewModel.RefreshCommandPreview(); else ShowCliNotFoundDialog(); }
        else if (result == ContentDialogResult.Secondary) { await ShowDownloadCliDialog(); }
    }

    // 下载对话框
    private async System.Threading.Tasks.Task ShowDownloadCliDialog()
    {
        var statusText = new TextBlock { Text = L10n.T("准备下载…"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", CurrentTheme) };
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
        // 关窗往往早于
        if (ViewModel.DetectCli(out var path))
        {
            ViewModel.SetStatus("已检测到 CLI：{0}", path);
            ViewModel.RefreshCommandPreview();
        }
        _ = downloading;
    }

    // 在tag 列表中定位精
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

    // 从 GitHub 拉取配套 CLI 并落
    // 精确 tag → 平台匹配 → 域
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
            // 只接受
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

            // URL 不可信
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
            // 边下边写盘
            // 顺带让进度条
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
                    statusText.Text = L10n.T("SHA256 校验失败，下载内容已作废");
                    return;
                }
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("CLI 发布包未提供 .sha256 清单，已跳过完整性校验");
            }

            var savePath = Path.Combine(AppContext.BaseDirectory, fileName);
            try
            {
                File.Move(tempPath, savePath, overwrite: true);
            }
            catch (UnauthorizedAccessException)
            {
                // 装在 Program Files 下时没管理
                statusText.Text = L10n.F("安装失败：程序目录不可写，请以管理员身份运行，或手动将文件放置到：{0}", savePath);
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

    // 密码请求
    private async void OnPasswordRequested()
    {
        var dlg = new PasswordDialog(ViewModel.PasswordNeedsConfirm)
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        var result = await dlg.ShowAsync();
        if (result == ContentDialogResult.Primary && !string.IsNullOrEmpty(dlg.Password))
        {
            ViewModel.RunWithPassword(dlg.Password);
        }
    }

    // 文件操作
    // 文件关联
    internal void AddFilesFromCommandLine(IEnumerable<string> paths)
    {
        var files = paths
            .Where(p => p.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase) && File.Exists(p))
            .ToList();
        if (files.Count == 0) return;
        ViewModel.AddInputPaths(files);
        ViewModel.SetStatus("已从文件关联打开 {0} 个 .ptd 文件", files.Count);
    }

    internal async void OnAddFiles(object sender, RoutedEventArgs e)
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
            ViewModel.SetStatus("[添加文件] 错误：{0}", ex.Message);
        }
    }

    internal async void OnAddDir(object sender, RoutedEventArgs e)
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
            ViewModel.SetStatus("[添加目录] 错误：{0}", ex.Message);
        }
    }

    internal void OnClearFiles(object sender, RoutedEventArgs e) => ViewModel.ClearInputPaths();

    private PreviewWindow? _previewWindow;

    internal async void OnPreviewClicked(object sender, RoutedEventArgs e)
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

        // 预览是解密行
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

        // 与 Qt 侧同一判据
        var identity = ViewModel.Identity?.Trim();
        byte[] password = Array.Empty<byte>();
        if (string.IsNullOrEmpty(identity))
        {
            // 预览恒
            var pwd = new PasswordDialog(false)
            {
                XamlRoot = Content.XamlRoot,
                RequestedTheme = CurrentTheme,
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
        // 选中下一项
        var idx = FileList.SelectedIndex;
        if (idx < 0 || idx + 1 >= FileList.Items.Count) return;
        FileList.SelectedIndex = idx + 1;
        OnPreviewClicked(this, new RoutedEventArgs());
    }

    internal void OnFileListDragOver(object sender, DragEventArgs e)
    {
        e.AcceptedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
    }

    internal async void OnFileListDrop(object sender, DragEventArgs e)
    {
        if (e.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems))
        {
            var items = await e.DataView.GetStorageItemsAsync();
            ViewModel.AddInputPaths(items.Select(i => i.Path));
        }
    }

    // 选项变
    internal void OnActionRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbEncrypt.IsChecked != true && RbDecrypt.IsChecked != true
            && RbBatchEncrypt.IsChecked != true && RbBatchDecrypt.IsChecked != true) return;
        // 互斥只取消另外
        ExclusiveGroup(GroupAction);
        if (RbEncrypt.IsChecked == true) ViewModel.ActionIndex = 0;
        else if (RbDecrypt.IsChecked == true) ViewModel.ActionIndex = 1;
        else if (RbBatchEncrypt.IsChecked == true) ViewModel.ActionIndex = 2;
        else if (RbBatchDecrypt.IsChecked == true) ViewModel.ActionIndex = 3;
        UpdateVisibility();
    }

    internal void OnModeChanged(object sender, SelectionChangedEventArgs e)
    {
        ViewModel.ModeIndex = ModeCombo.SelectedIndex;
        UpdateVisibility();
    }

    internal void OnFileCipherChanged(object sender, SelectionChangedEventArgs e)
    {
        ViewModel.FileCipherIndex = FileCipherCombo.SelectedIndex;
        UpdateVisibility();
    }

    internal void OnSourceChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SourceCombo.SelectedIndex >= 0) ViewModel.SourceIndex = SourceCombo.SelectedIndex;
    }

    private bool _optionSyncing;

    internal void OnOptionChanged(object sender, RoutedEventArgs e)
    {
        // 下面
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

    // 文件列表勾选框
    internal void OnItemCheckedChanged(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox cb && cb.DataContext is Models.SelectablePath sp)
            sp.IsSelected = cb.IsChecked == true;
    }

    // 列表项加载
    internal void OnItemLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox cb && cb.DataContext is Models.SelectablePath sp)
            cb.IsChecked = sp.IsSelected;
    }

    internal void OnCompressLevelChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        ViewModel.CompressLevel = (int)sender.Value;
    }

    internal void OnSplitSizeChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_optionSyncing) return;
        ViewModel.SplitSize = sender.Value;
    }

    internal void OnSplitUnitChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_optionSyncing) return;
        if (sender is ComboBox cb) ViewModel.SplitUnitIndex = cb.SelectedIndex < 0 ? 0 : cb.SelectedIndex;
    }

    internal void OnOutDirChanged(object sender, TextChangedEventArgs e) => ViewModel.OutputDir = OutDirEdit.Text;
    internal void OnKeyfileChanged(object sender, TextChangedEventArgs e) => ViewModel.Keyfile = KeyfileEdit.Text;
    internal void OnRecipientChanged(object sender, TextChangedEventArgs e) => ViewModel.Recipient = RecipientEdit.Text;
    internal void OnIdentityChanged(object sender, TextChangedEventArgs e) => ViewModel.Identity = IdentityEdit.Text;

    internal async void OnBrowseOutDir(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FolderPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var folder = await picker.PickSingleFolderAsync();
            if (folder != null) OutDirEdit.Text = folder.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[输出目录] 错误：{0}", ex.Message); }
    }

    // 加密盘
    internal void OnIntoVaultChanged(object sender, RoutedEventArgs e)
    {
        bool on = ChkIntoVault.IsChecked == true;
        VaultDirEdit.IsEnabled = on;
        BtnVaultBrowse.IsEnabled = on;
        if (!on) { VaultDirEdit.Text = ""; ViewModel.IntoVault = ""; }
        else ViewModel.IntoVault = VaultDirEdit.Text;
    }
    internal void OnVaultDirChanged(object sender, TextChangedEventArgs e)
        => ViewModel.IntoVault = ChkIntoVault.IsChecked == true ? VaultDirEdit.Text : "";
    internal async void OnBrowseVaultDir(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FolderPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var folder = await picker.PickSingleFolderAsync();
            if (folder != null) VaultDirEdit.Text = folder.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[加密盘] 错误：{0}", ex.Message); }
    }

    // 加密盘库管理

    // 新建
    // 这里不问密码
    internal async void OnVaultInit(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
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

    // 查看盘内文件
    internal async void OnVaultList(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var dir = await PickVaultPathAsync(L10n.T("查看盘内文件"), true);
        if (dir == null) return;
        var pw = await AskPasswordAsync(L10n.T("加密盘密码"), false);
        if (pw == null) return;
        await RunVaultCliAsync(L10n.T("查看盘内文件"),
            new List<string> { "--vault-list", dir, "--key-stdin" }, ToStdin(pw),
            scrollable: true);
    }

    // 修改盘密码
    internal async void OnVaultRekey(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
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
        var newPw = await AskPasswordAsync(L10n.T("新密码（需输入两次）"), true);
        if (newPw == null) { DeleteTempPass(tmp); return; }

        await RunVaultCliAsync(L10n.T("修改加密盘密码"),
            new List<string> { "--vault-rekey", dir, "-k", tmp, "--new-key-stdin" },
            ToStdin(newPw),
            L10n.T("盘中所有文件均已使用新密码重新加密。原恢复码失效，请重新生成。"),
            tmp);
    }

    // 生成恢复码
    internal async void OnVaultRecoveryCreate(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var dir = await PickVaultPathAsync(L10n.T("生成恢复码"), true);
        if (dir == null) return;
        var pw = await AskPasswordAsync(L10n.T("加密盘密码"), false);
        if (pw == null) return;
        await RunVaultCliAsync(L10n.T("生成恢复码"),
            new List<string> { "--vault-recovery", dir, "--recovery-arg", "create", "--key-stdin" },
            ToStdin(pw),
            L10n.T("请将上方恢复码抄录至纸张并离线保存；持有该恢复码即可打开此加密盘。"));
    }

    // 用恢复码找回密
    internal async void OnVaultRecoveryOpen(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var dir = await PickVaultPathAsync(L10n.T("用恢复码找回密码"), true);
        if (dir == null) return;
        var code = await PromptTextAsync(L10n.T("用恢复码找回密码"),
            L10n.T("请输入此前记录的 48 位恢复码（仅限数字）："), L10n.T("恢复码"));
        if (code == null) return;
        await RunVaultCliAsync(L10n.T("用恢复码找回密码"),
            new List<string> { "--vault-recovery", dir, "--recovery-arg", "open " + code }, null,
            L10n.T("上方显示的是原密码。找回后请尽快修改密码并重新生成恢复码。"));
    }

    // 选加密盘目录
    // FolderPicker 不支持自定义起
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
            Text = L10n.T("请选择该加密盘所在的文件夹"),
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
        // 记住这块盘
        App.Settings.Current.LastVaultDir = dir;
        App.Settings.Save();
        return dir;
    }

    // 密码弹窗
    private async Task<string?> AskPasswordAsync(string purpose, bool needConfirm)
    {
        var dlg = new PasswordDialog(needConfirm)
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            Title = purpose,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return null;
        return string.IsNullOrEmpty(dlg.Password) ? null : dlg.Password;
    }

    // 单行文本输入弹
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

    // 密码转 stdin 字节
    private static byte[] ToStdin(string pw) => Encoding.UTF8.GetBytes(pw);

    // 跑一次 CLI 加密盘命
    private async Task RunVaultCliAsync(string title, List<string> args, byte[]? stdin,
                                        string? hint = null, string? deleteAfter = null,
                                        bool scrollable = false)
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
            // M40
            _ = Task.Run(async () => { await Task.Delay(1500); DeleteTempPass(deleteAfter); });

        string detail = sb.ToString().Trim();
        if (result.ExitCode == 0)
        {
            ViewModel.SetStatus("{0}：操作成功完成。", title);
            var body = detail;
            if (!string.IsNullOrEmpty(hint)) body = (body + "\n\n" + hint).Trim();
            if (scrollable) await new ScrollOutputDialog(title, string.IsNullOrEmpty(body) ? L10n.T("操作成功完成。") : body).ShowAsync();
            else await ShowMessageAsync(title, string.IsNullOrEmpty(body) ? L10n.T("操作成功完成。") : body);
        }
        else
        {
            ViewModel.SetStatus("{0}：操作失败（退出码 {1}）", title, result.ExitCode);
            var body = string.IsNullOrEmpty(detail)
                ? L10n.F("命令执行失败（退出码 {0}）。", result.ExitCode)
                : L10n.F("命令失败（exit {0}）：\n{1}", result.ExitCode, detail);
            if (scrollable) await new ScrollOutputDialog(title, body).ShowAsync();
            else await ShowMessageAsync(title, body);
        }
    }

    // 加密盘控制端
    internal async void OnVaultMount(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.T("未找到挂载组件 FE-Mounter。请重新安装并勾选「加密盘挂载」，或将 FE-Mounter 放在本程序同目录。"));
            return;
        }
        // WinFSP 用户态 DLL 必须
        // 但 WinFSP
        // 此处两者任一存
        var wfsp = Path.Combine(Path.GetDirectoryName(mounter) ?? "", "winfsp-x64.dll");
        var wfspSys = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) ?? @"C:\Program Files (x86)",
            "WinFsp", "bin", "winfsp-x64.dll");
        if (!File.Exists(wfsp) && !File.Exists(wfspSys))
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.T("挂载组件缺少 WinFSP 运行时（winfsp-x64.dll），无法挂载。\n请重新安装本程序（安装时勾选「加密盘挂载」与「WinFSP 运行时」）。"));
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

        // 记住这次
        App.Settings.Current.LastVaultDir = dir;
        App.Settings.Current.LastMountPoint = point;
        App.Settings.Save();

        // 登记到多库注册
        try { await RunMounterAsync(mounter, "vaults", "add", dir); } catch { }

        // 挂载前格式化
        if (dlg.FormatVault)
        {
            if (string.IsNullOrEmpty(ViewModel.CliPath))
            {
                await ShowMessageAsync(L10n.T("挂载为磁盘"), L10n.T("尚未找到命令行程序，无法格式化。"));
                return;
            }
            bool okFmt = false; string fmtDetail = "";
            try
            {
                var svc = new CliProcessService();
                var sb = new StringBuilder();
                svc.OutputLine += line => { lock (sb) { sb.AppendLine(line); } };
                var tcs = new TaskCompletionSource<CommandResult>();
                svc.Finished += r => tcs.TrySetResult(r);
                svc.Execute(new CommandRequest
                {
                    ProgramPath = ViewModel.CliPath,
                    Arguments = new List<string> { "--vault-format", dir, "--key-stdin" },
                    StdinData = ToStdin(pw),
                });
                var r = await tcs.Task;
                okFmt = r.ExitCode == 0;
                fmtDetail = sb.ToString().Trim();
            }
            catch (Exception ex) { fmtDetail = ex.Message; }
            if (!okFmt)
            {
                await ShowMessageAsync(L10n.T("挂载为磁盘"),
                    string.IsNullOrEmpty(fmtDetail) ? L10n.T("格式化失败。") : L10n.F("格式化失败：\n{0}", fmtDetail));
                return;
            }
        }

        // 记录挂载点进 vault.meta
        var cli = ViewModel.CliPath;
        if (!string.IsNullOrEmpty(cli))
        {
            try
            {
                // M38: 逐项传参
                var psi = new ProcessStartInfo(cli)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("--vault-mount");
                psi.ArgumentList.Add(dir);
                psi.ArgumentList.Add("--mount-point");
                psi.ArgumentList.Add(point);
                Process.Start(psi);
            }
            catch { }
        }

        var tmp = WriteTempPass(pw);
        if (tmp == null)
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"), L10n.T("无法写入临时密码文件。"));
            return;
        }

        // winmount <挂载点> --vault <dir> [-
        var args = new List<string> { "winmount", point, "--vault", dir };
        if (dlg.ReadWrite) args.Add("--rw");
        args.Add("--idle-timeout");
        args.Add("60");
        args.Add("--pass-file");
        args.Add(tmp);

        bool ok = LaunchMounterDetached(mounter, args);
        // FE-Mounter 启动时即读取并
        _ = Task.Run(async () => { await Task.Delay(2000); DeleteTempPass(tmp); });

        if (ok)
        {
            RecordMount(dir, point);
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.F("正在挂载，盘符由后台进程持有。稍后可在「此电脑」中看到：{0}", point));
        }
        else
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.T("无法启动挂载组件。请确认 FE-Mounter 存在，且未被安全软件拦截。"));
    }

    // 卸载磁盘
    // 走 IPC eject
    internal async void OnVaultUnmount(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("卸载磁盘"),
                L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }
        var dir = await PickVaultPathAsync(L10n.T("卸载磁盘"), true);
        if (dir == null) return;
        var mp = (App.Settings.Current.LastMountPoint ?? "").Trim();
        var body = string.IsNullOrEmpty(mp)
            ? L10n.T("将卸载该加密盘的挂载，盘符会随之消失。")
            : L10n.F("将卸载该加密盘的挂载（{0}），盘符会随之消失。", mp);
        var ask = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            Title = L10n.T("卸载磁盘"),
            Content = body,
            PrimaryButtonText = L10n.T("卸载"),
            CloseButtonText = L10n.T("取消"),
            DefaultButton = ContentDialogButton.Close,
        };
        if (await ask.ShowAsync() != ContentDialogResult.Primary) return;
        await RunVaultIpcAsync(mounter, dir, new List<string> { "eject" }, null, L10n.T("卸载磁盘"));
        ForgetMount(dir);
    }

    // 记录 / 清除已挂载
    private void RecordMount(string dir, string point)
    {
        try
        {
            var list = App.Settings.Current.MountedVaults;
            list.RemoveAll(m => m.VaultDir.Equals(dir, StringComparison.OrdinalIgnoreCase));
            list.Add(new MountedVault { VaultDir = dir, MountPoint = point });
            App.Settings.Save();
        }
        catch { }
    }
    private void ForgetMount(string dir)
    {
        try
        {
            var list = App.Settings.Current.MountedVaults;
            if (list.RemoveAll(m => m.VaultDir.Equals(dir, StringComparison.OrdinalIgnoreCase)) > 0)
                App.Settings.Save();
        }
        catch { }
    }

    // 格式化
    internal async void OnVaultFormat(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var dir = await PickVaultPathAsync(L10n.T("格式化加密盘"), true);
        if (dir == null) return;
        var warn = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            Title = L10n.T("格式化加密盘"),
            Content = L10n.F("将清空该加密盘内的全部文件（{0}）。\n\n盘的身份与密码保留，格式化后仍可用原密码继续入盘；但盘内原有文件无法恢复。\n\n若该盘正被挂载，请先执行「卸载磁盘」。", dir),
            PrimaryButtonText = L10n.T("格式化"),
            PrimaryButtonStyle = ThemeService.StyleFor("AppDangerButtonStyle"),
            CloseButtonText = L10n.T("取消"),
            DefaultButton = ContentDialogButton.Close,
        };
        if (await warn.ShowAsync() != ContentDialogResult.Primary) return;
        var pw = await AskPasswordAsync(L10n.T("加密盘密码"), false);
        if (pw == null) return;
        await RunVaultCliAsync(L10n.T("格式化加密盘"),
            new List<string> { "--vault-format", dir, "--key-stdin" }, ToStdin(pw),
            L10n.T("加密盘已成功清空，可继续存入文件。"));
    }

    internal async void OnVaultLock(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("锁定"),
                L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }
        var dir = await PickVaultPathAsync(L10n.T("锁定"), true);
        if (dir == null) return;
        await RunVaultIpcAsync(mounter, dir, new List<string> { "lock" }, null, L10n.T("锁定"));
    }

    internal async void OnVaultUnlock(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var dir = await PickVaultPathAsync(L10n.T("解锁"), true);
        if (dir == null) return;
        await UnlockVaultDir(dir);
    }

    // 用单次输入
    // P2-1
    internal async Task UnlockVaultDir(string dir)
    {
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("解锁"),
                L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }

        // 免密路径
        // M42
        // DPAPI 缺程序集时 JIT
        // 此处兜底降级到
        byte[]? boundPw = null;
        try { boundPw = DeviceKeyService.TryGetPasswordBytes(dir); }
        catch { boundPw = null; }
        if (boundPw is { Length: > 0 })
        {
            var tmpDk = WriteTempPass(boundPw);
            // 字节已落临时文
            CryptographicOperations.ZeroMemory(boundPw);
            if (tmpDk != null)
            {
                await RunVaultIpcAsync(mounter, dir,
                    new List<string> { "unlock", "--pass-file", tmpDk }, tmpDk, L10n.T("解锁"));
                return;
            }
        }

        // 常规路径
        // 便于
        var pwd = new PasswordDialog(false)
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            Title = L10n.T("解锁加密盘"),
        };
        if (await pwd.ShowAsync() != ContentDialogResult.Primary) return;
        if (string.IsNullOrEmpty(pwd.Password)) return;

        var tmp = WriteTempPass(pwd.Password);
        if (tmp == null)
        {
            await ShowMessageAsync(L10n.T("解锁"), L10n.T("无法写入临时密码文件。"));
            return;
        }
        await RunVaultIpcAsync(mounter, dir,
            new List<string> { "unlock", "--pass-file", tmp }, tmp, L10n.T("解锁"));
    }

    // P1-1 设备加密管理页
    // 数据源 FE-Mounter `vaults
    // 后者只反映「本 GUI 挂
    internal async void OnVaultManager(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("加密盘管理"), L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }

        var dlg = new VaultManagerDialog(
            mounter,
            mount: async (dir, point) => await MountVaultDir(dir, point),
            unlock: async dir => await UnlockVaultDir(dir),
            doLock: async dir => await RunVaultIpcAsync(mounter, dir, new List<string> { "lock" }, null, L10n.T("锁定")),
            refreshHost: _ => { })   // 登记
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        await dlg.ShowAsync();
    }

    // P1-1
    private async Task MountVaultDir(string dir, string point)
    {
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"), L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }
        // 登记到多库注册
        await RunMounterAsync(mounter, "vaults", "add", dir);

        var pwd = new PasswordDialog(false)
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            Title = L10n.T("挂载为磁盘"),
        };
        if (await pwd.ShowAsync() != ContentDialogResult.Primary) return;
        if (string.IsNullOrEmpty(pwd.Password)) return;

        var tmp = WriteTempPass(pwd.Password);
        if (tmp == null)
        {
            await ShowMessageAsync(L10n.T("挂载为磁盘"), L10n.T("无法写入临时密码文件。"));
            return;
        }
        var args = new List<string> { "winmount", point, "--vault", dir, "--rw", "--idle-timeout", "60", "--pass-file", tmp };
        bool ok = LaunchMounterDetached(mounter, args);
        _ = Task.Run(async () => { await Task.Delay(2000); DeleteTempPass(tmp); });
        if (ok)
        {
            RecordMount(dir, point);
            await ShowMessageAsync(L10n.T("挂载为磁盘"),
                L10n.F("正在挂载，稍后可在「此电脑」中看到：{0}", point));
        }
    }

    private async Task RunMounterAsync(string mounter, params string[] args)
    {
        var cli = new CliProcessService();
        var tcs = new TaskCompletionSource<CommandResult>();
        cli.Finished += r => tcs.TrySetResult(r);
        cli.Execute(new CommandRequest
        {
            ProgramPath = mounter,
            Arguments = new List<string>(args),
        });
        await tcs.Task;
    }

    // 已挂载加密盘列
    internal async void OnMountedVaults(object sender, RoutedEventArgs e)
    {
        if (!await EnsureVaultAvailableAsync()) return;
        var mounter = FileEncryptorLocator.LocateMounter();
        if (mounter == null)
        {
            await ShowMessageAsync(L10n.T("已挂载加密盘"), L10n.T("未找到挂载组件 FE-Mounter。"));
            return;
        }
        var dlg = new MountedVaultsDialog(mounter,
            new List<MountedVault>(App.Settings.Current.MountedVaults), dir => _ = UnlockVaultDir(dir))
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
        };
        await dlg.ShowAsync();
    }

    // 写临时密码文件
    private string? WriteTempPass(string pw)
        => WriteTempPass(new UTF8Encoding(false).GetBytes(pw));

    // M42
    private string? WriteTempPass(byte[] pwBytes)
    {
        try
        {
            var tmp = Path.Combine(Path.GetTempPath(),
                $"fe_mountpw_{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}.tmp");
            // M39
            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var sid = WindowsIdentity.GetCurrent().User;
            if (sid == null) return null;
            sec.AddAccessRule(new FileSystemAccessRule(
                sid, FileSystemRights.FullControl, AccessControlType.Allow));
            using (var fs = new FileInfo(tmp).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, sec))
                fs.Write(pwBytes, 0, pwBytes.Length);
            // M41
            lock (_tempPassGate) _liveTempPasses.Add(tmp);
            return tmp;
        }
        catch { return null; }
    }

    // M41
    private static readonly List<string> _liveTempPasses = new();
    private static readonly object _tempPassGate = new();

    static MainWindow()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            lock (_tempPassGate)
            {
                foreach (var f in _liveTempPasses) DeleteTempPass(f);
                _liveTempPasses.Clear();
            }
        };
    }

    // M41
    private static void CleanupStaleTempPasses()
    {
        try
        {
            foreach (var f in Directory.GetFiles(Path.GetTempPath(), "fe_mountpw_*.tmp"))
                DeleteTempPass(f);
        }
        catch { }
    }

    // P2-3
    // 只 Delete
    private static void DeleteTempPass(string? path)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
            var n = new FileInfo(path).Length;
            if (n > 0)
            {
                // WriteThrough 绕开操作系统缓
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Write,
                    FileShare.None, 4096, FileOptions.WriteThrough);
                fs.Write(new byte[n]);
                fs.Flush(flushToDisk: true);
            }
            File.Delete(path);
            lock (_tempPassGate) _liveTempPasses.Remove(path);
        }
        catch { }
    }

    // detached 启动 FE-Mounter
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
            // 告知 mounter 自身路径
            try { psi.EnvironmentVariables["FE_GUI_PATH"] = Process.GetCurrentProcess().MainModule!.FileName; }
            catch { }
            foreach (var a in args) psi.ArgumentList.Add(a);
            Process.Start(psi);
            return true;
        }
        catch { return false; }
    }

    // 轮询 FE-Mounter 写
    private async void PollLockedAccess(DispatcherQueueTimer sender, object? args)
    {
        if (_unlockPromptActive) return;   // 已有解锁框
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                   "FileEncryptor", "GUI");
            if (!Directory.Exists(dir)) return;
            var files = Directory.GetFiles(dir, "fe_locked_*.event");
            foreach (var f in files)
            {
                string vault = "", mount = "";
                try
                {
                    foreach (var line in File.ReadAllLines(f))
                    {
                        if (line.StartsWith("vault=")) vault = line.Substring(6).Trim();
                        else if (line.StartsWith("mount=")) mount = line.Substring(6).Trim();
                    }
                }
                catch { }
                try { File.Delete(f); } catch { }
                // 内容校验
                if (string.IsNullOrEmpty(vault) || string.IsNullOrEmpty(mount)) continue;
                // 同 vault 短时间去重节
                var now = DateTime.UtcNow;
                lock (_unlockPromptTimes)
                {
                    // 顺手清理 5 分钟
                    List<string> stale = new();
                    foreach (var kv in _unlockPromptTimes)
                        if (now - kv.Value > TimeSpan.FromMinutes(5)) stale.Add(kv.Key);
                    foreach (var k in stale) _unlockPromptTimes.Remove(k);
                    if (_unlockPromptTimes.TryGetValue(vault, out var last)
                        && now - last < TimeSpan.FromSeconds(10))
                        continue;
                    _unlockPromptTimes[vault] = now;
                }
                // 已解锁
                if (!await IsVaultLockedAsync(vault)) continue;
                _unlockPromptActive = true;
                BringToForeground();
                _ = UnlockVaultDir(vault).ContinueWith(_ => _unlockPromptActive = false,
                    TaskScheduler.FromCurrentSynchronizationContext());
                break;   // 一次只处理一
            }
        }
        catch { }
    }

    // 锁定访问后让解
    // 最小化
    // 「拉起 GUI 却没弹密码
    private void BringToForeground()
    {
        try
        {
            var hwnd = WindowNative.GetWindowHandle(this);
            if (IsIconic(hwnd))
                ShowWindow(hwnd, 9);        // SW_RESTORE
            SetForegroundWindow(hwnd);
            Activate();
        }
        catch { }
    }

    // 查询该加密盘当
    private async Task<bool> IsVaultLockedAsync(string dir)
    {
        try
        {
            var mounter = FileEncryptorLocator.LocateMounter();
            if (mounter == null) return true;
            var cli = new CliProcessService();
            var sb = new StringBuilder();
            cli.OutputLine += l => { lock (sb) sb.AppendLine(l); };
            var tcs = new TaskCompletionSource<CommandResult>();
            cli.Finished += r => tcs.TrySetResult(r);
            cli.Execute(new CommandRequest
            {
                ProgramPath = mounter,
                Arguments = new List<string> { "ipc-call", "--vault", dir, "status" },
            });
            var r = await tcs.Task;
            if (r.ExitCode == 0 && sb.ToString().Contains("unlocked=1")) return false;
            return true;
        }
        catch { return true; }
    }

    // 经 FE-Mounter ipc-call 执行
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
            _ = Task.Run(async () =>
            {
                await Task.Delay(2000);
                try
                {
                    // 删除前先清零文
                    var len = new FileInfo(passFile).Length;
                    if (len > 0) File.WriteAllBytes(passFile, new byte[len]);
                }
                catch { }
                try { File.Delete(passFile); } catch { }
            });

        string detail = sb.ToString().Trim();
        if (result.ExitCode == 0)
        {
            ViewModel.SetStatus("{0}：操作成功完成。", title);
            if (!string.IsNullOrEmpty(detail)) await ShowMessageAsync(title, detail);
        }
        else
        {
            ViewModel.SetStatus("{0}：操作失败（退出码 {1}）", title, result.ExitCode);
            await ShowMessageAsync(title,
                string.IsNullOrEmpty(detail)
                    ? L10n.F("命令执行失败（退出码 {0}）。", result.ExitCode)
                    : L10n.F("命令失败（exit {0}）：\n{1}", result.ExitCode, detail));
        }
    }

    internal async void OnBrowseKeyfile(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) KeyfileEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[密钥文件] 错误：{0}", ex.Message); }
    }

    internal async void OnBrowseRecipient(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) RecipientEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[收件人] 错误：{0}", ex.Message); }
    }

    internal async void OnBrowseIdentity(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) IdentityEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[身份文件] 错误：{0}", ex.Message); }
    }

    internal async void OnBrowseWrapFile(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            if (ViewModel.IsWrapKeyMode) picker.FileTypeFilter.Add("*");
            else { picker.FileTypeFilter.Add(".fekw"); picker.FileTypeFilter.Add("*"); }
            var file = await picker.PickSingleFileAsync();
            if (file != null) WrapFileEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[密钥文件] 错误：{0}", ex.Message); }
    }

    internal async void OnBrowseWrapOut(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileSavePicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeChoices.Add(ViewModel.IsWrapKeyMode ? "包装文件" : "数据密钥",
                new List<string> { ViewModel.IsWrapKeyMode ? ".fekw" : ".dek" });
            var file = await picker.PickSaveFileAsync();
            if (file != null) WrapOutEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.SetStatus("[输出路径] 错误：{0}", ex.Message); }
    }

    internal async void OnBrowseWatermarkKey(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add(".pem");
            var file = await picker.PickSingleFileAsync();
            if (file == null) return;
            // 密钥内容直接进
            WatermarkKeyEdit.Password = await FileIO.ReadTextAsync(file);
            ViewModel.SetStatus("[水印私钥] 已载入：{0}", file.Name);
        } catch (Exception ex) { ViewModel.SetStatus("[水印私钥] 错误：{0}", ex.Message); }
    }

    private void UpdateVisibility()
    {
        bool isEncrypt = ViewModel.IsEncryptMode;
        bool isAsym = ViewModel.IsAsymmetric;
        bool isKeyGen = ViewModel.IsKeyGenMode;
        bool isWrap = ViewModel.IsWrapMode;
        bool isWrapKey = ViewModel.IsWrapKeyMode;
        bool wrapPubkey = isWrap && ViewModel.WrapUsesPublicKey;

        // 非对称
        bool asymMode = ModeCombo.SelectedIndex == 4;
        bool isKeyGenOnly = ViewModel.ActionIndex == 4;   // x448 只对「生成密钥对」

        // 加密模式整行只
        EncryptModeRow.Visibility = (isEncrypt && !isKeyGen) ? Visibility.Visible : Visibility.Collapsed;
        // 文件算法只
        var fileCipherVisible = asymMode && isEncrypt && !isKeyGen;
        FileCipherCell.Visibility = fileCipherVisible ? Visibility.Visible : Visibility.Collapsed;
        FileCipherLabel.Visibility = fileCipherVisible ? Visibility.Visible : Visibility.Collapsed;
        ModeCombo.SetValue(Microsoft.UI.Xaml.Controls.Grid.ColumnSpanProperty, fileCipherVisible ? 1 : 2);
        // 曲线开关
        ChkX448.Visibility = (asymMode || isKeyGenOnly) ? Visibility.Visible : Visibility.Collapsed;

        // 加密专属选项
        bool encOptionVisible = isEncrypt && !isKeyGen && !isWrap;
        // 藏起来
        if (!encOptionVisible)
        {
            if (ChkCompress.IsChecked == true) ChkCompress.IsChecked = false;
            if (ChkWatermark.IsChecked == true) ChkWatermark.IsChecked = false;
            if (ChkPack.IsChecked == true) ChkPack.IsChecked = false;
            if (ChkSplit.IsChecked == true) ChkSplit.IsChecked = false;
            // PQC 只影响载荷封装
            if (ChkPqc.IsChecked == true) ChkPqc.IsChecked = false;
        }
        SourceCombo.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkPack.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkSplit.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 分卷大小行只
        SplitSizeRow.Visibility = (encOptionVisible && ChkSplit.IsChecked == true)
            ? Visibility.Visible : Visibility.Collapsed;
        // 压缩整行
        CompressionRow.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkSha256.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 签名水印只服务
        ChkWatermark.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 后量子开关同样
        ChkPqc.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 公钥路线没有 KEK
        KeyfileEdit.Visibility = (!isAsym && !isKeyGen && !wrapPubkey) ? Visibility.Visible : Visibility.Collapsed;
        // 产物路径
        OutDirRow.Visibility = isWrap ? Visibility.Collapsed : Visibility.Visible;
        // 加密盘
        var vaultVisible = encOptionVisible && ViewModel.VaultAvailable;
        VaultRow.Visibility = vaultVisible ? Visibility.Visible : Visibility.Collapsed;
        if (!vaultVisible) ChkIntoVault.IsChecked = false;
        // 包装动作复用收
        RecipientPanel.Visibility = (isAsym && isEncrypt) || (isWrapKey && wrapPubkey)
            ? Visibility.Visible : Visibility.Collapsed;
        IdentityPanel.Visibility = (isAsym && !isEncrypt) || (ViewModel.IsUnwrapMode && wrapPubkey)
            ? Visibility.Visible : Visibility.Collapsed;
        // 同一面板
        RecipientLabel.Text = L10n.T(isWrapKey ? "收件人公钥：" : "收件人：");
        RecipientEdit.PlaceholderText = L10n.T(isWrapKey ? "公钥或公钥文件路径（--wrap-to）" : "公钥或公钥文件路径");
        IdentityLabel.Text = L10n.T(ViewModel.IsUnwrapMode ? "身份私钥：" : "身份文件：");
        ChkRestoreName.Visibility = ViewModel.ActionIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
        // PQC 在密钥生成时仍
        // 签名水印只
        UpdateWatermarkKeyRow();
        BtnRewrap.Visibility = isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        UpdateWrapPanel();

        // 切动作
        // 表现是滚动条莫
        MainScroll.UpdateLayout();
    }

    // 包装区块
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
        // 解包时算法写
        WrapAlgLabel.Text = L10n.T(wrapKey ? "包装算法" : "解密方式");
        WrapIntroText.Text = L10n.T(wrapKey
            ? (pubkey
                ? "使用收件人公钥封装 32 字节数据密钥，无需密码。"
                : "使用密码派生的密钥包装 32 字节数据密钥。")
            : (pubkey
                ? "从 .fekw 中取回 32 字节数据密钥，需要包装时收件人的身份私钥。"
                : "从 .fekw 中取回 32 字节数据密钥，需要包装时使用的密码。"));
    }

    // 水印私钥行
    private void UpdateWatermarkKeyRow()
        => WatermarkKeyRow.Visibility =
            (ChkWatermark.IsChecked == true && ViewModel.IsEncryptMode) ? Visibility.Visible : Visibility.Collapsed;

    // 运行
    internal async void OnRunClicked(object sender, RoutedEventArgs e)
    {
        if (ViewModel.CliPath == null)
        {
            ShowCliNotFoundDialog();
            return;
        }
        // 目录 + 删除类源处
        // 确认通过后下发 --source
        if (ViewModel.IsEncryptMode && !ViewModel.Pack && ViewModel.SourceIndex != 0)
        {
            var dirs = ViewModel.InputPaths.Where(p => p.IsSelected && Directory.Exists(p.Path)).ToList();
            if (dirs.Count > 0)
            {
                // ContentDialog 不在 XAML 视觉树里，L10n.T
                string how = ViewModel.SourceIndex switch
                {
                    2 => L10n.T("安全擦除（多次覆写）"),
                    3 => L10n.T("移至回收站"),
                    _ => L10n.T("删除"),
                };
                var show = dirs.Take(5).Select(d => d.Path).ToList();
                // 与 CLI 行
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
                    PrimaryButtonStyle = ThemeService.StyleFor("AppDangerButtonStyle"),
                    CloseButtonText = L10n.T("取消"),
                    DefaultButton = ContentDialogButton.Close,
                };
                if (await warn.ShowAsync() != ContentDialogResult.Primary)
                    return;
                ViewModel.SourceDeleteOk = true;
            }
        }
        // 入盘
        if (ViewModel.IsEncryptMode && ChkIntoVault.IsChecked == true)
        {
            var vd = (ViewModel.IntoVault ?? "").Trim();
            if (vd.Length == 0)
            {
                await ShowMessageAsync(L10n.T("缺少加密盘目录"), L10n.T("勾选「入加密盘」后请选择加密盘的存储目录，例如 D:\\Vault。"));
                VaultDirEdit.Focus(FocusState.Programmatic);
                return;
            }
            // 盘符根
            // 仅「去掉尾部斜杠
            string vdNoSlash = vd.TrimEnd('\\', '/');
            bool isDrive = vdNoSlash.Length >= 1 && char.IsLetter(vdNoSlash[0])
                && (vdNoSlash.Length == 1 || (vdNoSlash.Length == 2 && vdNoSlash[1] == ':'));
            if (isDrive)
            {
                await ShowMessageAsync(L10n.T("不支持使用盘符"),
                    L10n.T("「入加密盘」需要填写加密盘的存储目录，而不是挂载盘符。\n\n盘符（如 Z:）只是加密盘挂载后的访问视图，数据并不存放在那里。请填写数据实际所在的目录，例如 D:\\Vault。"));
                VaultDirEdit.Focus(FocusState.Programmatic);
                return;
            }
            if (!Directory.Exists(vd))
            {
                await ShowMessageAsync(L10n.T("加密盘目录无效"), L10n.F("找不到该目录：{0}\n请重新选择，或取消「入加密盘」改用普通加密。", vd));
                VaultDirEdit.Focus(FocusState.Programmatic);
                return;
            }
            // 非空且无 vault.meta
            if (!isDrive && !File.Exists(Path.Combine(vd, "vault.meta"))
                && Directory.EnumerateFileSystemEntries(vd).Any())
            {
                var ask = new ContentDialog
                {
                    XamlRoot = Content.XamlRoot,
                    RequestedTheme = CurrentTheme,
                    Title = L10n.T("初始化为新加密盘"),
                    Content = L10n.F("这个文件夹还不是加密盘：{0}\n请确认是否把它初始化为新的加密盘并写入文件。", vd),
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
        // 包装动作
        if (ViewModel.IsWrapMode)
        {
            if (!ViewModel.KeywrapAvailable)
            {
                await ShowMessageAsync(L10n.T("密钥包装不可用"),
                    L10n.T("配套的命令行程序没有密钥包装能力，无法包装或解包密钥。\n请更换带 OpenSSL 的 CLI。"));
                return;
            }
            // 包装输入是单
            var wrapIn = ViewModel.WrapInput ?? "";
            if (string.IsNullOrEmpty(wrapIn))
            {
                await ShowMessageAsync(L10n.T("缺少密钥文件"),
                    L10n.T(ViewModel.IsWrapKeyMode
                        ? "请先选择要包装的 32 字节数据密钥文件。"
                        : "请先选择要解包的 .fekw 包装文件。"));
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

    // CLI 确认询问
    // CLI 遇到 y/n 询问
    private async void OnConfirmPromptRequested(string text)
    {
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            RequestedTheme = CurrentTheme,
            // 问题文本来自 CLI
            Title = L10n.T("需要确认"),
            Content = text,
            PrimaryButtonText = L10n.T("是"),
            CloseButtonText = L10n.T("否"),
            DefaultButton = ContentDialogButton.Close,
        };
        bool yes = await dlg.ShowAsync() == ContentDialogResult.Primary;
        ViewModel.AnswerConfirm(yes);
    }
    internal void OnCancelClicked(object sender, RoutedEventArgs e) => ViewModel.Cancel();

    internal async void OnRewrapClicked(object sender, RoutedEventArgs e)
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
                ViewModel.SetStatus("密钥轮换功能开发中");
            }
        }
    }

    // 菜单
    internal void OnEditConfig(object sender, RoutedEventArgs e)
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

    // 自动
    private string? LocateUpdater()
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

    internal async void OnCheckForUpdate(object sender, RoutedEventArgs e)
    {
        var updater = LocateUpdater();
        if (updater == null)
        {
            await ShowMessageAsync(L10n.T("检查更新"), L10n.T("未找到更新器（Updater.exe）。请确认程序安装完整，或前往 GitHub 手动获取新版本。"));
            return;
        }
        try
        {
            var curVer = $"GUI {FileEncryptorLocator.GuiVersion} / CLI {FileEncryptorLocator.ExpectedCliVersion}";
            // 参数逐项传
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
                    Content = L10n.F("发现新版本 {0}。\n\n{1}\n\n{2}\n\n请确认是否现在下载并安装。", latest, notes, L10n.F("当前版本：{0}", curVer)),
                    PrimaryButtonText = L10n.T("下载并安装"),
                    CloseButtonText = L10n.T("关闭"),
                    XamlRoot = Content.XamlRoot,
                    RequestedTheme = CurrentTheme,
                };
                var r = await dlg.ShowAsync();
                if (r == ContentDialogResult.Primary)
                {
                    var url = root.GetProperty("download_url").GetString() ?? "";
                    var sha = root.TryGetProperty("sha256", out var s) ? s.GetString() ?? "" : "";
                    var sig = root.TryGetProperty("sig_url", out var g) ? g.GetString() ?? "" : "";
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

        var statusText = new TextBlock { Text = L10n.T("准备下载…"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", CurrentTheme) };
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

    internal async void OnCredits(object sender, RoutedEventArgs e)
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
        // 瑶璎珞额外加赞
        var sponsorLink = new HyperlinkButton { Content = L10n.T("赞助支持"), NavigateUri = new Uri("https://afdian.com/a/yaoyingluo"), Padding = new Thickness(0), Margin = new Thickness(16,0,0,0) };
        Grid.SetColumn(sponsorLink, 3); Grid.SetRow(sponsorLink, 0); grid.Children.Add(sponsorLink);
        AddRow(1, L10n.T("测试"), L10n.T("就不错了我"), "https://space.bilibili.com/1705671238");
        AddRow(2, L10n.T("宣传"), L10n.T("Twilight飞友"), "https://space.bilibili.com/3546728261224829");
        panel.Children.Add(grid);

        panel.Children.Add(new TextBlock { Text = L10n.T("\n本项目基于 libsodium 实现文件加密（XChaCha20-Poly1305 / AEGIS-256），采用 C++17 编写，跨平台运行于 Windows / Linux / macOS。"), TextWrapping = TextWrapping.Wrap, Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", CurrentTheme), FontSize = 12 });

        // 国庆节窗口内追
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

    internal async void OnReadme(object sender, RoutedEventArgs e)
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
        panel.Children.Add(new TextBlock { Text = L10n.T("许可证：AGPLv3（GNU Affero General Public License v3.0）"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,8,0,0) });
        panel.Children.Add(new HyperlinkButton { Content = L10n.T("https://www.gnu.org/licenses/agpl-3.0.html"), NavigateUri = new Uri("https://www.gnu.org/licenses/agpl-3.0.html"), Padding = new Thickness(0), Margin = new Thickness(0,2,0,0) });
        panel.Children.Add(new TextBlock { Text = L10n.T("本窗口为 README 摘要，完整文档请见项目根目录 README.md"), Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", CurrentTheme), FontSize = 12, Margin = new Thickness(0,8,0,0) });

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
        // M18
        // 会拼出指向错误
        if (rec.PathsStripped)
        {
            ViewModel.SetStatus(L10n.T(
                "该历史记录未保存完整路径，无法回放。可在设置中开启「任务历史保存完整路径」后，新任务才支持回放。"));
            return;
        }
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
        // 非对称模式
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
        // 算法下拉先设
        if (!string.IsNullOrEmpty(rec.WrapAlg))
            WrapAlgCombo.SelectedIndex = rec.WrapAlg switch { "kwp" => 0, "aes-kw" => 1, "pubkey" => 2, _ => WrapAlgCombo.SelectedIndex };
        if (!string.IsNullOrEmpty(rec.WrapInput)) WrapFileEdit.Text = rec.WrapInput;
        if (!string.IsNullOrEmpty(rec.WrapOutput)) WrapOutEdit.Text = rec.WrapOutput;
        ChkForce.IsChecked = rec.Force;
        ChkSha256.IsChecked = rec.Sha256;
        ChkCompress.IsChecked = rec.Compress;
        CompressLevel.Value = rec.CompressionLevel;
        SourceCombo.SelectedIndex = rec.SourceIndex;
        // 历史里只存占位
        var wmKey = rec.WatermarkKey ?? "";
        WatermarkKeyEdit.Password = wmKey.StartsWith("<") ? "" : wmKey;
        ViewModel.WatermarkKey = WatermarkKeyEdit.Password;
        // 打包
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
        ViewModel.SetStatus("已恢复任务：{0}", rec.ActionLabel);
    }

    internal void OnRetryCliDetection(object sender, RoutedEventArgs e)
    {
        if (ViewModel.DetectCli(out var path))
        {
            ViewModel.SetStatus("已检测到 CLI：{0}", path);
            ViewModel.RefreshCommandPreview();
        }
        else
        {
            ViewModel.SetStatus("未检测到 FileEncryptor CLI");
            ShowCliNotFoundDialog();
        }
    }

    // 窗口背景
    // 注意两处
    // 只设托管属性 SystemBackdrop
    // WinUI 的 setter 没递交到 DWM，窗口
    // DWM 的 Mica tint 跟随**系统**深浅
    // 深色系统 + 浅色应
    // 「黑白不一」
    public void ApplyBackdrop()
    {
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var mode = App.Settings.Current.BackgroundMode;
        // 应用实际生效
        var dark = CurrentTheme != ElementTheme.Light;

        if (_backgroundBrush.ImageSource != null)
        {
            // 有背景图
            SystemBackdrop = null;
        }
        else if (mode == BackgroundMode.Flat)
        {
            SystemBackdrop = null;
        }
        else
        {
            // MicaBackdrop.Kind 只读且跟随系统
            // Light 强制 MicaKind.Base，这样浅色应
            var mica = new MicaBackdrop();
            if (!dark) mica.Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.Base;
            SystemBackdrop = mica;
            int hr = DwmBackdrop.SetMica(hwnd);
            Debug.WriteLine($"DwmSetWindowAttribute(Mica) hr={hr} readback={DwmBackdrop.Query(hwnd)}");
        }

        // 背景
        ApplyNationalDayVisuals();
    }

    // 国庆主题
    private void ApplyNationalDayVisuals()
    {
        // 窗口底
        if (_backgroundBrush.ImageSource == null)
            RootGrid.Background = NationalDayTheme.WindowBackdropBrush();
        else
            _backgroundBrush.Opacity = 0.88;

        if (!NationalDayTheme.IsActive())
        {
            // 非国庆
            ApplyPanelBackdrops();
            return;
        }
        // 运行/取消
        NationalDayTheme.ApplyButtonColors(BtnRun, BtnCancel);
        ApplyTitleAccent();
        // 浅色
        NationalDayTheme.ApplyControlColors(RootGrid);
        // 功能区 / 文件选择
        ApplyPanelBackdrops();
        // 祝福语常驻功能
        BirthdayBar.Visibility = Visibility.Visible;
        RefreshBirthdayText();
    }

    private async void OnViewSettings(object sender, RoutedEventArgs e)
    {
        var dlg = new ViewSettingsDialog(_backgroundBrush) { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
        // 换过背景后要重
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

    // 更新源白名单
    private static readonly string[] s_allowedHosts = {
        "github.com", "api.github.com",
        "objects.githubusercontent.com", "codeload.github.com"
    };

    // 仅 GitHub 官方域名
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
