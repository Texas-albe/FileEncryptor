using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Windows.Storage;
using Windows.Storage.Pickers;
using FileEncryptorGUI.Services;
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
        Title = "FileEncryptorGUI 2.0.0";

        // 自定义标题栏：Acrylic 延伸到标题栏，按钮背景透明
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(DragRegion);
        var tb = AppWindow.TitleBar;
        tb.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
        tb.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        tb.ButtonHoverBackgroundColor = Windows.UI.Color.FromArgb(0x20, 0, 0, 0);
        tb.ButtonPressedBackgroundColor = Windows.UI.Color.FromArgb(0x30, 0, 0, 0);
        UpdateTitleBarButtonColors();

        // 16:9 窗口比例
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1280, 720));

        ChkForce.IsChecked = true;
        RbEncrypt.IsChecked = true;

        // 背景：自定义图片优先，否则 Acrylic
        RootGrid.Background = _backgroundBrush;
        ApplySavedBackground();
        if (_backgroundBrush.ImageSource == null)
            SystemBackdrop = new DesktopAcrylicBackdrop();
        ModeCombo.SelectedIndex = 0;
        SourceCombo.SelectedIndex = 0;

        // 标题栏图标
        try {
            var iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
            if (System.IO.File.Exists(iconPath))
                this.AppWindow.SetIcon(iconPath);
        } catch { /* 图标加载失败不影响功能 */ }

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
            }
        };

        ViewModel.PasswordRequested += OnPasswordRequested;
        ViewModel.TaskCompleted += OnTaskCompleted;
        ViewModel.TaskSummary += OnTaskSummary;
        this.Closed += (_, _) => App.Settings.Save();
    }

    private void OnFirstLoaded(object sender, RoutedEventArgs e)
    {
        RootGrid.Loaded -= OnFirstLoaded;
        if (!ViewModel.DetectCli(out _))
            ShowCliNotFoundDialog();
        else
            ViewModel.RefreshCommandPreview();
    }

    // ===== 密钥管理（ActionIndex 4-6） =====
    private void OnKeyMgmtRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbKeyGen.IsChecked == true) ViewModel.ActionIndex = 4;
        else if (RbDerive.IsChecked == true) ViewModel.ActionIndex = 5;
        else if (RbPubKey.IsChecked == true) ViewModel.ActionIndex = 6;
        UpdateVisibility();
    }

    // ===== 标题栏按钮颜色（深色主题固定白色） =====
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
    private async void ShowCliNotFoundDialog()
    {
        if (Content?.XamlRoot == null) { DispatcherQueue.TryEnqueue(ShowCliNotFoundDialog); return; }
        var names = FileEncryptorLocator.GetExpectedNames();
        var nameList = string.Join("\n", names.Select(n => "  • " + n));
        var panel = new StackPanel();
        var infoText = new TextBlock { Text = $"无法找到 FileEncryptor CLI 可执行文件\n\n程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。\n\n预期文件名：\n{nameList}\n\n当前程序目录：{AppContext.BaseDirectory}", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
        var statusText = new TextBlock { Text = "", Margin = new Thickness(0,8,0,0), Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray) };
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Visibility = Visibility.Collapsed, Margin = new Thickness(0,4,0,0) };
        panel.Children.Add(infoText); panel.Children.Add(statusText); panel.Children.Add(progress);
        var dlg = new ContentDialog { Title = "FileEncryptor CLI 未找到", Content = panel, PrimaryButtonText = "重试", SecondaryButtonText = "下载 CLI", CloseButtonText = "关闭", XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        var result = await dlg.ShowAsync();
        if (result == ContentDialogResult.Primary) { if (ViewModel.DetectCli(out _)) ViewModel.RefreshCommandPreview(); else ShowCliNotFoundDialog(); }
        else if (result == ContentDialogResult.Secondary) { await DownloadCliFromGithub(statusText, progress); }
    }

    private async System.Threading.Tasks.Task DownloadCliFromGithub(TextBlock statusText, ProgressBar progress)
    {
        try
        {
            statusText.Text = "正在从 GitHub 检索可用版本…";
            using var http = new System.Net.Http.HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("FileEncryptorGUI");
            var tagsJson = await http.GetStringAsync("https://api.github.com/repos/Texas-albe/FileEncryptor/tags");
            using var tagsDoc = System.Text.Json.JsonDocument.Parse(tagsJson);
            string bestTag = null; Version bestVer = null;
            var guiVer = FileEncryptorLocator.GuiVersion;
            foreach (var t in tagsDoc.RootElement.EnumerateArray())
            {
                var tag = t.GetProperty("name").GetString();
                if (tag != null && tag.StartsWith($"GUI{guiVer}_CLI"))
                {
                    var verStr = tag.Substring($"GUI{guiVer}_CLI".Length);
                    if (Version.TryParse(verStr, out var v) && (bestVer == null || v > bestVer)) { bestTag = tag; bestVer = v; }
                }
            }
            if (bestTag == null) { statusText.Text = $"未找到匹配 GUI {guiVer} 的 release"; return; }
            statusText.Text = $"找到 {bestTag}，正在获取下载链接…";
            var relJson = await http.GetStringAsync($"https://api.github.com/repos/Texas-albe/FileEncryptor/releases/tags/{bestTag}");
            using var relDoc = System.Text.Json.JsonDocument.Parse(relJson);
            string downloadUrl = null; string fileName = null;
            var suffix = OperatingSystem.IsWindows() ? ".exe" : "";
            foreach (var a in relDoc.RootElement.GetProperty("assets").EnumerateArray())
            {
                var an = a.GetProperty("name").GetString();
                if (an != null && an.StartsWith("FileEncryptorCLI-") && (suffix == "" || an.EndsWith(suffix)))
                { downloadUrl = a.GetProperty("browser_download_url").GetString(); fileName = an; break; }
            }
            if (downloadUrl == null) { statusText.Text = "未找到当前平台的 CLI 包"; return; }
            statusText.Text = $"下载中：{fileName}";
            progress.Visibility = Visibility.Visible;
            var bytes = await http.GetByteArrayAsync(downloadUrl);
            progress.Value = 100;
            var savePath = System.IO.Path.Combine(AppContext.BaseDirectory, fileName);
            System.IO.File.WriteAllBytes(savePath, bytes);
            statusText.Text = $"下载完成：{fileName}";
        }
        catch (Exception ex) { statusText.Text = $"下载失败：{ex.Message}"; }
    }

    // ===== 密码请求 =====
    private async void OnPasswordRequested()
    {
        var dlg = new PasswordDialog { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
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
            ViewModel.OutputText = "[添加文件] 错误: " + ex.Message;
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
            ViewModel.OutputText = "[添加目录] 错误: " + ex.Message;
        }
    }

    private void OnClearFiles(object sender, RoutedEventArgs e) => ViewModel.ClearInputPaths();

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

    private void OnSourceChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SourceCombo.SelectedIndex >= 0) ViewModel.SourceIndex = SourceCombo.SelectedIndex;
    }

    private void OnOptionChanged(object sender, RoutedEventArgs e)
    {
        ViewModel.Force = ChkForce.IsChecked == true;
        ViewModel.Sha256 = ChkSha256.IsChecked == true;
        ViewModel.Compress = ChkCompress.IsChecked == true;
        ViewModel.RestoreName = ChkRestoreName.IsChecked == true;
    }

    private void OnCompressLevelChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        ViewModel.CompressLevel = (int)sender.Value;
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
        } catch (Exception ex) { ViewModel.OutputText = "[输出目录] 错误: " + ex.Message; }
    }

    private async void OnBrowseKeyfile(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) KeyfileEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.OutputText = "[密钥文件] 错误: " + ex.Message; }
    }

    private async void OnBrowseRecipient(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) RecipientEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.OutputText = "[收件人] 错误: " + ex.Message; }
    }

    private async void OnBrowseIdentity(object sender, RoutedEventArgs e)
    {
        try {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");
            var file = await picker.PickSingleFileAsync();
            if (file != null) IdentityEdit.Text = file.Path;
        } catch (Exception ex) { ViewModel.OutputText = "[身份文件] 错误: " + ex.Message; }
    }

    private void UpdateVisibility()
    {
        bool isEncrypt = ViewModel.IsEncryptMode;
        bool isAsym = ViewModel.IsAsymmetric;
        bool isKeyGen = ViewModel.IsKeyGenMode;

        ModeCombo.Visibility = isKeyGen ? Visibility.Collapsed : Visibility.Visible;
        SourceCombo.Visibility = isEncrypt && !isKeyGen ? Visibility.Visible : Visibility.Collapsed;
        ChkCompress.Visibility = isEncrypt && !isAsym && !isKeyGen ? Visibility.Visible : Visibility.Collapsed;
        CompressLevel.Visibility = ChkCompress.Visibility;
        KeyfileEdit.Visibility = !isAsym && !isKeyGen ? Visibility.Visible : Visibility.Collapsed;
        RecipientPanel.Visibility = isAsym && isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        IdentityPanel.Visibility = isAsym && !isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        ChkRestoreName.Visibility = ViewModel.ActionIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
        ChkSha256.Visibility = isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        BtnRewrap.Visibility = isEncrypt ? Visibility.Visible : Visibility.Collapsed;
    }

    // ===== 运行 =====
    private void OnRunClicked(object sender, RoutedEventArgs e)
    {
        if (ViewModel.CliPath == null)
        {
            ShowCliNotFoundDialog();
            return;
        }
        ViewModel.Run();
    }
    private void OnCancelClicked(object sender, RoutedEventArgs e) => ViewModel.Cancel();

    private async void OnRewrapClicked(object sender, RoutedEventArgs e)
    {
        var dlg = new ContentDialog
        {
            Title = "密钥轮换（v6 容器）",
            Content = "选择一个已加密的 .ptd 文件，用旧口令解密后用新口令重新包裹 DEK。\n文件内容不变，仅更换口令。",
            PrimaryButtonText = "选择文件",
            SecondaryButtonText = "取消",
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
                // TODO: rewrap 流程
                ViewModel.StatusText = "密钥轮换功能实现中";
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
            ViewModel.StatusText = "配置文件不存在（首次运行 CLI 后生成）";
    }

    private void OnExit(object sender, RoutedEventArgs e) => Close();

    private async void OnCredits(object sender, RoutedEventArgs e)
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "FileEncryptor v2.0.0 — 鸣谢", FontWeight = Microsoft.UI.Text.FontWeights.Bold, FontSize = 18, Margin = new Thickness(0,0,0,12) });
        panel.Children.Add(new TextBlock { Text = "感谢以下贡献者的付出：", Margin = new Thickness(0,0,0,8) });

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
                var hl = new HyperlinkButton { Content = "个人主页", NavigateUri = new Uri(link), Padding = new Thickness(0) };
                Grid.SetColumn(hl, 2); Grid.SetRow(hl, row); grid.Children.Add(hl);
            }
        }
        AddRow(0, "代码开发", "瑶璎珞", "https://space.bilibili.com/3546692557212318");
        // 瑶璎珞额外加赞助链接
        var sponsorLink = new HyperlinkButton { Content = "赞助支持", NavigateUri = new Uri("https://afdian.com/a/yaoyingluo"), Padding = new Thickness(0), Margin = new Thickness(16,0,0,0) };
        Grid.SetColumn(sponsorLink, 3); Grid.SetRow(sponsorLink, 0); grid.Children.Add(sponsorLink);
        AddRow(1, "测试", "就不错了我", "https://space.bilibili.com/1705671238");
        AddRow(2, "宣传", "Twilight飞友", "https://space.bilibili.com/3546728261224829");
        panel.Children.Add(grid);

        panel.Children.Add(new TextBlock { Text = "\n本项目基于 libsodium 实现文件加密（XChaCha20-Poly1305 / AEGIS-256），采用 C++17 编写，跨平台运行于 Windows / Linux / macOS。", TextWrapping = TextWrapping.Wrap, Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray), FontSize = 12 });

        var dlg = new ContentDialog { Title = "鸣谢", Content = new ScrollViewer { Content = panel, MaxHeight = 400, VerticalScrollBarVisibility = ScrollBarVisibility.Hidden }, CloseButtonText = "关闭", XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
    }

    private async void OnReadme(object sender, RoutedEventArgs e)
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "FileEncryptor v2.0.0 — 项目摘要", FontWeight = Microsoft.UI.Text.FontWeights.Bold, FontSize = 18, Margin = new Thickness(0,0,0,12) });
        panel.Children.Add(new TextBlock { Text = "简介：跨平台（Windows / Linux / macOS）文件加密工具，基于 libsodium 实现 XChaCha20-Poly1305 与 AEGIS-256 加密。", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = "核心特性", FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
        panel.Children.Add(new TextBlock { Text = "• 加密算法：XChaCha20-Poly1305（默认）/ AEGIS-256，密钥经 Argon2id 派生" });
        panel.Children.Add(new TextBlock { Text = "• 单文件与批量：支持单文件加/解密，及目录批量加/解密（递归）" });
        panel.Children.Add(new TextBlock { Text = "• 断点续传：加密中断后可从上次进度继续，防静默数据丢失" });
        panel.Children.Add(new TextBlock { Text = "• 路径安全：拒绝目录穿越（..），白名单前缀校验" });
        panel.Children.Add(new TextBlock { Text = "• 限速：进程级令牌桶限速（YAML max_speed 配置）" });
        panel.Children.Add(new TextBlock { Text = "• 配置化：日志/并发/路径策略等运维参数经 YAML 配置", Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = "命令行用法", FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
        panel.Children.Add(new TextBlock { Text = "FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\nFileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]", FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"), Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = "密钥来源优先级", FontWeight = Microsoft.UI.Text.FontWeights.Bold, Margin = new Thickness(0,8,0,4) });
        panel.Children.Add(new TextBlock { Text = "-k <keyfile>（密钥文件） > --key-stdin（stdin 管道） > ENCRYPTOR_KEY（环境变量） > 交互式输入；非对称模式用 X25519 身份私钥 > 交互式输入", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,8) });
        panel.Children.Add(new TextBlock { Text = "许可证：GPLv3", Margin = new Thickness(0,8,0,0) });
        panel.Children.Add(new TextBlock { Text = "本窗口为 README 摘要，完整文档请见项目根目录 README.md", Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray), FontSize = 12, Margin = new Thickness(0,8,0,0) });

        var dlg = new ContentDialog { Title = "README 摘要", Content = new ScrollViewer { Content = panel, MaxHeight = 480, VerticalScrollBarVisibility = ScrollBarVisibility.Hidden }, CloseButtonText = "关闭", XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
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
        // 恢复操作模式
        ViewModel.ActionIndex = rec.Action switch
        {
            "encrypt" => 0,
            "decrypt" => 1,
            "batch-encrypt" => 2,
            "batch-decrypt" => 3,
            "keygen" => 4,
            "derive" => 5,
            "pubkey" => 6,
            _ => ViewModel.ActionIndex
        };
        // 恢复加密模式
        ViewModel.ModeIndex = rec.Mode switch
        {
            "xchacha20" => 0,
            "aegis256" => 1,
            "rage" => 2,
            _ => ViewModel.ModeIndex
        };
        // 恢复输出目录
        if (!string.IsNullOrEmpty(rec.OutputDir))
            OutDirEdit.Text = rec.OutputDir;
        // 恢复文件列表
        ViewModel.ClearInputPaths();
        ViewModel.AddInputPaths(rec.InputPaths);
        // 恢复所有参数
        ViewModel.SourceIndex = rec.SourceIndex;
        ViewModel.Force = rec.Force;
        ViewModel.Sha256 = rec.Sha256;
        ViewModel.Compress = rec.Compress;
        ViewModel.CompressLevel = rec.CompressionLevel;
        if (!string.IsNullOrEmpty(rec.Keyfile)) KeyfileEdit.Text = rec.Keyfile;
        if (!string.IsNullOrEmpty(rec.Recipient)) RecipientEdit.Text = rec.Recipient;
        if (!string.IsNullOrEmpty(rec.Identity)) IdentityEdit.Text = rec.Identity;
        ChkRestoreName.IsChecked = rec.RestoreName;
        // 同步 UI 控件状态
        ChkForce.IsChecked = rec.Force;
        ChkSha256.IsChecked = rec.Sha256;
        ChkCompress.IsChecked = rec.Compress;
        CompressLevel.Value = rec.CompressionLevel;
        SourceCombo.SelectedIndex = rec.SourceIndex;
        UpdateVisibility();
        ViewModel.StatusText = $"已恢复任务: {rec.ActionLabel}";
    }

    private void OnRetryCliDetection(object sender, RoutedEventArgs e)
    {
        if (ViewModel.DetectCli(out var path))
        {
            ViewModel.StatusText = $"已检测到 CLI: {path}";
            ViewModel.RefreshCommandPreview();
        }
        else
        {
            ViewModel.StatusText = "未检测到 FileEncryptor CLI";
            ShowCliNotFoundDialog();
        }
    }

    private async void OnViewSettings(object sender, RoutedEventArgs e)
    {
        var dlg = new ViewSettingsDialog(_backgroundBrush) { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
        // 如果清除了背景，恢复 Acrylic
        if (_backgroundBrush.ImageSource == null && SystemBackdrop == null)
            SystemBackdrop = new DesktopAcrylicBackdrop();
        else if (_backgroundBrush.ImageSource != null)
            SystemBackdrop = null;
    }

    private void ApplySavedBackground()
    {
        var path = App.Settings.Current.CustomBackgroundPath;
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        try
        {
            var bitmap = new BitmapImage();
            bitmap.UriSource = new Uri(path);
            _backgroundBrush.ImageSource = bitmap;
            _backgroundBrush.Stretch = Stretch.UniformToFill;
            _backgroundBrush.Opacity = 1.0;
        }
        catch { /* ignore */ }
    }
}

