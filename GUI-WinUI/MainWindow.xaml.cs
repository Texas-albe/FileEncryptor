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

        // 先初始化语言再翻译界面
        L10n.Init();
        ApplyLocalization();

        Title = $"FileEncryptorGUI {FileEncryptorLocator.GuiVersion}";
        TitleText.Text = Title;

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
        if (_backgroundBrush.ImageSource == null)
            SystemBackdrop = new DesktopAcrylicBackdrop();

        // 国庆节覆盖主题色
        if (NationalDayTheme.IsActive())
        {
            RootGrid.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(NationalDayTheme.WindowBg);
            SystemBackdrop = null;
            // 运行/取消按钮也走红系，否则绿色运行键是杂色
            NationalDayTheme.ApplyButtonColors(BtnRun, BtnCancel);
        }
        ModeCombo.SelectedIndex = 0;
        SourceCombo.SelectedIndex = 0;

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
            }
        };

        ViewModel.PasswordRequested += OnPasswordRequested;
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
        ViewModel.RefreshRuntimeTexts();
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
    }

    private void OnLangZh(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.Zh);
    private void OnLangEn(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.En);
    private void OnLangRu(object sender, RoutedEventArgs e) => ChangeLanguage(L10n.Ru);

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
    }

    // ===== 动作 / 密钥管理 =====
    // 两组单选分属不同 GroupName，选中态互不干扰；这里显式互斥，避免同时点亮两组
    private void ExclusiveGroup(bool keyMgmtGroup)
    {
        if (keyMgmtGroup)
        {
            RbEncrypt.IsChecked = false; RbDecrypt.IsChecked = false;
            RbBatchEncrypt.IsChecked = false; RbBatchDecrypt.IsChecked = false;
        }
        else
        {
            RbKeyGen.IsChecked = false; RbDerive.IsChecked = false; RbPubKey.IsChecked = false;
        }
    }

    private void OnKeyMgmtRadioChecked(object sender, RoutedEventArgs e)
    {
        if (RbKeyGen.IsChecked != true && RbDerive.IsChecked != true && RbPubKey.IsChecked != true) return;
        ExclusiveGroup(keyMgmtGroup: true);
        if (RbKeyGen.IsChecked == true) ViewModel.ActionIndex = 4;
        else if (RbDerive.IsChecked == true) ViewModel.ActionIndex = 5;
        else if (RbPubKey.IsChecked == true) ViewModel.ActionIndex = 6;
        UpdateVisibility();
    }

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
        var dlg = new ContentDialog { Title = L10n.T("FileEncryptor CLI 未找到"), Content = panel, PrimaryButtonText = L10n.T("重试"), SecondaryButtonText = L10n.T("下载 CLI"), CloseButtonText = L10n.T("关闭"), XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        var result = await dlg.ShowAsync();
        if (result == ContentDialogResult.Primary) { if (ViewModel.DetectCli(out _)) ViewModel.RefreshCommandPreview(); else ShowCliNotFoundDialog(); }
        else if (result == ContentDialogResult.Secondary) { await ShowDownloadCliDialog(); }
    }

    private async System.Threading.Tasks.Task ShowDownloadCliDialog()
    {
        var statusText = new TextBlock { Text = L10n.T("准备下载…"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), Foreground = new SolidColorBrush(Microsoft.UI.Colors.Gray) };
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0, Margin = new Thickness(0, 4, 0, 0) };
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
        _ = DownloadCliFromGithub(statusText, progress);
        await dlg.ShowAsync();
    }

    // 在 tag 列表中定位精确 tag：命中返回索引，未找到返回 -1
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
            // 只接受与预期版本精确配套的 tag；取“最大版本”会下到不匹配的 CLI
            var guiVer = FileEncryptorLocator.GuiVersion;
            var cliVer = FileEncryptorLocator.ExpectedCliVersion;
            var want = $"GUI{guiVer}_CLI{cliVer}";
            var idx = IndexOfTag(tagsDoc.RootElement, want);
            if (idx < 0)
            {
                statusText.Text = L10n.F("未找到预期的 CLI {0}（要求 tag GUI{1}_CLI{0}），已中止下载",
                    cliVer, guiVer);
                return;
            }
            statusText.Text = L10n.F("找到 {0}，正在获取下载链接…", want);
            var relJson = await http.GetStringAsync($"https://api.github.com/repos/Texas-albe/FileEncryptor/releases/tags/{want}");
            using var relDoc = System.Text.Json.JsonDocument.Parse(relJson);
            string downloadUrl = null; string fileName = null;
            var suffix = OperatingSystem.IsWindows() ? ".exe" : "";
            foreach (var a in relDoc.RootElement.GetProperty("assets").EnumerateArray())
            {
                var an = a.GetProperty("name").GetString();
                if (an != null && an.StartsWith("FileEncryptorCLI-") && (suffix == "" || an.EndsWith(suffix)))
                { downloadUrl = a.GetProperty("browser_download_url").GetString(); fileName = an; break; }
            }
            if (downloadUrl == null) { statusText.Text = L10n.T("未找到当前平台的 CLI 包"); return; }

            if (!IsAllowedDownloadHost(downloadUrl))
            {
                statusText.Text = L10n.T("下载链接域名不在白名单内，已中止");
                return;
            }
            fileName = Path.GetFileName(fileName.Trim());
            if (string.IsNullOrEmpty(fileName) || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                statusText.Text = L10n.T("下载文件名非法，已中止");
                return;
            }

            statusText.Text = L10n.F("下载中：{0}", fileName);
            progress.Visibility = Visibility.Visible;

            tempPath = Path.Combine(Path.GetTempPath(), $"fe_cli_{Guid.NewGuid():N}.tmp");
            var bytes = await http.GetByteArrayAsync(downloadUrl);
            progress.Value = 60;

            var expectedHash = await TryFetchSha256(http, downloadUrl);
            if (expectedHash != null)
            {
                using var sha = System.Security.Cryptography.SHA256.Create();
                var actualHash = Convert.ToHexString(sha.ComputeHash(bytes)).ToLowerInvariant();
                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    statusText.Text = L10n.T("SHA256 校验失败，下载内容已被丢弃");
                    return;
                }
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("CLI release 未提供 .sha256 清单，跳过完整性校验");
            }

            await File.WriteAllBytesAsync(tempPath, bytes);
            var savePath = Path.Combine(AppContext.BaseDirectory, fileName);
            File.Move(tempPath, savePath, overwrite: true);
            tempPath = null;
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
        ExclusiveGroup(keyMgmtGroup: false);
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
        } catch (Exception ex) { ViewModel.SetStatus("[输出目录] 错误: {0}", ex.Message); }
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

        // 非对称（X25519 / X448）模式下「文件算法」与曲线开关才有意义
        bool asymMode = ModeCombo.SelectedIndex == 3;
        bool isKeyGenOnly = ViewModel.ActionIndex == 4;   // -x448 只对「生成密钥对」有意义

        // 加密模式整行只服务加密动作：解密 / 批量解密 / 密钥管理三项下一律连左侧标签一起收起
        EncryptModeRow.Visibility = (isEncrypt && !isKeyGen) ? Visibility.Visible : Visibility.Collapsed;
        // 文件算法只在非对称模式露出；露出时模式下拉退回半宽，两个选择框等分同一行
        var fileCipherVisible = asymMode && isEncrypt && !isKeyGen;
        FileCipherCell.Visibility = fileCipherVisible ? Visibility.Visible : Visibility.Collapsed;
        FileCipherLabel.Visibility = fileCipherVisible ? Visibility.Visible : Visibility.Collapsed;
        ModeCombo.SetValue(Microsoft.UI.Xaml.Controls.Grid.ColumnSpanProperty, fileCipherVisible ? 1 : 2);
        // 曲线开关：非对称模式下控制封装曲线；生成密钥对时控制 -x448（CLI 只认这条）
        ChkX448.Visibility = (asymMode || isKeyGenOnly) ? Visibility.Visible : Visibility.Collapsed;

        // 加密专属选项：密钥管理三项目（生成密钥对 / 口令派生 / 导出公钥）下一律不出现
        bool encOptionVisible = isEncrypt && !isKeyGen;
        // 藏起来的开关先取消勾选，免得 CLI 收到对当前动作无意义的开关
        if (!encOptionVisible)
        {
            if (ChkCompress.IsChecked == true) ChkCompress.IsChecked = false;
            if (ChkWatermark.IsChecked == true) ChkWatermark.IsChecked = false;
        }
        SourceCombo.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 压缩整行（含标签与级别输入）同样只在加密动作出现，解密 / 批量解密 / 密钥管理下连行一起收起
        CompressionRow.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        ChkSha256.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        // 签名水印只服务于加密动作
        ChkWatermark.Visibility = encOptionVisible ? Visibility.Visible : Visibility.Collapsed;
        KeyfileEdit.Visibility = !isAsym && !isKeyGen ? Visibility.Visible : Visibility.Collapsed;
        RecipientPanel.Visibility = isAsym && isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        IdentityPanel.Visibility = isAsym && !isEncrypt ? Visibility.Visible : Visibility.Collapsed;
        ChkRestoreName.Visibility = ViewModel.ActionIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
        // PQC 在密钥生成时仍有意义（CLI 的 -g 读 --no-pqc），X448 由上一行单独控制；
        // 签名水印只在加密动作下露出（见上）。
        UpdateWatermarkKeyRow();
        BtnRewrap.Visibility = isEncrypt ? Visibility.Visible : Visibility.Collapsed;
    }

    // 水印私钥行：勾选「签名水印」后才显示（该行不改变动作语义，任何加密模式都可用）
    private void UpdateWatermarkKeyRow()
        => WatermarkKeyRow.Visibility =
            (ChkWatermark.IsChecked == true && ViewModel.IsEncryptMode) ? Visibility.Visible : Visibility.Collapsed;

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
            Title = L10n.T("密钥轮换（v6 容器）"),
            Content = L10n.T("选择一个已加密的 .ptd 文件，用旧口令解密后用新口令重新包裹 DEK。\n文件内容不变，仅更换口令。"),
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
                    Content = L10n.F("发现新版本 {0}。\n\n{1}\n\n是否现在下载并安装？", latest, notes),
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
                var cur = root.GetProperty("current_version").GetString();
                await ShowMessageAsync("检查更新", L10n.F("已是最新版本（{0}）。", cur));
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

        // 国庆节窗口内追加祝福语
        if (NationalDayTheme.IsActive())
        {
            panel.Children.Add(new TextBlock
            {
                Text = NationalDayTheme.BirthdayMessage(),
                TextWrapping = TextWrapping.Wrap,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                FontSize = 16,
                Margin = new Thickness(0, 12, 0, 0),
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
        panel.Children.Add(new TextBlock { Text = "FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\nFileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]", FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"), Margin = new Thickness(0,0,0,8) });
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
            _ => ViewModel.ActionIndex
        };
        ViewModel.ModeIndex = rec.Mode switch
        {
            "xchacha20" => 0,
            "aegis256" => 1,
            "sm4" => 2,
            "x25519" => 3,
            "x448" => 3,
            "asymmetric" => 3,
            _ => ViewModel.ModeIndex
        };
        // 非对称模式的文件算法一并回填，否则下拉会停在默认项却回放出对应的 -m
        ModeCombo.SelectedIndex = ViewModel.ModeIndex;
        FileCipherCombo.SelectedIndex = rec.FileCipher switch
        {
            "aegis256" => 1,
            "sm4" => 2,
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
        ChkForce.IsChecked = rec.Force;
        ChkSha256.IsChecked = rec.Sha256;
        ChkCompress.IsChecked = rec.Compress;
        CompressLevel.Value = rec.CompressionLevel;
        SourceCombo.SelectedIndex = rec.SourceIndex;
        // 历史里只存占位符，私钥需重新输入
        var wmKey = rec.WatermarkKey ?? "";
        WatermarkKeyEdit.Password = wmKey.StartsWith("<") ? "" : wmKey;
        ViewModel.WatermarkKey = WatermarkKeyEdit.Password;
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

    private async void OnViewSettings(object sender, RoutedEventArgs e)
    {
        var dlg = new ViewSettingsDialog(_backgroundBrush) { XamlRoot = Content.XamlRoot, RequestedTheme = CurrentTheme };
        await dlg.ShowAsync();
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
