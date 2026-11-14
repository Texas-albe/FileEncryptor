using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI;

// P1-1 设备加密管理页
// 一行列出
// 免密开关
// 数据源是 FE-Mounter
// 只能靠 settings.json 里
// 子串匹配
public sealed partial class VaultManagerDialog : ContentDialog
{
    private sealed class VaultRow
    {
        public string Vault { get; set; } = "";
        public string Mount { get; set; } = "";
        public bool Reachable { get; set; }
        public bool Unlocked { get; set; }
        public long? Idle { get; set; }
    }

    private sealed class StatusDoc
    {
        public int Count { get; set; }
        public List<VaultRow> Vaults { get; set; } = new();
    }

    private readonly string _mounter;
    private readonly Func<string, string, Task> _mount;   // (dir, mountPoint)
    private readonly Func<string, Task> _unlock;          // dir
    private readonly Func<string, Task> _doLock;          // dir
    private readonly Action<string> _refreshHost;         // 刷新宿主设置
    private readonly StackPanel _rows;
    private readonly TextBlock _summary;

    public VaultManagerDialog(string mounter,
                              Func<string, string, Task> mount,
                              Func<string, Task> unlock,
                              Func<string, Task> doLock,
                              Action<string> refreshHost)
    {
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };

        _mounter = mounter;
        _mount = mount;
        _unlock = unlock;
        _doLock = doLock;
        _refreshHost = refreshHost;

        _summary = new TextBlock { Margin = new Thickness(0, 0, 0, 6), TextWrapping = TextWrapping.Wrap };
        _rows = new StackPanel { Spacing = 4 };

        var refresh = new Button { Content = L10n.T("刷新"), HorizontalAlignment = HorizontalAlignment.Left };
        refresh.Click += async (_, _) => await LoadAsync();

        var batchLock = new Button { Content = L10n.T("全部锁定"), Margin = new Thickness(8, 0, 0, 0) };
        batchLock.Click += async (_, _) =>
        {
            // P1-2 批量锁
            await RunMounterAsync("vaults", "batch", "lock");
            await LoadAsync();
        };

        var toolbar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
        toolbar.Children.Add(refresh);
        toolbar.Children.Add(batchLock);

        var sp = new StackPanel { Spacing = 6, MaxWidth = 760 };
        sp.Children.Add(toolbar);
        sp.Children.Add(_summary);
        sp.Children.Add(_rows);

        // WinUI 滚动条是覆盖式
        // 行内容宽度可控
        // 垂直滚动条贴边
        Content = new ScrollViewer
        {
            Content = sp,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Padding = new Thickness(0, 0, 0, 12),
            MaxHeight = 460,
        };
        Title = L10n.T("加密盘管理");
        CloseButtonText = L10n.T("关闭");
        XamlRoot = ((MainWindow)App.MainWindow!).Content.XamlRoot;

        _ = LoadAsync();
    }

    // FE-Mounter 输出
    // 而本文件
    // 全部反序列化成
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    // mounter stdout 累积上限：畸形/海
    private const int kMaxStatusBytes = 4 * 1024 * 1024;

    private async Task<StatusDoc?> QueryAsync()
    {
        var cli = new CliProcessService();
        var sb = new System.Text.StringBuilder();
        // mounter stdout 累积设上限：超出
        cli.OutputLine += line =>
        {
            lock (sb)
            {
                if (sb.Length + line.Length + 2 <= kMaxStatusBytes) sb.AppendLine(line);
            }
        };
        var tcs = new TaskCompletionSource<CommandResult>();
        cli.Finished += r => tcs.TrySetResult(r);
        cli.Execute(new CommandRequest
        {
            ProgramPath = _mounter,
            Arguments = new List<string> { "vaults", "status" },
        });
        var r = await tcs.Task;
        if (r.ExitCode != 0) return null;

        string text;
        lock (sb) text = sb.ToString();
        // 输出里可能混有
        int b = text.IndexOf('{');
        int e = text.LastIndexOf('}');
        if (b < 0 || e <= b) return null;

        try
        {
            using var doc = JsonDocument.Parse(text.Substring(b, e - b + 1));
            var d = JsonSerializer.Deserialize<StatusDoc>(doc.RootElement.GetRawText(), JsonOpts);
            if (d == null) return null;
            // v.Vault/v.Mount 将作
            if (d.Vaults != null)
            {
                d.Vaults.RemoveAll(v => string.IsNullOrWhiteSpace(v.Vault)
                                        || !Directory.Exists(v.Vault));
                d.Count = d.Vaults.Count;
            }
            return d;
        }
        catch { return null; }
    }

    private async Task RunMounterAsync(params string[] args)
    {
        var cli = new CliProcessService();
        var tcs = new TaskCompletionSource<CommandResult>();
        cli.Finished += x => tcs.TrySetResult(x);
        cli.Execute(new CommandRequest
        {
            ProgramPath = _mounter,
            Arguments = new List<string>(args),
        });
        await tcs.Task;
    }

    private async Task LoadAsync()
    {
        _rows.Children.Clear();
        var doc = await QueryAsync();
        if (doc == null)
        {
            _summary.Text = L10n.T("无法获取加密盘状态，请确认挂载组件可用。");
            return;
        }
        if (doc.Count == 0)
        {
            _summary.Text = L10n.T("尚未注册任何加密盘。可先用「新建加密盘」创建，或用「挂载为磁盘」登记已有盘。");
            return;
        }

        int locked = 0, unlocked = 0, unmounted = 0;
        foreach (var v in doc.Vaults)
        {
            string status;
            Brush color;
            if (!v.Reachable)
            {
                status = L10n.T("未挂载");
                color = ThemeService.BrushFor("AppTextSecondaryBrush", RequestedTheme);
                unmounted++;
            }
            else if (v.Unlocked)
            {
                status = v.Idle.HasValue
                    ? string.Format(L10n.T("已解锁（{0} 秒后自动锁）"), v.Idle.Value)
                    : L10n.T("已解锁");
                color = ThemeService.BrushFor("AppSuccessBrush", RequestedTheme);
                unlocked++;
            }
            else
            {
                status = L10n.T("已锁定");
                color = ThemeService.BrushFor("AppDangerBrush", RequestedTheme);
                locked++;
            }

            var row = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 6,
                Padding = new Thickness(4, 3, 4, 3),
            };
            row.Children.Add(new TextBlock
            {
                Text = string.IsNullOrEmpty(v.Mount) ? "—" : v.Mount,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                Width = 60,
                VerticalAlignment = VerticalAlignment.Center,
            });
            var dirText = new TextBlock
            {
                Text = v.Vault,
                Width = 200,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center,
            };
            ToolTipService.SetToolTip(dirText, v.Vault);   // 完整路径放悬浮
            row.Children.Add(dirText);
            row.Children.Add(new TextBlock { Text = "●", Foreground = color, FontSize = 14, VerticalAlignment = VerticalAlignment.Center });
            row.Children.Add(new TextBlock { Text = status, Foreground = color, Width = 170, VerticalAlignment = VerticalAlignment.Center });

            // P2-1 免密开关
            var bound = DeviceKeyService.IsBound(v.Vault);
            var bindChk = new CheckBox
            {
                Content = L10n.T("本机免密"),
                IsChecked = bound,
                Width = 110,
                VerticalAlignment = VerticalAlignment.Center,
            };
            bindChk.Click += async (s, _) =>
            {
                if (bindChk.IsChecked == true)
                {
                    // 启用本机免密
                    var pwd = new PasswordDialog(false)
                    {
                        XamlRoot = XamlRoot,
                        RequestedTheme = this.RequestedTheme,
                        Title = L10n.T("本机免密"),
                    };
                    if (await pwd.ShowAsync() != ContentDialogResult.Primary || string.IsNullOrEmpty(pwd.Password))
                    {
                        bindChk.IsChecked = false;   // 取消
                        return;
                    }
                    // DPAPI 缺程序集时此处
                    bool ok;
                    try { ok = DeviceKeyService.Enable(v.Vault, pwd.Password); }
                    catch { ok = false; }
                    if (!ok)
                    {
                        bindChk.IsChecked = false;   // 失败回滚
                        await Msg(L10n.T("设备绑定"),
                                  L10n.T("无法启用本机免密，系统加密服务不可用。"));
                    }
                    else
                    {
                        await Msg(L10n.T("设备绑定"),
                                  L10n.T("已启用：今后在本机解锁此盘无需输入密码。"));
                    }
                }
                else
                {
                    DeviceKeyService.Forget(v.Vault);
                    await Msg(L10n.T("设备绑定"),
                              L10n.T("已关闭：此盘今后需输入密码解锁。"));
                }
            };
            row.Children.Add(bindChk);

            // 操作
            // 铁律
            // 只能开一个对话
            // 第二个 ShowAsync
            if (v.Reachable && v.Unlocked)
            {
                var b = new Button { Content = L10n.T("锁定"), Margin = new Thickness(4, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                b.Click += async (_, _) =>
                {
                    Hide();
                    await Task.Delay(120);   // 等退场动画结束
                    await _doLock(v.Vault);
                };
                row.Children.Add(b);
            }
            else if (v.Reachable)
            {
                var b = new Button { Content = L10n.T("解锁"), Margin = new Thickness(4, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                b.Click += async (_, _) =>
                {
                    Hide();
                    await Task.Delay(120);   // 等退场动画结束
                    await _unlock(v.Vault);
                };
                row.Children.Add(b);
            }
            else
            {
                var b = new Button { Content = L10n.T("挂载"), Margin = new Thickness(4, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                b.Click += async (_, _) =>
                {
                    Hide();
                    await Task.Delay(120);   // 等退场动画结束
                    var dlg = new VaultMountDialog(true, v.Mount) { XamlRoot = XamlRoot };
                    if (await dlg.ShowAsync() != ContentDialogResult.Primary) return;
                    await _mount(v.Vault, dlg.MountPoint);
                    _refreshHost?.Invoke(v.Vault);
                };
                row.Children.Add(b);
            }

            _rows.Children.Add(row);
        }

        _summary.Text = string.Format(L10n.T("共 {0} 个加密盘：已解锁 {1}，已锁定 {2}，未挂载 {3}"),
                                      doc.Count, unlocked, locked, unmounted);
    }

    private async Task Msg(string title, string body)
    {
        var d = new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = body, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = L10n.T("关闭"),
            XamlRoot = XamlRoot,
        };
        await d.ShowAsync();
    }
}
