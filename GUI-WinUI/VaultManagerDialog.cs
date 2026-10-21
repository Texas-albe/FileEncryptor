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

// P1-1 设备加密管理页：对标 BitLocker「管理 BitLocker」的一屏视图。
// 一行列出：盘符 / 存储目录 / 状态灯（已解锁·已锁定·未挂载）/ 自动锁剩余秒数 /
// 免密开关（本机设备绑定）/ 操作按钮（解锁·锁定·挂载）。
//
// 数据源是 FE-Mounter 的 `vaults status`（P1-2 新增，输出 JSON）——
// 此前只能靠 settings.json 里的本地挂载记录，且状态靠 Contains("unlocked=1")
// 子串匹配（错误串会误落「未响应」）。JSON 聚合让两端字段对齐不再靠字符串猜。
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
    private readonly Func<string, Task> _doLock;          // dir（lock 是 C# 关键字，参数改名）
    private readonly Action<string> _refreshHost;         // 刷新宿主设置（新增盘后同步）
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
            // P1-2 批量锁：FE-Mounter 侧扇出，这里只发一次
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

        // WinUI 滚动条是覆盖式（浮在内容上）：横向滚动条会压住行内控件下半部分。
        // 行内容宽度可控（约 690px），禁用横向滚动；底部 Padding 兜底防极端窄窗时
        // 垂直滚动条贴边时与最后一行重叠。
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

    // FE-Mounter 输出的 JSON 字段是全小写（count/vaults/vault/mount/reachable/unlocked），
    // 而本文件的 C# 属性是 PascalCase；System.Text.Json 默认区分大小写，不开这个选项会
    // 全部反序列化成默认值（Count=0 / Vaults 空）→ 管理页恒显示「尚未注册任何加密盘」。
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    // mounter stdout 累积上限：畸形/海量输出不得撑爆内存后再进 JsonDocument.Parse
    private const int kMaxStatusBytes = 4 * 1024 * 1024;

    private async Task<StatusDoc?> QueryAsync()
    {
        var cli = new CliProcessService();
        var sb = new System.Text.StringBuilder();
        // mounter stdout 累积设上限（4MB）：超出部分直接丢弃，畸形/海量输出不得撑爆内存后再进 JsonDocument.Parse
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
        // 输出里可能混有非 JSON 的诊断行（进度/警告），只取首尾花括号之间的片段
        int b = text.IndexOf('{');
        int e = text.LastIndexOf('}');
        if (b < 0 || e <= b) return null;

        try
        {
            using var doc = JsonDocument.Parse(text.Substring(b, e - b + 1));
            var d = JsonSerializer.Deserialize<StatusDoc>(doc.RootElement.GetRawText(), JsonOpts);
            if (d == null) return null;
            // v.Vault/v.Mount 将作为 IPC 参数与 DeviceKeyService 路径使用：反序列化后做存在性/目录校验，丢弃空路径或目录不存在的行；Count 以列表为准
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
            SolidColorBrush color;
            if (!v.Reachable)
            {
                status = L10n.T("未挂载");
                color = new SolidColorBrush(Microsoft.UI.Colors.Gray);
                unmounted++;
            }
            else if (v.Unlocked)
            {
                status = v.Idle.HasValue
                    ? string.Format(L10n.T("已解锁（{0} 秒后自动锁）"), v.Idle.Value)
                    : L10n.T("已解锁");
                color = new SolidColorBrush(Microsoft.UI.Colors.MediumSeaGreen);
                unlocked++;
            }
            else
            {
                status = L10n.T("已锁定");
                color = new SolidColorBrush(Microsoft.UI.Colors.OrangeRed);
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
            ToolTipService.SetToolTip(dirText, v.Vault);   // 完整路径放悬浮提示（宽度所限）
            row.Children.Add(dirText);
            row.Children.Add(new TextBlock { Text = "●", Foreground = color, FontSize = 14, VerticalAlignment = VerticalAlignment.Center });
            row.Children.Add(new TextBlock { Text = status, Foreground = color, Width = 170, VerticalAlignment = VerticalAlignment.Center });

            // P2-1 免密开关：本机设备绑定（DPAPI）。开→本机解锁无需库密码。
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
                    // 启用本机免密：需确认库密码（凭据即库密码经 DPAPI 存于本机）
                    var pwd = new PasswordDialog(false)
                    {
                        XamlRoot = XamlRoot,
                        RequestedTheme = this.RequestedTheme,
                        Title = L10n.T("本机免密"),
                    };
                    if (await pwd.ShowAsync() != ContentDialogResult.Primary || string.IsNullOrEmpty(pwd.Password))
                    {
                        bindChk.IsChecked = false;   // 取消则回滚勾选
                        return;
                    }
                    // DPAPI 缺程序集时此处抛 FileNotFoundException，兜底为失败
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

            // 操作按钮：按当前状态给可用动作，避免对未挂载盘发 IPC（必失败）
            // 铁律：后续流程都会弹 ContentDialog（密码框/消息框），而同一 XamlRoot
            // 同时只能开一个对话框——必须先 Hide 本页并让退场完成，再触发后续弹框，
            // 否则第二个 ShowAsync 在同一 XamlRoot 上冲突、异常被吞→按钮「没反应」
            if (v.Reachable && v.Unlocked)
            {
                var b = new Button { Content = L10n.T("锁定"), Margin = new Thickness(4, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                b.Click += async (_, _) =>
                {
                    Hide();
                    await Task.Delay(120);   // 等退场动画结束，规避同 XamlRoot 双框竞态
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
                    await Task.Delay(120);   // 等退场动画结束，规避同 XamlRoot 双框竞态
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
                    await Task.Delay(120);   // 等退场动画结束，规避同 XamlRoot 双框竞态
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
