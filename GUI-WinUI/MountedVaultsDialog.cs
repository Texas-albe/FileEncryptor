using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI;

// 已挂载加密盘列
public sealed partial class MountedVaultsDialog : ContentDialog
{
    private readonly string _mounter;
    private readonly List<MountedVault> _mounts;
    private readonly Action<string> _unlock;   // 传入 VaultDir
    private readonly StackPanel _rowsPanel;

    public MountedVaultsDialog(string mounter, List<MountedVault> mounts, Action<string> unlock)
    {
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };

        _mounter = mounter;
        _mounts = mounts;
        _unlock = unlock;

        _rowsPanel = new StackPanel { Spacing = 6 };

        var refresh = new Button { Content = L10n.T("刷新"), HorizontalAlignment = HorizontalAlignment.Left };
        refresh.Click += async (_, _) => { _rowsPanel.Children.Clear(); await LoadAsync(); };

        var sp = new StackPanel { Spacing = 8 };
        sp.Children.Add(refresh);
        sp.Children.Add(_rowsPanel);

        var scroller = new ScrollViewer
        {
            Content = sp,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            MaxHeight = 400,
        };

        Content = scroller;
        Title = L10n.T("已挂载加密盘");
        CloseButtonText = L10n.T("关闭");

        XamlRoot = ((MainWindow)App.MainWindow!).Content.XamlRoot;

        _ = LoadAsync();
    }

    private async Task LoadAsync()
    {
        if (_mounts.Count == 0)
        {
            _rowsPanel.Children.Add(new TextBlock { Text = L10n.T("当前没有已挂载的加密盘。") });
            return;
        }
        foreach (var m in _mounts)
        {
            bool locked = true;
            string status = L10n.T("查询中…");
            try
            {
                var resp = await IpcStatusAsync(m.VaultDir);
                if (resp.Contains("unlocked=1")) { locked = false; status = L10n.T("已解锁"); }
                else if (resp.Contains("unlocked=0")) { locked = true; status = L10n.T("已锁定"); }
                else status = resp.Length > 0 ? resp : L10n.T("未响应");
            }
            catch { status = L10n.T("查询失败"); }

            var row = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 10,
                Padding = new Thickness(4),
            };
            row.Children.Add(new TextBlock
            {
                Text = string.IsNullOrEmpty(m.MountPoint) ? L10n.T("（无盘符）") : m.MountPoint,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                Width = 70,
            });
            row.Children.Add(new TextBlock
            {
                Text = m.VaultDir,
                Width = 280,
                TextTrimming = TextTrimming.CharacterEllipsis,
            });
            row.Children.Add(new TextBlock
            {
                Text = status,
                Foreground = locked ? ThemeService.BrushFor("AppDangerBrush", RequestedTheme)
                                    : ThemeService.BrushFor("AppTextSecondaryBrush", RequestedTheme),
                Width = 70,
            });
            // 双击解锁
            // 同一 XamlRoot 不能双
            row.DoubleTapped += async (_, _) =>
            {
                if (locked && !string.IsNullOrEmpty(m.VaultDir))
                {
                    Hide();
                    await Task.Delay(120);   // 等退场动画结束
                    _unlock?.Invoke(m.VaultDir);
                }
            };
            _rowsPanel.Children.Add(row);
        }
    }

    private async Task<string> IpcStatusAsync(string dir)
    {
        var cli = new CliProcessService();
        var sb = new System.Text.StringBuilder();
        cli.OutputLine += line => { lock (sb) { sb.AppendLine(line); } };
        var tcs = new TaskCompletionSource<CommandResult>();
        cli.Finished += r => tcs.TrySetResult(r);
        cli.Execute(new CommandRequest
        {
            ProgramPath = _mounter,
            Arguments = new List<string> { "ipc-call", "--vault", dir, "status" },
        });
        var r = await tcs.Task;
        return r.ExitCode == 0 ? sb.ToString().Trim() : "";
    }
}
