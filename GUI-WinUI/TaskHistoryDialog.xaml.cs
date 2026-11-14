using Microsoft.UI.Xaml;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using System.Collections.Generic;
using System.Linq;
using FileEncryptorGUI.Models;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

public sealed partial class TaskHistoryDialog : ContentDialog
{
    public TaskRecord? SelectedTask { get; private set; }
    public bool HistoryChanged { get; private set; }

    private List<TaskRecord> _records;
    private ListView _list = null!;

    public TaskHistoryDialog(List<TaskRecord> records)
    {
        // 跟随用户
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };
        _records = records;
        Title = L10n.T("任务历史（双击恢复，右键删除）");
        CloseButtonText = L10n.T("关闭");

        var panel = new StackPanel { Spacing = 8, MaxHeight = 520 };

        // 顶部操作栏
        var topBar = new Grid { ColumnDefinitions = { new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }, new ColumnDefinition { Width = GridLength.Auto } } };
        var countText = new TextBlock { Text = L10n.F("共 {0} 条记录", records.Count), VerticalAlignment = VerticalAlignment.Center, Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", RequestedTheme) };
        var clearBtn = new Button { Content = L10n.T("清空全部"), Padding = new Thickness(12, 4, 12, 4), HorizontalAlignment = HorizontalAlignment.Right, Style = ThemeService.StyleFor("AppDangerButtonStyle") };
        clearBtn.Click += (_, _) =>
        {
            _records.Clear();
            TaskHistoryService.Save(_records, out _);
            if (_list != null) _list.Items.Clear();
            HistoryChanged = true;
            countText.Text = L10n.T("共 0 条记录");
        };
        Grid.SetColumn(countText, 0);
        Grid.SetColumn(clearBtn, 1);
        topBar.Children.Add(countText);
        topBar.Children.Add(clearBtn);
        panel.Children.Add(topBar);

        if (records.Count == 0)
        {
            panel.Children.Add(new TextBlock { Text = L10n.T("暂无历史记录"), Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", RequestedTheme) });
        }
        else
        {
            _list = new ListView { MaxHeight = 450 };
            foreach (var r in records.Take(100))
            {
                var item = new StackPanel { Spacing = 2, Padding = new Thickness(4), Tag = r };
                item.Children.Add(new TextBlock
                {
                    Text = $"[{r.StartedAt}] {r.ActionLabel} - {r.Status}",
                    FontWeight = FontWeights.Bold
                });
                item.Children.Add(new TextBlock
                {
                    Text = L10n.F("输入 {0} 个，{1}，耗时 {2}", r.InputCount, EtaEstimatorService.FormatBytes(r.TotalBytes), EtaEstimatorService.FormatDuration(r.DurationMs)),
                    FontSize = 12
                });
                // 右键菜单
                var flyout = new MenuFlyout();
                var delItem = new MenuFlyoutItem { Text = L10n.T("删除该记录") };
                delItem.Click += (_, _) =>
                {
                    _records.Remove(r);
                    TaskHistoryService.Save(_records, out _);
                    _list.Items.Remove(item);
                    HistoryChanged = true;
                    countText.Text = L10n.F("共 {0} 条记录", _records.Count);
                };
                flyout.Items.Add(delItem);
                item.ContextFlyout = flyout;
                _list.Items.Add(item);
            }
            _list.DoubleTapped += OnDoubleTapped;
            panel.Children.Add(_list);
        }
        // M18
        // 不必另找设置入
        var pathChk = new CheckBox
        {
            Content = L10n.T("任务历史保存完整路径"),
            IsChecked = App.Settings.Current.HistoryStorePaths,
            Margin = new Thickness(0, 4, 0, 0)
        };
        pathChk.Checked += (_, _) =>
        {
            App.Settings.Current.HistoryStorePaths = true;
            App.Settings.Save();
        };
        pathChk.Unchecked += (_, _) =>
        {
            App.Settings.Current.HistoryStorePaths = false;
            App.Settings.Save();
        };
        panel.Children.Add(pathChk);
        panel.Children.Add(new TextBlock
        {
            Text = L10n.T("开启后任务历史会记录完整文件路径（便于双击回放）；关闭则只记录文件名，不把「保护了哪些文件」明文留在磁盘上。"),
            FontSize = 12,
            Foreground = ThemeService.BrushFor("AppTextSecondaryBrush", RequestedTheme),
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 520
        });
        Content = panel;
    }

    private void OnDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (sender is ListView list && list.SelectedItem is StackPanel panel && panel.Tag is TaskRecord rec)
        {
            SelectedTask = rec;
            Hide();
        }
    }
}