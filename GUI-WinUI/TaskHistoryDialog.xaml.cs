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
        RequestedTheme = ElementTheme.Dark;
        _records = records;
        Title = "任务历史（双击恢复，右键删除）";
        CloseButtonText = "关闭";

        var panel = new StackPanel { Spacing = 8, MaxHeight = 520 };

        // 顶部操作栏
        var topBar = new Grid { ColumnDefinitions = { new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }, new ColumnDefinition { Width = GridLength.Auto } } };
        var countText = new TextBlock { Text = $"共 {records.Count} 条记录", VerticalAlignment = VerticalAlignment.Center, Opacity = 0.6 };
        var clearBtn = new Button { Content = "清空全部", Padding = new Thickness(12, 4, 12, 4), HorizontalAlignment = HorizontalAlignment.Right };
        clearBtn.Click += (_, _) =>
        {
            _records.Clear();
            TaskHistoryService.Save(_records, out _);
            if (_list != null) _list.Items.Clear();
            HistoryChanged = true;
            countText.Text = "共 0 条记录";
        };
        Grid.SetColumn(countText, 0);
        Grid.SetColumn(clearBtn, 1);
        topBar.Children.Add(countText);
        topBar.Children.Add(clearBtn);
        panel.Children.Add(topBar);

        if (records.Count == 0)
        {
            panel.Children.Add(new TextBlock { Text = "暂无历史记录", Opacity = 0.6 });
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
                    Text = $"输入 {r.InputCount} 个, {EtaEstimatorService.FormatBytes(r.TotalBytes)}, 耗时 {EtaEstimatorService.FormatDuration(r.DurationMs)}",
                    FontSize = 12
                });
                // 右键菜单
                var flyout = new MenuFlyout();
                var delItem = new MenuFlyoutItem { Text = "删除此条" };
                delItem.Click += (_, _) =>
                {
                    _records.Remove(r);
                    TaskHistoryService.Save(_records, out _);
                    _list.Items.Remove(item);
                    HistoryChanged = true;
                    countText.Text = $"共 {_records.Count} 条记录";
                };
                flyout.Items.Add(delItem);
                item.ContextFlyout = flyout;
                _list.Items.Add(item);
            }
            _list.DoubleTapped += OnDoubleTapped;
            panel.Children.Add(_list);
        }
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