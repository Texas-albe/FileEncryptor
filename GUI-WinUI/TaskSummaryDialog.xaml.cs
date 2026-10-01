using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

public sealed partial class TaskSummaryDialog : ContentDialog
{
    public TaskSummaryDialog(string title, string duration, string avgSpeed, string encryptedSize, int done, int skip, int fail)
    {
        RequestedTheme = ElementTheme.Dark;

        var panel = new StackPanel { Spacing = 8 };

        var titleText = new TextBlock { Text = title, FontSize = 16, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
        panel.Children.Add(titleText);

        var grid = new Grid { Margin = new Thickness(0, 8, 0, 0) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var items = new (string label, string value)[]
        {
            (L10n.T("用时"), duration),
            (L10n.T("平均速度"), avgSpeed),
            (L10n.T("加密后大小"), encryptedSize),
            (L10n.T("完成"), done.ToString()),
            (L10n.T("跳过"), skip.ToString()),
            (L10n.T("失败"), fail.ToString()),
        };

        for (int i = 0; i < items.Length; i++)
        {
            int row = i / 2;
            int col = i % 2;
            if (grid.RowDefinitions.Count <= row)
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var card = new StackPanel { Margin = new Thickness(0, 0, 8, 8) };
            var label = new TextBlock { Text = items[i].label, FontSize = 11, Opacity = 0.6 };
            var value = new TextBlock { Text = items[i].value, FontSize = 14, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
            if (items[i].label == L10n.T("失败") && fail > 0)
                value.Foreground = new SolidColorBrush(Colors.OrangeRed);
            card.Children.Add(label);
            card.Children.Add(value);
            Grid.SetRow(card, row);
            Grid.SetColumn(card, col);
            grid.Children.Add(card);
        }

        panel.Children.Add(grid);

        Content = panel;
        Title = L10n.T("任务完成");
        PrimaryButtonText = L10n.T("确定");
    }
}