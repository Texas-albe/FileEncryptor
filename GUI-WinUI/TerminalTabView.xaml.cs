using FileEncryptorGUI.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using System.Text;

namespace FileEncryptorGUI;

// 终端标签页
// 帧区替换显示 日志区滚动
public sealed partial class TerminalTabView : UserControl
{
    // 日志 Run 上限
    // 防长任务布局爆炸卡死
    private const int MaxRuns = 4000;

    private int _logRunCount;

    public TerminalTabView()
    {
        InitializeComponent();
        TerminalScroll.ContextFlyout = BuildContextMenu();
    }

    // 右键菜单
    private MenuFlyout BuildContextMenu()
    {
        var copy = new MenuFlyoutItem { Text = L10n.T("复制全部") };
        copy.Click += OnTermCopy;
        var clear = new MenuFlyoutItem { Text = L10n.T("清空") };
        clear.Click += OnTermClear;
        var menu = new MenuFlyout();
        menu.Items.Add(copy);
        menu.Items.Add(clear);
        return menu;
    }

    // 批量进度帧
    // 每帧整体替换 不堆叠
    public void SetFrame(IReadOnlyList<string> lines)
    {
        if (FrameParagraph == null) return;
        FrameParagraph.Inlines.Clear();
        for (int i = 0; i < lines.Count; i++)
        {
            FrameParagraph.Inlines.Add(new Run { Text = lines[i] });
            if (i + 1 < lines.Count)
                FrameParagraph.Inlines.Add(new LineBreak());
        }
        if (FrameScroll != null && FrameScroll.Visibility != Visibility.Visible)
            FrameScroll.Visibility = Visibility.Visible;
    }

    // 追加一段输出并
    public void Append(string text)
    {
        if (TerminalParagraph == null) return;
        TerminalParagraph.Inlines.Add(new Run { Text = text });
        _logRunCount++;
        // 超限删最旧段
        if (_logRunCount > MaxRuns)
        {
            int drop = _logRunCount - MaxRuns;
            for (int i = 0; i < drop && TerminalParagraph.Inlines.Count > 0; i++)
                TerminalParagraph.Inlines.RemoveAt(0);
            _logRunCount = TerminalParagraph.Inlines.Count;
        }
        // 先走一次布局
        TerminalScroll?.UpdateLayout();
        TerminalScroll?.ChangeView(null, TerminalScroll.ScrollableHeight, null, true);
    }

    public void Clear()
    {
        TerminalParagraph?.Inlines.Clear();
        _logRunCount = 0;
        if (FrameParagraph != null) FrameParagraph.Inlines.Clear();
        if (FrameScroll != null) FrameScroll.Visibility = Visibility.Collapsed;
    }

    // 输出全文
    // 含帧区 在前
    private string AllText()
    {
        var sb = new StringBuilder();
        if (FrameParagraph != null)
        {
            foreach (var inline in FrameParagraph.Inlines)
                if (inline is Run r) sb.Append(r.Text);
        }
        if (TerminalParagraph == null) return sb.ToString();
        foreach (var inline in TerminalParagraph.Inlines)
            if (inline is Run r) sb.Append(r.Text);
        return sb.ToString();
    }

    private void OnTermClear(object sender, RoutedEventArgs e) => Clear();

    private void OnTermCopy(object sender, RoutedEventArgs e)
    {
        string text = AllText();
        if (text.Length == 0) return;
        var dp = new Windows.ApplicationModel.DataTransfer.DataPackage();
        dp.SetText(text);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(dp);
    }
}
