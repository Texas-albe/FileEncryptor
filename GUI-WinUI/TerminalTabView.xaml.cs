using FileEncryptorGUI.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using System.Text;

namespace FileEncryptorGUI;

// 终端标签页
// 整页只有一个输
public sealed partial class TerminalTabView : UserControl
{
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

    // 追加一段输出并
    public void Append(string text)
    {
        if (TerminalParagraph == null) return;
        TerminalParagraph.Inlines.Add(new Run { Text = text });
        // 先走一次布局
        TerminalScroll?.UpdateLayout();
        TerminalScroll?.ChangeView(null, TerminalScroll.ScrollableHeight, null, true);
    }

    public void Clear()
    {
        TerminalParagraph?.Inlines.Clear();
    }

    // 输出全文
    private string AllText()
    {
        if (TerminalParagraph == null) return string.Empty;
        var sb = new StringBuilder();
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
