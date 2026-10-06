using System.Text;
using FileEncryptorGUI.Models;
using FileEncryptorGUI.Services;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace FileEncryptorGUI;

// 预览解密窗口：调 CLI --preview 取回明文前缀显示，不写出任何文件
public sealed class PreviewWindow
{
    private readonly CliProcessService _cli = new();
    private readonly Window _window;
    private readonly TextBlock _fileLabel;
    private readonly TextBox _view;
    private readonly TextBlock _status;
    private readonly Button _nextBtn;
    private readonly NumberBox _bytes;
    private readonly StringBuilder _pending = new();
    // 流式解码器：跨 chunk 保留不完整的多字节序列，避免 UTF-8 字符被块边界截断成乱码
    private readonly Decoder _utf8Decoder = Encoding.UTF8.GetDecoder();

    private string _programPath = "";
    private string _filePath = "";
    private byte[] _password = Array.Empty<byte>();
    private bool _done;

    public event Action? NextRequested;

    public PreviewWindow()
    {
        _fileLabel = new TextBlock { TextTrimming = TextTrimming.CharacterEllipsis };
        _view = new TextBox
        {
            AcceptsReturn = true,
            IsReadOnly = true,
            TextWrapping = TextWrapping.NoWrap,
            FontFamily = new FontFamily("Consolas"),
            IsSpellCheckEnabled = false,
        };
        _status = new TextBlock { TextWrapping = TextWrapping.Wrap, Opacity = 0.75 };
        _bytes = new NumberBox
        {
            Minimum = 64,
            Maximum = 1 << 20,
            SmallChange = 256,
            Value = 4096,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline,
        };
        _nextBtn = new Button { Content = L10n.T("下一个文件(&N)") };
        var closeBtn = new Button { Content = L10n.T("关闭(&C)") };
        closeBtn.Click += (_, _) => { _cli.Cancel(); _window.Close(); };

        _bytes.ValueChanged += (_, _) => { if (_done) NextRequested?.Invoke(); };
        _nextBtn.Click += (_, _) => NextRequested?.Invoke();

        var bytesLabel = new TextBlock { Text = L10n.T("预览字节数："), VerticalAlignment = VerticalAlignment.Center };
        var top = new Grid
        {
            ColumnDefinitions =
            {
                new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) },
                new ColumnDefinition { Width = GridLength.Auto },
                new ColumnDefinition { Width = GridLength.Auto },
            },
        };
        Grid.SetColumn(_fileLabel, 0);
        Grid.SetColumn(bytesLabel, 1);
        Grid.SetColumn(_bytes, 2);
        top.Children.Add(_fileLabel);
        top.Children.Add(bytesLabel);
        top.Children.Add(_bytes);

        var btnRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
        };
        btnRow.Children.Add(_nextBtn);
        btnRow.Children.Add(closeBtn);

        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(top);
        panel.Children.Add(_view);
        panel.Children.Add(_status);
        panel.Children.Add(btnRow);

        _window = new Window
        {
            Title = L10n.T("预览解密"),
            Content = panel,
        };
        _window.AppWindow.Resize(new Windows.Graphics.SizeInt32(900, 620));

        _cli.RawStdout += OnRaw;
        _cli.OutputLine += OnLine;
        _cli.Finished += OnFinished;
    }

    // 主窗切主题时跟着换配色
    public void ApplyTheme(ElementTheme theme)
    {
        if (_window.Content is FrameworkElement fe) fe.RequestedTheme = theme;
    }

    public void ShowFor(string programPath, string filePath, byte[] password, string displayName)
    {
        _programPath = programPath;
        _filePath = filePath;
        _password = password;
        _fileLabel.Text = L10n.F("文件：{0}", displayName);
        _view.Text = "";
        _pending.Clear();
        _utf8Decoder.Reset();   // 窗口复用时清掉上一次残留的半截字节
        _done = false;
        _nextBtn.Visibility = Visibility.Collapsed;
        _status.Text = L10n.T("正在解密…");
        _window.Activate();
        Start();
    }

    private void Start()
    {
        int max = _bytes.Value is double d ? (int)d : 4096;
        _cli.SetRawMode(true);
        var req = new CommandRequest
        {
            ProgramPath = _programPath,
            ShowConsole = false,
            // 密码走 stdin，不进 argv
            StdinData = _password,
        };
        req.Arguments.Add("-d");
        req.Arguments.Add("--preview");
        req.Arguments.Add("--max-bytes");
        req.Arguments.Add(max.ToString());
        req.Arguments.Add("--");
        req.Arguments.Add(_filePath);
        _cli.Execute(req);
    }

    private void OnRaw(byte[] chunk)
    {
        // 不能每 chunk 单独 UTF8.GetString：一个多字节字符可能横跨两块，
        // 单独解码会让两边各变成 U+FFFD。改用常驻 Decoder，它会把尾部不完整
        // 的字节留在内部缓冲，等下一块补齐再解。
        if (chunk.Length == 0) return;
        char[] chars = new char[_utf8Decoder.GetCharCount(chunk, 0, chunk.Length)];
        int n = _utf8Decoder.GetChars(chunk, 0, chunk.Length, chars, 0);
        if (n > 0) _pending.Append(chars, 0, n);
    }

    private void OnLine(string line)
    {
        if (line.StartsWith("Previewing first", StringComparison.Ordinal)) return;
        _status.Text = line;
    }

    private void OnFinished(CommandResult r)
    {
        _view.Text = ToDisplay(_pending.ToString());
        _done = true;
        _nextBtn.Visibility = Visibility.Visible;
        _status.Text = r.ExitCode == 0
            ? L10n.T("预览完成。预览不会写出解密文件。")
            : L10n.F("预览失败：{0}", r.ErrorString is { Length: > 0 } e ? e : L10n.F("CLI 返回码 {0}", r.ExitCode));
    }

    // 不可打印字节用 · 占位，保证行不乱、长度可见
    private static string ToDisplay(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        foreach (var c in raw)
        {
            if (c == '\n') sb.Append(c);
            else if (c == '\r') sb.Append("\\r");
            else if (c == '\t') sb.Append("\\t");
            else if (c < 0x20 || c == 0x7f) sb.Append('·');
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
