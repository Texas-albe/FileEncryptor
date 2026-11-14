// 只读文本 / 十六进
// 每页只读固定窗
// 文本页
// 十六进制页
using System.Text;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class PreviewPage : ContentPage
{
    private const int PageBytes = 8 * 1024;   // 文本 / 十六进制共
    private const int HexMaxLines = 512;      // 每页
    private const int ProbeBytes = 4 * 1024;  // 二进制探测只看

    private readonly VaultService _vault;
    private readonly string _rel;
    private readonly string _name;
    private readonly ulong _size;

    private bool _hex;
    private ulong _off;        // 当前页起始字节
    private ulong _nextOff;    // 当前页结束 = 下一
    private bool _nextEof;     // 已到文件末尾
    private int _loadVer;
    // 回退栈
    private readonly List<ulong> _back = new();
    private TextEncoding _enc = TextEncoding.Utf8;
    private bool _encProbed;

    private enum TextEncoding { Utf8, Utf16Le, Utf16Be }

    public PreviewPage(VaultService vault, string relPath, string name, ulong size, bool hex = false)
    {
        InitializeComponent();
        _vault = vault;
        _rel = relPath;
        _name = name;
        _size = size;
        _hex = hex;
        LblName.Text = name;
        LblMeta.Text = L10n.F("{0} · 只读", VaultItem.FormatSize(size));
        VaultService.SessionLocked += OnSessionLocked;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        VaultService.SessionLocked -= OnSessionLocked;
        VaultService.SessionLocked += OnSessionLocked;
        RenderMode();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        VaultService.SessionLocked -= OnSessionLocked;
        _loadVer++;          // 作废
        Content.Text = "";
    }

    private void RenderMode()
    {
        // 两种模式
        bool paged = _size > (ulong)PageBytes;
        BtnPrev.IsVisible = BtnNext.IsVisible = paged;
        LblOffset.IsVisible = paged;
        // 当前模式用选
        MarkMode(BtnText, !_hex);
        MarkMode(BtnHex, _hex);
        _ = LoadPageAsync();
    }

    private static void MarkMode(Button button, bool selected)
        => button.Style = (Style)Application.Current!.Resources[
            selected ? "SegmentSelected" : "SegmentUnselected"];

    private void ResetPaging()
    {
        _off = 0;
        _nextOff = 0;
        _nextEof = false;
        _back.Clear();
    }

    private void OnTextMode(object? sender, EventArgs e)
    {
        if (!_hex) return;
        _hex = false;
        ResetPaging();
        RenderMode();
    }

    private void OnHexMode(object? sender, EventArgs e)
    {
        if (_hex) return;
        _hex = true;
        ResetPaging();
        RenderMode();
    }

    private void OnReload(object? sender, EventArgs e) => RenderMode();

    private void OnPrev(object? sender, EventArgs e)
    {
        if (_back.Count == 0) return;
        _off = _back[^1];
        _back.RemoveAt(_back.Count - 1);
        RenderMode();
    }

    private void OnNext(object? sender, EventArgs e)
    {
        // 下一页起点
        if (_nextEof || _nextOff == 0 || _nextOff >= _size) return;
        if (_nextOff <= _off) return;   // 防御
        _back.Add(_off);
        _off = _nextOff;
        RenderMode();
    }

    private async Task LoadPageAsync()
    {
        int ver = ++_loadVer;
        // 载入期间禁用翻
        BtnPrev.IsEnabled = BtnNext.IsEnabled = false;
        try
        {
            Content.Text = L10n.T("读取中…");
            // 只读当前页窗口
            int want = _off >= _size ? 0 : (int)Math.Min((ulong)PageBytes, _size - _off);
            byte[] data = want <= 0
                ? Array.Empty<byte>()
                : await Task.Run(() => _vault.ReadRange(_rel, _off, want));
            if (ver != _loadVer) return;   // 已切页/切模式

            if (_hex)
            {
                string text = await Task.Run(() => FormatHex(data, _off));
                if (ver != _loadVer) return;
                _nextOff = _off + (ulong)Math.Min(data.Length, HexMaxLines * 16);
                _nextEof = data.Length < want;
                LblMeta.Text = L10n.F("{0} · 十六进制只读 · 每页 {1} KB", VaultItem.FormatSize(_size), PageBytes / 1024);
                Content.Text = want > 0 && data.Length == 0
                    ? L10n.T("后面没有可显示的数据（文件可能被截断）。")
                    : text;
            }
            else
            {
                TextPage page = await Task.Run(
                    () => BuildTextPage(data, _off, want, _enc, !_encProbed));
                if (ver != _loadVer) return;
                if (page.Detected is not null) { _enc = page.Detected.Value; _encProbed = true; }
                if (page.Binary)
                {
                    // 二进制或非 UTF-8
                    _hex = true;
                    RenderMode();
                    return;
                }
                _nextOff = page.Next;
                _nextEof = page.Eof;
                LblMeta.Text = L10n.F("{0} · 文本只读 · 每页 {1} KB", VaultItem.FormatSize(_size), PageBytes / 1024);
                Content.Text = page.Text;
            }

            LblOffset.Text = _size == 0 ? L10n.T("空文件") : $"0x{_off:X8} – 0x{_nextOff:X8}";
            BtnPrev.IsEnabled = _back.Count > 0;
            BtnNext.IsEnabled = !_nextEof && _nextOff < _size;
            await Scroll.ScrollToAsync(0, 0, false);   // 新页
        }
        catch (Exception ex)
        {
            if (ver != _loadVer) return;
            Content.Text = L10n.T("读取失败：") + ex.Message;
            BtnPrev.IsEnabled = _back.Count > 0;
            BtnNext.IsEnabled = false;
        }
    }

    private sealed record TextPage(string Text, ulong Next, bool Eof, bool Binary, TextEncoding? Detected);

    // 从当前窗口里切
    // 只在后台线程调
    private static TextPage BuildTextPage(byte[] data, ulong off, int want, TextEncoding enc, bool probe)
    {
        bool eof = data.Length < want;
        TextEncoding use = enc;
        int start = 0;
        TextEncoding? detected = null;
        if (off == 0)
        {
            // BOM 每次回到首页
            if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            {
                use = TextEncoding.Utf8; start = 3;
                if (probe) detected = TextEncoding.Utf8;
            }
            else if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
            {
                use = TextEncoding.Utf16Le; start = 2;
                if (probe) detected = TextEncoding.Utf16Le;
            }
            else if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF)
            {
                use = TextEncoding.Utf16Be; start = 2;
                if (probe) detected = TextEncoding.Utf16Be;
            }
            else if (probe)
            {
                detected = TextEncoding.Utf8;
                if (LooksBinary(data, Math.Min(data.Length, ProbeBytes)))
                    return new("", off, true, true, TextEncoding.Utf8);
            }
        }

        if (use == TextEncoding.Utf8)
        {
            int cut;
            int nl = -1;
            for (int i = data.Length - 1; i >= start; i--)
                if (data[i] == 0x0A) { nl = i; break; }
            if (nl >= start)
                cut = nl + 1;                 // 行边界
            else if (eof)
                cut = data.Length;            // 文件尾
            else
                cut = Utf8SafeCut(data, data.Length);   // 超长行
            if (cut <= start) cut = data.Length;        // 防御
            string text = new UTF8Encoding(false, false).GetString(data, start, cut - start);
            bool pageEof = eof && cut >= data.Length;
            return new(text, off + (ulong)cut, pageEof, false, detected);
        }

        // UTF-16
        int even = start + ((data.Length - start) / 2) * 2;
        if (even <= start) return new("", off + (ulong)data.Length, eof, false, detected);
        var codec = use == TextEncoding.Utf16Le
            ? new UnicodeEncoding(false, false) : new UnicodeEncoding(true, false);
        string s = codec.GetString(data, start, even - start);
        int li = s.LastIndexOf('\n');
        if (li >= 0)
        {
            ulong next = off + (ulong)(start + (li + 1) * 2);
            return new(s[..(li + 1)], next, false, false, detected);
        }
        return new(s, eof ? off + (ulong)data.Length : off + (ulong)even, eof, false, detected);
    }

    // 无换行
    private static int Utf8SafeCut(byte[] d, int at)
    {
        int cut = at;
        while (cut > 0 && (d[cut - 1] & 0xC0) == 0x80) cut--;   // 跳过续字节
        if (cut == 0) return 0;
        byte lead = d[cut - 1];
        int len = lead < 0x80 ? 1 : (lead & 0xE0) == 0xC0 ? 2 : (lead & 0xF0) == 0xE0 ? 3
                : (lead & 0xF8) == 0xF0 ? 4 : 0;
        if (len == 0) return at;                // 非法前导
        return cut - 1 + len <= at ? at : cut - 1;
    }

    // 二进制探测只看
    private static bool LooksBinary(byte[] data, int probe)
    {
        int bad = 0;
        for (int i = 0; i < probe; i++)
        {
            byte b = data[i];
            if (b == 0) return true;
            if (b < 8 || (b > 13 && b < 32) || b == 127) bad++;
        }
        if (bad > probe / 10) return true;
        return !Utf8LooksValid(data, probe);
    }

    // 允许窗口末尾截
    private static bool Utf8LooksValid(byte[] d, int n)
    {
        int i = 0;
        while (i < n)
        {
            byte b = d[i];
            int len = b < 0x80 ? 1
                : (b & 0xE0) == 0xC0 ? 2
                : (b & 0xF0) == 0xE0 ? 3
                : (b & 0xF8) == 0xF0 ? 4 : 0;
            if (len == 0) return false;
            if (i + len > n) return true;      // 末尾
            for (int k = 1; k < len; k++)
                if ((d[i + k] & 0xC0) != 0x80) return false;
            i += len;
        }
        return true;
    }

    private static string FormatHex(byte[] data, ulong baseOff)
    {
        // 行数硬上限
        int limit = Math.Min(data.Length, HexMaxLines * 16);
        var sb = new StringBuilder(limit * 5 + 64);
        for (int i = 0; i < limit; i += 16)
        {
            sb.Append((baseOff + (ulong)i).ToString("X8")).Append("  ");
            int end = Math.Min(i + 16, limit);
            for (int j = i; j < end; j++) sb.Append(data[j].ToString("X2")).Append(' ');
            for (int j = end; j < i + 16; j++) sb.Append("   ");
            sb.Append(" |");
            for (int j = i; j < end; j++)
            {
                char c = (char)data[j];
                sb.Append(c >= 32 && c < 127 ? c : '.');
            }
            sb.Append("|\n");
        }
        return sb.ToString();
    }

    private void OnSessionLocked()
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            _loadVer++;
            Content.Text = "";
            try { await Navigation.PopAsync(); } catch { }
        });
    }
}
