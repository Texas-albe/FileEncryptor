// 外挂字幕解析
// SRT 完整解析
using System.Text;

namespace FileEncryptorMobile.Services;

public sealed class SubtitleCue
{
    public long StartMs;
    public long EndMs;
    public string Text = "";
}

public sealed class SubtitleTrack
{
    // 上限
    private const long MaxFileBytes = 512 * 1024;
    private const int MaxLines = 20000;
    private const int MaxCues = 8000;
    public const int MaxCueChars = 500;

    private readonly SubtitleCue[] _cues;
    private SubtitleTrack(SubtitleCue[] cues) => _cues = cues;
    public int Count => _cues.Length;

    // 取当前文本
    public string? TextAt(long positionMs)
    {
        for (int i = 0; i < _cues.Length; i++)
        {
            var c = _cues[i];
            if (positionMs < c.StartMs) break;
            if (positionMs < c.EndMs && c.EndMs > c.StartMs) return c.Text;
        }
        return null;
    }

    // 探测同目录同名 .srt
    // 字幕是派生明文
    public static SubtitleTrack? TryLoad(string videoPath)
    {
        try
        {
            string dir = Path.GetDirectoryName(videoPath) ?? "";
            string name = Path.GetFileNameWithoutExtension(videoPath);
            if (dir.Length == 0 || name.Length == 0 || !Directory.Exists(dir)) return null;
            string? srt = null, ass = null;
            foreach (string f in Directory.EnumerateFiles(dir))
            {
                if (!string.Equals(Path.GetFileNameWithoutExtension(f), name,
                    StringComparison.OrdinalIgnoreCase)) continue;
                string e = Path.GetExtension(f);
                if (e.Equals(".srt", StringComparison.OrdinalIgnoreCase)) srt = f;
                else if (e.Equals(".ass", StringComparison.OrdinalIgnoreCase)) ass = f;
            }
            SubtitleTrack? t = srt is null ? null : ParseSrt(srt);
            if (t is not null && t.Count > 0) return t;
            t = ass is null ? null : ParseAss(ass);
            if (t is not null && t.Count > 0) return t;
        }
        catch { /* 字幕缺失或损坏不影响播放 */ }
        return null;
    }

    // StreamReader 自动识别并去掉 UTF-8/UTF-16
    // 编码边界
    private static string ReadText(string path)
    {
        using var sr = new StreamReader(path, Encoding.UTF8, true);
        return sr.ReadToEnd();
    }

    private static string[] SplitLines(string text) =>
        text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

    // 超限不加载
    private static bool WithinLimit(string path)
    {
        try { return new FileInfo(path).Length <= MaxFileBytes; }
        catch { return false; }
    }

    private static string ClampCue(string s) =>
        s.Length > MaxCueChars ? s.Substring(0, MaxCueChars) : s;

    // SRT
    private static SubtitleTrack? ParseSrt(string path)
    {
        if (!WithinLimit(path)) return null;
        var lines = SplitLines(ReadText(path));
        if (lines.Length > MaxLines) return null;
        var cues = new List<SubtitleCue>();
        int i = 0;
        while (i < lines.Length)
        {
            while (i < lines.Length && lines[i].Trim().Length == 0) i++;
            if (i >= lines.Length) break;
            if (int.TryParse(lines[i].Trim(), out _) &&
                i + 1 < lines.Length && lines[i + 1].Contains("-->", StringComparison.Ordinal)) i++;
            if (i >= lines.Length) break;
            int arrow = lines[i].IndexOf("-->", StringComparison.Ordinal);
            if (arrow < 0) { i++; continue; }
            long start = ParseSrtTime(lines[i].Substring(0, arrow));
            long end = ParseSrtTime(lines[i].Substring(arrow + 3));
            i++;
            var buf = new List<string>();
            while (i < lines.Length && lines[i].Trim().Length > 0)
            {
                buf.Add(StripInline(lines[i]));
                i++;
            }
            if (start >= 0 && end > start && buf.Count > 0 && cues.Count < MaxCues)
                cues.Add(new SubtitleCue { StartMs = start, EndMs = end,
                    Text = ClampCue(string.Join("\n", buf)) });
        }
        if (cues.Count == 0) return null;
        cues.Sort((a, b) => a.StartMs.CompareTo(b.StartMs));
        return new SubtitleTrack(cues.ToArray());
    }

    // SRT 时间
    private static long ParseSrtTime(string s)
    {
        s = s.Trim();
        int sp = s.IndexOfAny(new[] { ' ', '\t' });
        if (sp > 0) s = s.Substring(0, sp);
        s = s.Replace(',', '.');
        var p = s.Split(':');
        if (p.Length < 3) return -1;
        if (!int.TryParse(p[0], out int h) || !int.TryParse(p[1], out int m)) return -1;
        var sec = p[2].Split('.');
        if (!int.TryParse(sec[0], out int ss)) return -1;
        int ms = 0;
        if (sec.Length > 1 && int.TryParse(sec[1].PadRight(3, '0').Substring(0, 3), out int v)) ms = v;
        return ((long)h * 3600 + m * 60 + ss) * 1000 + ms;
    }

    // ASS 边界
    // 忽略样式、定位、卡
    private static SubtitleTrack? ParseAss(string path)
    {
        if (!WithinLimit(path)) return null;
        var lines = SplitLines(ReadText(path));
        if (lines.Length > MaxLines) return null;
        bool inEvents = false;
        int startCol = 1, endCol = 2, textCol = 9;
        var cues = new List<SubtitleCue>();
        foreach (var raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("[", StringComparison.Ordinal))
            {
                inEvents = line.Equals("[Events]", StringComparison.OrdinalIgnoreCase);
                continue;
            }
            if (!inEvents) continue;
            if (line.StartsWith("Format:", StringComparison.OrdinalIgnoreCase))
            {
                var cols = line.Substring(7).Split(',');
                for (int k = 0; k < cols.Length; k++)
                {
                    string c = cols[k].Trim();
                    if (c.Equals("Start", StringComparison.OrdinalIgnoreCase)) startCol = k;
                    else if (c.Equals("End", StringComparison.OrdinalIgnoreCase)) endCol = k;
                    else if (c.Equals("Text", StringComparison.OrdinalIgnoreCase)) textCol = k;
                }
                continue;
            }
            if (!line.StartsWith("Dialogue:", StringComparison.OrdinalIgnoreCase)) continue;
            string body = line.Substring(9).TrimStart();
            var f = body.Split(',');
            int need = Math.Max(Math.Max(startCol, endCol), textCol);
            if (f.Length <= need) continue;
            long start = ParseAssTime(f[startCol].Trim());
            long end = ParseAssTime(f[endCol].Trim());
            string txt = string.Join(",", f, textCol, f.Length - textCol);
            txt = StripInline(txt).Replace("\\N", "\n").Replace("\\n", "\n").Replace("\\h", " ");
            if (start >= 0 && end > start && txt.Length > 0 && cues.Count < MaxCues)
                cues.Add(new SubtitleCue { StartMs = start, EndMs = end, Text = ClampCue(txt) });
        }
        if (cues.Count == 0) return null;
        cues.Sort((a, b) => a.StartMs.CompareTo(b.StartMs));
        return new SubtitleTrack(cues.ToArray());
    }

    // ASS 时间
    private static long ParseAssTime(string s)
    {
        var p = s.Trim().Split(':');
        if (p.Length < 3) return -1;
        if (!int.TryParse(p[0], out int h) || !int.TryParse(p[1], out int m)) return -1;
        var sec = p[2].Split('.');
        if (!int.TryParse(sec[0], out int ss)) return -1;
        int cs = 0;
        if (sec.Length > 1 && int.TryParse(sec[1].PadRight(2, '0').Substring(0, 2), out int v)) cs = v;
        return ((long)h * 3600 + m * 60 + ss) * 1000 + cs * 10;
    }

    // 剥离 <...>
    private static string StripInline(string s)
    {
        var sb = new StringBuilder();
        bool tag = false, brace = false;
        foreach (char c in s)
        {
            if (c == '<') { tag = true; continue; }
            if (c == '>') { tag = false; continue; }
            if (c == '{') { brace = true; continue; }
            if (c == '}') { brace = false; continue; }
            if (!tag && !brace) sb.Append(c);
        }
        return sb.ToString();
    }
}
