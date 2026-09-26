namespace FileEncryptorGUI.Services;

public enum StrengthLevel { Empty, Weak, Medium, Strong }

public class StrengthResult
{
    public StrengthLevel Level { get; set; }
    public string Label { get; set; } = "";
    public string ColorHex { get; set; } = "#888888";
    public int EntropyBits { get; set; }
    public string Detail { get; set; } = "";
}

public static class PasswordStrengthService
{
    public const int MinPasswordLength = 6;

    private static int CharsetSize(string pw, out bool lower, out bool upper, out bool digit, out bool symbol)
    {
        int size = 0;
        lower = upper = digit = symbol = false;
        foreach (char ch in pw)
        {
            if (ch >= 'a' && ch <= 'z') { if (!lower) { lower = true; size += 26; } }
            else if (ch >= 'A' && ch <= 'Z') { if (!upper) { upper = true; size += 26; } }
            else if (ch >= '0' && ch <= '9') { if (!digit) { digit = true; size += 10; } }
            else { if (!symbol) { symbol = true; size += 33; } }
        }
        return size;
    }

    public static StrengthResult Evaluate(string pw)
    {
        var r = new StrengthResult();
        if (string.IsNullOrEmpty(pw))
        {
            r.Level = StrengthLevel.Empty;
            r.Label = "未输入";
            r.ColorHex = "#888888";
            return r;
        }

        int cs = CharsetSize(pw, out bool lower, out bool upper, out bool digit, out bool symbol);
        int len = pw.Length;
        int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);

        int entropy = 0;
        if (cs > 0) entropy = (int)Math.Round(len * Math.Log2(cs));
        r.EntropyBits = entropy;

        if (len < 6 || entropy < 28)
        {
            r.Level = StrengthLevel.Weak;
            r.Label = "弱";
            r.ColorHex = "#D32F2F";
        }
        else if (len < 10 && entropy < 48)
        {
            r.Level = StrengthLevel.Medium;
            r.Label = "中";
            r.ColorHex = "#F9A825";
        }
        else
        {
            r.Level = StrengthLevel.Strong;
            r.Label = "强";
            r.ColorHex = "#2E7D32";
        }

        string kindStr = "";
        if (lower) kindStr += "小写 ";
        if (upper) kindStr += "大写 ";
        if (digit) kindStr += "数字 ";
        if (symbol) kindStr += "符号 ";
        if (string.IsNullOrEmpty(kindStr)) kindStr = "无";
        r.Detail = $"长度 {len} | 种类 {kinds} | 熵 ~{entropy} bits | {kindStr.Trim()}";

        return r;
    }

    public static bool MeetsPolicy(string password, out string reason)
    {
        reason = "";
        int len = password.Length;
        if (len < MinPasswordLength)
        {
            reason = $"口令过短（至少 {MinPasswordLength} 个字符）。";
            return false;
        }

        bool lower = false, upper = false, digit = false, symbol = false, nonAscii = false;
        foreach (char ch in password)
        {
            if (ch <= 0x7F)
            {
                if (ch >= 'a' && ch <= 'z') lower = true;
                else if (ch >= 'A' && ch <= 'Z') upper = true;
                else if (ch >= '0' && ch <= '9') digit = true;
                else symbol = true;
            }
            else nonAscii = true;
        }
        if (nonAscii) return true;

        int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        if (kinds >= 2 || len >= 16) return true;

        reason = "口令过弱：请至少含 2 类字符（小写/大写/数字/符号），或长度 >= 16。";
        return false;
    }
}
