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
    public const int MinPasswordLength = 8;

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
            r.Label = L10n.T("未输入");
            r.ColorHex = "#888888";
            return r;
        }

        int cs = CharsetSize(pw, out bool lower, out bool upper, out bool digit, out bool symbol);
        int len = pw.Length;
        int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);

        int entropy = 0;
        if (cs > 0) entropy = (int)Math.Round(len * Math.Log2(cs), MidpointRounding.AwayFromZero);
        r.EntropyBits = entropy;

        if (len < 6 || entropy < 28)
        {
            r.Level = StrengthLevel.Weak;
            r.Label = L10n.T("弱");
            r.ColorHex = "#D32F2F";
        }
        else if (len < 10 && entropy < 48)
        {
            r.Level = StrengthLevel.Medium;
            r.Label = L10n.T("中");
            r.ColorHex = "#F9A825";
        }
        else
        {
            r.Level = StrengthLevel.Strong;
            r.Label = L10n.T("强");
            r.ColorHex = "#2E7D32";
        }

        string kindStr = "";
        if (lower) kindStr += L10n.T("小写 ");
        if (upper) kindStr += L10n.T("大写 ");
        if (digit) kindStr += L10n.T("数字 ");
        if (symbol) kindStr += L10n.T("符号 ");
        if (string.IsNullOrEmpty(kindStr)) kindStr = L10n.T("无");
        r.Detail = L10n.F("长度 {0} | 种类 {1} | 熵 ~{2} bits | {3}", len, kinds, entropy, kindStr.Trim());

        return r;
    }

    public static bool MeetsPolicy(string password, out string reason)
    {
        reason = "";
        int len = password.Length;
        if (len < MinPasswordLength)
        {
            reason = L10n.F("密码过短（至少 {0} 个字符）。", MinPasswordLength);
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
        // 非 ASCII（CJK 等）只算一类字符：此前「含非 ASCII 即放行」会让
        // 「的的的的的的的的」这类重复汉字被判为合格，实际熵近乎为零。
        int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) +
                    (symbol ? 1 : 0) + (nonAscii ? 1 : 0);
        if (kinds >= 2 || len >= 16)
        {
            bool allSame = true;
            for (int i = 1; i < password.Length; i++)
            {
                if (password[i] != password[0]) { allSame = false; break; }
            }
            if (!allSame) return true;
            reason = L10n.T("密码过弱：请不要使用重复字符。");
            return false;
        }

        reason = L10n.T("密码过弱：请至少含 2 类字符（小写/大写/数字/符号），或长度 >= 16。");
        return false;
    }
}
