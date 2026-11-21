// 口令强度策略
// 强度不足时上层
using FileEncryptorMobile.Services;
namespace FileEncryptorMobile.Services;

public static class PasswordPolicy
{
    private const int MinLen = 12;

    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "12345678", "123456789", "1234567890", "87654321", "5201314",
        "password", "password1", "passw0rd", "qwerty123", "qwertyui",
        "abc12345", "abcdefgh", "11111111", "00000000", "88888888", "66666666",
        "iloveyou", "admin123", "admin888", "letmein1", "woaini1314",
    };

    // ok = 通
    public static bool Check(string pw, out string why)
    {
        why = "";
        if (pw.Length < MinLen) { why = L10n.F("密码长度至少为 {0} 位。", MinLen); return false; }
        if (Common.Contains(pw)) { why = L10n.T("这是常见弱密码，容易被字典破解。"); return false; }
        if (pw.Distinct().Count() == 1) { why = L10n.T("密码不能全部为同一字符。"); return false; }
        // CJK 口令
        if (pw.All(char.IsDigit)) { why = L10n.T("密码不能只包含数字。"); return false; }
        if (pw.All(c => c < 128 && char.IsLetter(c))) { why = L10n.T("密码不能只包含字母。"); return false; }
        return true;
    }
}
