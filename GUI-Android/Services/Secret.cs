// 口令 byte[] 基础设施
using System.Security.Cryptography;
using System.Text;

namespace FileEncryptorMobile.Services;

public static class Secret
{
    public static byte[] From(string s) => Encoding.UTF8.GetBytes(s);

    // 含 NUL 结尾
    public static byte[] FromZ(string s)
    {
        var buf = new byte[Encoding.UTF8.GetByteCount(s) + 1];
        Encoding.UTF8.GetBytes(s, 0, s.Length, buf, 0);
        return buf;   // 末字节保持 0
    }

    // ZeroMemory 不会
    public static void Wipe(byte[]? b)
    {
        if (b is not null && b.Length > 0) CryptographicOperations.ZeroMemory(b);
    }
}
