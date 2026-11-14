using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace FileEncryptorGUI.Services;

// P2-1 设备绑定解锁
// 思路
// 当前用户/机器匹
// 「便携解锁」备用
// 安全边界
// DPAPI 绑定当前用户
// 明文库密码**不落
// 「关闭本机免密」= 删
// blob 用 Entropy 绑定 vault 路径哈希
public static class DeviceKeyService
{
    // DPAPI 附加熵
    // 不用路径原文
    private static byte[] EntropyFor(string vaultDir)
    {
        var norm = (vaultDir ?? string.Empty).Replace('/', '\\').TrimEnd('\\').ToUpperInvariant();
        var h = SHA256.HashData(Encoding.UTF8.GetBytes(norm));
        var e = new byte[16];
        Array.Copy(h, e, 16);
        return e;
    }

    private static string StoreDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     "FileEncryptor", "devicekeys");

    private static string PathFor(string vaultDir)
    {
        var h = SHA256.HashData(Encoding.UTF8.GetBytes(
            (vaultDir ?? string.Empty).Replace('/', '\\').TrimEnd('\\').ToUpperInvariant()));
        var name = Convert.ToHexString(h, 0, 8).ToLowerInvariant();   // 16 位 hex
        return Path.Combine(StoreDir, name + ".dpapi");
    }

    // 生成并保存「本机
    // 解锁时若该盘已
    // 返回 false 表示 DPAPI 不可用
    // P2-3
    // 注意
    // CLI 侧
    public static bool Enable(string vaultDir, string password)
    {
        if (string.IsNullOrEmpty(password)) return false;
        byte[]? pwBytes = null;
        byte[]? entropy = null;
        try
        {
            Directory.CreateDirectory(StoreDir);
            pwBytes = Encoding.UTF8.GetBytes(password);
            entropy = EntropyFor(vaultDir);
            var blob = ProtectedData.Protect(
                pwBytes, entropy,
                DataProtectionScope.CurrentUser);
            // 原子写
            // 该盘永远无法免
            var final = PathFor(vaultDir);
            var tmp = final + ".tmp";
            File.WriteAllBytes(tmp, blob);
            File.Move(tmp, final, overwrite: true);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (pwBytes != null) CryptographicOperations.ZeroMemory(pwBytes);
            if (entropy != null) CryptographicOperations.ZeroMemory(entropy);
        }
    }

    // DEPRECATED
    public static string? TryGetPassword(string vaultDir)
    {
        byte[]? plain = null;
        byte[]? entropy = null;
        try
        {
            var p = PathFor(vaultDir);
            if (!File.Exists(p)) return null;
            var blob = File.ReadAllBytes(p);
            if (blob.Length == 0) return null;
            entropy = EntropyFor(vaultDir);
            plain = ProtectedData.Unprotect(blob, entropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            // DPAPI 解密失败＝换了用
            return null;
        }
        finally
        {
            // P2-3
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
            if (entropy != null) CryptographicOperations.ZeroMemory(entropy);
        }
    }

    // M42: byte[] API
    public static byte[]? TryGetPasswordBytes(string vaultDir)
    {
        byte[]? plain = null;
        byte[]? entropy = null;
        try
        {
            var p = PathFor(vaultDir);
            if (!File.Exists(p)) return null;
            var blob = File.ReadAllBytes(p);
            if (blob.Length == 0) return null;
            entropy = EntropyFor(vaultDir);
            plain = ProtectedData.Unprotect(blob, entropy, DataProtectionScope.CurrentUser);
            // 返回副本
            var result = new byte[plain.Length];
            Array.Copy(plain, result, plain.Length);
            return result;
        }
        catch
        {
            // DPAPI 解密失败＝换了用
            return null;
        }
        finally
        {
            // P2-3
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
            if (entropy != null) CryptographicOperations.ZeroMemory(entropy);
        }
    }

    public static bool IsBound(string vaultDir)
    {
        try { return File.Exists(PathFor(vaultDir)); }
        catch { return false; }
    }

    // 忘记设备密钥
    public static void Forget(string vaultDir)
    {
        try
        {
            var p = PathFor(vaultDir);
            if (File.Exists(p))
            {
                // 先覆写
                try
                {
                    var n = new FileInfo(p).Length;
                    if (n > 0) File.WriteAllBytes(p, new byte[n]);
                }
                catch { }
                File.Delete(p);
            }
        }
        catch { }
    }
}
