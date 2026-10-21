using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace FileEncryptorGUI.Services;

// P2-1 设备绑定解锁（对标 BitLocker 的「设备绑定 + 便携恢复密钥」）
//
// 思路：把库密码用 Windows DPAPI（CurrentUser 域）保护后落盘。解锁时若该盘已绑定且
// 当前用户/机器匹配，则用解出的库密码直接解锁，无需用户再次输入；库密码本身仍是
// 「便携解锁」备用的唯一真相，换机器时凭记忆/恢复码解锁。
//
// 安全边界（务必保持）：
//   - DPAPI 绑定当前用户：换用户/漫游域不可用，攻击者拿到 blob 也解不开。
//   - 明文库密码**不落盘**：仅以 DPAPI blob 形式存在（本机可解）。
//   - 「关闭本机免密」= 删除 blob，该盘回到「每次输库密码」。
//   - blob 用 Entropy 绑定 vault 路径哈希：拷到别的盘/别的库用不了。
public static class DeviceKeyService
{
    // DPAPI 附加熵：混入 vault 路径，使 blob 与具体加密盘绑定。
    // 不用路径原文（会出现在文件名/长度侧信道里），只取 SHA256 前 16 字节。
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

    // 生成并保存「本机免密」凭据：把库密码以 DPAPI（CurrentUser）保护后落盘。
    // 解锁时若该盘已绑定，用解出的库密码直接解锁，无需用户再次输入。
    // 返回 false 表示 DPAPI 不可用、密码为空或写盘失败（调用方应提示并降级到「每次输密码」）。
    // P2-3：口令的 UTF-8 缓冲与 DPAPI 解出的明文缓冲用完立即清零。
    // 注意：返回的 string 是托管不可变对象，无法清零——这是 .NET 口令处理的固有上限，
    // CLI 侧（C++）用 SecureBuffer 才是真正可清零的路径，UI 侧只能缩短明文存活窗口。
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
            // 原子写：先写临时文件再替换，避免中断留下半截 blob（半截会被 DPAPI 拒绝，
            // 导致该盘永远无法免密解锁）。
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

    // DEPRECATED：返回的 string 是不可变副本、无法清零，长驻托管堆；新代码请改用 TryGetPasswordBytes（byte[]，调用方用完 CryptographicOperations.ZeroMemory 清零）。仅为兼容保留。
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
            // DPAPI 解密失败＝换了用户/机器/系统重装，等同于没有绑定
            return null;
        }
        finally
        {
            // P2-3：DPAPI 解出的明文缓冲用完立即清零
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
            if (entropy != null) CryptographicOperations.ZeroMemory(entropy);
        }
    }

    // M42: byte[] API ：DPAPI 解出的口令以字节缓冲交给调用方，调用方用完负责 CryptographicOperations.ZeroMemory 清零，避免 string 副本长驻托管堆
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
            // 返回副本：原缓冲在 finally 清零，副本生命周期交由调用方掌管
            var result = new byte[plain.Length];
            Array.Copy(plain, result, plain.Length);
            return result;
        }
        catch
        {
            // DPAPI 解密失败＝换了用户/机器/系统重装，等同于没有绑定
            return null;
        }
        finally
        {
            // P2-3：DPAPI 解出的明文缓冲用完立即清零
            if (plain != null) CryptographicOperations.ZeroMemory(plain);
            if (entropy != null) CryptographicOperations.ZeroMemory(entropy);
        }
    }

    public static bool IsBound(string vaultDir)
    {
        try { return File.Exists(PathFor(vaultDir)); }
        catch { return false; }
    }

    // 忘记设备密钥：删除 blob，本盘回到「每次输库密码」。
    public static void Forget(string vaultDir)
    {
        try
        {
            var p = PathFor(vaultDir);
            if (File.Exists(p))
            {
                // 先覆写再删，避免 blob 残留在磁盘可恢复区
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
