#pragma warning disable CA1416 // 本文件整体
// 应用私有
// 回收站元数据、收
using Android.OS;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using System.Security.Cryptography;
using System.Text;

namespace FileEncryptorMobile.Platforms.Android;

public static class SecureJsonStore
{
    private const string Provider = "AndroidKeyStore";
    private const string Alias = "fe_vault_meta_key";
    private const string Transform = "AES/GCM/NoPadding";
    private const int TagBits = 128;
    private static readonly object Gate = new();

    private static string Dir
    {
        get
        {
            string d = Path.Combine(FileSystem.AppDataDirectory, "secure");
            Directory.CreateDirectory(d);
            return d;
        }
    }

    private static string PathOf(string name)
    {
        // 文件名取哈希
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(name));
        return Path.Combine(Dir, Convert.ToHexString(hash.AsSpan(0, 16)).ToLowerInvariant() + ".bin");
    }

    public static string? Load(string name)
    {
        lock (Gate)
        {
            try
            {
                string p = PathOf(name);
                if (!File.Exists(p)) return null;
                byte[] buf = File.ReadAllBytes(p);
                if (buf.Length < 12) return null;
                var iv = new byte[12];
                Buffer.BlockCopy(buf, 0, iv, 0, 12);
                var ct = new byte[buf.Length - 12];
                Buffer.BlockCopy(buf, 12, ct, 0, ct.Length);
                var cipher = Cipher.GetInstance(Transform);
                cipher.Init(Javax.Crypto.CipherMode.DecryptMode, GetOrCreateKey(),
                    new GCMParameterSpec(TagBits, iv));
                return Encoding.UTF8.GetString(cipher.DoFinal(ct));
            }
            catch { return null; }
        }
    }

    public static void Save(string name, string json)
    {
        lock (Gate)
        {
            try
            {
                var cipher = Cipher.GetInstance(Transform);
                cipher.Init(Javax.Crypto.CipherMode.EncryptMode, GetOrCreateKey());
                byte[] ct = cipher.DoFinal(Encoding.UTF8.GetBytes(json));
                byte[] iv = cipher.GetIV()!;
                var buf = new byte[iv.Length + ct.Length];
                Buffer.BlockCopy(iv, 0, buf, 0, iv.Length);
                Buffer.BlockCopy(ct, 0, buf, iv.Length, ct.Length);
                string p = PathOf(name);
                string tmp = p + ".tmp";
                File.WriteAllBytes(tmp, buf);
                File.Move(tmp, p, true);   // 原子替换
            }
            catch { /* 存储失败不应让主流程崩溃 */ }
        }
    }

    public static void Delete(string name)
    {
        lock (Gate)
        {
            try { File.Delete(PathOf(name)); } catch { }
        }
    }

    private static IKey GetOrCreateKey()
    {
        var ks = KeyStore.GetInstance(Provider);
        ks.Load(null);
        if (!ks.ContainsAlias(Alias))
        {
            var kg = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, Provider);
            var b = new KeyGenParameterSpec.Builder(Alias,
                    KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                .SetBlockModes(KeyProperties.BlockModeGcm)
                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                .SetKeySize(256);
            kg.Init(b.Build());
            kg.GenerateKey();
        }
        return ks.GetKey(Alias, null)!;
    }
}
