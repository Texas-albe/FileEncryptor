#pragma warning disable CA1416
// 库主密钥 PQC 混合封
using Javax.Crypto;
using Javax.Crypto.Spec;
using System.Text;
using System.Text.Json;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Platforms.Android;

public static class PqcVault
{
    // v2
    private const string Alias = "fe_vault_pqc_key_v2";
    private const string BlobName = ".fepqc";
    private const int MagicLen = 5;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("FEPQ2");

    private static string KeyPath(string vaultDir)
    {
        string h = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(vaultDir)))[..24];
        return Path.Combine(FileSystem.AppDataDirectory, "pqc", h + ".bin");
    }

    private static string BlobPath(string vaultDir) => Path.Combine(vaultDir, BlobName);

    public static bool IsAvailable()
    {
        try { return FileCryptoService.AsymSupported(); }
        catch { return false; }
    }

    // 登记前校验
    public static bool CanEnable()
    {
        try { return IsAvailable() && BiometricVault.IsAvailable(); }
        catch { return false; }
    }

    // 只认 v2 密文
    public static bool HasCredential(string vaultDir)
    {
        if (string.IsNullOrEmpty(vaultDir) || !File.Exists(BlobPath(vaultDir))) return false;
        try
        {
            string kp = KeyPath(vaultDir);
            if (!File.Exists(kp)) return false;
            byte[] head = new byte[MagicLen];
            using var fs = File.OpenRead(kp);
            if (fs.Read(head, 0, MagicLen) != MagicLen) return false;
            return Encoding.ASCII.GetString(head) == "FEPQ2";
        }
        catch { return false; }
    }

    // 盐绑定库身份
    public static byte[]? ReadVaultSalt(string vaultDir)
    {
        try
        {
            string meta = File.ReadAllText(Path.Combine(vaultDir, "vault.meta"));
            using var doc = JsonDocument.Parse(meta);
            if (!doc.RootElement.TryGetProperty("salt", out var el)) return null;
            byte[] salt = Convert.FromHexString(el.GetString() ?? "");
            return salt.Length == 16 ? salt : null;
        }
        catch { return null; }
    }

    // 登记
    public static async Task<string?> EnableAsync(string vaultDir, byte[] passphrase)
    {
        byte[]? priv = null;
        try
        {
            if (!CanEnable()) return L10n.T("当前设备不支持生物ID验证。");
            byte[]? salt = ReadVaultSalt(vaultDir);
            if (salt is null) return L10n.T("无法读取加密库信息");
            var (blob, keyPriv) = await Task.Run(() => FileCryptoService.PqcSeal(passphrase, salt!));
            priv = keyPriv;
            var key = BiometricKeystoreHelper.GetOrCreateKey(Alias);
            if (key is null) return L10n.T("无法创建安全密钥");
            var cipher = Cipher.GetInstance(BiometricKeystoreHelper.Transform);
            cipher.Init(CipherMode.EncryptMode, key);
            byte[] p = priv!;
            var r = await BiometricKeystoreHelper.AuthenticateAsync(cipher, c =>
            {
                byte[] ct = c.DoFinal(p)!;
                byte[] iv = c.GetIV()!;
                int n = BiometricKeystoreHelper.IvLen;
                byte[] wrapped = new byte[MagicLen + n + ct.Length];
                Buffer.BlockCopy(Magic, 0, wrapped, 0, MagicLen);
                Buffer.BlockCopy(iv, 0, wrapped, MagicLen, n);
                Buffer.BlockCopy(ct, 0, wrapped, MagicLen + n, ct.Length);
                string kp = KeyPath(vaultDir);
                string? dir = Path.GetDirectoryName(kp);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                // 先私钥后 blob
                File.WriteAllBytes(kp, wrapped);
                File.WriteAllBytes(BlobPath(vaultDir), blob);
                return null;
            }, L10n.T("验证生物ID以开启后量子保护"),
               L10n.T("验证后即可用指纹或面容解锁"));
            return r.Ok ? null : L10n.T("生物ID验证未通过");
        }
        catch (Exception ex) { return ex.Message; }
        finally { Secret.Wipe(priv); }
    }

    // 解封
    public static async Task<byte[]?> UnsealAsync(string vaultDir)
    {
        byte[]? priv = null;
        try
        {
            byte[]? salt = ReadVaultSalt(vaultDir);
            if (salt is null || !HasCredential(vaultDir)) return null;
            byte[] wrapped = File.ReadAllBytes(KeyPath(vaultDir));
            int n = BiometricKeystoreHelper.IvLen;
            if (wrapped.Length <= MagicLen + n) return null;
            byte[] iv = new byte[n];
            byte[] ct = new byte[wrapped.Length - MagicLen - n];
            Buffer.BlockCopy(wrapped, MagicLen, iv, 0, n);
            Buffer.BlockCopy(wrapped, MagicLen + n, ct, 0, ct.Length);
            var key = BiometricKeystoreHelper.GetOrCreateKey(Alias);
            if (key is null) return null;
            var cipher = Cipher.GetInstance(BiometricKeystoreHelper.Transform);
            cipher.Init(CipherMode.DecryptMode, key,
                new GCMParameterSpec(BiometricKeystoreHelper.TagBits, iv));
            var r = await BiometricKeystoreHelper.AuthenticateAsync(cipher, c => c.DoFinal(ct),
                L10n.T("验证后解锁加密库"), L10n.T("验证生物ID"));
            if (!r.Ok || r.Data is null) return null;
            priv = r.Data;
            byte[] blob = File.ReadAllBytes(BlobPath(vaultDir));
            byte[] p = priv!;
            byte[] s = salt;
            return await Task.Run(() => FileCryptoService.PqcOpen(blob, p, s));
        }
        catch { return null; }
        finally { Secret.Wipe(priv); }
    }

    // 只删本库凭据
    public static void Clear(string vaultDir)
    {
        try { File.Delete(BlobPath(vaultDir)); } catch { }
        try { File.Delete(KeyPath(vaultDir)); } catch { }
    }
}
