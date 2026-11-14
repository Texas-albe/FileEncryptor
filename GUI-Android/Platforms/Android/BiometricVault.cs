#pragma warning disable CA1416 // Android 9+ 路径
// 生物识别解锁
using Android.Content;
using Android.Hardware.Biometrics;
using Android.OS;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Microsoft.Maui.ApplicationModel;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Platforms.Android;

public static class BiometricVault
{
    private const string Alias = "fe_vault_bio_key";
    // 凭据随库走
    private const string FileName = ".febio";

    public static bool HasCredential(string vaultDir)
        => !string.IsNullOrEmpty(vaultDir) && File.Exists(Path.Combine(vaultDir, FileName));

    // 设备是否支持
    public static bool IsAvailable()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.P) return false;
        try
        {
            var bm = (BiometricManager?)Platform.AppContext.GetSystemService(Context.BiometricService);
            if (bm is null) return false;
#pragma warning disable CA1416 // 30+ 接口
            var r = bm.CanAuthenticate((int)BiometricManagerAuthenticators.BiometricStrong);
#pragma warning restore CA1416
            return r == BiometricCode.Success;
        }
        catch { return false; }
    }

    // 登记主密码
    public static async Task<string?> SaveAsync(string vaultDir, byte[] passphrase)
    {
        try
        {
            var key = BiometricKeystoreHelper.GetOrCreateKey(Alias);
            if (key is null) return L10n.T("无法创建安全密钥");
            var cipher = Cipher.GetInstance(BiometricKeystoreHelper.Transform);
            cipher.Init(CipherMode.EncryptMode, key);
            var r = await BiometricKeystoreHelper.AuthenticateAsync(cipher, c =>
            {
                byte[] ct = c.DoFinal(passphrase)!;
                byte[] iv = c.GetIV()!;
                var buf = new byte[iv.Length + ct.Length];
                Buffer.BlockCopy(iv, 0, buf, 0, iv.Length);
                Buffer.BlockCopy(ct, 0, buf, iv.Length, ct.Length);
                File.WriteAllBytes(Path.Combine(vaultDir, FileName), buf);
                return null;
            }, L10n.T("验证后开启指纹或面容解锁"),
               L10n.T("验证一次后，即可使用指纹或面容解锁加密库"));
            return r.Ok ? null : L10n.T("指纹或面容验证未通过");
        }
        catch (Exception ex) { return ex.Message; }
    }

    // 取回主密码
    public static async Task<byte[]?> LoadAsync(string vaultDir)
    {
        try
        {
            var key = BiometricKeystoreHelper.GetOrCreateKey(Alias);
            var blob = File.ReadAllBytes(Path.Combine(vaultDir, FileName));
            int n = BiometricKeystoreHelper.IvLen;
            if (blob.Length <= n) return null;
            var iv = new byte[n];
            var ct = new byte[blob.Length - n];
            Buffer.BlockCopy(blob, 0, iv, 0, n);
            Buffer.BlockCopy(blob, n, ct, 0, ct.Length);
            var cipher = Cipher.GetInstance(BiometricKeystoreHelper.Transform);
            cipher.Init(CipherMode.DecryptMode, key,
                new GCMParameterSpec(BiometricKeystoreHelper.TagBits, iv));
            var r = await BiometricKeystoreHelper.AuthenticateAsync(cipher, c => c.DoFinal(ct),
                L10n.T("验证后解锁加密库"), L10n.T("用指纹或面容验证"));
            return r.Ok ? r.Data : null;
        }
        catch { return null; }
    }

    // 关闭凭据
    public static void Clear(string vaultDir)
    {
        try { File.Delete(Path.Combine(vaultDir, FileName)); } catch { }
        try
        {
            var ks = KeyStore.GetInstance(BiometricKeystoreHelper.Provider);
            ks.Load(null);
            if (ks.ContainsAlias(Alias)) ks.DeleteEntry(Alias);
        }
        catch { }
    }
}
