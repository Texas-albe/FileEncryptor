#pragma warning disable CA1416
// 生物认证密钥公
using Android.Hardware.Biometrics;
using Android.OS;
using Android.Security.Keystore;
using Android.Content;
using Java.Security;
using Javax.Crypto;
using Microsoft.Maui.ApplicationModel;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Platforms.Android;

internal static class BiometricKeystoreHelper
{
    internal const string Provider = "AndroidKeyStore";
    internal const string Transform = "AES/GCM/NoPadding";
    internal const int IvLen = 12;
    internal const int TagBits = 128;

    // 取或建认证密钥
    internal static IKey? GetOrCreateKey(string alias)
    {
        var ks = KeyStore.GetInstance(Provider);
        ks.Load(null);
        if (!ks.ContainsAlias(alias))
        {
            var kg = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, Provider);
            var b = new KeyGenParameterSpec.Builder(alias,
                    KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                .SetBlockModes(KeyProperties.BlockModeGcm)
                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                .SetUserAuthenticationRequired(true);
            if (Build.VERSION.SdkInt >= BuildVersionCodes.R)
                b.SetUserAuthenticationParameters(0, (int)KeyPropertiesAuthType.BiometricStrong);
            kg.Init(b.Build());
            kg.GenerateKey();
        }
        return ks.GetKey(alias, null);
    }

    // 认证后用同一 Cipher 收
    internal static Task<(bool Ok, byte[]? Data)> AuthenticateAsync(
        Cipher cipher, Func<Cipher, byte[]?> body, string title, string subtitle)
    {
        var tcs = new TaskCompletionSource<(bool Ok, byte[]? Data)>();
        var act = Platform.CurrentActivity;
        if (act is null) { tcs.TrySetResult((false, null)); return tcs.Task; }
        try
        {
            var prompt = new BiometricPrompt.Builder(act)
                .SetTitle(title)
                .SetSubtitle(subtitle)
                .SetNegativeButton(L10n.T("取消"), act.MainExecutor, new CancelClick(tcs))
                .Build();
            prompt.Authenticate(new BiometricPrompt.CryptoObject(cipher),
                new CancellationSignal(), act.MainExecutor, new AuthCallback(tcs, cipher, body));
        }
        catch { tcs.TrySetResult((false, null)); }
        return tcs.Task;
    }

    private sealed class CancelClick : Java.Lang.Object, IDialogInterfaceOnClickListener
    {
        private readonly TaskCompletionSource<(bool Ok, byte[]? Data)> _tcs;
        public CancelClick(TaskCompletionSource<(bool Ok, byte[]? Data)> tcs) => _tcs = tcs;
        public void OnClick(IDialogInterface? dialog, int which)
            => _tcs.TrySetResult((false, null));
    }

    private sealed class AuthCallback : BiometricPrompt.AuthenticationCallback
    {
        private readonly TaskCompletionSource<(bool Ok, byte[]? Data)> _tcs;
        private readonly Cipher _cipher;
        private readonly Func<Cipher, byte[]?> _body;
        public AuthCallback(TaskCompletionSource<(bool Ok, byte[]? Data)> tcs,
            Cipher cipher, Func<Cipher, byte[]?> body)
        { _tcs = tcs; _cipher = cipher; _body = body; }
        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult? result)
        {
            try
            {
                var c = result?.CryptoObject?.Cipher ?? _cipher;
                _tcs.TrySetResult((true, _body(c)));
            }
            catch { _tcs.TrySetResult((false, null)); }
        }
        public override void OnAuthenticationError(BiometricErrorCode errorCode,
            Java.Lang.ICharSequence? errString)
            => _tcs.TrySetResult((false, null));
        // 单次失败可重试
        public override void OnAuthenticationFailed() { }
    }
}
