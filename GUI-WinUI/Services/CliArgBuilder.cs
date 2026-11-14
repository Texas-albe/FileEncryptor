using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Linq;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

// GUI 参数到 argv
public static class CliArgBuilder
{
    // 密码框里存
    private static string ResolveKeySource(string key, ShellOptions options)
        => IsPrivateKeyMaterial(key) ? TempFileFor(key, options) : key;

    public static bool IsPrivateKeyMaterial(string? v)
        => !string.IsNullOrEmpty(v) && v.Contains("PRIVATE KEY", StringComparison.Ordinal);

    // 入盘目标原样
    private static string ResolveVaultTarget(string target)
    {
        return (target ?? "").Trim();
    }

    // 私钥明文只落
    // 用静态字段存路
    // 前一个任务结束
    private static string TempFileFor(string key, ShellOptions options)
    {
        var path = Path.Combine(Path.GetTempPath(),
            "fe_wm_" + Guid.NewGuid().ToString("N") + ".pem");
        // 创建句柄时即带
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var me = WindowsIdentity.GetCurrent().User;
        if (me == null) return key;
        sec.AddAccessRule(new FileSystemAccessRule(
            me, FileSystemRights.FullControl, AccessControlType.Allow));
        // 创建即带限制 DACL
        using (var fs = new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, sec))
        using (var sw = new StreamWriter(fs, new UTF8Encoding(false)))
        {
            sw.Write(key);
        }
        TightenTempAcl(path);
        options.WatermarkTempKeyPath = path;
        return path;
    }

    // 显式收紧 ACL
    private static void TightenTempAcl(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var rules = sec.GetAccessRules(includeExplicit: true, includeInherited: true,
                typeof(System.Security.Principal.NTAccount))
                .Cast<System.Security.AccessControl.FileSystemAccessRule>().ToList();
            foreach (var r in rules) sec.RemoveAccessRule(r);
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            if (me != null)
            {
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    me, System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
            }
            fi.SetAccessControl(sec);
        }
        catch { /* 收紧失败不阻断：文件仍会由任务结束时删除 */ }
    }

    // 删除本次任务自
    public static void CleanupWatermarkTemp(ShellOptions options)
    {
        var path = options?.WatermarkTempKeyPath;
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            // 先零填充
            var n = new FileInfo(path).Length;
            if (n > 0) File.WriteAllBytes(path, new byte[n]);
        }
        catch { }
        try { File.Delete(path); } catch { }
        options!.WatermarkTempKeyPath = null;
    }

    public static List<string> BuildArguments(ShellOptions options)
    {
        var args = new List<string>();

        // 密钥包装
        // 密码 / 私钥不落 argv
        if (options.Action == CryptoAction.WrapKey) return BuildWrapArgs(options);
        if (options.Action == CryptoAction.UnwrapKey) return BuildUnwrapArgs(options);

        switch (options.Action)
        {
            case CryptoAction.Encrypt: args.Add("-e"); break;
            case CryptoAction.Decrypt: args.Add("-d"); break;
            case CryptoAction.BatchEncrypt: args.Add("-be"); break;
            case CryptoAction.BatchDecrypt: args.Add("-bd"); break;
            case CryptoAction.KeyGen: args.Add("-g"); break;
            case CryptoAction.Derive: args.Add("-G"); break;
            case CryptoAction.PubKey: args.Add("-Y"); break;
        }

        // 模式
        // 两条
        if (options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            if (options.Mode == CryptoMode.Asymmetric)
            {
                args.Add("-m"); args.Add(options.UseX448 ? "x448" : "x25519");
                args.Add("-m"); args.Add(FileModeToken(options.FileMode));
            }
            else
            {
                args.Add("-m"); args.Add(ModeToken(options.Mode));
            }
        }

        // 生成密钥
        if (options.Action == CryptoAction.KeyGen && options.UseX448) args.Add("-x448");

        // 加密盘入盘
        bool isVaultIngest = options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt
                             && !string.IsNullOrEmpty(options.IntoVault);
        if (isVaultIngest)
        {
            // 填的是盘符
            // 由 CLI 守卫给出「看起
            var target = ResolveVaultTarget(options.IntoVault!);
            args.Add("--into-vault"); args.Add(target);
        }

        // 输出目录
        if (!string.IsNullOrEmpty(options.OutputDir)) { args.Add("-o"); args.Add(options.OutputDir); }

        bool isEnc = options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt;

        // 加密压缩包
        if (isEnc && options.Pack) args.Add("-p");

        // 分卷
        if (isEnc && options.Split)
        {
            args.Add("--split");
            args.Add(FormatSplitSize(options.SplitSize, options.SplitUnit));
        }

        // 源文件处理
        if (isEnc)
        {
            switch (options.SourceDisposition)
            {
                case SourceDisposition.Delete: args.Add("-de"); break;
                case SourceDisposition.Wipe: args.Add("--wipe-source"); break;
                case SourceDisposition.Recycle: args.Add("--recycle-source"); break;
            }
            // 目录 + 删除类处置
            if (options.SourceDeleteOk && options.SourceDisposition != SourceDisposition.Keep)
                args.Add("--source-delete-ok");
        }

        if (options.ForceOverwrite) args.Add("-y");

        // 密钥文件
        if (!string.IsNullOrEmpty(options.KeyfilePath) && options.Mode != CryptoMode.Asymmetric)
        {
            args.Add("-k"); args.Add(options.KeyfilePath);
        }

        // 非对称加密
        if (options.Mode == CryptoMode.Asymmetric &&
            options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt &&
            !string.IsNullOrEmpty(options.RecipientPath))
        {
            args.Add("-r"); args.Add(options.RecipientPath);
        }

        // 非对称解密
        if (options.Mode == CryptoMode.Asymmetric &&
            options.Action is CryptoAction.Decrypt or CryptoAction.BatchDecrypt &&
            !string.IsNullOrEmpty(options.IdentityPath))
        {
            args.Add("-k"); args.Add(options.IdentityPath);
        }

        // 批量解密
        if (options.Action == CryptoAction.BatchDecrypt && options.RestoreName)
        {
            args.Add("--restore-name");
        }

        // SHA256 校验单
        if (options.WriteSha256 && options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            args.Add("--sha256");
        }

        // 后量子开关
        bool pqcAffects = options.Action == CryptoAction.KeyGen || options.Watermark;
        if (pqcAffects && !options.Pqc) args.Add("--no-pqc");

        // 尾部水印
        if (options.Watermark &&
            options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            args.Add("--watermark");
            if (!string.IsNullOrEmpty(options.WatermarkKeyPath))
            {
                args.Add("--wm-sign");
                args.Add(ResolveKeySource(options.WatermarkKeyPath, options));
            }
        }

        // zstd 压缩
        if (options.Compress && options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            args.Add("-zstd");
            if (options.CompressionLevel != 0)
            {
                args.Add("--compression-level");
                args.Add(options.CompressionLevel.ToString());
            }
        }

        // 密钥经 stdin 注入
        bool needsStdinKey = options.Mode != CryptoMode.Asymmetric &&
                             string.IsNullOrEmpty(options.KeyfilePath) &&
                             options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt
                                 or CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt
                                 or CryptoAction.Derive;
        if (needsStdinKey) args.Add("--key-stdin");

        // 批量模式
        if (options.Action is CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt)
        {
            foreach (var p in options.InputPaths) { args.Add("-i"); args.Add(p); }
        }
        else if (options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt or CryptoAction.PubKey)
        {
            // - 终止选项解析
            if (options.InputPaths.Count > 0) { args.Add("--"); args.Add(options.InputPaths[0]); }
        }

        return args;
    }

    // 把 32 字节 DEK 包进 FEKW blob
    private static List<string> BuildWrapArgs(ShellOptions o)
    {
        var args = new List<string> { "--wrap-key", o.WrapInput, "--wrap-alg", WrapAlgToken(o.WrapAlg) };
        if (!string.IsNullOrEmpty(o.WrapOutput)) { args.Add("--wrap-out"); args.Add(o.WrapOutput); }
        if (o.WrapAlg == WrapAlg.Pubkey)
        {
            // 公钥路线
            if (!string.IsNullOrEmpty(o.RecipientPath)) { args.Add("--wrap-to"); args.Add(o.RecipientPath); }
        }
        else if (!string.IsNullOrEmpty(o.KeyfilePath)) { args.Add("-k"); args.Add(o.KeyfilePath); }
        else args.Add("--key-stdin");
        if (o.ForceOverwrite) args.Add("-y");
        return args;
    }

    // 从 FEKW blob 取回 DEK
    private static List<string> BuildUnwrapArgs(ShellOptions o)
    {
        var args = new List<string> { "--unwrap-key", o.WrapInput };
        // 解包时算法写
        if (o.WrapAlg != WrapAlg.Pubkey)
        {
            if (!string.IsNullOrEmpty(o.KeyfilePath)) { args.Add("-k"); args.Add(o.KeyfilePath); }
            else args.Add("--key-stdin");
        }
        else if (!string.IsNullOrEmpty(o.IdentityPath)) { args.Add("--identity"); args.Add(o.IdentityPath); }
        if (!string.IsNullOrEmpty(o.WrapOutput)) { args.Add("--unwrap-out"); args.Add(o.WrapOutput); }
        if (o.ForceOverwrite) args.Add("-y");
        return args;
    }

    private static string WrapAlgToken(WrapAlg a) => a switch
    {
        WrapAlg.AesKw => "aes-kw",
        WrapAlg.Pubkey => "pubkey",
        _ => "kwp"
    };

    // 组装 --split 尺寸串
    private static string FormatSplitSize(double value, SplitUnit unit)
    {
        double v = value > 0 ? value : 1;
        string suffix = unit switch
        {
            SplitUnit.GB => "GB",
            SplitUnit.TB => "TB",
            _ => "MB",
        };
        return v.ToString("0.####", System.Globalization.CultureInfo.InvariantCulture) + suffix;
    }

    private static string ModeToken(CryptoMode m) => m switch
    {
        CryptoMode.Aegis256 => "aegis256",
        CryptoMode.AesGcm => "aes-gcm",
        CryptoMode.Sm4 => "sm4",
        _ => "xchacha20"
    };

    private static string FileModeToken(CryptoMode m) => m switch
    {
        CryptoMode.Aegis256 => "aegis256",
        CryptoMode.AesGcm => "aes-gcm",
        CryptoMode.Sm4 => "sm4",
        _ => "xchacha20"
    };

    public static string BuildPreview(string programPath, ShellOptions options)
    {
        var sb = new StringBuilder();
        sb.Append('"').Append(programPath).Append('"');
        var prev = "";
        foreach (var a in BuildArguments(options))
        {
            sb.Append(' ');
            // 密钥取值只显示
            if (!a.StartsWith("-") && (prev == "--wm-sign" || prev == "--wm-verify"
                                       || IsPrivateKeyMaterial(a)))
                sb.Append("<private-key>");
            // 值参数统一加引
            else if (a.StartsWith("-"))
                sb.Append(a);
            else
                sb.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
            prev = a;
        }
        if (options.Mode != CryptoMode.Asymmetric && string.IsNullOrEmpty(options.KeyfilePath) &&
            options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt
                or CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt or CryptoAction.Derive)
        {
            sb.Append(L10n.T("  # 密钥经 stdin 管道注入"));
        }
        // 包装动作
        if (options.Action is CryptoAction.WrapKey or CryptoAction.UnwrapKey)
        {
            if (options.WrapAlg == WrapAlg.Pubkey) sb.Append(L10n.T("  # 使用收件人密钥材料"));
            else if (!string.IsNullOrEmpty(options.KeyfilePath)) sb.Append(L10n.T("  # 密码来自 -k 文件"));
            else sb.Append(L10n.T("  # 密码经 stdin 管道注入"));
        }
        // 预览只拼字符串
        CleanupWatermarkTemp(options);
        return sb.ToString();
    }
}
