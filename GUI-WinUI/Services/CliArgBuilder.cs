using System.Text;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

// GUI 参数到 argv 的映射
public static class CliArgBuilder
{
    // 任务结束时删掉这份临时私钥
    private static string? _wmKeyTempPath;

    // 密码框里存的是私钥明文，而 CLI 的 --wm-sign 只收文件路径
    private static string ResolveKeySource(string key)
        => IsPrivateKeyMaterial(key) ? TempFileFor(key) : key;

    public static bool IsPrivateKeyMaterial(string? v)
        => !string.IsNullOrEmpty(v) && v.Contains("PRIVATE KEY", StringComparison.Ordinal);

    private static string TempFileFor(string key)
    {
        _wmKeyTempPath ??= Path.Combine(Path.GetTempPath(),
            "fe_wm_" + Guid.NewGuid().ToString("N") + ".pem");
        File.WriteAllText(_wmKeyTempPath, key);
        return _wmKeyTempPath;
    }

    public static void CleanupWatermarkTemp()
    {
        if (_wmKeyTempPath == null) return;
        try { File.Delete(_wmKeyTempPath); } catch { }
        _wmKeyTempPath = null;
    }

    public static List<string> BuildArguments(ShellOptions options)
    {
        var args = new List<string>();
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

        // 模式：CLI 的 -m 后写覆盖前写，但 -m x25519/x448 只置 asym_mode 标志、不改算法，
        // 所以两条都带上即为「非对称封装 + 指定文件载荷对称算法」。
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

        // 生成密钥对的曲线选择（默认 X25519）
        if (options.Action == CryptoAction.KeyGen && options.UseX448) args.Add("-x448");

        // 输出目录
        if (!string.IsNullOrEmpty(options.OutputDir)) { args.Add("-o"); args.Add(options.OutputDir); }

        // 源文件处理
        if (options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            switch (options.SourceDisposition)
            {
                case SourceDisposition.Delete: args.Add("-de"); break;
                case SourceDisposition.Wipe: args.Add("--wipe-source"); break;
                case SourceDisposition.Recycle: args.Add("--recycle-source"); break;
            }
        }

        if (options.ForceOverwrite) args.Add("-y");

        // 密钥文件（对称模式）
        if (!string.IsNullOrEmpty(options.KeyfilePath) && options.Mode != CryptoMode.Asymmetric)
        {
            args.Add("-k"); args.Add(options.KeyfilePath);
        }

        // 非对称加密：收件人
        if (options.Mode == CryptoMode.Asymmetric &&
            options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt &&
            !string.IsNullOrEmpty(options.RecipientPath))
        {
            args.Add("-r"); args.Add(options.RecipientPath);
        }

        // 非对称解密：身份私钥文件
        if (options.Mode == CryptoMode.Asymmetric &&
            options.Action is CryptoAction.Decrypt or CryptoAction.BatchDecrypt &&
            !string.IsNullOrEmpty(options.IdentityPath))
        {
            args.Add("-k"); args.Add(options.IdentityPath);
        }

        // 批量解密还原文件名
        if (options.Action == CryptoAction.BatchDecrypt && options.RestoreName)
        {
            args.Add("--restore-name");
        }

        // SHA256 校验单
        if (options.WriteSha256 && options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            args.Add("--sha256");
        }

        // 后量子开关：CLI 仅在密钥生成、水印签名/验签处读取；其它动作带上会让旧 CLI 报未知开关
        bool pqcAffects = options.Action == CryptoAction.KeyGen || options.Watermark;
        if (pqcAffects && !options.Pqc) args.Add("--no-pqc");

        // 尾部水印：仅加密动作；带私钥时下发 --wm-sign（私钥可留空 = 写未签名记录，不阻断加密）
        if (options.Watermark &&
            options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            args.Add("--watermark");
            if (!string.IsNullOrEmpty(options.WatermarkKeyPath))
            {
                args.Add("--wm-sign");
                args.Add(ResolveKeySource(options.WatermarkKeyPath));
            }
        }

        // zstd 压缩（非对称 .ptd 同样支持，CLI run_asym 会把级别透传给 encrypt_file）
        if (options.Compress && options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            args.Add("-zstd");
            if (options.CompressionLevel != 0)
            {
                args.Add("--compression-level");
                args.Add(options.CompressionLevel.ToString());
            }
        }

        // 密钥经 stdin 注入（-- 之前）：控制台模式同样经由 stdin，只是窗口可见
        bool needsStdinKey = options.Mode != CryptoMode.Asymmetric &&
                             string.IsNullOrEmpty(options.KeyfilePath) &&
                             options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt
                                 or CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt
                                 or CryptoAction.Derive;
        if (needsStdinKey) args.Add("--key-stdin");

        // 批量模式：-i 输入
        if (options.Action is CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt)
        {
            foreach (var p in options.InputPaths) { args.Add("-i"); args.Add(p); }
        }
        else if (options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt or CryptoAction.PubKey)
        {
            // -- 终止选项解析
            if (options.InputPaths.Count > 0) { args.Add("--"); args.Add(options.InputPaths[0]); }
        }

        return args;
    }

    private static string ModeToken(CryptoMode m) => m switch
    {
        CryptoMode.Aegis256 => "aegis256",
        CryptoMode.Sm4 => "sm4",
        _ => "xchacha20"
    };

    private static string FileModeToken(CryptoMode m) => m switch
    {
        CryptoMode.Aegis256 => "aegis256",
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
            // 密钥取值只显示占位符：临时文件落盘失败时这里是私钥明文
            if (!a.StartsWith("-") && (prev == "--wm-sign" || prev == "--wm-verify"
                                       || IsPrivateKeyMaterial(a)))
                sb.Append("<private-key>");
            // 值参数统一加引号
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
        return sb.ToString();
    }
}
