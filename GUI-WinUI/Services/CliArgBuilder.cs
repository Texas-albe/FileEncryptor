using System.Text;
using System.Linq;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

// GUI 参数到 argv 的映射
public static class CliArgBuilder
{
    // 密码框里存的是私钥明文，而 CLI 的 --wm-sign 只收文件路径
    private static string ResolveKeySource(string key, ShellOptions options)
        => IsPrivateKeyMaterial(key) ? TempFileFor(key, options) : key;

    public static bool IsPrivateKeyMaterial(string? v)
        => !string.IsNullOrEmpty(v) && v.Contains("PRIVATE KEY", StringComparison.Ordinal);

    // 私钥明文只落在这一个任务自己的临时文件里（路径挂在 ShellOptions 上）。
    // 原来用静态字段存路径：单任务串行没事，一旦并发任务，后一个会覆盖前一个的路径，
    // 前一个任务结束时删错文件、私钥残留。ACL 显式收紧到仅当前用户，不继承 %TEMP% 默认 DACL。
    private static string TempFileFor(string key, ShellOptions options)
    {
        var path = Path.Combine(Path.GetTempPath(),
            "fe_wm_" + Guid.NewGuid().ToString("N") + ".pem");
        using (var fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var sw = new StreamWriter(fs, new UTF8Encoding(false)))
        {
            sw.Write(key);
        }
        TightenTempAcl(path);
        options.WatermarkTempKeyPath = path;
        return path;
    }

    // 显式收紧 ACL：断继承 + 清空既有规则 + 只留当前用户完全控制
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

    // 删除本次任务自己的水印私钥临时文件（每任务独立，不会误删并发任务的文件）
    public static void CleanupWatermarkTemp(ShellOptions options)
    {
        var path = options?.WatermarkTempKeyPath;
        if (string.IsNullOrEmpty(path)) return;
        try { File.Delete(path); } catch { }
        options!.WatermarkTempKeyPath = null;
    }

    public static List<string> BuildArguments(ShellOptions options)
    {
        var args = new List<string>();

        // 密钥包装：与加解密流程完全独立，只有 --wrap-key / --unwrap-key 一组参数。
        // 口令 / 私钥不落 argv：统一走 --key-stdin 或 -k <file>，理由同水印私钥。
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

        bool isEnc = options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt;

        // 加密压缩包：目录树 / 多文件打成单个 .ptd。短选项 -p，长选项 --pack。必须排在 -- 之前。
        if (isEnc && options.Pack) args.Add("-p");

        // 分卷：把产出的 .ptd 切成 <base>.001.ptd/002/…；--split 的值是尺寸串（2GB/512MB/4096）
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
            // 目录 + 删除类处置：界面已弹窗确认，告知 CLI 免掉交互询问
            if (options.SourceDeleteOk && options.SourceDisposition != SourceDisposition.Keep)
                args.Add("--source-delete-ok");
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
                args.Add(ResolveKeySource(options.WatermarkKeyPath, options));
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

    // 把 32 字节 DEK 包进 FEKW blob
    private static List<string> BuildWrapArgs(ShellOptions o)
    {
        var args = new List<string> { "--wrap-key", o.WrapInput, "--wrap-alg", WrapAlgToken(o.WrapAlg) };
        if (!string.IsNullOrEmpty(o.WrapOutput)) { args.Add("--wrap-out"); args.Add(o.WrapOutput); }
        if (o.WrapAlg == WrapAlg.Pubkey)
        {
            // 公钥路线：--wrap-to 接字符串或文件都认，这里给界面填的路径
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
        // 解包时算法写在 blob 头里，但界面上的选择用于决定「口令还是私钥」
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

    // 组装 --split 尺寸串；CLI 的 parse_split_size 认 1024 进制 KB/MB/GB/TB
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
        // 包装动作：口令路线走 stdin，公钥路线靠收件人密钥材料
        if (options.Action is CryptoAction.WrapKey or CryptoAction.UnwrapKey)
        {
            if (options.WrapAlg == WrapAlg.Pubkey) sb.Append(L10n.T("  # 使用收件人密钥材料"));
            else if (!string.IsNullOrEmpty(options.KeyfilePath)) sb.Append(L10n.T("  # 口令来自 -k 文件"));
            else sb.Append(L10n.T("  # 口令经 stdin 管道注入"));
        }
        // 预览只拼字符串、不真正跑 CLI，临时私钥用完即删
        CleanupWatermarkTemp(options);
        return sb.ToString();
    }
}
