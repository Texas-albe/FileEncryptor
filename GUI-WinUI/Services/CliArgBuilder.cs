using System.Text;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

/// <summary>GUI 参数 → FileEncryptor argv（1:1 映射 Qt 版）；密钥经 stdin 注入，不进命令行/环境变量。</summary>
public static class CliArgBuilder
{
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

        // 模式
        if (options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt)
        {
            if (options.Mode == CryptoMode.Aegis256) { args.Add("-m"); args.Add("aegis256"); }
            else if (options.Mode == CryptoMode.Asymmetric) { args.Add("-m"); args.Add("rage"); }
        }

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

        // zstd 压缩
        if (options.Compress && options.Action is CryptoAction.Encrypt or CryptoAction.BatchEncrypt &&
            options.Mode != CryptoMode.Asymmetric)
        {
            args.Add("-zstd");
            if (options.CompressionLevel != 0)
            {
                args.Add("--compression-level");
                args.Add(options.CompressionLevel.ToString());
            }
        }

        // 批量模式：-i 输入
        if (options.Action is CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt)
        {
            foreach (var p in options.InputPaths) { args.Add("-i"); args.Add(p); }
        }
        else if (options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt or CryptoAction.PubKey)
        {
            if (options.InputPaths.Count > 0) args.Add(options.InputPaths[0]);
        }

        // 密钥经 stdin 注入（对称模式且无密钥文件时）
        bool needsStdinKey = options.Mode != CryptoMode.Asymmetric &&
                             string.IsNullOrEmpty(options.KeyfilePath) &&
                             options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt
                                 or CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt
                                 or CryptoAction.Derive;
        if (needsStdinKey) args.Add("--key-stdin");

        return args;
    }

    public static string BuildPreview(string programPath, ShellOptions options)
    {
        var sb = new StringBuilder();
        // 程序路径包裹双引号
        sb.Append('"').Append(programPath).Append('"');
        foreach (var a in BuildArguments(options))
        {
            sb.Append(' ');
            // 开关（以 - 开头）不加引号，值参数（含路径）全部包裹双引号
            if (a.StartsWith("-"))
                sb.Append(a);
            else
                sb.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
        }
        if (options.Mode != CryptoMode.Asymmetric && string.IsNullOrEmpty(options.KeyfilePath) &&
            options.Action is CryptoAction.Encrypt or CryptoAction.Decrypt
                or CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt or CryptoAction.Derive)
        {
            sb.Append("  # 密钥经 stdin 管道注入");
        }
        return sb.ToString();
    }
}
