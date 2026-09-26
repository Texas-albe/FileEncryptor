using System.IO;
using System.Diagnostics;

namespace FileEncryptorGUI.Services;

/// <summary>探测 FileEncryptor CLI 路径：环境变量→同目录→ProgramFiles→PATH，优先匹配同版本号 CLI。</summary>
public static class FileEncryptorLocator
{
    public const string GuiVersion = "2.0.0";
    public const string CliDownloadUrl =
        "https://github.com/Texas-albe/FileEncryptor/releases/tag/GUI2.0.0_CLI2.4.2";

    // 期望的 CLI 版本（与 GUI 配套发布的版本）
    public static string ExpectedCliVersion => "2.4.2";

    public static string[] GetExpectedNames()
    {
        var ver = ExpectedCliVersion;
        return new[]
        {
            $"FileEncryptorCLI-{ver}-cmd-Windows.exe",
            "FileEncryptorCLI.exe",
            "FileEncryptor.exe",
            "file-encryptor-cli.exe",
            "fe.exe",
        };
    }

    private static bool IsExecutable(string path)
    {
        try { return File.Exists(path); } catch { return false; }
    }

    private static string? FindInDir(string dir, string[] names)
    {
        if (!Directory.Exists(dir)) return null;
        foreach (var name in names)
        {
            var cand = Path.Combine(dir, name);
            if (IsExecutable(cand)) return cand;
        }
        return null;
    }

    public static string? Locate()
    {
        var names = GetExpectedNames();

        // 1) 环境变量
        var envPath = Environment.GetEnvironmentVariable("FILEENCRYPTOR_EXE");
        if (!string.IsNullOrEmpty(envPath) && IsExecutable(envPath))
            return envPath;

        // 2) 同目录
        var selfDir = AppContext.BaseDirectory;
        var found = FindInDir(selfDir, names);
        if (found != null) return found;

        // 3) 安装目录 %ProgramFiles%\FileEncryptor\
        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "FileEncryptor");
        found = FindInDir(installDir, names);
        if (found != null) return found;

        // 4) PATH
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            foreach (var p in pathEnv.Split(Path.PathSeparator))
            {
                found = FindInDir(p, names);
                if (found != null) return found;
            }
        }

        return null;
    }

    public static bool Exists(out string? foundPath)
    {
        foundPath = Locate();
        return foundPath != null;
    }
}
