using System.Collections.Generic;
using System.IO;
using System.Diagnostics;

namespace FileEncryptorGUI.Services;

// 探测 CLI 路径
public static class FileEncryptorLocator
{
    public const string GuiVersion = "3.1.1";
    public static string CliDownloadUrl =>
        $"https://github.com/Texas-albe/FileEncryptor/releases/tag/GUI{GuiVersion}_CLI{ExpectedCliVersion}";

    // 配套 CLI 版本
    public static string ExpectedCliVersion => "3.1.1";

    public static string[] GetExpectedNames()
    {
        var ver = ExpectedCliVersion;
        return new[]
        {
            $"FileEncryptorCLI-{ver}-cmd-Windows.exe",
            // 预发布后缀
            "FileEncryptorCLI-3.1.1-cmd-Windows.exe",
            "FileEncryptorCLI.exe",
            "FileEncryptor.exe",
            "file-encryptor-cli.exe",
            "fe.exe",
        };
    }

    // 加密盘挂载持有
    public static string[] GetMounterExpectedNames()
    {
        if (OperatingSystem.IsWindows())
            return new[] { "FE-Mounter.exe", "fe-mounter.exe" };
        return new[] { "FE-Mounter", "fe-mounter" };
    }

    public static string? LocateMounter()
    {
        var envPath = Environment.GetEnvironmentVariable("FE_MOUNTER_EXE");
        if (!string.IsNullOrEmpty(envPath) && IsExecutable(envPath)) return envPath;

        var names = GetMounterExpectedNames();
        var selfDir = AppContext.BaseDirectory;
        var found = FindInDir(selfDir, names);
        if (found != null) return found;

        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FileEncryptor");
        found = FindInDir(installDir, names);
        if (found != null) return found;

        // PATH 回退已去除
        return null;
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
        // 探测
        // 免得调用点各写
        var hit = LocateCore();
        CleanupOutdated(hit);
        return hit;
    }

    private static string? LocateCore()
    {
        var names = GetExpectedNames();

        // 环境变量
        var envPath = Environment.GetEnvironmentVariable("FILEENCRYPTOR_EXE");
        if (!string.IsNullOrEmpty(envPath) && IsExecutable(envPath))
            return envPath;

        // 同目录
        var selfDir = AppContext.BaseDirectory;
        var found = FindInDir(selfDir, names);
        if (found != null) return found;

        // 安装目录
        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "FileEncryptor");
        found = FindInDir(installDir, names);
        if (found != null) return found;

        // PATH 回退已去除
        return null;
    }

    public static bool Exists(out string? foundPath)
    {
        foundPath = Locate();
        return foundPath != null;
    }

    // 清掉程序目录里
    // 为什么要清
    // 升级装新版
    // 只删版本号严格
    // 免得用户手动放
    public static string[] CleanupOutdated(string? keepPath = null)
    {
        var want = ParseVersion(ExpectedCliVersion);
        var keepFull = keepPath != null ? Path.GetFullPath(keepPath) : null;
        var removed = new List<string>();
        if (want == null) return removed.ToArray();

        // 只看程序目录
        var dir = AppContext.BaseDirectory;
        string[] files;
        try { files = Directory.GetFiles(dir); }
        catch { return removed.ToArray(); }

        foreach (var f in files)
        {
            var fileVer = CliVersionOfFile(Path.GetFileName(f));
            if (fileVer == null) continue;
            // 只删严格低于目
            if (!VersionLess(fileVer.Value, want.Value)) continue;
            if (keepFull != null
                && string.Equals(Path.GetFullPath(f), keepFull, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                File.Delete(f);
                removed.Add(Path.GetFileName(f));
            }
            catch
            {
                // 正在运行 / 无权限
            }
        }
        return removed.ToArray();
    }

    // "FileEncryptorCLI
    private static (int Major, int Minor, int Patch)? CliVersionOfFile(string fileName)
    {
        // 只认自带版本号
        if (!fileName.StartsWith("FileEncryptorCLI-", StringComparison.OrdinalIgnoreCase))
            return null;
        var rest = fileName.Substring("FileEncryptorCLI-".Length);
        // 版本号段
        // 不能用 IndexOfAny
        // "2.8.1-cmd-Windows.exe"
        // 0.0 < 2.7.1 于
        var end = rest.IndexOf('-');
        if (end < 0) end = rest.IndexOf('.');
        if (end <= 0) return null;
        return ParseVersion(rest.Substring(0, end));
    }

    // a < b
    private static bool VersionLess(
        (int Major, int Minor, int Patch) a,
        (int Major, int Minor, int Patch) b)
    {
        if (a.Major != b.Major) return a.Major < b.Major;
        if (a.Minor != b.Minor) return a.Minor < b.Minor;
        return a.Patch < b.Patch;
    }

    private static (int Major, int Minor, int Patch)? ParseVersion(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var parts = s.Trim().Split('.');
        if (parts.Length == 0 || parts.Length > 3) return null;
        int major = 0, minor = 0, patch = 0;
        if (!int.TryParse(parts[0], out major)) return null;
        if (parts.Length > 1 && !int.TryParse(parts[1], out minor)) return null;
        if (parts.Length > 2 && !int.TryParse(parts[2], out patch)) return null;
        return (major, minor, patch);
    }
}
