using System.Collections.Generic;
using System.IO;
using System.Diagnostics;

namespace FileEncryptorGUI.Services;

// 探测 CLI 路径
public static class FileEncryptorLocator
{
    public const string GuiVersion = "3.0.0";
    public static string CliDownloadUrl =>
        $"https://github.com/Texas-albe/FileEncryptor/releases/tag/GUI{GuiVersion}_CLI{ExpectedCliVersion}";

    // 配套 CLI 版本
    public static string ExpectedCliVersion => "3.0.0";

    public static string[] GetExpectedNames()
    {
        var ver = ExpectedCliVersion;
        return new[]
        {
            $"FileEncryptorCLI-{ver}-cmd-Windows.exe",
            // 预发布后缀：CMake project(VERSION) 只支持数值版，产物名无 -alpha.N
            "FileEncryptorCLI-3.0.0-cmd-Windows.exe",
            "FileEncryptorCLI.exe",
            "FileEncryptor.exe",
            "file-encryptor-cli.exe",
            "fe.exe",
        };
    }

    // 加密盘挂载持有进程：与 CLI 分离的可选组件（MSI 的 VaultFeature 才装）
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
        // 探测在哪触发都顺手清掉目录里版本过低的 CLI，
        // 免得调用点各写一遍、漏一处就攒了旧版
        var hit = LocateCore();
        CleanupOutdated(hit);
        return hit;
    }

    private static string? LocateCore()
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

        // 3) 安装目录
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

    // 清掉程序目录里版本号低于目标版本的 CLI。
    //
    // 为什么要清：CLI 文件名带版本号（FileEncryptorCLI-2.7.0-cmd-Windows.exe），
    // 每次升级装新版都不会覆盖旧版，目录里会堆着一串老版本。它们体积不小，
    // 留着也容易被误当成可执行目标。与定位流程放在一起，任何一次探测都顺带清。
    //
    // 只删版本号严格小于目标版本的文件：同版本与更高版本一律不动，
    // 免得用户手动放的定制版或更新的预发布版被误删。
    public static string[] CleanupOutdated(string? keepPath = null)
    {
        var want = ParseVersion(ExpectedCliVersion);
        var keepFull = keepPath != null ? Path.GetFullPath(keepPath) : null;
        var removed = new List<string>();
        if (want == null) return removed.ToArray();

        // 只看程序目录：别的地方（PATH、系统目录）不由我们处置
        var dir = AppContext.BaseDirectory;
        string[] files;
        try { files = Directory.GetFiles(dir); }
        catch { return removed.ToArray(); }

        foreach (var f in files)
        {
            var fileVer = CliVersionOfFile(Path.GetFileName(f));
            if (fileVer == null) continue;
            // 只删严格低于目标版本的：同版本与更高版本一律不动
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
                // 正在运行 / 无权限：留着，不打扰用户
            }
        }
        return removed.ToArray();
    }

    // "FileEncryptorCLI-2.7.0-cmd-Windows.exe" -> (2,7,0)；认不出来返回 null
    private static (int Major, int Minor, int Patch)? CliVersionOfFile(string fileName)
    {
        // 只认自带版本号的文件名，别的 exe 一律不碰
        if (!fileName.StartsWith("FileEncryptorCLI-", StringComparison.OrdinalIgnoreCase))
            return null;
        var rest = fileName.Substring("FileEncryptorCLI-".Length);
        // 版本号段以 '-cmd-' 收尾，取第一个 '-'；没有再退回第一个 '.'。
        // 不能用 IndexOfAny(['-','.'])：它返回最先出现的那个，
        // "2.8.1-cmd-Windows.exe" 会命中下标 1 的 '.'，版本被截成 "2"，
        // 2.0.0 < 2.7.1 于是把新版当旧版删了。
        var end = rest.IndexOf('-');
        if (end < 0) end = rest.IndexOf('.');
        if (end <= 0) return null;
        return ParseVersion(rest.Substring(0, end));
    }

    // a < b 则为 true（可空元组不支持 <，逐段比）
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
