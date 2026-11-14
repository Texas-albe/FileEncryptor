// GitHub 更新检查
// 预发布判定
using System.Globalization;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

// 检查结果
public sealed class UpdateInfo
{
    public bool HasUpdate;
    public string Current = "";
    public string Latest = "";
    public bool IsPreRelease;
    public string ApkName = "";
    public string ApkUrl = "";
    public long ApkSize;
    public string ReleaseUrl = "";
    public string Notes = "";
}

public static class UpdateService
{
    private const string RepoApi =
        "https://api.github.com/repos/Texas-albe/FileEncryptor/releases?per_page=10";

    // APK 名前缀
    private const string ApkPrefix = "com.yaoyingluo.fileencryptor";

    // 标题取版本
    private static readonly Regex MobileVerRe = new(
        @"GUI[\s-]*\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.]+)?\s*_\s*(\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.]+)?)",
        RegexOptions.IgnoreCase);

    // 预发布序
    private static readonly Regex PreRe = new(
        @"-(alpha|beta|rc)\.?(\d*)", RegexOptions.IgnoreCase);

    private static readonly HttpClient Http = new();

    static UpdateService()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("FileEncryptorAndroid");
        Http.Timeout = TimeSpan.FromSeconds(20);
    }

    // 当前版本
    public static async Task<UpdateInfo> CheckAsync(string current)
    {
        var info = new UpdateInfo { Current = current, Latest = current };
        string json;
        try
        {
            json = await Http.GetStringAsync(RepoApi);
        }
        catch (Exception ex)
        {
            info.HasUpdate = false;
            info.Notes = "";
            info.ReleaseUrl = "";
            info.ApkUrl = "";
            info.ApkName = "";
            info.ApkSize = 0;
            info.IsPreRelease = false;
            info.Latest = current;
            throw new InvalidOperationException(Describe(ex), ex);
        }

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() == 0)
            throw new InvalidOperationException(L10n.T("还没有已发布的版本"));

        var rel = root[0];
        string tag = rel.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
        string title = rel.TryGetProperty("name", out var nm) ? nm.GetString() ?? "" : "";
        // 取安卓版本
        // 拒桌面端号
        string label = title.Length > 0 ? title : tag;
        info.Latest = ParseMobileVer(title);
        if (info.Latest.Length == 0) info.Latest = ParseMobileVer(tag);
        if (info.Latest.Length == 0)
            throw new InvalidOperationException(L10n.F("无法从发布信息「{0}」解析版本号", label));

        bool ghPre = rel.TryGetProperty("prerelease", out var p) && p.GetBoolean();
        string htmlUrl = rel.TryGetProperty("html_url", out var h) ? h.GetString() ?? "" : "";
        info.ReleaseUrl = htmlUrl;

        // 资产匹配
        if (rel.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in assets.EnumerateArray())
            {
                string name = a.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                if (name.Length == 0) continue;
                string ln = name.ToLowerInvariant();
                if (!ln.StartsWith(ApkPrefix, StringComparison.Ordinal)) continue;
                if (!ln.EndsWith(".apk", StringComparison.Ordinal)) continue;
                info.ApkName = name;
                info.ApkUrl = a.TryGetProperty("browser_download_url", out var u)
                    ? u.GetString() ?? "" : "";
                info.ApkSize = a.TryGetProperty("size", out var s) ? s.GetInt64() : 0;
                break;
            }
        }

        info.Notes = rel.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        if (info.Notes.Length > 120) info.Notes = info.Notes[..120];
        int nl = info.Notes.IndexOf('\n');
        if (nl >= 0) info.Notes = info.Notes[..nl];

        info.IsPreRelease = ghPre || HasPreSuffix(info.ApkName) || HasPreSuffix(info.Latest);
        info.HasUpdate = Compare(info.Latest, current) > 0;
        return info;
    }

    // 下载安装包
    public static async Task<string> DownloadApkAsync(UpdateInfo info, IProgress<double>? progress)
    {
        if (info.ApkUrl.Length == 0)
            throw new InvalidOperationException(L10n.T("此版本未提供 Android 安装包"));
        string dir = Path.Combine(FileSystem.CacheDirectory, "updates");
        Directory.CreateDirectory(dir);
        string dest = Path.Combine(dir, SanitizeName(info.ApkName));

        using var resp = await Http.GetAsync(info.ApkUrl, HttpCompletionOption.ResponseHeadersRead);
        resp.EnsureSuccessStatusCode();
        long total = resp.Content.Headers.ContentLength ?? info.ApkSize;
        await using var src = await resp.Content.ReadAsStreamAsync();
        var buf = new byte[131072];
        long got = 0;
        int n;
        await using (var dst = File.Create(dest))
        {
            while ((n = await src.ReadAsync(buf)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n));
                got += n;
                if (total > 0) progress?.Report(Math.Min(1.0, (double)got / total));
            }
            await dst.FlushAsync();
        }
        if (got == 0 || (total > 0 && got != total))
        {
            try { File.Delete(dest); } catch { }
            throw new InvalidOperationException(L10n.T("安装包下载不完整，已取消安装"));
        }
        progress?.Report(1.0);
        return dest;
    }

    private static string Describe(Exception ex) => ex switch
    {
        HttpRequestException => L10n.T("网络请求失败，请检查网络连接"),
        TaskCanceledException => L10n.T("连接超时，请稍后再试"),
        JsonException => L10n.T("返回数据解析失败"),
        _ => ex.Message,
    };

    // 比较版本
    private static int Compare(string a, string b)
    {
        var (ca, pa) = SplitVer(a);
        var (cb, pb) = SplitVer(b);
        var na = Core3(ca);
        var nb = Core3(cb);
        for (int i = 0; i < 3; i++)
            if (na[i] != nb[i]) return na[i].CompareTo(nb[i]);
        // 数字相同
        int ra = PreRank(pa);
        int rb = PreRank(pb);
        if (ra != rb) return ra.CompareTo(rb);
        return PreNum(pa).CompareTo(PreNum(pb));
    }

    private static (string core, string pre) SplitVer(string v)
    {
        v = v.Trim();
        int dash = v.IndexOf('-');
        if (dash < 0) return (v, "");
        return (v[..dash], v[dash..]);
    }

    private static int[] Core3(string core)
    {
        var parts = core.Split('.');
        int[] r = { 0, 0, 0 };
        for (int i = 0; i < r.Length && i < parts.Length; i++)
            int.TryParse(parts[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out r[i]);
        return r;
    }

    private static int PreRank(string pre)
    {
        if (pre.Length == 0) return 4; // 稳定版
        var m = PreRe.Match(pre);
        if (!m.Success) return 0;
        return m.Groups[1].Value.ToLowerInvariant() switch
        {
            "alpha" => 1,
            "beta" => 2,
            _ => 3,
        };
    }

    private static int PreNum(string pre)
    {
        var m = PreRe.Match(pre);
        if (!m.Success) return 0;
        return int.TryParse(m.Groups[2].Value, out int n) ? n : 0;
    }

    // 预发布判定
    private static bool HasPreSuffix(string s) => PreRe.IsMatch(s);

    // 取安卓版本
    private static string ParseMobileVer(string text)
    {
        var m = MobileVerRe.Match(text);
        return m.Success ? m.Groups[1].Value : "";
    }

    private static string SanitizeName(string name)
    {
        string leaf = name[(name.LastIndexOf('/') + 1)..];
        foreach (char c in Path.GetInvalidFileNameChars())
            leaf = leaf.Replace(c, '_');
        return leaf.Length == 0 ? "update.apk" : leaf;
    }
}
