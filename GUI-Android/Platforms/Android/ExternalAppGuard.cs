// 外部应用回收
// 第三方查看器
using Android.App;
using Android.Content;
using Microsoft.Maui.ApplicationModel;

namespace FileEncryptorMobile.Platforms.Android;

public static class ExternalAppGuard
{
    // 回前台后重试
    // 只杀后台进程
    private static readonly int[] RetryDelaysMs = { 0, 400, 1200, 2500, 4000 };

    private static readonly object _lk = new();
    private static readonly HashSet<string> _pkgs = new(StringComparer.Ordinal);
    private static readonly HashSet<string> _previews = new(StringComparer.Ordinal);
    private static readonly List<global::Android.Net.Uri> _uris = new();

    // 记录
    public static void TrackPackage(string? pkg)
    {
        if (string.IsNullOrEmpty(pkg)) return;
        lock (_lk) _pkgs.Add(pkg);
    }

    // 记录本次预览解
    public static void TrackPreview(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return;
        lock (_lk) _previews.Add(dir);
    }

    // 记录已授权
    public static void TrackUri(global::Android.Net.Uri? uri)
    {
        if (uri is null) return;
        lock (_lk) _uris.Add(uri);
    }

    // 回到前台
    public static void OnReturnedToApp()
    {
        List<string> pkgs, dirs;
        List<global::Android.Net.Uri> uris;
        lock (_lk)
        {
            if (_pkgs.Count == 0 && _previews.Count == 0 && _uris.Count == 0) return;
            pkgs = _pkgs.ToList(); _pkgs.Clear();
            dirs = _previews.ToList(); _previews.Clear();
            uris = _uris.ToList(); _uris.Clear();
        }
        // 删文件
        _ = Task.Run(async () =>
        {
            var ctx = Platform.AppContext;
            string self = ctx.PackageName ?? "";
            var am = (ActivityManager?)ctx.GetSystemService(Context.ActivityService);
            foreach (int delay in RetryDelaysMs)
            {
                if (delay > 0) await Task.Delay(delay).ConfigureAwait(false);
                foreach (string d in dirs) DeletePreview(d);
                RevokeAll(ctx, uris);
                if (am is null) continue;
                foreach (string p in pkgs)
                {
                    if (p.Length == 0 || p == self) continue;
                    try { am.KillBackgroundProcesses(p); } catch { /* 系统应用/无权限时忽略 */ }
                }
            }
        });
    }

    // 撤回读授权
    private static void RevokeAll(Context ctx, List<global::Android.Net.Uri> uris)
    {
        foreach (global::Android.Net.Uri u in uris)
        {
            try { ctx.RevokeUriPermission(u, ActivityFlags.GrantReadUriPermission); } catch { }
        }
    }

    // 明文预览
    private static void DeletePreview(string? dir)
    {
        if (string.IsNullOrEmpty(dir)) return;
        try
        {
            if (Directory.Exists(dir))
            {
                foreach (string f in Directory.EnumerateFiles(dir))
                {
                    try { File.Delete(f); } catch { }
                }
                try { Directory.Delete(dir, true); } catch { }
            }
        }
        catch { /* 清理失败不致命 */ }
    }
}
