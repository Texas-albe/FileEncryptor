// 敏感缓存清理
// cache 下四类明文痕迹
// cim_* SAF 只给临时读权限
// thumbs/ 库内图片/视频解
// thumbsrc/ 缩略图生成过程
// view/ 画廊全图解密
// viewsrc/ 全图生成过程
// preview/ 点开预览时整文
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile.Services;

public static class CacheJanitor
{
    private static readonly string[] DerivedDirs =
        { "preview", "thumbs", "thumbsrc", "view", "viewsrc" };

    // 全清
    public static void PurgeSensitive()
    {
        try
        {
            string cache = FileSystem.CacheDirectory;
            foreach (string d in DerivedDirs) TryDeleteDir(Path.Combine(cache, d));
            foreach (string f in Directory.EnumerateFiles(cache, "cim_*"))
                TryDeleteFile(f);
            foreach (string f in Directory.EnumerateFiles(cache, "fem_*"))
                TryDeleteFile(f);
        }
        catch { /* 缓存目录枚举失败不致命 */ }
    }

    // 锁库时用
    // 切后台可能正压
    public static void PurgeOnLock()
    {
        try
        {
            string cache = FileSystem.CacheDirectory;
            foreach (string d in DerivedDirs) TryDeleteDir(Path.Combine(cache, d));
        }
        catch { }
    }

    // 单个 SAF 副本用完即
    public static void DeleteCim(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        TryDeleteFile(path);
    }

    // 用户二次确认
    public static int PurgeExports()
    {
        int n = 0;
        string def = "";
        try { def = FileEncryptorMobile.Platforms.Android.VaultStorageHelper.ExportDir(); } catch { }
        // 默认导出目录
        if (def.Length > 0 && Directory.Exists(def))
        {
            try
            {
                foreach (string f in Directory.EnumerateFiles(def, "*", SearchOption.AllDirectories))
                { try { File.Delete(f); n++; } catch { } }
            }
            catch { }
        }
        // 自定义目录可能
        string custom = "";
        try { custom = Preferences.Default.Get("crypto_out_dir", ""); } catch { }
        if (!string.IsNullOrEmpty(custom) && !SameDir(custom, def))
            foreach (string p in OutputRegistry.InDir(custom)) n += DeleteTracked(p);
        OutputRegistry.Clear();
        return n;
    }

    // 文件直接删
    private static int DeleteTracked(string path)
    {
        int n = 0;
        try
        {
            if (File.Exists(path)) { File.Delete(path); return 1; }
            if (!Directory.Exists(path)) return 0;
            foreach (string f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            { try { File.Delete(f); n++; } catch { } }
            try { Directory.Delete(path, true); } catch { }
        }
        catch { }
        return n;
    }

    private static bool SameDir(string a, string b)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private static void TryDeleteDir(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
    }

    private static void TryDeleteFile(string f)
    {
        try { if (File.Exists(f)) File.Delete(f); } catch { }
    }
}
