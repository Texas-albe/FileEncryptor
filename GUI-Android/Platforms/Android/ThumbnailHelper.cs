// 列表缩略图
// 只在缓存缺失
using Android.Graphics;
using Android.Media;
using IOPath = System.IO.Path;
using FileEncryptorMobile.Services;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile.Platforms.Android;

public static class ThumbnailHelper
{
    // 超过上限
    // 上限放宽
    private const long MaxImageBytes = 192L * 1024 * 1024;
    private const int VideoHeadBytes = 4 * 1024 * 1024;
    private const int VideoTailBytes = 8 * 1024 * 1024;
    private const int TargetPx = 108;          // 列表缩略图短边
    // 画廊全图短边
    // ImageView 以像素 1
    private const int MaxViewPx = 1600;

    // 画廊全图短边
    // 1500px
    // 不带采样 →
    private static int ViewPx()
    {
        try
        {
            var dm = global::Android.App.Application.Context!.Resources!.DisplayMetrics!;
            return Math.Clamp(dm.WidthPixels, 960, MaxViewPx);
        }
        catch { return 1080; }
    }

    private static readonly HashSet<string> ImageExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".avif",
    };

    private static readonly HashSet<string> VideoExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".m4v", ".mkv", ".mov", ".avi", ".3gp", ".webm", ".ts", ".flv", ".wmv",
    };

    private static string Ext(string name) => IOPath.GetExtension(name) ?? "";

    // 输出格式
    // 。这些格式改存
    private static Bitmap.CompressFormat PickFormat(string name)
    {
        string e = Ext(name).ToLowerInvariant();
        return e switch
        {
            ".png" or ".webp" or ".gif" => Bitmap.CompressFormat.Png,
            _ => Bitmap.CompressFormat.Jpeg,
        };
    }

    // 后缀集合
    public static bool IsImage(string name) => VaultItem.IsImageName(name);
    public static bool IsVideo(string name) => VaultItem.IsVideoName(name);
    public static bool IsMedia(string name) => IsImage(name) || IsVideo(name);

    // 缓存路径
    public static string CachePath(VaultItem item)
    {
        string dir = IOPath.Combine(FileSystem.CacheDirectory, "thumbs");
        Directory.CreateDirectory(dir);
        return IOPath.Combine(dir, Key(item) + ".jpg");
    }

    private static string Key(VaultItem item)
    {
        // 毫秒级键
        string raw = $"{item.RelPath}|{item.Size}|{item.Mtime.ToUnixTimeMilliseconds()}";
        return Convert.ToHexString(
            System.Security.Cryptography.MD5.HashData(
                System.Text.Encoding.UTF8.GetBytes(raw)))[..16].ToLowerInvariant();
    }

    // 生成缩略图
    public static string? Build(VaultService vault, VaultItem item)
    {
        try
        {
            string cache = CachePath(item);
            if (File.Exists(cache))
            {
                try
                {
                    if (new FileInfo(cache).Length > 0 && IsDecodable(cache)) return cache;
                }
                catch { }
                try { File.Delete(cache); } catch { }
            }
            if (item.Size == 0) return null;
            // 视频头尾稀疏读
            if (IsVideo(item.Name)) return BuildVideo(vault, item, cache);
            if (item.Size > (ulong)MaxImageBytes) return null;

            string tmpDir = IOPath.Combine(FileSystem.CacheDirectory, "thumbsrc");
            Directory.CreateDirectory(tmpDir);
            string tmp = IOPath.Combine(tmpDir, Guid.NewGuid().ToString("N") + Ext(item.Name));
            int fd = LibcNative.open(tmp,
                LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
            if (fd < 0) return null;
            try { vault.ExportFd(item.RelPath, fd, null); }   // 流式解密直落临
            catch { try { File.Delete(tmp); } catch { } return null; }
            finally { LibcNative.close(fd); }

            try
            {
                using Bitmap? src = IsVideo(item.Name) ? VideoFrame(tmp) : DecodeImage(tmp, TargetPx, cap: false);
                if (src is null) return null;
                using Bitmap thumb = Scale(src, TargetPx);
                string part = cache + ".part";
                using (var os = new FileStream(part, FileMode.Create, FileAccess.Write))
                    thumb.Compress(PickFormat(item.Name), 82, os);
                File.Move(part, cache, overwrite: true);
                return cache;
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
        catch { return null; }
    }

    // 视频头尾稀疏读
    private static string? BuildVideo(VaultService vault, VaultItem item, string cache)
    {
        ulong size = item.Size;
        if (size > 8UL * 1024 * 1024 * 1024) return null;
        string tmpDir = IOPath.Combine(FileSystem.CacheDirectory, "thumbsrc");
        Directory.CreateDirectory(tmpDir);
        string tmp = IOPath.Combine(tmpDir, Guid.NewGuid().ToString("N") + Ext(item.Name));
        try
        {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write))
            {
                int head = (int)Math.Min(size, (ulong)VideoHeadBytes);
                byte[] h = vault.ReadRange(item.RelPath, 0, head);
                fs.Write(h, 0, h.Length);
                if (size > (ulong)head)
                {
                    int tail = (int)Math.Min(size - (ulong)head, (ulong)VideoTailBytes);
                    ulong off = size - (ulong)tail;
                    byte[] t = vault.ReadRange(item.RelPath, off, tail);
                    // 稀疏占位
                    fs.SetLength((long)size);
                    fs.Position = (long)off;
                    fs.Write(t, 0, t.Length);
                }
            }
            using Bitmap? src = VideoFrame(tmp);
            if (src is null) return null;
            using Bitmap thumb = Scale(src, TargetPx);
            string part = cache + ".part";
            using (var os = new FileStream(part, FileMode.Create, FileAccess.Write))
                thumb.Compress(Bitmap.CompressFormat.Jpeg, 82, os);
            File.Move(part, cache, overwrite: true);
            return cache;
        }
        catch { return null; }
        finally { try { File.Delete(tmp); } catch { } }
    }

    // 高清缓存已
    public static bool HasViewCache(VaultItem item)
    {
        try
        {
            string p = IOPath.Combine(FileSystem.CacheDirectory, "view",
                Key(item) + "-v4" + ViewExt(item.Name));
            return File.Exists(p) && IsDecodable(p);
        }
        catch { return false; }
    }

    // 原样落盘
    private static string ViewExt(string name)
    {
        string e = Ext(name).ToLowerInvariant();
        return string.IsNullOrEmpty(e) ? ".jpg" : e;
    }

    // 画廊全图
    // 小图
    // 旧版
    public static string? BuildView(VaultService vault, VaultItem item, out string? status)
    {
        status = null;
        try
        {
            if (!IsImage(item.Name))
            {
                status = L10n.T("后缀不支持");
                Warn(L10n.F("BuildView 跳过：非图片 {0}", NativeImageHost.Tag(item.Name)));
                return null;
            }
            if (item.Size == 0 || item.Size > (ulong)MaxImageBytes)
            {
                status = L10n.F("体积 {0}MB 超限", item.Size / 1024 / 1024);
                Warn(L10n.F("BuildView 跳过：尺寸 {0} 超出上限", item.Size));
                return null;
            }
            string ext = ViewExt(item.Name);
            string dir = IOPath.Combine(FileSystem.CacheDirectory, "view");
            string cache = IOPath.Combine(dir, Key(item) + "-v4" + ext);
            // 同格只上屏一次
            if (File.Exists(cache) && IsDecodable(cache) && HasRealContent(cache))
            {
                status = L10n.T("缓存命中");
                return cache;
            }

            string tmpDir = IOPath.Combine(FileSystem.CacheDirectory, "viewsrc");
            Directory.CreateDirectory(tmpDir);
            string tmp = IOPath.Combine(tmpDir, Guid.NewGuid().ToString("N") + Ext(item.Name));
            int fd = LibcNative.open(tmp,
                LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
            if (fd < 0) return null;
            try { vault.ExportFd(item.RelPath, fd, null); }   // 流式解密直落临
            catch (Exception ex)
            {
                status = L10n.T("解密失败");
                Warn(L10n.F("BuildView 解密失败：{0} → {1}", NativeImageHost.Tag(item.Name), ex.Message));
                try { File.Delete(tmp); } catch { }
                return null;
            }
            finally { LibcNative.close(fd); }

            try
            {
                var b = new BitmapFactory.Options { InJustDecodeBounds = true };
                BitmapFactory.DecodeFile(tmp, b);
                if (b.OutWidth <= 0 || b.OutHeight <= 0)
                {
                    status = L10n.T("解码失败");
                    Warn(L10n.F("BuildView 头坏：{0}", NativeImageHost.Tag(item.Name)));
                    return null;
                }
                Directory.CreateDirectory(dir);
                // 列表缩略图照旧
                using (var tb = DecodeSmooth(tmp, 360))
                    if (tb is not null) SaveThumb(tb, item);
                // Move 而非 Copy
                File.Move(tmp, cache, overwrite: true);
                if (!IsDecodable(cache) || !HasRealContent(cache))
                {
                    try { File.Delete(cache); } catch { }
                    status = L10n.T("落盘内容异常");
                    return null;
                }
                status = L10n.F("{0}×{1} 原样", b.OutWidth, b.OutHeight);
                Warn(L10n.F("BuildView 原样：{0} → {1}", NativeImageHost.Tag(item.Name), status));
                return cache;
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
        catch (Exception ex)
        {
            status = L10n.T("异常");
            Warn(L10n.F("BuildView 异常：{0} → {1}", NativeImageHost.Tag(item.Name), ex.Message));
            return null;
        }
    }

    // 写缓存
    private static void WriteBitmap(Bitmap src, string path, bool png, int quality)
    {
        string part = path + ".part";
        using (var os = new FileStream(part, FileMode.Create, FileAccess.Write))
            src.Compress(png ? Bitmap.CompressFormat.Png : Bitmap.CompressFormat.Jpeg, quality, os);
        File.Move(part, path, overwrite: true);
    }

    // 高清目标长边
    private static int ViewLongPx()
    {
        try
        {
            var dm = global::Android.App.Application.Context!.Resources!.DisplayMetrics!;
            return Math.Clamp(Math.Max(dm.WidthPixels, dm.HeightPixels), 1600, 2200);
        }
        catch { return 2000; }
    }

    // 两级解码
    // 纯 2
    private static Bitmap? DecodeSmooth(string path, int maxLongest)
    {
        var bounds = new BitmapFactory.Options { InJustDecodeBounds = true };
        BitmapFactory.DecodeFile(path, bounds);
        int w = bounds.OutWidth, h = bounds.OutHeight;
        if (w <= 0 || h <= 0) return null;
        int s = 1;
        while (s < 64 && (Math.Max(w, h) / s > maxLongest * 2 ||
                         (long)(w / s) * (h / s) > MaxDecodePixels)) s *= 2;
        var raw = BitmapFactory.DecodeFile(path, new BitmapFactory.Options { InSampleSize = s });
        if (raw is null) return null;
        int rw = raw.Width, rh = raw.Height;
        double k = Math.Min(1.0, (double)maxLongest / Math.Max(rw, rh));
        k = Math.Min(k, Math.Sqrt((double)MaxDecodePixels / ((long)rw * rh)));
        int tw = Math.Max(1, (int)Math.Round(rw * k));
        int th = Math.Max(1, (int)Math.Round(rh * k));
        if (tw == rw && th == rh) return raw;
        var dst = Bitmap.CreateScaledBitmap(raw, tw, th, true);
        if (dst is null || dst.Handle == raw.Handle) return raw;
        raw.Recycle();
        return dst;
    }

    // 落盘文件可解码
    private static bool IsDecodable(string path)
    {
        try
        {
            var b = new BitmapFactory.Options { InJustDecodeBounds = true };
            BitmapFactory.DecodeFile(path, b);
            return b.OutWidth > 0 && b.OutHeight > 0;
        }
        catch { return false; }
    }

    // 轻量内容校验
    // 而文件头
    private static bool HasRealContent(string path)
    {
        try
        {
            // InSampleSize=32
            var o = new BitmapFactory.Options { InSampleSize = 32 };
            using var bmp = BitmapFactory.DecodeFile(path, o);
            if (bmp is null) return false;
            int w = bmp.Width, h = bmp.Height;
            if (w <= 0 || h <= 0) return false;
            int[] px = new int[w * h];
            bmp.GetPixels(px, 0, w, 0, 0, w, h);
            // 任意非近黑像素
            foreach (int c in px)
            {
                int r = (c >> 16) & 0xFF, g = (c >> 8) & 0xFF, b = c & 0xFF;
                if (r > 8 || g > 8 || b > 8) return true;
            }
            return false;
        }
        catch { return false; }
    }

    // 画廊顺手存缩略
    // 列表页
    private static void SaveThumb(Bitmap src, VaultItem item)
    {
        try
        {
            string cache = CachePath(item);
            if (File.Exists(cache)) return;
            using Bitmap thumb = Scale(src, TargetPx);
            string part = cache + ".part";
            using (var os = new FileStream(part, FileMode.Create, FileAccess.Write))
                thumb.Compress(PickFormat(item.Name), 82, os);
            File.Move(part, cache, overwrite: true);
        }
        catch { }
    }

    // 失败原因写 logcat
    private static void Warn(string msg)
    {
        try { global::Android.Util.Log.Warn(MainApplication.TagCore, msg); } catch { }
    }

    // 大图先
    private static Bitmap? DecodeImage(string path) => DecodeImage(path, TargetPx, cap: false);

    // cap=true  → 保证解码后短边 ≤
    // 控件
    // cap=false → 保证解码后短边 ∈
    private static Bitmap? DecodeImage(string path, int targetPx, bool cap)
    {
        var bounds = new BitmapFactory.Options { InJustDecodeBounds = true };
        BitmapFactory.DecodeFile(path, bounds);
        if (bounds.OutWidth <= 0 || bounds.OutHeight <= 0) return null;

        var opt = new BitmapFactory.Options { InSampleSize = SampleSize(bounds.OutWidth, bounds.OutHeight, targetPx, cap) };
        return BitmapFactory.DecodeFile(path, opt);
    }

    // 解码位图预算
    // 中低端机直接 OOM
    private const long MaxDecodePixels = 12L * 1024 * 1024;   // 约 32MB

    private static int SampleSize(int w, int h, int target, bool cap)
    {
        int min = Math.Min(w, h);
        int s = 1;
        if (cap)
        {
            // 保证解码后短边 ≤ target
            // 4000×3000
            while (s < 64 && min / s > target) s *= 2;
        }
        else
        {
            while (s < 64 && min / (s * 2) >= target) s *= 2;
        }
        // 内存预算兜底
        while (s < 64 && (long)(w / s) * (h / s) > MaxDecodePixels) s *= 2;
        return s;
    }

    private static Bitmap? VideoFrame(string path)
    {
        var retr = new MediaMetadataRetriever();
        try
        {
            retr.SetDataSource(path);
            // 取首帧
            return retr.GetFrameAtTime(0)
                ?? retr.GetFrameAtTime(1_000_000)
                ?? retr.GetFrameAtTime(5_000_000);
        }
        catch { return null; }
        finally { try { retr.Release(); } catch { } }
    }

    // 等比缩放到短边 target
    // allowUpscale=false 时只缩不放
    private static Bitmap Scale(Bitmap src, int target, bool allowUpscale = true)
    {
        int w = src.Width, h = src.Height;
        if (w <= 0 || h <= 0) return src;
        int minSide = Math.Min(w, h);
        if (!allowUpscale && minSide <= target) return src;
        double s = (double)target / minSide;
        int nw = Math.Max(1, (int)Math.Round(w * s));
        int nh = Math.Max(1, (int)Math.Round(h * s));
        Bitmap? dst = Bitmap.CreateScaledBitmap(src, nw, nh, true);
        if (dst is null) return Bitmap.CreateBitmap(src);
        // 同尺寸
        // 交给调用方双重
        if (dst.Handle == src.Handle) return Bitmap.CreateBitmap(src);
        return dst;
    }
}
