// zip 导入
// 受 vdisk 写入接口限制
using System.IO.Compression;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

public sealed class ZipImportResult
{
    public int Ok, Failed, Skipped, Total;
    public readonly List<string> Errors = new();
    public bool Cancelled;
}

public static class ZipImportService
{
    private const long MaxEntryBytes = 128L * 1024 * 1024;
    private const long MaxTotalBytes = 2L * 1024 * 1024 * 1024;
    private const int MaxEntries = 5000;
    private const long MaxRatio = 200;

    // fd
    public static ZipImportResult Import(VaultService vault, int fd, string destDir,
        BatchTracker tracker, CancellationToken ct)
    {
        var res = new ZipImportResult();
        var pfd = Android.OS.ParcelFileDescriptor.AdoptFd(fd);
        try
        {
            // Java 流不是 .NET Stream：先整包读
            // 容器本体上限 256MB
            const long MaxZipBytes = 256L * 1024 * 1024;
            var zipBytes = new MemoryStream();
            var fis = new Java.IO.FileInputStream(pfd.FileDescriptor);
            try
            {
                var buf = new byte[64 * 1024];
                int n;
                while ((n = fis.Read(buf)) > 0)
                {
                    if (zipBytes.Length + n > MaxZipBytes)
                        throw new InvalidDataException(L10n.T("压缩包超过 256MB，无法导入"));
                    zipBytes.Write(buf, 0, n);
                }
            }
            finally { try { fis.Close(); } catch { } }
            zipBytes.Position = 0;
            using var zip = new ZipArchive(zipBytes, ZipArchiveMode.Read, leaveOpen: false);
            var entries = zip.Entries;
            if (entries.Count == 0) throw new InvalidDataException(L10n.T("压缩包为空"));
            if (entries.Count > MaxEntries)
                throw new InvalidDataException(L10n.F("条目数 {0} 超过上限 {1}", entries.Count, MaxEntries));

            long total = 0;
            foreach (var e in entries)
            {
                if (e.Length > MaxEntryBytes)
                    throw new InvalidDataException(L10n.F("单条 {0} 解压后超过 128MB，已拒绝", e.FullName));
                total += e.Length;
                if (total > MaxTotalBytes)
                    throw new InvalidDataException(L10n.T("解压总量超过 2GB 上限，已拒绝"));
            }

            res.Total = entries.Count;
            tracker.Begin(entries.Count, total);
            var made = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int idx = 0;
            foreach (var e in entries)
            {
                if (ct.IsCancellationRequested) { res.Cancelled = true; break; }
                idx++;
                string name = e.FullName.Replace('\\', '/');
                if (!IsValidEntry(name))
                {
                    res.Failed++;
                    tracker.StartSlot(idx, idx, name, 0);
                    tracker.EndSlot(idx, false);
                    if (res.Errors.Count < 8) res.Errors.Add(L10n.F("{0}：非法路径", name));
                    continue;
                }
                bool isDir = name.EndsWith('/');
                string relName = name.TrimEnd('/');
                string rel = destDir.Length == 0 ? relName : $"{destDir}/{relName}";
                if (isDir)
                {
                    try { EnsureDirs(vault, rel, made); res.Ok++; }
                    catch (Exception ex)
                    {
                        res.Failed++;
                        if (res.Errors.Count < 8) res.Errors.Add($"{rel}：{ex.Message}");
                    }
                    tracker.StartSlot(idx, idx, rel, 0);
                    tracker.EndSlot(idx, true);
                    continue;
                }
                if (e.CompressedLength > 0 && e.Length / e.CompressedLength > MaxRatio)
                {
                    res.Failed++;
                    tracker.StartSlot(idx, idx, rel, 0);
                    tracker.EndSlot(idx, false);
                    if (res.Errors.Count < 8) res.Errors.Add(L10n.F("{0}：压缩比超过 {1}:1，已拒绝", rel, MaxRatio));
                    continue;
                }
                tracker.StartSlot(idx, idx, rel, (ulong)e.Length);
                try
                {
                    string parent = ParentOf(rel);
                    if (parent.Length > 0) EnsureDirs(vault, parent, made);

                    byte[] data;
                    using (var es = e.Open())
                    using (var ms = new MemoryStream(e.Length > 0 ? (int)e.Length : 16))
                    {
                        var buf = new byte[64 * 1024];
                        int n;
                        while ((n = es.Read(buf, 0, buf.Length)) > 0)
                        {
                            if (ct.IsCancellationRequested) break;
                            if (ms.Length + n > MaxEntryBytes)
                                throw new InvalidDataException(L10n.T("解压后超过 128MB，已中止该条"));
                            ms.Write(buf, 0, n);
                            tracker.ReportSlot(idx, (ulong)ms.Length, (ulong)e.Length);
                        }
                        if (ct.IsCancellationRequested) { res.Cancelled = true; break; }
                        data = ms.ToArray();
                    }
                    string target = UniquePath(vault, rel, false);
                    vault.CreateFile(target);
                    vault.WriteFile(target, data);
                    res.Ok++;
                    tracker.EndSlot(idx, true);
                }
                catch (Exception ex)
                {
                    res.Failed++;
                    tracker.EndSlot(idx, false);
                    if (res.Errors.Count < 8) res.Errors.Add($"{rel}：{ex.Message}");
                }
            }
            return res;
        }
        finally
        {
            try { pfd.Close(); } catch { }
        }
    }

    // 拒绝绝对路径、..、保
    private static bool IsValidEntry(string name)
    {
        if (name.Length == 0 || name.Length > 1024) return false;
        if (name.StartsWith('/') || name.Contains('\0')) return false;
        if (name.Contains(':')) return false;   // Windows 盘符/ADS
        string check = name.TrimEnd('/');
        if (check.Length == 0) return false;
        if (VaultService.IsReservedPath(check)) return false;
        foreach (string seg in check.Split('/'))
        {
            if (seg.Length == 0 || seg == "." || seg == ".." || seg.Length > 255) return false;
        }
        return true;
    }

    private static void EnsureDirs(VaultService v, string rel, HashSet<string> made)
    {
        if (rel.Length == 0) return;
        string cur = "";
        foreach (string seg in rel.Split('/'))
        {
            cur = cur.Length == 0 ? seg : $"{cur}/{seg}";
            if (!made.Add(cur)) continue;
            try { v.CreateDir(cur); }
            catch (VaultException ex) when (ex.Status == VDiskStatus.Exist) { }
        }
    }

    private static string ParentOf(string rel)
    {
        int slash = rel.LastIndexOf('/');
        return slash < 0 ? "" : rel[..slash];
    }

    private static string UniquePath(VaultService v, string rel, bool isDir)
    {
        if (!v.TryGetAttr(rel, out _, out _)) return rel;
        int slash = rel.LastIndexOf('/');
        string dir = slash < 0 ? "" : rel[..slash];
        string name = slash < 0 ? rel : rel[(slash + 1)..];
        string stem = name, ext = "";
        if (!isDir)
        {
            int dot = name.LastIndexOf('.');
            if (dot > 0) { stem = name[..dot]; ext = name[dot..]; }
        }
        for (int i = 1; i < 1000; i++)
        {
            string candName = $"{stem} ({i}){ext}";
            string cand = dir.Length == 0 ? candName : $"{dir}/{candName}";
            if (!v.TryGetAttr(cand, out _, out _)) return cand;
        }
        return rel + "-" + Guid.NewGuid().ToString("N");
    }
}
