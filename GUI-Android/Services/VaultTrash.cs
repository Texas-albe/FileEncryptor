// 回收站
// 元数据
using System.Text.Json;
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

public sealed class TrashMeta
{
    public string TrashRel { get; set; } = "";
    public string OrigRel { get; set; } = "";
    public string Name { get; set; } = "";
    public bool IsDir { get; set; }
    public ulong Size { get; set; }
    public long DeletedAt { get; set; }   // unix 秒
}

// 回收站列表项
public sealed class TrashEntry
{
    public string TrashRel { get; init; } = "";
    public string? OrigRel { get; init; }
    public string Name { get; init; } = "";
    public bool IsDir { get; init; }
    public ulong Size { get; init; }
    public long DeletedAt { get; init; }

    public string SizeText => IsDir ? L10n.T("目录") : VaultItem.FormatSize(Size);
    public string TimeText => DeletedAt > 0
        ? DateTimeOffset.FromUnixTimeSeconds(DeletedAt).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
        : L10n.T("时间未知");
    public string OriginText => OrigRel is { Length: > 0 } ? L10n.F("原位置：{0}", OrigRel) : L10n.T("原位置未知（仅可删除）");

    // 剩余保留天数
    public long DaysLeft
    {
        get
        {
            int days = VaultTrash.RetentionDays;
            if (days <= 0 || DeletedAt <= 0) return -1;
            var expire = DateTimeOffset.FromUnixTimeSeconds(DeletedAt).AddDays(days);
            return (long)(expire - DateTimeOffset.Now).TotalDays;
        }
    }

    public string ExpireText
    {
        get
        {
            long left = DaysLeft;
            if (left < 0) return L10n.T("不会自动清理");
            if (left <= 0) return L10n.T("已到期，待清理");
            return left <= 3 ? L10n.F("即将到期（剩余 {0} 天）", left) : L10n.F("剩余 {0} 天", left);
        }
    }

    public bool IsExpiring => DaysLeft >= 0 && DaysLeft <= 3;
}

public static class VaultTrash
{
    // 保留天数
    private const string DaysKey = "vault_trash_days";
    public const int DefaultDays = 30;

    public static int RetentionDays
    {
        get => Math.Clamp(Preferences.Default.Get(DaysKey, DefaultDays), 0, 3650);
        set => Preferences.Default.Set(DaysKey, Math.Clamp(value, 0, 3650));
    }

    private static string StoreName(VaultService v) => "trash:" + v.RootDir;

    private static List<TrashMeta> Load(VaultService v)
    {
        string? json = SecureJsonStore.Load(StoreName(v));
        if (json is null) return new List<TrashMeta>();
        try { return JsonSerializer.Deserialize<List<TrashMeta>>(json) ?? new(); }
        catch { return new List<TrashMeta>(); }
    }

    private static void Save(VaultService v, List<TrashMeta> list)
        => SecureJsonStore.Save(StoreName(v), JsonSerializer.Serialize(list));

    private static void EnsureDir(VaultService v)
    {
        if (v.TryGetAttr(VaultService.ReservedName, out _, out _)) return;
        try { v.CreateDir(VaultService.ReservedName); }
        catch (VaultException ex) when (ex.Status == VDiskStatus.Exist) { }
    }

    // 删除 → 移入回收站
    public static void MoveToTrash(VaultService v, string relPath, string name, bool isDir, ulong size)
    {
        EnsureDir(v);
        string token = DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
        string dest = $"{VaultService.ReservedName}/{token}";
        v.Rename(relPath, dest);
        var list = Load(v);
        list.RemoveAll(m => m.TrashRel == dest);
        list.Add(new TrashMeta
        {
            TrashRel = dest,
            OrigRel = relPath,
            Name = name,
            IsDir = isDir,
            Size = size,
            DeletedAt = DateTimeOffset.Now.ToUnixTimeSeconds(),
        });
        Save(v, list);
    }

    // 列表
    public static List<TrashEntry> List(VaultService v)
    {
        var meta = Load(v);
        // 元数据可能
        var byRel = new Dictionary<string, TrashMeta>(StringComparer.Ordinal);
        foreach (var m in meta) byRel[m.TrashRel] = m;
        var outList = new List<TrashEntry>();
        List<VaultItem> kids;
        try { kids = v.ListDir(VaultService.ReservedName); }
        catch (VaultException ex) when (ex.Status == VDiskStatus.NotFound) { return outList; }
        foreach (var it in kids)
        {
            string rel = $"{VaultService.ReservedName}/{it.Name}";
            var m = byRel.GetValueOrDefault(rel);
            outList.Add(new TrashEntry
            {
                TrashRel = rel,
                OrigRel = m?.OrigRel,
                Name = (m?.Name is { Length: > 0 }) ? m!.Name : it.Name,
                IsDir = it.IsDir,
                Size = it.Size,
                DeletedAt = m?.DeletedAt ?? it.Mtime.ToUnixTimeSeconds(),
            });
        }
        outList.Sort((a, b) => b.DeletedAt.CompareTo(a.DeletedAt));
        return outList;
    }

    // 恢复
    public static string Restore(VaultService v, TrashEntry e)
    {
        string target = e.OrigRel ?? "";
        if (target.Length == 0)
            throw new VaultException(VDiskStatus.NotFound, L10n.T("缺少原路径记录，无法恢复；可仅删除该条目"));
        if (v.TryGetAttr(target, out _, out _)) target = FreePath(v, target);
        EnsureParents(v, target);
        v.Rename(e.TrashRel, target);
        var list = Load(v);
        list.RemoveAll(m => m.TrashRel == e.TrashRel);
        Save(v, list);
        return target;
    }

    public static void DeleteForever(VaultService v, TrashEntry e)
    {
        v.DeleteEx(e.TrashRel, null, null);
        var list = Load(v);
        list.RemoveAll(m => m.TrashRel == e.TrashRel);
        Save(v, list);
    }

    // 清空
    public static void Empty(VaultService v)
    {
        if (v.TryGetAttr(VaultService.ReservedName, out _, out _))
            v.DeleteEx(VaultService.ReservedName, null, null);
        Save(v, new List<TrashMeta>());
    }

    // 按保留天数清理
    public static int PurgeExpired(VaultService v, int days)
    {
        if (days <= 0) return 0;
        long cutoff = DateTimeOffset.Now.AddDays(-days).ToUnixTimeSeconds();
        int n = 0;
        foreach (var e in List(v))
        {
            if (e.DeletedAt > 0 && e.DeletedAt < cutoff)
            {
                try { DeleteForever(v, e); n++; } catch { }
            }
        }
        return n;
    }

    private static string FreePath(VaultService v, string rel)
    {
        int slash = rel.LastIndexOf('/');
        string dir = slash < 0 ? "" : rel[..slash];
        string baseName = slash < 0 ? rel : rel[(slash + 1)..];
        int dot = baseName.LastIndexOf('.');
        string stem = dot <= 0 ? baseName : baseName[..dot];
        string ext = dot <= 0 ? "" : baseName[dot..];
        for (int i = 1; i < 1000; i++)
        {
            string cand = dir.Length == 0
                ? L10n.F("{0} (恢复 {1}){2}", stem, i, ext)
                : L10n.F("{0}/{1} (恢复 {2}){3}", dir, stem, i, ext);
            if (!v.TryGetAttr(cand, out _, out _)) return cand;
        }
        return $"{rel}-{Guid.NewGuid():N}";
    }

    private static void EnsureParents(VaultService v, string rel)
    {
        int slash = rel.LastIndexOf('/');
        if (slash < 0) return;
        string dir = rel[..slash];
        string cur = "";
        foreach (string part in dir.Split('/'))
        {
            if (part.Length == 0) continue;
            cur = cur.Length == 0 ? part : $"{cur}/{part}";
            try { v.CreateDir(cur); }
            catch (VaultException ex) when (ex.Status == VDiskStatus.Exist) { }
        }
    }
}
