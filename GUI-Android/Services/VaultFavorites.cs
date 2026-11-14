// 收藏书签
// 不写入库内
using System.Text.Json;
using FileEncryptorMobile.Platforms.Android;

namespace FileEncryptorMobile.Services;

public static class VaultFavorites
{
    private static string StoreName(VaultService v) => "fav:" + v.RootDir;

    public static List<string> Load(VaultService v)
    {
        string? json = SecureJsonStore.Load(StoreName(v));
        if (json is null) return new List<string>();
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? new(); }
        catch { return new List<string>(); }
    }

    private static void Save(VaultService v, List<string> list)
        => SecureJsonStore.Save(StoreName(v), JsonSerializer.Serialize(list));

    public static bool Contains(VaultService v, string rel) => Load(v).Contains(rel);

    // 切换收藏状态
    public static bool Toggle(VaultService v, string rel)
    {
        var list = Load(v);
        bool added;
        if (list.Contains(rel)) { list.Remove(rel); added = false; }
        else { list.Add(rel); added = true; }
        Save(v, list);
        return added;
    }

    public static void Remove(VaultService v, string rel)
    {
        var list = Load(v);
        if (list.Remove(rel)) Save(v, list);
    }
}
