// 本应用产出
using Microsoft.Maui.Storage;
using System.Text.Json;

namespace FileEncryptorMobile.Services;

internal static class OutputRegistry
{
    private const string Key = "crypto_outputs_v1";
    private const int Cap = 200;
    private static readonly object s_lk = new();

    private static List<string> Load()
    {
        try
        {
            string s = Preferences.Default.Get(Key, "");
            return s.Length == 0 ? new List<string>()
                : JsonSerializer.Deserialize<List<string>>(s) ?? new List<string>();
        }
        catch { return new List<string>(); }
    }

    private static void Save(List<string> items)
    {
        try { Preferences.Default.Set(Key, JsonSerializer.Serialize(items)); } catch { }
    }

    // 只保留
    public static void Track(IEnumerable<string> paths)
    {
        lock (s_lk)
        {
            var list = Load();
            var seen = new HashSet<string>(list, StringComparer.Ordinal);
            foreach (string p in paths)
                if (!string.IsNullOrEmpty(p) && seen.Add(p)) list.Add(p);
            if (list.Count > Cap) list = list.GetRange(list.Count - Cap, Cap);
            Save(list);
        }
    }

    // 只返回清单内、仍
    public static List<string> InDir(string dir)
    {
        string root = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        lock (s_lk)
        {
            var kept = new List<string>();
            foreach (string p in Load())
            {
                try
                {
                    string full = Path.GetFullPath(p);
                    if (!full.StartsWith(root, StringComparison.Ordinal)) { kept.Add(p); continue; }
                    if (File.Exists(full) || Directory.Exists(full)) kept.Add(full);
                }
                catch { }
            }
            return kept;
        }
    }

    public static void Forget(IEnumerable<string> paths)
    {
        var gone = new HashSet<string>(paths, StringComparer.Ordinal);
        lock (s_lk) Save(Load().FindAll(p => !gone.Contains(p)));
    }

    public static void Clear()
    {
        lock (s_lk) { try { Preferences.Default.Remove(Key); } catch { } }
    }
}
