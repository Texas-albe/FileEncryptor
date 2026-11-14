// 外部应用分享进
using System.Collections.Generic;

namespace FileEncryptorMobile.Services;

public static class ShareInbox
{
    private static readonly object s_lock = new();
    private static readonly List<string> s_items = new();

    public static bool HasPending { get { lock (s_lock) return s_items.Count > 0; } }

    public static void Add(IEnumerable<string> uris)
    {
        lock (s_lock)
            foreach (var u in uris)
                if (!string.IsNullOrEmpty(u) && !s_items.Contains(u)) s_items.Add(u);
    }

    public static List<string> Take()
    {
        lock (s_lock)
        {
            var copy = new List<string>(s_items);
            s_items.Clear();
            return copy;
        }
    }
}
