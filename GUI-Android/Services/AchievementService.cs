// 成就核心服务 Minecraft 进度格式
using System.IO;
using System.Text.Json;

namespace FileEncryptorMobile.Services;

// 文本组件 三语
public class AdvText
{
    public string Text { get; set; } = "";
    public string? TextEn { get; set; }
    public string? TextRu { get; set; }

    public string Of(string lang) => lang switch
    {
        "en" => TextEn ?? Text,
        "ru" => TextRu ?? Text,
        _ => Text
    };
}

// 准则定义
public class CriterionDef
{
    public string Trigger { get; set; } = "";
    // 计数下限 null=触发即达成
    public long? Min { get; set; }
    // 计数上限 null=无上界
    public long? Max { get; set; }
}

// 显示信息
public class AdvDisplay
{
    public string Icon { get; set; } = "";
    public AdvText Title { get; set; } = new();
    public AdvText Description { get; set; } = new();
    // task goal challenge
    public string Frame { get; set; } = "task";
    // 仅根进度有效
    public string? Background { get; set; }
    public bool ShowToast { get; set; } = true;
    // 未完成时隐藏自身与子树
    public bool Hidden { get; set; }
}

// 进度定义
public class AdvDef
{
    public string Id { get; set; } = "";
    public string? Parent { get; set; }
    public AdvDisplay? Display { get; set; }
    public Dictionary<string, CriterionDef> Criteria { get; set; } = new();
    // 子列表间 AND 内部 OR
    public List<List<string>>? Requirements { get; set; }
    public int Experience { get; set; }
}

// 进度状态 对齐 MC 玩家文件
public class AdvState
{
    // 准则名 -> 达成时刻
    public Dictionary<string, string> Criteria { get; set; } = new();
    // 计数仅内存 不落盘
    [System.Text.Json.Serialization.JsonIgnore]
    public Dictionary<string, long> Progress { get; set; } = new();
    public bool Done { get; set; }
}

// 列表面板条目
public class AchievementEntry
{
    public AdvDef Def { get; init; } = new();
    public AdvState State { get; init; } = new();
    public bool Visible { get; init; }
}

public static class AchievementService
{
    private static readonly object Lock = new();
    private static readonly string StatePath =
        Path.Combine(FileSystem.AppDataDirectory, "achievements.state.json");
    private const string PackAsset = "pack.json";

    private static List<AdvDef> _defs = new();
    private static Dictionary<string, AdvDef> _index = new();
    private static Dictionary<string, AdvState> _state = new();

    // 解锁回调 toast
    public static event Action<AdvDef>? Unlocked;

    public static void Load()
    {
        lock (Lock)
        {
            _defs = ReadDefs();
            PruneTree();
            _state = ReadState();
        }
    }

    // 事件计数判解锁
    // 返回本次新完成
    public static List<AdvDef> Observe(string ev, long n = 1)
    {
        var gained = new List<AdvDef>();
        if (string.IsNullOrEmpty(ev)) return gained;
        lock (Lock)
        {
            foreach (var d in _defs)
            {
                var st = StateOf(d.Id);
                if (st.Done) continue;
                var touched = false;
                foreach (var (name, c) in d.Criteria)
                {
                    if (c.Trigger != ev) continue;
                    if (st.Criteria.ContainsKey(name)) continue;
                    // 无条件 触发即达成
                    if (c.Min == null && c.Max == null)
                    {
                        st.Criteria[name] = Now();
                        touched = true;
                        continue;
                    }
                    if (n <= 0) continue;
                    st.Progress.TryGetValue(name, out var p);
                    p += n;
                    if (c.Max != null && p > c.Max) p = c.Max.Value;
                    st.Progress[name] = p;
                    if (p >= (c.Min ?? 0) && (c.Max == null || p <= c.Max))
                    {
                        st.Criteria[name] = Now();
                        touched = true;
                    }
                }
                if (touched && IsDone(d, st))
                {
                    st.Done = true;
                    gained.Add(d);
                }
            }
            if (gained.Count > 0) Save();
        }
        // 锁外回调 防死锁
        foreach (var d in gained) Unlocked?.Invoke(d);
        return gained;
    }

    // 列表面板用 仅可见项
    public static List<AchievementEntry> Entries()
    {
        lock (Lock)
        {
            var cache = new Dictionary<string, bool>();
            var list = new List<AchievementEntry>();
            foreach (var d in _defs)
            {
                var vis = Visible(d, cache);
                if (!vis) continue;
                list.Add(new AchievementEntry
                {
                    Def = d, State = StateOf(d.Id), Visible = true
                });
            }
            return list;
        }
    }

    // 完成度概览
    public static (int Done, int Total) Progress()
    {
        lock (Lock)
        {
            var n = 0;
            foreach (var d in _defs)
                if (StateOf(d.Id).Done) n++;
            return (n, _defs.Count);
        }
    }

    private static AdvState StateOf(string id)
    {
        if (!_state.TryGetValue(id, out var st))
        {
            st = new AdvState();
            _state[id] = st;
        }
        return st;
    }

    // requirements 判定 缺省全达成
    private static bool IsDone(AdvDef d, AdvState st)
    {
        if (d.Criteria.Count == 0) return false;
        if (d.Requirements != null)
        {
            foreach (var grp in d.Requirements)
            {
                if (grp.Count == 0) return false;
                var any = false;
                foreach (var name in grp)
                    if (st.Criteria.ContainsKey(name)) { any = true; break; }
                if (!any) return false;
            }
            return true;
        }
        foreach (var name in d.Criteria.Keys)
            if (!st.Criteria.ContainsKey(name)) return false;
        return true;
    }

    // MC 显示规则 根可见 父可见且非hidden 完成恒可见
    private static bool Visible(AdvDef d, Dictionary<string, bool> cache)
    {
        if (cache.TryGetValue(d.Id, out var v)) return v;
        bool vis;
        if (StateOf(d.Id).Done) vis = true;
        else if (d.Display == null || d.Display.Hidden) vis = false;
        else if (d.Parent == null) vis = true;
        else
        {
            _index.TryGetValue(d.Parent, out var pd);
            vis = pd != null && Visible(pd, cache);
        }
        cache[d.Id] = vis;
        return vis;
    }

    // 剥离孤儿与循环引用
    private static void PruneTree()
    {
        _index = _defs.ToDictionary(x => x.Id, x => x);
        var alive = _index.Keys.ToHashSet();
        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var id in alive.ToList())
            {
                var p = _index[id].Parent;
                if (p != null && !alive.Contains(p))
                {
                    alive.Remove(id);
                    changed = true;
                }
            }
        }
        if (alive.Count != _index.Count)
            _defs = _defs.Where(x => alive.Contains(x.Id)).ToList();
        _index = _defs.ToDictionary(x => x.Id, x => x);
    }

    private static string Now() => DateTime.Now.ToString("o");

    private static List<AdvDef> ReadDefs()
    {
        var list = new List<AdvDef>();
        try
        {
            if (!FileSystem.Current.AppPackageFileExistsAsync(PackAsset)
                    .GetAwaiter().GetResult())
                return list;
            using var packStream = FileSystem.Current.OpenAppPackageFileAsync(PackAsset)
                .GetAwaiter().GetResult();
            using var packReader = new StreamReader(packStream);
            using var pack = JsonDocument.Parse(packReader.ReadToEnd());
            if (!pack.RootElement.TryGetProperty("achievements", out var ids)) return list;
            foreach (var item in ids.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) continue;
                var id = item.GetString();
                if (string.IsNullOrEmpty(id)) continue;
                var sid = id!;
                var asset = ToAssetPath(sid);
                if (asset == null) continue;
                try
                {
                    if (!FileSystem.Current.AppPackageFileExistsAsync(asset)
                            .GetAwaiter().GetResult()) continue;
                    using var stream = FileSystem.Current.OpenAppPackageFileAsync(asset)
                        .GetAwaiter().GetResult();
                    using var reader = new StreamReader(stream);
                    using var doc = JsonDocument.Parse(reader.ReadToEnd());
                    var d = ParseOne(sid, doc.RootElement);
                    if (d != null && d.Criteria.Count > 0) list.Add(d);
                }
                catch { }
            }
        }
        catch { }
        return list;
    }

    // fileencryptor:story/root -> achievements/story/root.json
    private static string? ToAssetPath(string id)
    {
        var colon = id.IndexOf(':');
        if (colon < 0 || colon == id.Length - 1) return null;
        return "achievements/" + id[(colon + 1)..].Replace('/', '/') + ".json";
    }

    private static AdvDef? ParseOne(string id, JsonElement o)
    {
        var d = new AdvDef { Id = id };
        if (o.TryGetProperty("parent", out var pv) && pv.ValueKind == JsonValueKind.String)
            d.Parent = pv.GetString();
        if (o.TryGetProperty("display", out var dv) && dv.ValueKind == JsonValueKind.Object)
            d.Display = ParseDisplay(dv);
        if (o.TryGetProperty("criteria", out var cv) && cv.ValueKind == JsonValueKind.Object)
        {
            foreach (var cp in cv.EnumerateObject())
            {
                var co = cp.Value;
                var c = new CriterionDef();
                if (co.TryGetProperty("trigger", out var tv) && tv.ValueKind == JsonValueKind.String)
                    c.Trigger = tv.GetString() ?? "";
                if (co.TryGetProperty("conditions", out var conds) &&
                    conds.ValueKind == JsonValueKind.Object &&
                    conds.TryGetProperty("count", out var cnt))
                {
                    // 界限范围 数字或 minmax
                    if (cnt.ValueKind == JsonValueKind.Number)
                    {
                        c.Min = c.Max = cnt.GetInt64();
                    }
                    else if (cnt.ValueKind == JsonValueKind.Object)
                    {
                        if (cnt.TryGetProperty("min", out var mn) && mn.ValueKind == JsonValueKind.Number)
                            c.Min = mn.GetInt64();
                        if (cnt.TryGetProperty("max", out var mx) && mx.ValueKind == JsonValueKind.Number)
                            c.Max = mx.GetInt64();
                    }
                }
                d.Criteria[cp.Name] = c;
            }
        }
        if (o.TryGetProperty("requirements", out var rv) && rv.ValueKind == JsonValueKind.Array)
        {
            var reqs = new List<List<string>>();
            foreach (var grp in rv.EnumerateArray())
            {
                var g = new List<string>();
                if (grp.ValueKind == JsonValueKind.Array)
                    foreach (var item in grp.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String)
                            g.Add(item.GetString() ?? "");
                reqs.Add(g);
            }
            d.Requirements = reqs;
        }
        if (o.TryGetProperty("rewards", out var rw) && rw.ValueKind == JsonValueKind.Object &&
            rw.TryGetProperty("experience", out var ex) && ex.ValueKind == JsonValueKind.Number)
            d.Experience = ex.GetInt32();
        return d;
    }

    private static AdvDisplay ParseDisplay(JsonElement dv)
    {
        var disp = new AdvDisplay();
        if (dv.TryGetProperty("icon", out var iv) && iv.ValueKind == JsonValueKind.String)
            disp.Icon = iv.GetString() ?? "";
        if (dv.TryGetProperty("title", out var ti)) disp.Title = ParseText(ti);
        if (dv.TryGetProperty("description", out var de)) disp.Description = ParseText(de);
        if (dv.TryGetProperty("frame", out var fr) && fr.ValueKind == JsonValueKind.String)
        {
            var f = fr.GetString();
            if (f == "task" || f == "goal" || f == "challenge") disp.Frame = f;
        }
        if (dv.TryGetProperty("background", out var bg) && bg.ValueKind == JsonValueKind.String)
            disp.Background = bg.GetString();
        if (dv.TryGetProperty("show_toast", out var st2) && st2.ValueKind is JsonValueKind.True or JsonValueKind.False)
            disp.ShowToast = st2.GetBoolean();
        if (dv.TryGetProperty("hidden", out var hd) && hd.ValueKind is JsonValueKind.True or JsonValueKind.False)
            disp.Hidden = hd.GetBoolean();
        return disp;
    }

    // 文本组件 字符串或对象
    private static AdvText ParseText(JsonElement e)
    {
        var t = new AdvText();
        if (e.ValueKind == JsonValueKind.String)
        {
            t.Text = e.GetString() ?? "";
            return t;
        }
        if (e.ValueKind == JsonValueKind.Object)
        {
            if (e.TryGetProperty("text", out var x) && x.ValueKind == JsonValueKind.String)
                t.Text = x.GetString() ?? "";
            if (e.TryGetProperty("text_en", out var en) && en.ValueKind == JsonValueKind.String)
                t.TextEn = en.GetString();
            if (e.TryGetProperty("text_ru", out var ru) && ru.ValueKind == JsonValueKind.String)
                t.TextRu = ru.GetString();
        }
        return t;
    }

    private static Dictionary<string, AdvState> ReadState()
    {
        try
        {
            if (!File.Exists(StatePath)) return new Dictionary<string, AdvState>();
            var json = File.ReadAllText(StatePath);
            return JsonSerializer.Deserialize<Dictionary<string, AdvState>>(json)
                   ?? new Dictionary<string, AdvState>();
        }
        catch { return new Dictionary<string, AdvState>(); }
    }

    private static void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(_state,
                new JsonSerializerOptions { WriteIndented = true });
            var tmp = StatePath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, StatePath, overwrite: true);
        }
        catch { }
    }
}
