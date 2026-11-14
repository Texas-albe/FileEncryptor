using FileEncryptorMobile.Services;
namespace FileEncryptorMobile.Services;

// 访问事件类型
public enum AccessEventKind
{
    PairOk,
    PairFail,
    LoginOk,
    LoginFail,
    Download,
    Denied,
}

// 一条访问记录
public readonly struct AccessEntry
{
    public DateTime Time { get; }
    public AccessEventKind Kind { get; }
    public string Tag { get; }
    public AccessEntry(DateTime time, AccessEventKind kind, string tag)
    { Time = time; Kind = kind; Tag = tag; }
}

// 内存环形访问日
// 绝不含文件名、路
public static class AccessLog
{
    public const int Capacity = 200;
    private static readonly object Gate = new();
    private static readonly AccessEntry[] Buf = new AccessEntry[Capacity];
    private static int _head;
    private static int _count;

    // tag 必须是 Tag
    public static void Add(AccessEventKind kind, string tag)
    {
        var e = new AccessEntry(DateTime.Now, kind, tag);
        lock (Gate)
        {
            Buf[_head] = e;
            _head = (_head + 1) % Capacity;
            if (_count < Capacity) _count++;
        }
    }

    // 返回
    public static AccessEntry[] Snapshot()
    {
        lock (Gate)
        {
            var arr = new AccessEntry[_count];
            int start = (_head - _count + Capacity) % Capacity;
            for (int i = 0; i < _count; i++)
                arr[i] = Buf[(start + i) % Capacity];
            return arr;
        }
    }

    public static void Clear()
    {
        lock (Gate)
        {
            _head = 0;
            _count = 0;
            Array.Clear(Buf, 0, Buf.Length);
        }
    }

    // 不可逆短标记
    public static string Tag(string? who)
    {
        if (string.IsNullOrEmpty(who)) return "-";
        ulong h = 14695981039346656037UL;
        foreach (char c in who) { h ^= c; h *= 1099511628211UL; }
        return "f" + (h & 0xFFFFFFFFUL).ToString("x8");
    }

    public static string KindText(AccessEventKind kind) => kind switch
    {
        AccessEventKind.PairOk => L10n.T("配对成功"),
        AccessEventKind.PairFail => L10n.T("配对失败"),
        AccessEventKind.LoginOk => L10n.T("登录成功"),
        AccessEventKind.LoginFail => L10n.T("登录失败"),
        AccessEventKind.Download => L10n.T("下载"),
        AccessEventKind.Denied => L10n.T("拒绝"),
        _ => L10n.T("其他"),
    };

    // 实时日志入口用
    public static string KindTextEn(AccessEventKind kind) => kind switch
    {
        AccessEventKind.PairOk => "PAIR-OK",
        AccessEventKind.PairFail => "PAIR-FAIL",
        AccessEventKind.LoginOk => "LOGIN-OK",
        AccessEventKind.LoginFail => "LOGIN-FAIL",
        AccessEventKind.Download => "DOWNLOAD",
        AccessEventKind.Denied => "DENIED",
        _ => "EVENT",
    };
}
