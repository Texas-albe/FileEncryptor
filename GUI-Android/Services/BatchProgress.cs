// 批量进度
// 汇总
using System.Diagnostics;

namespace FileEncryptorMobile.Services;

// 格式化
public static class Fmt
{
    private static readonly string[] s_units = { "B", "KB", "MB", "GB", "TB" };

    // B / KB / MB / GB /
    public static string Bytes(long b)
    {
        if (b < 0) return "-";
        double v = b;
        string[] u = s_units;
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        string s = i == 0 ? $"{b}" : v < 10 ? $"{v:F2}" : v < 100 ? $"{v:F1}" : $"{v:F0}";
        return s + u[i];
    }

    public static string Rate(double bps)
        => bps <= 0 || double.IsNaN(bps) || double.IsInfinity(bps) ? "-" : Bytes((long)bps) + "/s";

    // MM
    public static string Eta(double sec)
    {
        if (double.IsNaN(sec) || double.IsInfinity(sec) || sec < 0) return "--:--";
        int t = (int)Math.Round(sec);
        int h = t / 3600, m = t % 3600 / 60, s = t % 60;
        return h > 0 ? $"{h}:{m:D2}:{s:D2}" : $"{m:D2}:{s:D2}";
    }
}

public sealed class BatchSnapshot
{
    public string Current = "";          // 当前文件名
    public ulong CurDone, CurTotal;      // 当前文件明文字
    public long Processed, Total;        // 全局已处理 / 总字
    public int Index, Count;             // 当前文件序号 / 总
    public int Done, Failed, Skipped;    // 已成功 / 失败 / 跳
    public int Cancelled;                // 已取消
    public double RateBps, EtaSec;       // 滑动窗口速率
    public bool CountMode;               // true 时 Processed/Total 是文件数
    public double OverallPct => Total <= 0 ? 0 : Math.Min(100, Processed * 100.0 / Total);
    public double CurPct => CurTotal == 0 ? 0 : Math.Min(100, CurDone * 100.0 / CurTotal);
}

public sealed class BatchTracker
{
    // 与 CLI 同
    private const long NotifyIntervalMs = 80;
    private const double WindowSec = 3.0;

    private readonly Stopwatch _sw = new();
    private readonly Queue<(double t, long bytes)> _samples = new();
    private double _lastSampleT;
    private long _lastSampleBytes;
    private long _total;
    private int _index, _count, _done, _failed, _skipped, _cancelled;
    private long _lastNotify;
    private bool _countMode;
    private bool _finished;      // Finish 后迟到回调直接
    private readonly object _lk = new();

    // 并行
    private sealed class Slot
    {
        public int Index;
        public string Name = "";
        public ulong Done, Total;
        public bool Ended;
    }
    private readonly Dictionary<int, Slot> _slots = new();
    // 聚合模式
    private bool _agg;
    private long _aggProcessed;

    public event Action<BatchSnapshot>? Updated;

    public void Begin(int fileCount, long totalBytes) => Reset(fileCount, totalBytes, false);

    private void Reset(int fileCount, long totalBytes, bool agg, bool countMode = false)
    {
        lock (_lk)
        {
            _count = fileCount;
            _total = totalBytes;
            _index = 0;
            _done = _failed = _skipped = _cancelled = 0;
            _countMode = countMode;
            _slots.Clear();
            _agg = agg; _aggProcessed = 0;
            _samples.Clear();
            _lastSampleT = 0;
            _lastSampleBytes = 0;
            _finished = false;
            _sw.Restart();
        }
        Notify(force: true);
    }

    // native 内部并行
    public void BeginAggregate(int fileCount, long totalBytes) => Reset(fileCount, totalBytes, true);

    // 按文件计数模式
    public void BeginCount(int fileCount) => Reset(fileCount, fileCount, true, true);

    public void StartSlot(int id, int index, string name, ulong size)
    {
        lock (_lk)
        {
            if (_agg) { _index = Math.Max(_index, index); return; }
            _slots[id] = new Slot { Index = index, Name = name, Done = 0, Total = size, Ended = false };
            _index = Math.Max(_index, index);
        }
        Notify(force: true);
    }

    // native 进度回调
    public void ReportSlot(int id, ulong done, ulong total)
    {
        lock (_lk)
        {
            if (_agg) return;
            if (!_slots.TryGetValue(id, out Slot? s)) return;
            s.Done = done;
            if (total > 0) s.Total = total;
            Sample();
        }
        Notify(force: false);
    }

    public void EndSlot(int id, bool ok)
    {
        lock (_lk)
        {
            if (ok) _done++; else _failed++;
            if (!_agg && _slots.TryGetValue(id, out Slot? s))
            {
                s.Done = s.Total;   // 补齐该文件剩余
                s.Ended = true;
            }
            Sample();
        }
        Notify(force: true);
    }

    // 聚合模式
    public void ReportAggregate(ulong done, ulong total)
    {
        lock (_lk)
        {
            _aggProcessed = (long)Math.Min(done, (ulong)long.MaxValue);
            if (total > 0)
            {
                _total = (long)Math.Min(total, (ulong)long.MaxValue);
                // 计数模式
                if (_countMode && _count == 0) _count = _total > int.MaxValue ? int.MaxValue : (int)_total;
            }
            // 计数模式没有逐
            // 保证 UI
            if (_countMode && _total > 0)
            {
                int totalCount = _count;
                int cur = (int)Math.Min(done, (ulong)int.MaxValue);
                int next = cur + (done < (ulong)_total ? 1 : 0);
                _index = Math.Min(next, totalCount);
            }
            Sample();
        }
        Notify(force: false);
    }

    // 标记「正
    // 名字只进内存快
    public void SetCurrent(int index, string name)
    {
        lock (_lk)
        {
            if (index > 0) _index = index;
            _slots.Clear();
            _slots[-1] = new Slot { Index = _index, Name = name, Done = 0, Total = 0, Ended = false };
        }
        Notify(force: true);
    }

    // 聚合模式下逐
    public void EndAggregateFile(string name, bool ok)
    {
        lock (_lk)
        {
            if (ok) _done++; else _failed++;
            _index = Math.Min(_index + 1, _count);
            _slots.Clear();
            _slots[-1] = new Slot { Index = _index, Name = name, Done = 0, Total = 0, Ended = true };
            Sample();
        }
        Notify(force: true);
    }

    // 被取消
    // 保留已开始
    public void CancelSlot(int id, int index, string name)
    {
        lock (_lk)
        {
            _cancelled++;
            if (!_agg)
            {
                if (_slots.TryGetValue(id, out Slot? s)) s.Ended = true;
                else _slots[id] = new Slot { Index = index, Name = name, Done = 0, Total = 0, Ended = true };
                _index = Math.Max(_index, index);
            }
            Sample();
        }
        Notify(force: true);
    }

    // 被取消
    public void CancelAggregateFile(string name)
    {
        lock (_lk)
        {
            _cancelled++;
            _index = Math.Min(_index + 1, _count);
            _slots.Clear();
            _slots[-1] = new Slot { Index = _index, Name = name, Done = 0, Total = 0, Ended = true };
            Sample();
        }
        Notify(force: true);
    }

    public void Finish()
    {
        Notify(force: true);   // 末帧强制刷新
        lock (_lk) { _sw.Stop(); _finished = true; }
        Updated = null;
    }

    public BatchSnapshot Snapshot()
    {
        lock (_lk)
        {
            long processed = _agg ? _aggProcessed : SlotsDone();
            double rate = Rate();
            double left = Math.Max(0, _total - processed);
            Slot? cur = PickCurrent();
            return new BatchSnapshot
            {
                Current = cur?.Name ?? "",
                CurDone = cur?.Done ?? 0,
                CurTotal = cur?.Total ?? 0,
                Processed = processed,
                Total = _total,
                // 单文件槽位模式
                // 聚合/计数模式没
                Index = cur is not null ? cur.Index : _index,
                Count = _count,
                Done = _done,
                Failed = _failed,
                Skipped = _skipped,
                Cancelled = _cancelled,
                CountMode = _countMode,
                RateBps = _countMode ? 0 : rate,
                // 速率
                EtaSec = _countMode || rate <= 0 ? double.NaN : left / rate,
            };
        }
    }

    // 全局已处理 = 各槽
    private long SlotsDone()
    {
        long sum = 0;
        foreach (Slot s in _slots.Values) sum += (long)Math.Min(s.Done, s.Total);
        return sum;
    }

    // 当前展示项
    private Slot? PickCurrent()
    {
        Slot? live = null, last = null;
        foreach (Slot s in _slots.Values)
        {
            if (!s.Ended && (live is null || s.Index < live.Index)) live = s;
            if (last is null || s.Index > last.Index) last = s;
        }
        return live ?? last;
    }

    // 窗口增量比窗口时长
    private double Rate()
    {
        if (_samples.Count < 2) return 0;
        // 相对末样本裁窗
        while (_samples.Count > 2 && _lastSampleT - _samples.Peek().t > WindowSec) _samples.Dequeue();
        var first = _samples.Peek();
        double dt = _lastSampleT - first.t;
        long db = _lastSampleBytes - first.bytes;
        return dt <= 0.01 || db <= 0 ? 0 : db / dt;
    }

    private void Sample()
    {
        double t = _sw.Elapsed.TotalSeconds;
        long b = _agg ? _aggProcessed : SlotsDone();
        _samples.Enqueue((t, b));
        _lastSampleT = t;
        _lastSampleBytes = b;
        if (_samples.Count > 512) _samples.Dequeue();
    }

    private void Notify(bool force)
    {
        lock (_lk) { if (_finished) return; }   // 批已结束
        if (Updated is null) return;
        long now = _sw.ElapsedMilliseconds;
        if (!force && now - _lastNotify < NotifyIntervalMs) return;
        _lastNotify = now;
        var snap = Snapshot();
        Updated?.Invoke(snap);
    }
}
