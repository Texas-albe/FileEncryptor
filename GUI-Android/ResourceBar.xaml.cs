// 执行期占用栏
// RAM 走 ActivityManager，失败回退 /
// 用 System.Threading.Timer
#pragma warning disable CA1416 // Android 平台 API
using System.IO;
using System.Globalization;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class ResourceBar : ContentView
{
    private System.Threading.Timer? _timer;
    private ulong _lastTotal, _lastIdle;
    private bool _haveSys;
    private int _sysStale;
    private double _lastUp, _lastTicks;
    private bool _haveSelf;

    public ResourceBar()
    {
        InitializeComponent();
        // Loaded 自托管启动兜底
        Loaded += (s, e) => Start();
    }

    // 页面可见启采样
    public void Start()
    {
        if (_timer is not null) return;
        _timer = new System.Threading.Timer(_ => SampleOnce(), null, 500, 500);
        SampleOnce();   // 立即出一帧
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    // 采样放后台
    private int _sampling;

    private void SampleOnce()
    {
        if (Interlocked.Exchange(ref _sampling, 1) != 0) return;
        _ = Task.Run(() =>
        {
            try
            {
                string cpu, ram;
                try { cpu = SampleCpu(); } catch { return; }
                try { ram = SampleRam(); } catch { return; }
                try
                {
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        LblCpu.Text = cpu;
                        LblRam.Text = ram;
                    });
                }
                catch { }
            }
            finally { Volatile.Write(ref _sampling, 0); }
        });
    }

    private string SampleCpu()
    {
        try { return SampleCpuSys() ?? SampleCpuSelf() ?? L10n.T("CPU 受限"); }
        catch { return L10n.T("CPU 受限"); }
    }

    // 系统总体
    private string? SampleCpuSys()
    {
        string? line = ReadFirstLine("/proc/stat");
        if (line is null) return null;
        var f = ParseUlongs(line);
        if (f.Count < 4) return null;
        ulong total = 0;
        for (int i = 0; i < f.Count && i < 8; i++) total += f[i];
        ulong idleAll = f[3] + (f.Count > 4 ? f[4] : 0);
        if (total == 0) return null;
        if (!_haveSys || total < _lastTotal)
        {
            _lastTotal = total; _lastIdle = idleAll; _haveSys = true; _sysStale = 0;
            return "CPU 0%";
        }
        ulong dt = total - _lastTotal, di = idleAll - _lastIdle;
        _lastTotal = total; _lastIdle = idleAll;
        if (dt == 0 || di > dt)
        {
            // 部分 ROM
            if (++_sysStale >= 3) return null;
            return "CPU 0%";
        }
        _sysStale = 0;
        double pct = (1.0 - (double)di / dt) * 100;
        return $"CPU {Math.Clamp(pct, 0, 100):F0}%";
    }

    // 回退
    private string? SampleCpuSelf()
    {
        double up = ReadDouble("/proc/uptime", 0);
        double ticks = SelfCpuTicks();
        if (up <= 0 || ticks < 0) return null;
        if (!_haveSelf || up < _lastUp || ticks < _lastTicks)
        {
            _lastUp = up; _lastTicks = ticks; _haveSelf = true;
            return "CPU 0%";
        }
        double du = up - _lastUp;
        double dt = (ticks - _lastTicks) / 100.0;   // CLK_TCK=100
        _lastUp = up; _lastTicks = ticks;
        if (du <= 0 || dt <= 0) return "CPU 0%";
        int cores = Math.Max(1, Environment.ProcessorCount);
        double pct = dt / du / cores * 100;
        return $"CPU {Math.Clamp(pct, 0, 100):F0}%";
    }

    private static double ReadDouble(string path, int idx)
    {
        string? line = ReadFirstLine(path);
        if (line is null) return 0;
        var sp = line.Split((char[])null!, StringSplitOptions.RemoveEmptyEntries);
        return sp.Length > idx && double.TryParse(sp[idx], NumberStyles.Float,
            CultureInfo.InvariantCulture, out double v) ? v : 0;
    }

    // comm 可能含空格/括号
    private static double SelfCpuTicks()
    {
        string? line = ReadFirstLine("/proc/self/stat");
        if (line is null) return -1;
        int p = line.LastIndexOf(')');
        if (p < 0 || p + 2 >= line.Length) return -1;
        var sp = line[(p + 2)..].Split((char[])null!, StringSplitOptions.RemoveEmptyEntries);
        if (sp.Length < 13) return -1;
        if (!double.TryParse(sp[11], NumberStyles.Float, CultureInfo.InvariantCulture, out double u)) return -1;
        if (!double.TryParse(sp[12], NumberStyles.Float, CultureInfo.InvariantCulture, out double s)) return -1;
        return u + s;
    }

    // RAM
    // 都失败才显示「—」
    private string SampleRam()
    {
        try
        {
#if ANDROID
            var ctx = Android.App.Application.Context;
            var am = (Android.App.ActivityManager)ctx!.GetSystemService(Android.Content.Context.ActivityService)!;
            var mi = new Android.App.ActivityManager.MemoryInfo();
            am.GetMemoryInfo(mi);
            long total = (long)mi.TotalMem;
            long avail = (long)mi.AvailMem;
            long used = total > avail ? total - avail : 0;
            return L10n.F("内存 {0} / {1}", Fmt.Bytes(used), Fmt.Bytes(total));
#else
            return SampleRamMeminfo();
#endif
        }
        catch
        {
            try { return SampleRamMeminfo(); }
            catch { return L10n.T("内存 —"); }
        }
    }

    private static string SampleRamMeminfo()
    {
        ulong total = 0, avail = 0;
        foreach (var line in SafeLines("/proc/meminfo"))
        {
            if (line.StartsWith("MemTotal:")) total = Kb(line);
            else if (line.StartsWith("MemAvailable:")) avail = Kb(line);
        }
        if (total == 0) return L10n.T("内存 —");
        ulong used = total > avail ? total - avail : 0;
        return L10n.F("内存 {0} / {1}", Fmt.Bytes((long)(used * 1024)), Fmt.Bytes((long)(total * 1024)));
    }

    // /proc 文件长度报 0：StreamReader 失败时再试 ReadLines
    private static string? ReadFirstLine(string path)
    {
        try { using var sr = new StreamReader(path); return sr.ReadLine(); }
        catch { }
        try { return File.ReadLines(path).FirstOrDefault(); }
        catch { return null; }
    }

    private static List<ulong> ParseUlongs(string line)
    {
        var list = new List<ulong>();
        var sp = line.Split((char[])null!, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 1; i < sp.Length; i++)
            if (ulong.TryParse(sp[i], out ulong v)) list.Add(v);
        return list;
    }

    private static IEnumerable<string> SafeLines(string path)
    {
        try { return File.ReadLines(path); }
        catch { return System.Array.Empty<string>(); }
    }

    // meminfo 数值单位
    private static ulong Kb(string line)
    {
        var sp = line.Split((char[])null!, StringSplitOptions.RemoveEmptyEntries);
        if (sp.Length >= 2 && ulong.TryParse(sp[1], out ulong v)) return v;
        return 0;
    }
}
