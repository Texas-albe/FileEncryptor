using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

public class EtaEstimate
{
    public bool Valid { get; set; }
    public long TotalMs { get; set; }
    public long RemainingMs { get; set; }
    public double BytesPerSec { get; set; }
    public int SampleCount { get; set; }
    public bool FromProgress { get; set; }
}

public static class EtaEstimatorService
{
    public static EtaEstimate Estimate(long bytes, string action, string mode, List<TaskRecord> history)
    {
        var est = new EtaEstimate();
        if (bytes <= 0) return est;

        // 分层取样：同 action+mode → 同 action → 全体
        var samples = history
            .Where(r => r.Status == "success" && r.TotalBytes > 0 && r.DurationMs > 0)
            .ToList();

        var sameBoth = samples.Where(r => r.Action == action && r.Mode == mode).ToList();
        var sameAction = samples.Where(r => r.Action == action).ToList();

        var pool = sameBoth.Count >= 2 ? sameBoth :
                   sameAction.Count >= 2 ? sameAction :
                   samples.Count >= 2 ? samples : null;

        if (pool == null || pool.Count == 0) return est;

        var rates = pool.Select(r => r.TotalBytes * 1000.0 / r.DurationMs).OrderBy(r => r).ToList();
        double median = rates[rates.Count / 2];
        if (rates.Count % 2 == 0 && rates.Count >= 2)
            median = (rates[rates.Count / 2 - 1] + rates[rates.Count / 2]) / 2.0;

        est.BytesPerSec = median;
        est.TotalMs = (long)(bytes * 1000.0 / median);
        est.RemainingMs = est.TotalMs;
        est.SampleCount = pool.Count;
        est.Valid = true;
        return est;
    }

    public static EtaEstimate FromProgress(int done, int total, long elapsedMs, EtaEstimate hist)
    {
        if (done <= 0 || total <= 0) return hist;
        double fraction = (double)done / total;
        if (fraction <= 0) return hist;
        long totalMs = (long)(elapsedMs / fraction);
        return new EtaEstimate
        {
            Valid = true,
            TotalMs = totalMs,
            RemainingMs = Math.Max(0, totalMs - elapsedMs),
            BytesPerSec = hist.BytesPerSec,
            SampleCount = 0,
            FromProgress = true
        };
    }

    public static string FormatDuration(long ms)
    {
        if (ms < 1000) return "<1s";
        long sec = ms / 1000;
        if (sec < 60) return $"{sec}s";
        long min = sec / 60; sec %= 60;
        if (min < 60) return $"{min}m {sec}s";
        long hr = min / 60; min %= 60;
        return $"{hr}h {min}m";
    }

    public static string FormatRate(double bytesPerSec)
    {
        if (bytesPerSec < 1024) return $"{bytesPerSec:F0} B/s";
        if (bytesPerSec < 1024 * 1024) return $"{bytesPerSec / 1024:F1} KB/s";
        if (bytesPerSec < 1024.0 * 1024 * 1024) return $"{bytesPerSec / (1024 * 1024):F1} MB/s";
        return $"{bytesPerSec / (1024.0 * 1024 * 1024):F2} GB/s";
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }
}
