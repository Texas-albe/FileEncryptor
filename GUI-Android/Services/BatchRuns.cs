// 批量任务注册表
using System.Collections.Generic;
using ProgressUi = FileEncryptorMobile.ProgressPage;

namespace FileEncryptorMobile.Services;

public sealed class BatchRun
{
    public required string Title { get; init; }
    public required BatchTracker Tracker { get; init; }
    public Func<bool>? Cancel;
}

public static class BatchRuns
{
    static readonly List<BatchRun> _runs = new();
    static readonly object _lk = new();

    public static BatchRun? Current
    {
        get { lock (_lk) return _runs.Count > 0 ? _runs[^1] : null; }
    }

    public static event Action? Changed;

    public static BatchRun Begin(string title, BatchTracker tracker, Func<bool> cancel)
    {
        var run = new BatchRun { Title = title, Tracker = tracker, Cancel = cancel };
        lock (_lk) _runs.Add(run);
        Changed?.Invoke();
        return run;
    }

    public static void End(BatchRun run)
    {
        lock (_lk) _runs.Remove(run);
        Changed?.Invoke();
    }

    // 重入应用
    public static void ShowProgress()
    {
        if (Current is null) return;
        if (ProgressUi.UserHidden || ProgressUi.IsShowing) return;
        ProgressUi.Show();
    }
}
