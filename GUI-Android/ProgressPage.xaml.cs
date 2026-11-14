// 批量任务浮层
// 类名沿用 ProgressPage，现
using FileEncryptorMobile.Services;
using Microsoft.Maui.ApplicationModel;

namespace FileEncryptorMobile;

public partial class ProgressPage : ContentView
{
    private readonly CancellationTokenSource _cts = new();
    private BatchRun? _run;
    private Func<bool>? _externalCancel;

    // 浮层实例常驻到
    private static ProgressPage? _panel;
    private static Grid? _root;

    public static bool IsShowing => _panel is not null && _root is not null && _root.Children.Contains(_panel);
    // 主动隐藏
    public static bool UserHidden { get; private set; }

    public ProgressPage(string title)
    {
        InitializeComponent();
        LblTitle.Text = title;
    }

    // 兼容构造
    public ProgressPage(string title, BatchRun run) : this(title)
    {
        _run = run;
        _externalCancel = run.Cancel;
    }

    private void OnCardTapped(object? sender, TappedEventArgs e) { }
    private void OnMaskTapped(object? sender, TappedEventArgs e) => Hide();
    private void OnHide(object? sender, EventArgs e) => Hide();

    // 订阅进度源
    public void Attach(BatchTracker tracker)
        => tracker.Updated += snap => MainThread.BeginInvokeOnMainThread(() => Apply(snap));

    private void Apply(BatchSnapshot s)
    {
        LblOverall.Text = s.Total > 0
            ? (s.CountMode
                ? L10n.F("{0:F1}%　{1} / {2} 个文件", s.OverallPct, s.Processed, s.Total)
                : $"{s.OverallPct:F1}%　{Fmt.Bytes(s.Processed)} / {Fmt.Bytes(s.Total)}")
            : (s.CountMode ? L10n.T("正在准备…") : $"{Fmt.Bytes(s.Processed)}");
        LblRate.Text = s.CountMode
            ? ""
            : L10n.F("{0}　剩余 {1}", Fmt.Rate(s.RateBps), Fmt.Eta(s.EtaSec));

        LblFile.Text = s.Count > 0
            ? $"[{s.Index}/{s.Count}] {s.Current}"
            : s.Current;
        // 单文件进度只
        bool hasFileProgress = s.CurTotal > 0;
        BarFile.IsVisible = hasFileProgress;
        BarFile.Progress = hasFileProgress ? s.CurPct / 100 : 0;
        LblFilePct.IsVisible = hasFileProgress;
        LblFilePct.Text = hasFileProgress
            ? $"{s.CurPct:F0}%　{Fmt.Bytes((long)s.CurDone)} / {Fmt.Bytes((long)s.CurTotal)}"
            : "";

        string files = L10n.F("完成 {0} · 失败 {1} · 跳过 {2}", s.Done, s.Failed, s.Skipped);
        if (s.Cancelled > 0) files += L10n.F(" · 取消 {0}", s.Cancelled);
        LblFiles.Text = L10n.F("{0} · 共 {1}", files, s.Count);
    }

    private void OnCancel(object? sender, EventArgs e) => RequestCancel();

    public bool RequestCancel()
    {
        if (_externalCancel is not null) return _externalCancel();
        if (_cts.IsCancellationRequested) return false;
        MainThread.BeginInvokeOnMainThread(() =>
        {
            BtnCancel.IsEnabled = false;
            BtnCancel.Text = L10n.T("正在取消…");
            _cts.Cancel();
        });
        return true;
    }

    internal CancellationToken Token => _cts.Token;

    public static bool RequestCancelCurrent() => _panel?.RequestCancel() ?? false;

    // 挂到指定页
    public static void Show(Page? host = null)
    {
        var page = (host ?? Shell.Current?.CurrentPage) as ContentPage;
        if (page is null || _panel is null) return;
        var root = EnsureRoot(page);
        if (_root is not null && _root != root && _root.Children.Contains(_panel))
            _root.Children.Remove(_panel);
        if (!root.Children.Contains(_panel))
        {
            int g = Interlocked.Increment(ref s_fadeGen);
            _panel.CancelAnimations();
            _panel.Opacity = 0;
            root.Children.Add(_panel);
            _ = _panel.FadeTo(1, 180, Easing.CubicOut);
        }
        _root = root;
        UserHidden = false;
        _panel.ResBar.Start();
    }

    public static void Hide()
    {
        _panel?.ResBar.Stop();
        var panel = _panel;
        var root = _root;
        UserHidden = true;
        if (root is null || panel is null || !root.Children.Contains(panel)) return;
        // 淡出后代次校验
        int gen = Interlocked.Increment(ref s_fadeGen);
        panel.CancelAnimations();
        _ = FadeOutAsync(root, panel, gen);
    }

    private static async Task FadeOutAsync(Grid root, VisualElement panel, int gen)
    {
        try { await panel.FadeTo(0, 140, Easing.CubicIn); } catch { }
        if (Volatile.Read(ref s_fadeGen) == gen && root.Children.Contains(panel))
            root.Children.Remove(panel);
        panel.Opacity = 1;
    }

    private static Grid EnsureRoot(ContentPage page)
    {
        if (page.Content is Grid g && g.ClassId == "fe_overlay_root") return g;
        var old = page.Content;
        var root = new Grid { ClassId = "fe_overlay_root" };
        if (old is not null) root.Children.Add(old);
        page.Content = root;
        return root;
    }

    private static void BeginPanel(ProgressPage panel)
    {
        Hide();
        _panel = panel;
        UserHidden = false;
    }

    private static void FinishPanel()
    {
        Hide();
        _panel = null;
        _root = null;
        UserHidden = false;
    }

    // 串行任务队列
    // 等待
    private static readonly SemaphoreSlim s_queue = new(1, 1);
    private static int s_queued;
    private static int s_fadeGen; // 浮层动效代次
    public static int Queued => Volatile.Read(ref s_queued);

    // 浮层展示期间执
    // after 用来展示本次结
    // 保证每次操作
    public static async Task<T> RunAsync<T>(ContentPage owner, string title,
        Func<BatchTracker, CancellationToken, Task<T>> work, Func<T, Task>? after = null)
    {
        Interlocked.Increment(ref s_queued);
        try { await s_queue.WaitAsync().ConfigureAwait(true); }
        finally { Interlocked.Decrement(ref s_queued); }

        var panel = new ProgressPage(title);
        var tracker = new BatchTracker();
        panel.Attach(tracker);
        var run = BatchRuns.Begin(title, tracker, RequestCancelCurrent);
        panel._run = run;
        BeginPanel(panel);
        VaultService.BeginLongOp();
        var act = Platform.CurrentActivity;
        if (act is not null)
        {
            // 任务启动即补申
            try { MainActivity.EnsureNotificationPermission(act as global::Android.App.Activity); } catch { }
            // 前台服务起不来
            try { BatchForegroundService.Attach(act, title, tracker, RequestCancelCurrent); }
            catch { }
        }
        Show(owner);
        bool cancelled = false;
        bool succeeded = false;
        T result = default!;
        try
        {
            result = await work(tracker, panel.Token);
            succeeded = true;
            return result;
        }
        catch (OperationCanceledException) { cancelled = true; throw; }
        finally
        {
            var snap = tracker.Snapshot();
            tracker.Finish();
            if (act is not null)
            {
                if (cancelled)
                    BatchForegroundService.ShowCompleted(act, title, L10n.T("已取消，未处理的文件保留在原位置"));
                else if (snap.Count > 0)
                    BatchForegroundService.ShowCompleted(act, title,
                        L10n.F("完成 {0} · 失败 {1} · 共 {2}", snap.Done, snap.Failed, snap.Count));
                try { BatchForegroundService.Detach(act); }
                catch { }
            }
            BatchRuns.End(run);
            FinishPanel();
            VaultService.EndLongOp();
            if (succeeded && after is not null)
            {
                try { await after(result); }
                catch { /* 结果展示失败不阻断队列释放与后续任务 */ }
            }
            s_queue.Release();
        }
    }
}
