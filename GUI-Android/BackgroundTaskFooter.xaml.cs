// Flyout 底部
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class BackgroundTaskFooter : ContentView
{
    private BatchRun? _sub;

    public BackgroundTaskFooter()
    {
        InitializeComponent();
        BatchRuns.Changed += () => MainThread.BeginInvokeOnMainThread(Refresh);
        Refresh();
    }

    private void Refresh()
    {
        var run = BatchRuns.Current;
        if (!ReferenceEquals(run, _sub))
        {
            if (_sub is not null) _sub.Tracker.Updated -= OnProgress;
            _sub = run;
            if (run is not null) run.Tracker.Updated += OnProgress;
        }
        Root.IsVisible = run is not null;
        if (run is not null) Apply(run.Title, run.Tracker.Snapshot());
    }

    private void OnProgress(BatchSnapshot s)
        => MainThread.BeginInvokeOnMainThread(() =>
        {
            var run = BatchRuns.Current;
            if (run is not null) Apply(run.Title, s);
        });

    private void Apply(string title, BatchSnapshot s)
        => LblTask.Text = $"{title} {s.OverallPct:F1}%";

    private void OnOpen(object? sender, TappedEventArgs e)
    {
        var shell = Shell.Current;
        if (shell is not null) shell.FlyoutIsPresented = false;
        ProgressPage.Show();
    }
}
