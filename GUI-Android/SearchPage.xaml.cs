// 库内搜索
// 可随时取消
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class SearchPage : ContentPage
{
    private const int MaxResults = 2000;
    private const int MaxDepth = 16;

    private readonly VaultService _vault;
    private readonly string _startPath;
    private readonly Action<VaultItem> _onPick;
    private CancellationTokenSource? _cts;
    private int _ver;

    public SearchPage(VaultService vault, string startPath, Action<VaultItem> onPick)
    {
        InitializeComponent();
        _vault = vault;
        _startPath = startPath;
        _onPick = onPick;
        VaultService.SessionLocked += OnSessionLocked;
        SearchBox.Focus();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        // 部分 ROM push 无系统过渡
        UiFx.AppearFade(this, dy: 0, ms: 240);
        VaultService.SessionLocked -= OnSessionLocked;
        VaultService.SessionLocked += OnSessionLocked;
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _cts?.Cancel();
        VaultService.SessionLocked -= OnSessionLocked;
    }

    private void OnQueryChanged(object? sender, TextChangedEventArgs e)
    {
        _cts?.Cancel();
        int ver = ++_ver;
        string q = e.NewTextValue?.Trim() ?? "";
        if (q.Length == 0)
        {
            ResultList.ItemsSource = null;
            LblStatus.Text = L10n.T("只搜文件名，不解密内容。");
            return;
        }
        var cts = new CancellationTokenSource();
        _cts = cts;
        bool whole = SwRecursive.IsToggled;
        _ = Task.Run(async () =>
        {
            try { await Task.Delay(300, cts.Token); } catch { return; }
            if (cts.IsCancellationRequested) return;
            var hits = await Task.Run(() => Search(q, whole, cts.Token));
            if (cts.IsCancellationRequested || ver != _ver) return;
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (ver != _ver) return;
                ResultList.ItemsSource = hits;
                LblStatus.Text = hits.Count == 0
                    ? L10n.T("无匹配结果")
                    : L10n.F("找到 {0} 项", hits.Count) + (hits.Count >= MaxResults ? L10n.F("，仅显示前 {0} 条", MaxResults) : "");
            });
        });
    }

    private List<VaultItem> Search(string query, bool wholeVault, CancellationToken ct)
    {
        var hits = new List<VaultItem>();
        string root = wholeVault ? "" : _startPath;
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));
        int dirs = 0;
        while (queue.Count > 0 && hits.Count < MaxResults)
        {
            if (ct.IsCancellationRequested) break;
            var (dir, depth) = queue.Dequeue();
            List<VaultItem> kids;
            try { kids = _vault.ListDir(dir); }
            catch (VaultException) { continue; }
            dirs++;
            foreach (var it in kids)
            {
                if (it.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
                {
                    hits.Add(it);
                    if (hits.Count >= MaxResults) break;
                }
                if (it.IsDir && depth + 1 < MaxDepth) queue.Enqueue((it.RelPath, depth + 1));
            }
            if (dirs % 20 == 0)
            {
                int d = dirs;
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    if (!ct.IsCancellationRequested)
                        LblStatus.Text = L10n.F("已扫描 {0} 个目录，找到 {1} 项…", d, hits.Count);
                });
            }
        }
        return hits;
    }

    private async void OnResultTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not VaultItem item) return;
        try
        {
            _onPick(item);
            await Navigation.PopAsync();
        }
        catch (Exception ex) { await DisplayAlertAsync(L10n.T("打开失败"), ex.Message, L10n.T("确定")); }
    }

    private void OnRecursiveChanged(object? sender, ToggledEventArgs e)
    {
        // 切换范围
        _cts?.Cancel();
        OnQueryChanged(sender, new TextChangedEventArgs("", SearchBox.Text ?? ""));
    }

    private async void OnClose(object? sender, EventArgs e) => await Navigation.PopAsync();

    private void OnSessionLocked()
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            _cts?.Cancel();
            try { await Navigation.PopAsync(); } catch { }
        });
    }
}
