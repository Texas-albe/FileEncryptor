// 收藏夹
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class FavoritesPage : ContentPage
{
    private readonly VaultService _vault;
    private readonly Action<VaultItem> _onPick;

    public FavoritesPage(VaultService vault, Action<VaultItem> onPick)
    {
        InitializeComponent();
        _vault = vault;
        _onPick = onPick;
        VaultService.SessionLocked += OnSessionLocked;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        // 部分 ROM push 无系统过渡
        UiFx.AppearFade(this, dy: 0, ms: 240);
        VaultService.SessionLocked -= OnSessionLocked;
        VaultService.SessionLocked += OnSessionLocked;
        Load();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        VaultService.SessionLocked -= OnSessionLocked;
    }

    private void Load()
    {
        var list = new List<VaultItem>();
        var keep = new List<string>();
        var stored = VaultFavorites.Load(_vault);
        foreach (string rel in stored)
        {
            if (!_vault.TryGetAttr(rel, out ulong size, out bool isDir))
                continue;   // 改名/移动后失效
            keep.Add(rel);
            int slash = rel.LastIndexOf('/');
            list.Add(new VaultItem
            {
                Name = slash < 0 ? rel : rel[(slash + 1)..],
                RelPath = rel,
                IsDir = isDir,
                Size = size,
                Mtime = DateTimeOffset.Now,
            });
        }
        // 回写清理
        foreach (string stale in stored.Where(r => !keep.Contains(r)))
            VaultFavorites.Remove(_vault, stale);
        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        FavList.ItemsSource = list;
        LblHint.Text = list.Count == 0 ? L10n.T("收藏夹为空") : L10n.F("共 {0} 项（仅本设备保存）", list.Count);
    }

    private async void OnItemTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not VaultItem item) return;
        try
        {
            _onPick(item);
            await Navigation.PopAsync();
        }
        catch (Exception ex) { await DisplayAlertAsync(L10n.T("打开失败"), ex.Message, L10n.T("确定")); }
    }

    private void OnRemove(object? sender, EventArgs e)
    {
        if (sender is not Button b || b.CommandParameter is not VaultItem item) return;
        VaultFavorites.Remove(_vault, item.RelPath);
        Load();
    }

    private async void OnClose(object? sender, EventArgs e) => await Navigation.PopAsync();

    private void OnSessionLocked()
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try { await Navigation.PopAsync(); } catch { }
        });
    }
}
