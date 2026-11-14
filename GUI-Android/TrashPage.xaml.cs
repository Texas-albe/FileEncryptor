// 回收站页
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class TrashPage : ContentPage
{
    private readonly VaultService _vault = VaultService.Shared;
    private int _loadVer;

    public TrashPage()
    {
        InitializeComponent();
        VaultService.SessionLocked += OnSessionLocked;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        VaultService.SessionLocked -= OnSessionLocked;
        VaultService.SessionLocked += OnSessionLocked;
        LoadAsync();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        VaultService.SessionLocked -= OnSessionLocked;
    }

    private async void LoadAsync()
    {
        int ver = ++_loadVer;
        try
        {
            var (list, trash) = await Task.Run(() =>
            {
                var items = VaultTrash.List(_vault);
                ulong t = 0;
                try { t = _vault.StatSpaceEx().Trash; } catch { }
                return (items, t);
            });
            if (ver != _loadVer) return;
            TrashList.ItemsSource = list;
            // 空列表没有可清
            BtnEmpty.IsVisible = list.Count > 0;
            int soon = list.Count(e => e.IsExpiring);
            string tail = soon > 0 ? L10n.F(" 其中 {0} 项即将到期。", soon) : "";
            LblHint.Text = list.Count == 0
                ? L10n.F("回收站为空。删除的文件默认保留 {0} 天。", VaultTrash.RetentionDays)
                : L10n.F("共 {0} 项，占用 {1}；默认保留 {2} 天，到期自动清理。", list.Count, VaultItem.FormatSize(trash), VaultTrash.RetentionDays) + tail;
        }
        catch (Exception ex)
        {
            LblHint.Text = L10n.T("读取回收站失败：") + ex.Message;
        }
    }

    private async void OnRestore(object? sender, EventArgs e)
    {
        if (sender is not Button b || b.CommandParameter is not TrashEntry item) return;
        try
        {
            string target = await Task.Run(() => VaultTrash.Restore(_vault, item));
            await DisplayAlertAsync(L10n.T("已恢复"), L10n.F("「{0}」已恢复到 {1}", item.Name, target), L10n.T("确定"));
            LoadAsync();
        }
        catch (Exception ex) { await DisplayAlertAsync(L10n.T("恢复失败"), ex.Message, L10n.T("确定")); }
    }

    private async void OnDelete(object? sender, EventArgs e)
    {
        if (sender is not Button b || b.CommandParameter is not TrashEntry item) return;
        if (!await DisplayAlertAsync(L10n.T("永久删除"),
                L10n.F("彻底删除「{0}」？无法恢复。", item.Name), L10n.T("永久删除"), L10n.T("取消"))) return;
        try
        {
            await Task.Run(() => VaultTrash.DeleteForever(_vault, item));
            LoadAsync();
        }
        catch (Exception ex) { await DisplayAlertAsync(L10n.T("删除失败"), ex.Message, L10n.T("确定")); }
    }

    private async void OnEmpty(object? sender, EventArgs e)
    {
        if (!await DisplayAlertAsync(L10n.T("清空回收站"),
                L10n.T("清空回收站？全部内容将彻底删除。"), L10n.T("清空"), L10n.T("取消"))) return;
        try
        {
            await Task.Run(() => VaultTrash.Empty(_vault));
            LoadAsync();
        }
        catch (Exception ex) { await DisplayAlertAsync(L10n.T("清空失败"), ex.Message, L10n.T("确定")); }
    }

    private async void OnClose(object? sender, EventArgs e)
        => await Navigation.PopModalAsync();

    private void OnSessionLocked()
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try { await Navigation.PopModalAsync(); } catch { }
        });
    }
}
