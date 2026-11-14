// 库内目录选择器
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class DirPickerPage : ContentPage
{
    private readonly VaultService _vault;
    private readonly Func<string, Task> _onPick;
    private string _path;

    public DirPickerPage(VaultService vault, string startPath, Func<string, Task> onPick)
    {
        InitializeComponent();
        _vault = vault;
        _onPick = onPick;
        _path = startPath;
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

    private bool _loading;
    private int _loadGen;

    // 后台加载
    private void Load()
    {
        if (_loading) return;
        _loading = true;
        int gen = ++_loadGen;
        string path = _path;
        DirList.ItemsSource = null;
        Busy.IsVisible = true;
        Busy.IsRunning = true;
        PathLabel.Text = "/" + path;
        Task.Run(() =>
        {
            List<VaultItem> dirs;
            Exception? err = null;
            try { dirs = _vault.ListDir(path).Where(i => i.IsDir).ToList(); }
            catch (Exception ex) { dirs = new List<VaultItem>(); err = ex; }
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (gen != _loadGen) return;   // 已切到别
                _loading = false;
                Busy.IsVisible = false;
                Busy.IsRunning = false;
                if (err is not null) { PathLabel.Text = L10n.T("读取失败：") + err.Message; return; }
                DirList.ItemsSource = dirs;
            });
        });
    }

    private void OnDirTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not VaultItem item || !item.IsDir) return;
        _path = item.RelPath;
        Load();
    }

    private void OnUp(object? sender, EventArgs e)
    {
        int slash = _path.LastIndexOf('/');
        _path = slash < 0 ? "" : _path[..slash];
        Load();
    }

    private async void OnPickHere(object? sender, EventArgs e)
    {
        try
        {
            // 先回列表页
            // 若先跑任务本页
            await Navigation.PopAsync();
            await _onPick(_path);
        }
        catch (Exception ex) { await DisplayAlertAsync(L10n.T("移动失败"), ex.Message, L10n.T("确定")); }
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
