// 鸣谢页
using Microsoft.Maui.ApplicationModel;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class CreditsPage : ContentPage
{
    public CreditsPage()
    {
        InitializeComponent();
        LblTitle.Text = L10n.F("FileEncryptor v{0} — 鸣谢", AppInfo.Current.VersionString);
    }

    private async void OnLinkTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not string url || url.Length == 0) return;
        try
        {
            await Launcher.Default.OpenAsync(new Uri(url));
        }
        catch
        {
            await DisplayAlertAsync(L10n.T("无法打开"), L10n.T("未能启动浏览器，请手动访问该链接。"), L10n.T("确定"));
        }
    }

    private async void OnClose(object? sender, EventArgs e)
    {
        await Navigation.PopModalAsync();
    }
}
