using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 设置标签页
public sealed partial class SettingsTabView : UserControl
{
    // 同步期间屏蔽事
    private bool _syncing;

    private MainWindow? Host => MainWindow.Instance;

    public SettingsTabView()
    {
        InitializeComponent();
        BgImageEdit.Text = App.Settings.Current.CustomBackgroundPath ?? "";
        SyncTheme(App.Settings.Current.Theme);
        SyncLang(L10n.Current);
    }

    public void SyncTheme(Services.AppTheme theme)
    {
        _syncing = true;
        ThemeLightRb.IsChecked = theme == Services.AppTheme.Light;
        ThemeDarkRb.IsChecked = theme == Services.AppTheme.Dark;
        ThemeSystemRb.IsChecked = theme == Services.AppTheme.System;
        _syncing = false;
    }

    public void SyncLang(string lang)
    {
        _syncing = true;
        LangZhRb.IsChecked = lang == L10n.Zh;
        LangEnRb.IsChecked = lang == L10n.En;
        LangRuRb.IsChecked = lang == L10n.Ru;
        _syncing = false;
    }

    private void OnThemeLight(object sender, RoutedEventArgs e) { if (!_syncing) Host?.OnThemeLight(sender, e); }
    private void OnThemeDark(object sender, RoutedEventArgs e) { if (!_syncing) Host?.OnThemeDark(sender, e); }
    private void OnThemeSystem(object sender, RoutedEventArgs e) { if (!_syncing) Host?.OnThemeSystem(sender, e); }
    private void OnLangZh(object sender, RoutedEventArgs e) { if (!_syncing) Host?.OnLangZh(sender, e); }
    private void OnLangEn(object sender, RoutedEventArgs e) { if (!_syncing) Host?.OnLangEn(sender, e); }
    private void OnLangRu(object sender, RoutedEventArgs e) { if (!_syncing) Host?.OnLangRu(sender, e); }

    private async void OnBrowseBackground(object sender, RoutedEventArgs e)
    {
        var host = Host;
        if (host == null) return;
        var path = await host.PickBackgroundImageAsync();
        if (path != null) BgImageEdit.Text = path;
    }

    private void OnClearBackground(object sender, RoutedEventArgs e)
    {
        BgImageEdit.Text = "";
        Host?.ApplyCustomBackground(null);
    }

    private void OnApplyBackground(object sender, RoutedEventArgs e)
    {
        Host?.ApplyCustomBackground(BgImageEdit.Text);
    }

    private void OnRetryCliDetection(object sender, RoutedEventArgs e) => Host?.OnRetryCliDetection(sender, e);
    private void OnEditConfig(object sender, RoutedEventArgs e) => Host?.OnEditConfig(sender, e);
    private void OnCheckForUpdate(object sender, RoutedEventArgs e) => Host?.OnCheckForUpdate(sender, e);
    private void OnCredits(object sender, RoutedEventArgs e) => Host?.OnCredits(sender, e);
    private void OnReadme(object sender, RoutedEventArgs e) => Host?.OnReadme(sender, e);
}
