using System.Collections.Generic;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 加密盘管理标签
public sealed partial class VaultTabView : UserControl
{
    private MainWindow? Host => MainWindow.Instance;

    public VaultTabView()
    {
        InitializeComponent();
        RefreshList();
    }

    public void RefreshList()
    {
        RefreshHint();
        MountedVaultsList.ItemsSource = new List<MountedVault>(App.Settings.Current.MountedVaults);
    }

    // 能力状态提示
    public void RefreshHint()
    {
        if (VaultHintBar == null) return;
        var host = Host;
        if (host == null) return;
        var reason = host.ViewModel.VaultAvailable ? "" : host.VaultUnavailableReason();
        VaultHintBar.Message = reason;
        VaultHintBar.IsOpen = reason.Length > 0;
    }

    private async void OnMountedVaultDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        var host = Host;
        if (host == null) return;
        var item = (e.OriginalSource as FrameworkElement)?.DataContext as MountedVault;
        if (item == null) return;
        await host.UnlockVaultDir(item.VaultDir);
        RefreshList();
    }

    private void OnRefreshMounted(object sender, RoutedEventArgs e) => RefreshList();
    private void OnVaultManager(object sender, RoutedEventArgs e) => Host?.OnVaultManager(sender, e);
    private void OnVaultInit(object sender, RoutedEventArgs e) => Host?.OnVaultInit(sender, e);
    private void OnVaultList(object sender, RoutedEventArgs e) => Host?.OnVaultList(sender, e);
    private void OnVaultRekey(object sender, RoutedEventArgs e) => Host?.OnVaultRekey(sender, e);
    private void OnVaultRecoveryCreate(object sender, RoutedEventArgs e) => Host?.OnVaultRecoveryCreate(sender, e);
    private void OnVaultRecoveryOpen(object sender, RoutedEventArgs e) => Host?.OnVaultRecoveryOpen(sender, e);
    private void OnVaultMount(object sender, RoutedEventArgs e) => Host?.OnVaultMount(sender, e);
    private void OnMountedVaults(object sender, RoutedEventArgs e) => Host?.OnMountedVaults(sender, e);
    private void OnVaultUnmount(object sender, RoutedEventArgs e) => Host?.OnVaultUnmount(sender, e);
    private void OnVaultFormat(object sender, RoutedEventArgs e) => Host?.OnVaultFormat(sender, e);
    private void OnVaultLock(object sender, RoutedEventArgs e) => Host?.OnVaultLock(sender, e);
    private void OnVaultUnlock(object sender, RoutedEventArgs e) => Host?.OnVaultUnlock(sender, e);
}
