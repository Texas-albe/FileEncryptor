using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 主页工作区标签
// 控件字段全部 public
// MainWindow 通过 ActiveHome 代理属性访
public sealed partial class HomeTabView : UserControl
{
    private MainWindow? Host => MainWindow.Instance;

    public HomeTabView()
    {
        InitializeComponent();
        // Binding 依赖 DataContext 指向主窗体
        DataContext = MainWindow.Instance;

        // WinUI 的横向滚动条
        // 滚动条显示时内
        foreach (var scroller in new[] { ActionScroll, KeyMgmtScroll, WrapScroll, OptionsScroll })
        {
            scroller.LayoutUpdated += (_, _) =>
            {
                var reserve = scroller.ComputedHorizontalScrollBarVisibility == Visibility.Visible ? 14.0 : 0.0;
                if (scroller.Padding.Bottom != reserve)
                    scroller.Padding = new Thickness(0, 0, 0, reserve);
            };
        }
    }

    private void OnActionRadioChecked(object sender, RoutedEventArgs e) => Host?.OnActionRadioChecked(sender, e);
    private void OnAddDir(object sender, RoutedEventArgs e) => Host?.OnAddDir(sender, e);
    private void OnAddFiles(object sender, RoutedEventArgs e) => Host?.OnAddFiles(sender, e);
    private void OnBrowseIdentity(object sender, RoutedEventArgs e) => Host?.OnBrowseIdentity(sender, e);
    private void OnBrowseKeyfile(object sender, RoutedEventArgs e) => Host?.OnBrowseKeyfile(sender, e);
    private void OnBrowseOutDir(object sender, RoutedEventArgs e) => Host?.OnBrowseOutDir(sender, e);
    private void OnBrowseRecipient(object sender, RoutedEventArgs e) => Host?.OnBrowseRecipient(sender, e);
    private void OnBrowseVaultDir(object sender, RoutedEventArgs e) => Host?.OnBrowseVaultDir(sender, e);
    private void OnBrowseWatermarkKey(object sender, RoutedEventArgs e) => Host?.OnBrowseWatermarkKey(sender, e);
    private void OnBrowseWrapFile(object sender, RoutedEventArgs e) => Host?.OnBrowseWrapFile(sender, e);
    private void OnBrowseWrapOut(object sender, RoutedEventArgs e) => Host?.OnBrowseWrapOut(sender, e);
    private void OnCancelClicked(object sender, RoutedEventArgs e) => Host?.OnCancelClicked(sender, e);
    private void OnClearFiles(object sender, RoutedEventArgs e) => Host?.OnClearFiles(sender, e);
    private void OnCompressLevelChanged(NumberBox sender, NumberBoxValueChangedEventArgs args) => Host?.OnCompressLevelChanged(sender, args);
    private void OnFileCipherChanged(object sender, SelectionChangedEventArgs e) => Host?.OnFileCipherChanged(sender, e);
    private void OnFileListDragOver(object sender, DragEventArgs e) => Host?.OnFileListDragOver(sender, e);
    private void OnFileListDrop(object sender, DragEventArgs e) => Host?.OnFileListDrop(sender, e);
    private void OnIdentityChanged(object sender, TextChangedEventArgs e) => Host?.OnIdentityChanged(sender, e);
    private void OnIntoVaultChanged(object sender, RoutedEventArgs e) => Host?.OnIntoVaultChanged(sender, e);
    private void OnItemCheckedChanged(object sender, RoutedEventArgs e) => Host?.OnItemCheckedChanged(sender, e);
    private void OnItemLoaded(object sender, RoutedEventArgs e) => Host?.OnItemLoaded(sender, e);
    private void OnKeyMgmtRadioChecked(object sender, RoutedEventArgs e) => Host?.OnKeyMgmtRadioChecked(sender, e);
    private void OnKeyfileChanged(object sender, TextChangedEventArgs e) => Host?.OnKeyfileChanged(sender, e);
    private void OnModeChanged(object sender, SelectionChangedEventArgs e) => Host?.OnModeChanged(sender, e);
    private void OnOptionChanged(object sender, RoutedEventArgs e) => Host?.OnOptionChanged(sender, e);
    private void OnExcludeChanged(object sender, TextChangedEventArgs e) => Host?.OnExcludeChanged(sender, e);
    private void OnOutDirChanged(object sender, TextChangedEventArgs e) => Host?.OnOutDirChanged(sender, e);
    private void OnPreviewClicked(object sender, RoutedEventArgs e) => Host?.OnPreviewClicked(sender, e);
    private void OnRecipientChanged(object sender, TextChangedEventArgs e) => Host?.OnRecipientChanged(sender, e);
    private void OnRewrapClicked(object sender, RoutedEventArgs e) => Host?.OnRewrapClicked(sender, e);
    private void OnRunClicked(object sender, RoutedEventArgs e) => Host?.OnRunClicked(sender, e);
    private void OnSourceChanged(object sender, SelectionChangedEventArgs e) => Host?.OnSourceChanged(sender, e);
    private void OnSplitSizeChanged(NumberBox sender, NumberBoxValueChangedEventArgs args) => Host?.OnSplitSizeChanged(sender, args);
    private void OnSplitUnitChanged(object sender, SelectionChangedEventArgs e) => Host?.OnSplitUnitChanged(sender, e);
    private void OnVaultDirChanged(object sender, TextChangedEventArgs e) => Host?.OnVaultDirChanged(sender, e);
    private void OnWrapAlgChanged(object sender, SelectionChangedEventArgs e) => Host?.OnWrapAlgChanged(sender, e);
    private void OnWrapInputChanged(object sender, TextChangedEventArgs e) => Host?.OnWrapInputChanged(sender, e);
    private void OnWrapOutputChanged(object sender, TextChangedEventArgs e) => Host?.OnWrapOutputChanged(sender, e);
    private void OnWrapRadioChecked(object sender, RoutedEventArgs e) => Host?.OnWrapRadioChecked(sender, e);
}
