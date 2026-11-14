using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 挂载
public sealed partial class VaultMountDialog : ContentDialog
{
    public string MountPoint => MpBox.Text.Trim();
    public string Password => PwBox.Password;
    public bool ReadWrite => RwChk != null && RwChk.IsChecked == true;
    // 挂载前清空
    public bool FormatVault => FmtChk != null && FmtChk.IsChecked == true;
    // 本机免密
    public bool NoPassword => NoPwdChk != null && NoPwdChk.IsChecked == true;

    private readonly TextBox MpBox = null!;
    private readonly PasswordBox PwBox = null!;
    private readonly CheckBox? RwChk;
    private readonly CheckBox? FmtChk;
    private readonly CheckBox? NoPwdChk;

    // defaultPoint
    // vaultDir
    public VaultMountDialog(bool allowReadWrite, string defaultPoint = "", string vaultDir = "")
    {
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };

        var panel = new StackPanel { Spacing = 10 };

        MpBox = new TextBox
        {
            PlaceholderText = L10n.T("盘符如 Z: 或目录如 C:\\fe_mnt"),
            Text = string.IsNullOrWhiteSpace(defaultPoint) ? "Z:" : defaultPoint.Trim(),
            Width = 320,
        };
        panel.Children.Add(new TextBlock { Text = L10n.T("盘符"), FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        panel.Children.Add(MpBox);
        // 固定 1 分钟空闲自
        panel.Children.Add(new TextBlock
        {
            Text = L10n.T("挂载后 1 分钟无操作将自动锁定。"),
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
        });

        PwBox = new PasswordBox
        {
            PlaceholderText = L10n.T("加密盘密码"),
            PasswordChar = "●",
            PasswordRevealMode = PasswordRevealMode.Peek,
            Width = 320,
        };
        panel.Children.Add(new TextBlock { Text = L10n.T("密码"), FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        panel.Children.Add(PwBox);

        // 本机免密
        // 已绑定
        NoPwdChk = new CheckBox
        {
            Content = L10n.T("本机免密（今后在本机解锁此盘不再输密码）"),
            IsChecked = !string.IsNullOrEmpty(vaultDir) && DeviceKeyService.IsBound(vaultDir),
        };
        panel.Children.Add(NoPwdChk);

        if (allowReadWrite)
        {
            RwChk = new CheckBox
            {
                Content = L10n.T("可写挂载（需 vault_rw）"),
                IsChecked = false,
            };
            panel.Children.Add(RwChk);
        }

        // 挂载前格式化
        // 适合「盘里有旧数
        FmtChk = new CheckBox
        {
            Content = L10n.T("挂载前清空此加密盘（格式化）"),
            IsChecked = false,
        };
        panel.Children.Add(FmtChk);

        Content = panel;
        Title = L10n.T("挂载为磁盘");
        PrimaryButtonText = L10n.T("确定");
        SecondaryButtonText = L10n.T("取消");
        IsPrimaryButtonEnabled = false;

        MpBox.TextChanged += (_, _) => Validate();
        PwBox.PasswordChanged += (_, _) => Validate();
    }

    private void Validate()
    {
        IsPrimaryButtonEnabled = !string.IsNullOrEmpty(MpBox.Text.Trim())
            && PwBox.Password.Length > 0;
    }
}
