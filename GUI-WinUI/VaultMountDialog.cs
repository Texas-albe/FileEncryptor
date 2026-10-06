using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

// 挂载为磁盘对话框：盘符/目录（默认填上次用的）+ 密码 + 可写勾选
public sealed partial class VaultMountDialog : ContentDialog
{
    public string MountPoint => MpBox.Text.Trim();
    public string Password => PwBox.Password;
    public bool ReadWrite => RwChk != null && RwChk.IsChecked == true;

    private readonly TextBox MpBox = null!;
    private readonly PasswordBox PwBox = null!;
    private readonly CheckBox? RwChk;

    // defaultPoint：上次用的盘符，空则用 Z:
    public VaultMountDialog(bool allowReadWrite, string defaultPoint = "")
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
        // 固定 1 分钟空闲自动锁（FE-Mounter --idle-timeout），只告知、不给开关
        panel.Children.Add(new TextBlock
        {
            Text = L10n.T("挂上后 1 分钟不操作会自动锁定。"),
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

        if (allowReadWrite)
        {
            RwChk = new CheckBox
            {
                Content = L10n.T("可写挂载（需 vault_rw）"),
                IsChecked = false,
            };
            panel.Children.Add(RwChk);
        }

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
