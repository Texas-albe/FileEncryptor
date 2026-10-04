using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

public sealed partial class PasswordDialog : ContentDialog
{
    public string Password => PwdBox.Password;

    // 解密只需输入一次：没有确认框，也不做强度策略校验（既有口令可能不满足现行策略）
    public bool NeedConfirm { get; init; } = true;

    private PasswordBox PwdBox = null!;
    private PasswordBox? ConfirmBox;
    private TextBlock StrengthText = null!;
    private TextBlock MatchText = null!;

    public PasswordDialog()
    {
        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };

        var panel = new StackPanel { Spacing = 10 };

        PwdBox = new PasswordBox
        {
            PlaceholderText = L10n.T("口令"),
            PasswordChar = "●",
            PasswordRevealMode = PasswordRevealMode.Peek,
            Width = 320
        };

        StrengthText = new TextBlock { FontSize = 12, Text = "" };
        MatchText = new TextBlock { FontSize = 12, Foreground = new SolidColorBrush(Colors.Red) };

        panel.Children.Add(PwdBox);
        if (NeedConfirm)
        {
            ConfirmBox = new PasswordBox
            {
                PlaceholderText = L10n.T("确认口令"),
                PasswordChar = "●",
                PasswordRevealMode = PasswordRevealMode.Peek,
                Width = 320
            };
            panel.Children.Add(ConfirmBox);
            panel.Children.Add(StrengthText);
        }
        panel.Children.Add(MatchText);

        Content = panel;
        Title = L10n.T("输入口令");
        PrimaryButtonText = L10n.T("确定");
        SecondaryButtonText = L10n.T("取消");
        IsPrimaryButtonEnabled = false;

        if (NeedConfirm)
        {
            PwdBox.PasswordChanged += (_, _) => { UpdateStrength(); ValidateMatch(); };
            ConfirmBox!.PasswordChanged += (_, _) => ValidateMatch();
        }
        else
        {
            PwdBox.PasswordChanged += (_, _) => IsPrimaryButtonEnabled = PwdBox.Password.Length > 0;
        }
    }

    private void UpdateStrength()
    {
        if (!NeedConfirm) return;
        var result = PasswordStrengthService.Evaluate(PwdBox.Password);
        if (result.Level == StrengthLevel.Empty) { StrengthText.Text = ""; return; }
        StrengthText.Text = L10n.F("强度：{0}", result.Label);
        StrengthText.Foreground = new SolidColorBrush(ParseColor(result.ColorHex));
    }

    // 颜色格式校验，非法回退灰色
    private static Windows.UI.Color ParseColor(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex[0] != '#') return Colors.Gray;
        var d = hex.Substring(1);
        if (d.Length == 6)
        {
            if (byte.TryParse(d.Substring(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var r) &&
                byte.TryParse(d.Substring(2, 2), System.Globalization.NumberStyles.HexNumber, null, out var g) &&
                byte.TryParse(d.Substring(4, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
                return Windows.UI.Color.FromArgb(0xFF, r, g, b);
            return Colors.Gray;
        }
        if (d.Length == 8)
        {
            if (byte.TryParse(d.Substring(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var a) &&
                byte.TryParse(d.Substring(2, 2), System.Globalization.NumberStyles.HexNumber, null, out var r) &&
                byte.TryParse(d.Substring(4, 2), System.Globalization.NumberStyles.HexNumber, null, out var g) &&
                byte.TryParse(d.Substring(6, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
                return Windows.UI.Color.FromArgb(a, r, g, b);
            return Colors.Gray;
        }
        return Colors.Gray;
    }

    private void ValidateMatch()
    {
        var pwd = PwdBox.Password;
        // 解密：只校验非空。既有口令可能不满足现行强度策略，据此拒绝会锁死用户自己的文件
        if (!NeedConfirm)
        {
            MatchText.Text = "";
            IsPrimaryButtonEnabled = pwd.Length > 0;
            return;
        }
        var confirm = ConfirmBox?.Password ?? "";
        if (pwd.Length < 6) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; return; }
        if (string.IsNullOrEmpty(confirm)) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; return; }
        if (pwd != confirm) { MatchText.Text = L10n.T("两次输入的口令不一致"); IsPrimaryButtonEnabled = false; return; }
        // 确认口令同走策略校验
        if (!PasswordStrengthService.MeetsPolicy(pwd, out var reason))
        {
            MatchText.Text = reason;
            IsPrimaryButtonEnabled = false;
            return;
        }
        MatchText.Text = "";
        IsPrimaryButtonEnabled = true;
    }
}
