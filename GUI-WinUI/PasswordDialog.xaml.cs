using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

public sealed partial class PasswordDialog : ContentDialog
{
    public string Password => PwdBox.Password;

    private PasswordBox PwdBox = null!;
    private PasswordBox ConfirmBox = null!;
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
            PlaceholderText = "口令",
            PasswordChar = "●",
            PasswordRevealMode = PasswordRevealMode.Peek,
            Width = 320
        };

        ConfirmBox = new PasswordBox
        {
            PlaceholderText = "确认口令",
            PasswordChar = "●",
            PasswordRevealMode = PasswordRevealMode.Peek,
            Width = 320
        };

        StrengthText = new TextBlock { FontSize = 12, Text = "" };
        MatchText = new TextBlock { FontSize = 12, Foreground = new SolidColorBrush(Colors.Red) };

        panel.Children.Add(PwdBox);
        panel.Children.Add(ConfirmBox);
        panel.Children.Add(StrengthText);
        panel.Children.Add(MatchText);

        Content = panel;
        Title = "输入口令";
        PrimaryButtonText = "确定";
        SecondaryButtonText = "取消";
        IsPrimaryButtonEnabled = false;

        PwdBox.PasswordChanged += (_, _) => { UpdateStrength(); ValidateMatch(); };
        ConfirmBox.PasswordChanged += (_, _) => ValidateMatch();
    }

    private void UpdateStrength()
    {
        var result = PasswordStrengthService.Evaluate(PwdBox.Password);
        if (result.Level == StrengthLevel.Empty) { StrengthText.Text = ""; return; }
        StrengthText.Text = $"强度：{result.Label}";
        StrengthText.Foreground = new SolidColorBrush(ParseColor(result.ColorHex));
    }

    // 仅接受 #RGB / #RRGGBB / #AARRGGBB，非法格式回退灰色，避免 Substring/Parse 越界
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
        if (pwd.Length < 6) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; return; }
        if (string.IsNullOrEmpty(ConfirmBox.Password)) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; return; }
        if (pwd != ConfirmBox.Password) { MatchText.Text = "两次输入的口令不一致"; IsPrimaryButtonEnabled = false; return; }
        // 确认口令时同样走策略校验，避免 GUI 提前放行弱口令
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
