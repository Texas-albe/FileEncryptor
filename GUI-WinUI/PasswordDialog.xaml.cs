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
        StrengthText.Foreground = new SolidColorBrush(
            ColorHelper.FromArgb(0xFF,
                byte.Parse(result.ColorHex.Substring(1, 2), System.Globalization.NumberStyles.HexNumber),
                byte.Parse(result.ColorHex.Substring(3, 2), System.Globalization.NumberStyles.HexNumber),
                byte.Parse(result.ColorHex.Substring(5, 2), System.Globalization.NumberStyles.HexNumber)));
    }

    private void ValidateMatch()
    {
        bool hasPwd = PwdBox.Password.Length >= 6;
        bool match = PwdBox.Password == ConfirmBox.Password;
        if (!hasPwd) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; }
        else if (string.IsNullOrEmpty(ConfirmBox.Password)) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; }
        else if (!match) { MatchText.Text = "两次输入的口令不一致"; IsPrimaryButtonEnabled = false; }
        else { MatchText.Text = ""; IsPrimaryButtonEnabled = true; }
    }
}
