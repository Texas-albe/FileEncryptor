using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using FileEncryptorGUI.Services;

namespace FileEncryptorGUI;

public sealed partial class PasswordDialog : ContentDialog
{
    public string Password => PwdBox.Password;

    // 是否二次确认。只
    // 用 init 属性时构造里
    // 解密只需输入一
    public bool NeedConfirm { get; }

    private PasswordBox PwdBox = null!;
    private PasswordBox? ConfirmBox;
    private TextBlock StrengthText = null!;
    private TextBlock MatchText = null!;

    public PasswordDialog(bool needConfirm = true)
    {
        NeedConfirm = needConfirm;

        RequestedTheme = App.Settings.Current.Theme switch
        {
            Services.AppTheme.Light => ElementTheme.Light,
            Services.AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default
        };

        var panel = new StackPanel { Spacing = 10 };

        PwdBox = new PasswordBox
        {
            PlaceholderText = L10n.T("密码"),
            PasswordChar = "●",
            PasswordRevealMode = PasswordRevealMode.Peek,
            Width = 320
        };

        StrengthText = new TextBlock { FontSize = 12, Text = "" };
        MatchText = new TextBlock { FontSize = 12, Foreground = ThemeService.BrushFor("AppDangerBrush", RequestedTheme) };

        panel.Children.Add(PwdBox);
        if (NeedConfirm)
        {
            ConfirmBox = new PasswordBox
            {
                PlaceholderText = L10n.T("确认密码"),
                PasswordChar = "●",
                PasswordRevealMode = PasswordRevealMode.Peek,
                Width = 320
            };
            panel.Children.Add(ConfirmBox);
            panel.Children.Add(StrengthText);
        }
        panel.Children.Add(MatchText);

        Content = panel;
        Title = L10n.T("输入密码");
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
        StrengthText.Foreground = result.Level switch
        {
            StrengthLevel.Weak => ThemeService.BrushFor("AppDangerBrush", RequestedTheme),
            StrengthLevel.Medium => ThemeService.BrushFor("AppCautionBrush", RequestedTheme),
            StrengthLevel.Strong => ThemeService.BrushFor("AppSuccessBrush", RequestedTheme),
            _ => ThemeService.BrushFor("AppTextSecondaryBrush", RequestedTheme),
        };
    }

    private void ValidateMatch()
    {
        var pwd = PwdBox.Password;
        // 解密
        if (!NeedConfirm)
        {
            MatchText.Text = "";
            IsPrimaryButtonEnabled = pwd.Length > 0;
            return;
        }
        var confirm = ConfirmBox?.Password ?? "";
        if (pwd.Length < 6) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; return; }
        if (string.IsNullOrEmpty(confirm)) { MatchText.Text = ""; IsPrimaryButtonEnabled = false; return; }
        if (pwd != confirm) { MatchText.Text = L10n.T("两次输入的密码不一致"); IsPrimaryButtonEnabled = false; return; }
        // 确认密码同走策
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
