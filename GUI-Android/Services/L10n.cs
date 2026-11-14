// 多语言
using System.Globalization;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile.Services;

public static class L10n
{
    // 语言偏好键
    public const string PrefKey = "ui_lang";
    private static int _lang;
    public static int Lang => _lang;

    // App 构造时调用
    public static void Init()
    {
        string v = Preferences.Default.Get(PrefKey, "");
        if (v.Length == 0)
            v = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName switch
            {
                "en" => "en",
                "ru" => "ru",
                _ => "zh",
            };
        _lang = v switch { "en" => 1, "ru" => 2, _ => 0 };
    }

    // 设置语言并持久
    public static void SetLang(string code)
    {
        _lang = code switch { "en" => 1, "ru" => 2, _ => 0 };
        Preferences.Default.Set(PrefKey, code);
        // 静态文案失效
        VaultItem.InvalidateText();
        SettingsPage.InvalidateChoices();
    }

    // 翻译单个串
    public static string T(string zh) => _lang switch
    {
        1 => L10nEn.Get(zh),
        2 => L10nRu.Get(zh),
        _ => zh,
    };

    // 带参格式化
    public static string F(string zh, params object?[] args)
        => string.Format(T(zh), args);
}
