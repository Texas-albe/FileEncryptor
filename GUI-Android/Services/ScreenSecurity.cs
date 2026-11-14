// 截屏保护
// 关闭需
using Android.Views;

namespace FileEncryptorMobile.Services;

internal static class ScreenSecurity
{
    public const string Key = "secure_screenshot";
    public static bool Enabled => Preferences.Default.Get(Key, true);

    // 主窗口即时增删 FLAG_SECURE
    public static void Apply(global::Android.Views.Window? w)
    {
        if (w is null) return;
        if (Enabled) w.AddFlags(WindowManagerFlags.Secure);
        else w.ClearFlags(WindowManagerFlags.Secure);
    }

    // overlay / 栏窗口
    public static WindowManagerFlags OverlayFlags(WindowManagerFlags baseFlags) =>
        baseFlags | (Enabled ? WindowManagerFlags.Secure : 0);
}
