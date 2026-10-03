// 直接调 DWM 设置窗口系统背景，绕过 Window.SystemBackdrop。
// 原因：托管属性赋值后 DWM 侧 DWMWA_SYSTEMBACKDROP_TYPE 仍是 0(NONE)，
// WinUI 3.1.x 的 setter 在窗口已激活后不再向 DWM 递交请求。
using System;
using System.Runtime.InteropServices;

namespace FileEncryptorGUI.Services;

internal static class DwmBackdrop
{
    // DWMWA_SYSTEMBACKDROP_TYPE = 38
    private const int AttrSystemBackdropType = 38;

    // DWMSBT_MAIN = 1，即 Mica
    private const int BackdropMica = 1;
    // DWMSBT_TRANSIENTWINDOW = 2，即 Acrylic
    private const int BackdropAcrylic = 2;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd, int attr, ref int value, int size);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmGetWindowAttribute(
        IntPtr hwnd, int attr, out int value, int size);

    // 返回当前系统背景类型：0=NONE 1=Mica 2=Acrylic 3=Tabbed，-1=查询失败
    public static int Query(IntPtr hwnd)
    {
        int v = 0;
        int hr = DwmGetWindowAttribute(hwnd, AttrSystemBackdropType, out v, sizeof(int));
        return hr == 0 ? v : -1;
    }

    private static int Set(IntPtr hwnd, int kind)
    {
        int v = kind;
        return DwmSetWindowAttribute(hwnd, AttrSystemBackdropType, ref v, sizeof(int));
    }

    // 硬设 Mica。返回 DWM 的 HRESULT，0 表示成功。
    public static int SetMica(IntPtr hwnd) => Set(hwnd, BackdropMica);

    // 硬设 Acrylic。返回 DWM 的 HRESULT，0 表示成功。
    public static int SetAcrylic(IntPtr hwnd) => Set(hwnd, BackdropAcrylic);
}