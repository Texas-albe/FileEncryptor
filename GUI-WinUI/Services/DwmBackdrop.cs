// 调 DWM 设置窗口系统
// 原因
// WinUI 3.1.x
using System;
using System.Runtime.InteropServices;

namespace FileEncryptorGUI.Services;

internal static class DwmBackdrop
{
    // DWMWA_SYSTEMBACKDROP_TYPE = 38
    private const int AttrSystemBackdropType = 38;

    // DWMSBT_MAIN = 1
    private const int BackdropMica = 1;
    // DWMSBT_TRANSIENTWINDOW = 2，即 Acrylic
    private const int BackdropAcrylic = 2;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd, int attr, ref int value, int size);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmGetWindowAttribute(
        IntPtr hwnd, int attr, out int value, int size);

    // 返回当前系统背
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

    // 硬设 Mica
    public static int SetMica(IntPtr hwnd) => Set(hwnd, BackdropMica);

    // 硬设 Acrylic
    public static int SetAcrylic(IntPtr hwnd) => Set(hwnd, BackdropAcrylic);
}