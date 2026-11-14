using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FileEncryptorGUI.Services;

// P0-1 进程对象 DACL 加固
// 背景
// 父进程传入自定
// 使同机其他非特
// 失败一律静默
internal static class ProcessHardening
{
    private const uint SDDL_REVISION_1 = 1;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;
    private const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(
        IntPtr handle, uint securityInformation, IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool pbDebuggerPresent);

    [DllImport("wer.dll", CharSet = CharSet.Unicode)]
    private static extern int WerAddExcludedApplication(string exeName, bool allUsers);

    private const int ProcessImageLoadPolicy = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMitigationImageLoadPolicy
    {
        public uint Flags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(
        int policy, ref ProcessMitigationImageLoadPolicy p, int size);

    // P1-2 镜像加载策略
    // 必须
    public static void HardenImageLoad()
    {
        try
        {
            var pol = new ProcessMitigationImageLoadPolicy
            {
                Flags = 0x1 | 0x2 | 0x4,   
            };
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, ref pol,
                                       System.Runtime.InteropServices.Marshal.SizeOf<ProcessMitigationImageLoadPolicy>());
        }
        catch { }
    }

    // P1-3 把自身登记进 WER 排
    // 全部用户需要管
    public static void DisableCrashDump()
    {
        try
        {
            var name = System.IO.Path.GetFileName(
                System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "");
            if (string.IsNullOrEmpty(name)) return;
            if (WerAddExcludedApplication(name, true) != 0) WerAddExcludedApplication(name, false);
        }
        catch { }
    }

    // P2 调试器检测
    public static bool IsDebuggerAttached()
    {
        try
        {
            if (IsDebuggerPresent()) return true;
            bool remote = false;
            if (CheckRemoteDebuggerPresent(
                    System.Diagnostics.Process.GetCurrentProcess().Handle, ref remote) && remote)
                return true;
        }
        catch { }
        return false;
    }

    public static void Harden()
    {
        try
        {
            var sid = WindowsIdentity.GetCurrent().User?.Value;
            if (string.IsNullOrEmpty(sid)) return;

            // D:P = 受保护
            var sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, SDDL_REVISION_1, out var sd, out _))
                return;
            try
            {
                SetKernelObjectSecurity(
                    System.Diagnostics.Process.GetCurrentProcess().Handle,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    sd);
            }
            finally
            {
                LocalFree(sd);
            }
        }
        catch
        {
            // 加固失败不阻断
        }
    }
}
