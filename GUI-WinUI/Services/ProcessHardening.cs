using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FileEncryptorGUI.Services;

// P0-1 进程对象 DACL 加固（Windows）
//
// 背景：进程对象的默认 DACL 取自创建者 token，环境不同可能偏宽松（被服务拉起、
// 父进程传入自定义 SD 等）。本进程内存里有口令、派生密钥与明文缓冲。
//
// 目的：显式把 DACL 收紧为「当前用户 + SYSTEM + Administrators」并阻断继承，
// 使同机其他非特权用户无法 OpenProcess(PROCESS_VM_READ / QUERY) 读内存或注入。
// 失败一律静默：加固属纵深防御，不应阻断 GUI 启动。
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

    // P1-2 镜像加载策略：禁远程镜像、禁低完整性镜像、系统 DLL 强制走 System32。
    // 必须在加载任何非系统 DLL 之前调用。失败静默。
    public static void HardenImageLoad()
    {
        try
        {
            var pol = new ProcessMitigationImageLoadPolicy
            {
                Flags = 0x1 | 0x2 | 0x4,   // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
            };
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, ref pol,
                                       System.Runtime.InteropServices.Marshal.SizeOf<ProcessMitigationImageLoadPolicy>());
        }
        catch { }
    }

    // P1-3 把自身登记进 WER 排除列表，不再产生崩溃转储（dump 会带走内存里的口令/KEK/明文）。
    // 全部用户需要管理员权限，失败退化为仅当前用户。失败静默。
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

    // P2 调试器检测（仅用于告警，不做阻断）
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

    // 幂等，启动时调用一次
    public static void Harden()
    {
        try
        {
            var sid = WindowsIdentity.GetCurrent().User?.Value;
            if (string.IsNullOrEmpty(sid)) return;

            // D:P = 受保护的 DACL；依次放行 SYSTEM、Administrators、当前用户
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
            // 加固失败不阻断启动
        }
    }
}
