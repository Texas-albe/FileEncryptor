#include "OsHarden.h"

#ifdef Q_OS_WIN

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <vector>

namespace OsHarden {

void hardenImageLoadPolicy()
{
    // 三条一起开，堵住「从不可信位置加载可执行镜像」这条注入主路
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY pol;
    memset(&pol, 0, sizeof pol);
    pol.NoRemoteImages = 1;
    pol.NoLowMandatoryLabelImages = 1;
    pol.PreferSystem32Images = 1;
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &pol, sizeof pol);
}

void disableCrashDump()
{
    // 崩溃 dump 会把进程内存（口令/KEK/明文）整体写盘，故把自身排除出 WER。
    // M44：真正在内存持有口令/KEK/明文的是子进程 FileEncryptorCLI，一并排除。
    // WerAddExcludedApplication 只收文件名（不含路径），与 GUI 同安装目录部署的约定
    // 由文件名本身命中；拿不到自身路径时同样用文件名兜底。
    // wer.dll 动态加载：老系统无此 API 时静默降级。
    HMODULE wer = LoadLibraryW(L"wer.dll");
    if (!wer) return;
    typedef HRESULT (WINAPI *WerAddFn)(PCWSTR, BOOL);
    WerAddFn add = reinterpret_cast<WerAddFn>(GetProcAddress(wer, "WerAddExcludedApplication"));
    if (!add) { FreeLibrary(wer); return; }
    auto exclude=[&add](const wchar_t* name) {
        if (!name || !*name) return;
        // 文档要求：只传文件名（含扩展名），不含路径
        if (FAILED(add(name, TRUE))) add(name, FALSE);   // 全部用户失败则退化为当前用户
    };
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p)
            if (*p == L'\\' || *p == L'/') name = p + 1;
        exclude(name);
    }
    exclude(L"FileEncryptorCLI.exe");
    FreeLibrary(wer);
}

bool isDebuggerAttached()
{
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return true;
    return false;
}

void hardenProcessDacl()
{
    // 当前进程的令牌用户 SID
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return;
    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    std::vector<unsigned char> buf(need ? need : 256);
    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    BOOL got = GetTokenInformation(tok, TokenUser, buf.data(), (DWORD)buf.size(), &need);
    CloseHandle(tok);
    if (!got || !tu->User.Sid) return;

    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL, adminsSid = NULL;
    AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0, 0, 0, 0, 0, 0, 0, &systemSid);
    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                             0, 0, 0, 0, 0, 0, &adminsSid);

    EXPLICIT_ACCESSW ea[3];
    memset(ea, 0, sizeof ea);
    int n = 0;
    PSID sids[3] = { tu->User.Sid, systemSid, adminsSid };
    for (int i = 0; i < 3; ++i) {
        if (!sids[i]) continue;
        ea[n].grfAccessPermissions = PROCESS_ALL_ACCESS;
        ea[n].grfAccessMode = SET_ACCESS;
        ea[n].grfInheritance = NO_INHERITANCE;
        ea[n].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[n].Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea[n].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sids[i]);
        ++n;
    }

    PACL dacl = NULL;
    if (SetEntriesInAclW(n, ea, NULL, &dacl) == ERROR_SUCCESS && dacl) {
        // SE_KERNEL_OBJECT：对进程句柄改 DACL；PROTECTED 阻断继承来的宽松 ACE
        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        NULL, NULL, dacl, NULL);
        LocalFree(dacl);
    }

    if (systemSid) FreeSid(systemSid);
    if (adminsSid) FreeSid(adminsSid);
}

} // namespace OsHarden

#else // 非 Windows：无对应机制

#include <sys/resource.h>

namespace OsHarden {
void hardenProcessDacl() {}
void hardenImageLoadPolicy() {}
void disableCrashDump() {
    // M44：Linux 无 WER，但 core dump 同样会倒出内存（口令/KEK/明文），
    // 对本进程直接禁核。资源限制经 fork/exec 继承，QProcess 启动的
    // FileEncryptorCLI 子进程同样生效；detached 启动的其他进程如需保证，
    // 应在其启动环境里另行设置。
    struct rlimit rl;
    if (getrlimit(RLIMIT_CORE, &rl) == 0) {
        rl.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &rl);
    }
}
bool isDebuggerAttached() { return false; }
} // namespace OsHarden

#endif
