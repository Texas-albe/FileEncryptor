// P0-1 进程对象 DACL 加固
// 背景
// 父进程传入自定
// 使同机其他非特
// 口令、派生密钥
// 失败一律静默
// POSIX 无对应机制

#include "fe_common.h"
#include <cstdio>

#ifdef _WIN32
#include <sddl.h>
#include <aclapi.h>
#include <vector>
#endif

// P1-2 镜像加载策略
// 三条策略一起开
// NoRemoteImages 禁止
// NoLowMandatoryLabelImages 禁止加载完整性
// PreferSystem32Images 系统 DLL 一律
// 必须
void fe_harden_image_load_policy() {
#ifdef _WIN32
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY pol;
    memset(&pol, 0, sizeof pol);
    pol.NoRemoteImages = 1;
    pol.NoLowMandatoryLabelImages = 1;
    pol.PreferSystem32Images = 1;
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &pol, sizeof pol);
#endif
}

// P1-3 禁崩溃转储
// 做法
// wer.dll 动态加载
// bAllUsers 需要管理员权限
void fe_harden_no_crash_dump() {
#ifdef _WIN32
    HMODULE wer = LoadLibraryW(L"wer.dll");
    if (!wer) return;
    auto add = reinterpret_cast<HRESULT (WINAPI*)(PCWSTR, BOOL)>(
        GetProcAddress(wer, "WerAddExcludedApplication"));
    if (!add) { FreeLibrary(wer); return; }
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        // 文档要求
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p)
            if (*p == L'\\' || *p == L'/') name = p + 1;
        if (FAILED(add(name, TRUE))) add(name, FALSE);   // 全部用户失败
    }
    FreeLibrary(wer);
#endif
}

void fe_harden_process_dacl() {
#ifdef _WIN32
    // 当前进程
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
    PSID system_sid = NULL, admins_sid = NULL;
    AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0, 0, 0, 0, 0, 0, 0, &system_sid);
    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                             0, 0, 0, 0, 0, 0, &admins_sid);

    EXPLICIT_ACCESSW ea[3];
    memset(ea, 0, sizeof ea);
    int n = 0;
    PSID sids[3] = { tu->User.Sid, system_sid, admins_sid };
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
    DWORD erc = SetEntriesInAclW(n, ea, NULL, &dacl);
    if (erc == ERROR_SUCCESS && dacl) {
        // SE_KERNEL_OBJECT
        DWORD rc = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        NULL, NULL, dacl, NULL);
        LocalFree(dacl);
        // 低危 B 组
        if (rc != ERROR_SUCCESS)
            fprintf(stderr, "[fe] harden: process DACL tighten failed (SetSecurityInfo err=%lu)\n",
                    (unsigned long)rc);
    } else {
        fprintf(stderr, "[fe] harden: process DACL build failed (SetEntriesInAclW err=%lu)\n",
                (unsigned long)erc);
    }

    if (system_sid) FreeSid(system_sid);
    if (admins_sid) FreeSid(admins_sid);
#endif
}
