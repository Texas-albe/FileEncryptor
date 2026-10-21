// P0-1 进程对象 DACL 加固（Windows）
//
// 背景：进程对象的默认 DACL 来自创建者 token，环境不同可能偏宽松（被服务拉起、
// 父进程传入自定义 SD 等）。默认只按「同登录会话」隔离并不可靠。
//
// 目的：显式把 DACL 收紧为「当前用户 + SYSTEM + Administrators」并阻断继承，
// 使同机其他非特权用户无法 OpenProcess(PROCESS_VM_READ / QUERY) 读走
// 口令、派生密钥与明文缓冲，也无法注入。
//
// 失败一律静默：加固是纵深防御，不应因此阻断挂载服务或 GUI 启动。
// POSIX 无对应机制（ptrace 受 Yama/ptrace_scope 约束），此处为空实现。

#include "fe_common.h"
#include <cstdio>

#ifdef _WIN32
#include <sddl.h>
#include <aclapi.h>
#include <vector>
#endif

// P1-2 镜像加载策略：禁远程 DLL
//
// 三条策略一起开，堵住「从不可信位置加载可执行镜像」这条注入主路：
//   NoRemoteImages            —— 禁止从远程设备（UNC/网络映射盘/WebDAV）加载镜像
//   NoLowMandatoryLabelImages —— 禁止加载完整性级别低于本进程的镜像（低 IL 进程可写的目录）
//   PreferSystem32Images      —— 系统 DLL 一律从 System32 取，杜绝同目录同名劫持
// 必须在加载任何非系统 DLL 之前调用（此处由 main() 首行保证）。失败静默。
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

// P1-3 禁崩溃转储：崩溃 dump 会把进程内存整体写盘，其中包含口令、派生 KEK 与明文缓冲。
// 做法：把自身可执行名登记进 WER 排除列表（排除后 WER 不再为该程序生成报告与转储）。
// wer.dll 动态加载：老系统没有该 API 时静默降级，不影响主功能。
// bAllUsers 需要管理员权限；失败则退化为仅当前用户（HKCU），仍能覆盖日常使用。
void fe_harden_no_crash_dump() {
#ifdef _WIN32
    HMODULE wer = LoadLibraryW(L"wer.dll");
    if (!wer) return;
    auto add = reinterpret_cast<HRESULT (WINAPI*)(PCWSTR, BOOL)>(
        GetProcAddress(wer, "WerAddExcludedApplication"));
    if (!add) { FreeLibrary(wer); return; }
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        // 文档要求：只传文件名（含扩展名），不含路径
        const wchar_t* name = path;
        for (const wchar_t* p = path; *p; ++p)
            if (*p == L'\\' || *p == L'/') name = p + 1;
        if (FAILED(add(name, TRUE))) add(name, FALSE);   // 全部用户失败则退化为当前用户
    }
    FreeLibrary(wer);
#endif
}

void fe_harden_process_dacl() {
#ifdef _WIN32
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
        // SE_KERNEL_OBJECT：对进程句柄改 DACL；PROTECTED 阻断继承来的宽松 ACE
        DWORD rc = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        NULL, NULL, dacl, NULL);
        LocalFree(dacl);
        // 低危 B 组：收紧失败必须留痕——这是多用户同机场景下唯一的内存读取屏障，静默失败等于屏障缺失而无人知晓。
        if (rc != ERROR_SUCCESS)
            fprintf(stderr, "[fe] harden: process DACL tighten failed (SetSecurityInfo err=%lu)\n",
                    (unsigned long)rc);
    } else {
        // 同上：DACL 构建失败同样留痕（屏障缺失可观测）。
        fprintf(stderr, "[fe] harden: process DACL build failed (SetEntriesInAclW err=%lu)\n",
                (unsigned long)erc);
    }

    if (system_sid) FreeSid(system_sid);
    if (admins_sid) FreeSid(admins_sid);
#endif
}
