// fe_winfsp：Windows 只读挂载（WinFSP 原生 API，设计文档 M3）。
// 「进程本身即服务」：SvcStart 自给自足——从服务命令行(g_svc_*)加载 libvdisk、打开/
// 解锁 vault、起 IPC、挂载，不依赖 main 提前解锁的进程内全局。
#include "fe_common.h"
#if FE_HAVE_WINFSP
// TOKEN_USER 等需 _WIN32_WINNT >= 0x0500 才在 winnt.h 中可见（windows.h 的版本守卫会拦）
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#  define WINVER 0x0601
#endif
#include <winfsp.h>
#include <sddl.h>
#include <windows.h>
#include <winnt.h>      // TOKEN_USER / LPTOKEN_USER（windows.h 已带守卫，此处显式补）
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>
#include <chrono>
#include <new>
#pragma comment(lib, "advapi32.lib")

// 调试输出（FE_MOUNT_DEBUG=1 时打印每次回调，定位 0xC0000010 等）
#define WFDBG(...) do { if (getenv("FE_MOUNT_DEBUG")) fprintf(stderr, __VA_ARGS__); } while (0)

std::string g_svc_vault, g_svc_pass, g_svc_mp, g_svc_lib;
bool g_svc_rw = false;            // M6 可写挂载开关
uint32_t g_svc_idle = 0;          // M5 空闲超时自动锁（0=关闭）
static VDiskApi    g_wapi;          // 静态存储，回调经 g_wv=&g_wapi 访问（避免局部悬垂）
static VDiskApi*    g_wv = nullptr;
static VDiskHandle* g_wh = nullptr;
static FSP_FILE_SYSTEM* g_wfs = nullptr;
static FSP_FILE_SYSTEM_INTERFACE g_wf_iface = {};

// WinFSP 路径（\a\b）→ vdisk 虚拟路径（/a/b）
static std::string wfspath_to_vpath(const WCHAR* FileName) {
    std::string raw = wide_to_utf8(FileName);
    std::string out;
    for (char c : raw) {
        if (c == '\\' || c == '/') { if (out.empty() || out.back() != '/') out += '/'; }
        else out += c;
    }
    if (out.empty()) out = "/";
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    return out;
}

static void wf_fill_fileinfo(FSP_FSCTL_FILE_INFO* fi, bool isdir, uint64_t size, uint64_t mtime) {
    memset(fi, 0, sizeof(*fi));
    fi->FileAttributes  = isdir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    fi->ReparseTag      = 0;
    fi->AllocationSize  = isdir ? 0 : size;
    fi->FileSize        = size;
    UINT64 ft = ((UINT64)mtime + 11644473600ULL) * 10000000ULL;   // unix 秒 → FILETIME
    fi->CreationTime = ft; fi->LastAccessTime = ft; fi->LastWriteTime = ft; fi->ChangeTime = ft;
    fi->IndexNumber = 0; fi->HardLinks = 0; fi->EaSize = 0;
}

static NTSTATUS wf_st(VDiskStatus st) {
    if (st == VDISK_OK) return STATUS_SUCCESS;
    // 锁定态一律拒绝访问（而非 DEVICE_NOT_READY）：让 Explorer 明确报「拒绝访问」，
    // 避免「设备未就绪」被当可重试而误以为盘可开。盘符仍可见、双击即拒。
    if (st == VDISK_E_LOCKED) return STATUS_ACCESS_DENIED;
    if (st == VDISK_E_NOTFOUND) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (st == VDISK_E_NOTIMPL) return STATUS_NOT_SUPPORTED;
    if (st == VDISK_E_RO) return STATUS_MEDIA_WRITE_PROTECTED;   // 只读挂载拒绝写
    return FspNtStatusFromWin32(ERROR_READ_FAULT);
}

struct FeCtx { bool is_dir; std::string vpath; PVOID dir_buffer; };

// 自相对 SD，给「当前用户 + Administrators + SYSTEM」完全控制。
// 去掉 WD(Everyone)：解锁态下盘上是明文，Everyone-FA 等于同机任何用户可读。
// O:BAG:BA 不能省：FSD 访问检查需要合法 Owner，缺则判 STATUS_INVALID_SECURITY_DESCR。
static PSECURITY_DESCRIPTOR wf_build_sd() {
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        DWORD sz = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &sz);   // 首次必失败，仅取大小
        // TOKEN_USER 的首字段即 PSID；手动偏移取，避开该类型的 SDK 版本守卫（winfsp.h 锁了低版本）
        if (sz >= sizeof(void*) * 2 && sz <= 1024) {
            std::vector<BYTE> buf(sz);
            if (GetTokenInformation(tok, TokenUser, buf.data(), sz, &sz) && sz >= sizeof(void*) * 2) {
                void* sid = *reinterpret_cast<void**>(buf.data());
                wchar_t* sidbuf = nullptr;
                if (sid && ConvertSidToStringSidW(sid, &sidbuf)) {
                    // 给 Everyone(WD) 授 FA：解锁后的挂载卷对交互用户可读/可执行/枚举，
                    // 不依赖 FE-Mounter 以何种身份（用户/服务）运行。解密挂载卷本就等同明文，
                    // 授权范围与 Veracrypt/BitLocker 挂载盘一致。
                    std::wstring sddl = std::wstring(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)(A;;FA;;;")
                                      + sidbuf + L")";
                    LocalFree(sidbuf);
                    PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;
                    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            sddl.c_str(), SDDL_REVISION_1, &sd, &need)) {
                        CloseHandle(tok);
                        return sd;   // 调用方接管（LocalAlloc）
                    }
                }
            }
        }
        CloseHandle(tok);
    }
    PSECURITY_DESCRIPTOR sd = nullptr; DWORD need = 0;   // 取不到用户 SID 时的保守兜底
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)", SDDL_REVISION_1, &sd, &need)) return nullptr;
    return sd;
}

static NTSTATUS wf_fill_sd(PSECURITY_DESCRIPTOR buf, SIZE_T* PSize) {
    static PSECURITY_DESCRIPTOR cached = nullptr;   // LocalAlloc 生命周期 = 进程
    static SIZE_T cached_size = 0;
    if (!cached) {
        cached = wf_build_sd();
        if (!cached) {
            NTSTATUS es = FspNtStatusFromWin32(ERROR_INVALID_SID);
            WFDBG("[fe] build SD failed 0x%08lX\n", (unsigned long)es);
            return es;
        }
        cached_size = GetSecurityDescriptorLength(cached);
        WFDBG("[fe] SD ready size=%llu\n", (unsigned long long)cached_size);
    }
    if (!PSize) return STATUS_SUCCESS;
    if (!buf) { *PSize = cached_size; return STATUS_SUCCESS; }
    if (*PSize < cached_size) { *PSize = cached_size; return STATUS_BUFFER_OVERFLOW; }
    memcpy(buf, cached, cached_size);
    *PSize = cached_size;
    return STATUS_SUCCESS;
}

static NTSTATUS wf_GetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo) {
    WFDBG("[fe] GetVolumeInfo\n");
    // 容量随库内实际占用动态扩展（vdisk_stat_space）。不能填固定 1TiB：
    // explorer/磁盘管理会按此显示，与真实占用严重脱节。
    uint64_t used = 0, total = 0;
    if (!g_wv->stat_space || g_wv->stat_space(g_wh, &used, &total) != VDISK_OK || total == 0) {
        total = 64ull << 20; used = 0;   // 库不支持统计时的保守兜底
    }
    VolumeInfo->TotalSize = total;
    VolumeInfo->FreeSize  = (total > used) ? (total - used) : 0;
    VolumeInfo->VolumeLabelLength = (UINT16)wcslen(L"FE-Vault");
    wcscpy_s(VolumeInfo->VolumeLabel, sizeof VolumeInfo->VolumeLabel / sizeof(WCHAR), L"FE-Vault");
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetSecurityByName(FSP_FILE_SYSTEM*, PWSTR FileName, PUINT32 PFileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize) {
    std::string vp = wfspath_to_vpath(FileName);
    WFDBG("[fe] GetSecurityByName '%s'\n", vp.c_str());
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (st != VDISK_OK) return wf_st(st);
    if (PFileAttributes) *PFileAttributes = isdir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    return wf_fill_sd(SecurityDescriptor, PSecurityDescriptorSize);
}
static NTSTATUS wf_open_common(PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (getenv("FE_MOUNT_DEBUG"))
        fprintf(stderr, "[fe] open '%s' opts=0x%lX acc=0x%lX getattr=%d\n",
                vp.c_str(), (unsigned long)CreateOptions, (unsigned long)GrantedAccess, (int)st);
    if (st != VDISK_OK) return wf_st(st);
    FeCtx* c = new (std::nothrow) FeCtx{ isdir != 0, vp, nullptr };
    if (!c) return STATUS_INSUFFICIENT_RESOURCES;
    *PFileContext = c;
    if (FileInfo) wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Open(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    return wf_open_common(FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
}
// Create 与 Open 签名不同（多 FileAttributes/SecurityDescriptor/AllocationSize）。
// 可写挂载：文件不存在则创建（O_CREAT 语义，CREATE_NEW 时已存在应返 STATUS_OBJECT_NAME_COLLISION）。
// 只读挂载：存在即只读打开，不存在返 NOT_FOUND（等价 Open）。
static NTSTATUS wf_Create(FSP_FILE_SYSTEM*, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
    UINT32 FileAttributes, PSECURITY_DESCRIPTOR, UINT64 AllocationSize,
    PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    WFDBG("[fe] Create '%s' rw=%d\n", vp.c_str(), g_svc_rw ? 1 : 0);
    bool exists = (g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr) == VDISK_OK);
    if (!exists) {
        if (!g_svc_rw) return STATUS_OBJECT_NAME_NOT_FOUND;   // 只读：不可创建
        if (g_wv->create_file(g_wh, vp.c_str()) != VDISK_OK) {
            if (!g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr))
                return STATUS_OBJECT_NAME_COLLISION;
            return STATUS_ACCESS_DENIED;
        }
    } else if (CreateOptions & FILE_CREATE) {
        return STATUS_OBJECT_NAME_COLLISION;   // FILE_CREATE 要求新建
    }
    return wf_open_common(FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
}
static VOID wf_Cleanup(FSP_FILE_SYSTEM*, PVOID FileContext, PWSTR FileName, ULONG Flags) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c) return;
    // 删除的唯一执行点：Flags 含 FspCleanupDelete 表示 FSD 已标记该文件删除、现在真正删。
    // （SDK winfsp.h:364 三阶段协议；CanDelete/SetDelete 都只做预检、绝不删）
    WFDBG("[fe] Cleanup '%s' flags=0x%lX\n", c->vpath.c_str(), (unsigned long)Flags);
    if ((Flags & FspCleanupDelete) && g_svc_rw) {
        // 目录也走这里：库层 delete_file 删索引条目 + 擦除其下 .ptd。
        // 此前用 !c->is_dir 拦掉目录 → CanDelete 放行但实际不删，explorer 报「成功」而目录仍在（E2）。
        VDiskStatus st = g_wv->delete_file(g_wh, c->vpath.c_str());
        WFDBG("[fe] Cleanup delete '%s' (dir=%d) -> %s\n", c->vpath.c_str(), c->is_dir ? 1 : 0,
              st == VDISK_OK ? "ok" : g_wv->strerror(st));
    }
    if (c->dir_buffer) FspFileSystemDeleteDirectoryBuffer(&c->dir_buffer);
    delete c;
}
static VOID wf_Close(FSP_FILE_SYSTEM*, PVOID FileContext) {
    (void)FileContext;  // context lifetime is managed in Cleanup
}
static NTSTATUS wf_Read(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, PULONG PBytesTransferred) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    uint64_t len = Length;
    VDiskStatus st = g_wv->read_file(g_wh, c->vpath.c_str(), Offset, (uint8_t*)Buffer, &len);
    if (st != VDISK_OK) return wf_st(st);
    *PBytesTransferred = (ULONG)len;
    return STATUS_SUCCESS;
}
// M6 写支持：覆盖写 / 扩展（删除见 wf_CanDelete + wf_Cleanup 的 FspCleanupDelete 分支）
static NTSTATUS wf_Write(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
    UINT64 Offset, ULONG Length, BOOLEAN, BOOLEAN, PULONG PBytesTransferred,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    VDiskStatus st = g_wv->write_file(g_wh, c->vpath.c_str(), Offset, (const uint8_t*)Buffer, (uint64_t)Length);
    if (st != VDISK_OK) return wf_st(st);
    *PBytesTransferred = Length;
    if (FileInfo) {  // 回填 FileInfo 让系统看到新大小
        uint64_t mtime = 0, sz = 0; uint8_t isdir = 0;
        g_wv->getattr(g_wh, c->vpath.c_str(), &sz, &mtime, &isdir);
        wf_fill_fileinfo(FileInfo, false, sz, mtime);
    }
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SetFileSize(FSP_FILE_SYSTEM*, PVOID FileContext, UINT64 NewSize,
    BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    if (!c || c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    if (!SetAllocationSize) {  // 仅 EOF 调整改文件大小；AllocationSize 仅预留则忽略
        VDiskStatus st = g_wv->truncate_file(g_wh, c->vpath.c_str(), NewSize);
        if (st != VDISK_OK) return wf_st(st);
    }
    if (FileInfo) {
        uint64_t mtime = 0, sz = NewSize; uint8_t isdir = 0;
        g_wv->getattr(g_wh, c->vpath.c_str(), &sz, &mtime, &isdir);
        wf_fill_fileinfo(FileInfo, false, sz, mtime);
    }
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    FeCtx* c = (FeCtx*)FileContext;
    WFDBG("[fe] GetFileInfo '%s'\n", c ? c->vpath.c_str() : "?");
    if (!c) return STATUS_INVALID_PARAMETER;
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    g_wv->getattr(g_wh, c->vpath.c_str(), &size, &mtime, &isdir);
    wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_GetDirInfoByName(FSP_FILE_SYSTEM*, PVOID, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo) {
    std::string vp = wfspath_to_vpath(FileName);
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    VDiskStatus st = g_wv->getattr(g_wh, vp.c_str(), &size, &mtime, &isdir);
    if (st != VDISK_OK) return wf_st(st);
    std::string base = vp.substr(vp.find_last_of('/') + 1);
    std::wstring wb = utf8_to_wide(base);
    DirInfo->Size = (UINT16)(FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + wb.size() * sizeof(WCHAR));
    wf_fill_fileinfo(&DirInfo->FileInfo, isdir != 0, size, mtime);
    memcpy(DirInfo->FileNameBuf, wb.c_str(), wb.size() * sizeof(WCHAR));
    return STATUS_SUCCESS;
}
static NTSTATUS wf_ReadDirectory(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext0, PWSTR, PWSTR Marker,
    PVOID Buffer, ULONG BufferLength, PULONG PBytesTransferred) {
    FeCtx* c = (FeCtx*)FileContext0;
    WFDBG("[fe] ReadDirectory '%s'\n", c ? c->vpath.c_str() : "?");
    if (!c || !c->is_dir) return STATUS_INVALID_DEVICE_REQUEST;
    NTSTATUS r = STATUS_SUCCESS;
    if (FspFileSystemAcquireDirectoryBuffer(&c->dir_buffer, 0 == Marker, &r)) {
        uint64_t n = 0;
        if (g_wv->readdir(g_wh, c->vpath.c_str(), nullptr, &n) == VDISK_OK && n > 0) {
            std::vector<VDiskEntry> ents((size_t)n);
            VDiskEntry* parr = ents.data();
            if (g_wv->readdir(g_wh, c->vpath.c_str(), &parr, &n) == VDISK_OK) {
                for (uint64_t i = 0; i < n; i++) {
                    union { UINT8 B[FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + 512 * sizeof(WCHAR)];
                            FSP_FSCTL_DIR_INFO D; } buf;
                    FSP_FSCTL_DIR_INFO* di = &buf.D;
                    std::wstring wb = utf8_to_wide(ents[i].name);
                    memset(di, 0, sizeof(buf));
                    di->Size = (UINT16)(FIELD_OFFSET(FSP_FSCTL_DIR_INFO, FileNameBuf) + wb.size() * sizeof(WCHAR));
                    wf_fill_fileinfo(&di->FileInfo, ents[i].is_dir != 0, ents[i].size, ents[i].mtime);
                    memcpy(di->FileNameBuf, wb.c_str(), wb.size() * sizeof(WCHAR));
                    if (!FspFileSystemFillDirectoryBuffer(&c->dir_buffer, di, &r)) break;
                }
            }
        }
        FspFileSystemReleaseDirectoryBuffer(&c->dir_buffer);
    }
    if (!NT_SUCCESS(r)) return r;
    FspFileSystemReadDirectoryBuffer(&c->dir_buffer, Marker, Buffer, BufferLength, PBytesTransferred);
    return STATUS_SUCCESS;
}
// 删除：CanDelete 仅做预检（绝不删文件，SDK winfsp.h:586 明确要求）。
// 真正删除在 Cleanup 且 Flags 含 FspCleanupDelete 时执行——这是 WinFsp 的三阶段协议
// （打开 → CanDelete 预检 → Cleanup 删除），与官方 memfs 样例一致。
static NTSTATUS wf_CanDelete(FSP_FILE_SYSTEM*, PVOID, PWSTR FileName) {
    if (!g_svc_rw) { WFDBG("[fe] CanDelete denied (read-only)\n"); return STATUS_MEDIA_WRITE_PROTECTED; }
    std::string vp = wfspath_to_vpath(FileName);
    return (g_wv->getattr(g_wh, vp.c_str(), nullptr, nullptr, nullptr) == VDISK_OK)
        ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

// 已打开句柄的安全查询（dir/Explorer 打开目录后会走 GetSecurity 而非 GetSecurityByName）。
// 不实现时落 NULL 槽位 → WinFsp 返回 STATUS_INVALID_DEVICE_REQUEST(0xC0000010) → "函数不正确"。
static NTSTATUS wf_GetSecurity(FSP_FILE_SYSTEM*, PVOID,
    PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T* PSecurityDescriptorSize) {
    WFDBG("[fe] GetSecurity\n");
    return wf_fill_sd(SecurityDescriptor, PSecurityDescriptorSize);
}
static NTSTATUS wf_SetSecurity(FSP_FILE_SYSTEM*, PVOID, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR) {
    WFDBG("[fe] SetSecurity (ignored, read-only)\n");
    return STATUS_SUCCESS;   // 只读库：忽略安全修改
}
static NTSTATUS wf_SetBasicInfo(FSP_FILE_SYSTEM*, PVOID, UINT32, UINT64, UINT64, UINT64, UINT64,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    WFDBG("[fe] SetBasicInfo (ignored)\n");
    (void)FileInfo;
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Flush(FSP_FILE_SYSTEM*, PVOID, FSP_FSCTL_FILE_INFO*) {
    WFDBG("[fe] Flush\n");
    // 卷刷新 (FileContext==NULL)：容量由 wf_GetVolumeInfo 提供，无需在此回填
    return STATUS_SUCCESS;
}
static NTSTATUS wf_Overwrite(FSP_FILE_SYSTEM*, PVOID FileContext, UINT32, BOOLEAN, UINT64,
    FSP_FSCTL_FILE_INFO* FileInfo) {
    WFDBG("[fe] Overwrite\n");
    FeCtx* c = (FeCtx*)FileContext;
    if (!c) return STATUS_INVALID_PARAMETER;
    if (FileInfo) {
        uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
        g_wv->getattr(g_wh, c->vpath.c_str(), &size, &mtime, &isdir);
        wf_fill_fileinfo(FileInfo, isdir != 0, size, mtime);
    }
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SetVolumeLabel(FSP_FILE_SYSTEM*, PWSTR, FSP_FSCTL_VOLUME_INFO* VolumeInfo) {
    WFDBG("[fe] SetVolumeLabel (unsupported)\n");
    (void)VolumeInfo;
    return STATUS_INVALID_DEVICE_REQUEST;   // 不支持改卷标，与 passthrough 一致
}

// M5 空闲守护线程：vdisk 侧的超时判定是惰性的（只在 I/O 到来时检查），
// 用户开着盘窗口不动就永远没有 I/O，自动锁不会触发。
// 这里按秒轮询 idle_remaining()，到点主动 lock()，让「1 分钟不用就锁」真正生效。
// 轮询间隔取 1s：锁的时机误差 ≤1s，可接受；不 busy-wait。
void idle_watchdog_thread() {
    while (!g_ipc_stop.load()) {
        bool done = false;
        for (int i = 0; i < 10 && !done; ++i) {   // 每秒醒一次，中途可被 stop 打断
            if (g_ipc_stop.load()) { done = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (done) break;
        if (!g_ipc_unlocked.load() || !g_wv || !g_wh) continue;
        if (g_wapi.idle_remaining(g_wh) == 0) {
            g_wapi.lock(g_wh);
            g_ipc_unlocked = false;
            fprintf(stderr, "[fe] idle timeout: auto-locked\n");
        }
    }
}

static NTSTATUS wf_SvcStart(FSP_SERVICE* Service, ULONG, PWSTR*) {
    // 自给自足：从服务命令行加载 vdisk、打开/解锁 vault、起 IPC、挂载
    std::string err;
    if (!vdisk_load(g_wapi, g_svc_lib, err)) { fprintf(stderr, "[fe] load libvdisk: %s\n", err.c_str()); return STATUS_UNSUCCESSFUL; }
    g_wv = &g_wapi;
    g_wh = g_wapi.open(g_svc_vault.c_str());
    if (!g_wh) { fprintf(stderr, "[fe] open vault failed: %s\n", g_svc_vault.c_str()); return STATUS_UNSUCCESSFUL; }
    if (!g_svc_pass.empty()) {
        if (g_wapi.unlock(g_wh, g_svc_pass.c_str(), 0) != VDISK_OK) { fprintf(stderr, "[fe] unlock failed\n"); g_wapi.close(g_wh); g_wh = nullptr; return STATUS_UNSUCCESSFUL; }
        g_ipc_unlocked = true;
        secure_zero(g_svc_pass.data(), g_svc_pass.size());   // 解锁后即清，不在内存长期驻留（§4.1）
        g_svc_pass.clear();
    } else {
        g_ipc_unlocked = false;   // 无密码：锁定启动，等 IPC unlock（§4.1 默认锁定）
    }
    g_ipc_v = g_wv; g_ipc_h = &g_wh; g_ipc_stop = false;
    // M5 空闲超时：GUI 挂载固定传 60（1 分钟不用就自动锁），必须在解锁后设，否则立刻被计时
    if (g_svc_idle > 0 && g_wapi.set_idle_timeout) g_wapi.set_idle_timeout(g_wh, g_svc_idle);
    std::thread(ipc_server_thread).detach();
    // 空闲守护：vdisk 的超时判定是「惰性」的，只在有 I/O 到来时才检查。
    // Explorer 打开盘后若不再操作（甚至只是挂着窗口），就永远没有 I/O 触发检查，
    // 自动锁形同虚设。这里独立起一个定时器主动查剩余时间，到点直接锁。
    if (g_svc_idle > 0 && g_wapi.idle_remaining && g_wapi.lock)
        std::thread(idle_watchdog_thread).detach();

    FSP_FSCTL_VOLUME_PARAMS vol; memset(&vol, 0, sizeof vol);
    FILETIME nowft; GetSystemTimeAsFileTime(&nowft);
    vol.Version = sizeof(FSP_FSCTL_VOLUME_PARAMS);
    vol.SectorSize = 512; vol.SectorsPerAllocationUnit = 1; vol.MaxComponentLength = 255;
    vol.VolumeCreationTime = ((PLARGE_INTEGER)&nowft)->QuadPart;
    vol.VolumeSerialNumber = 0x20261005;
    vol.FileInfoTimeout = 1000; vol.CaseSensitiveSearch = 0; vol.CasePreservedNames = 1;
    vol.UnicodeOnDisk = 1; vol.PersistentAcls = 1; vol.PostCleanupWhenModifiedOnly = 1;
    vol.PassQueryDirectoryPattern = 1; vol.FlushAndPurgeOnCleanup = 1; vol.UmFileContextIsUserContext2 = 1;
    // 删除链路必需：让 FSD 把 Disposition（删除请求）投递到 Cleanup，Cleanup 才能收到
    // FspCleanupDelete 并执行删除。缺此项则 del 静默不生效。
    vol.PostDispositionWhenNecessaryOnly = 1;
    if (!g_svc_rw) vol.ReadOnlyVolume = 1;
    wcscpy_s(vol.FileSystemName, sizeof vol.FileSystemName / sizeof(WCHAR), L"FE-Vault");
    FSP_FILE_SYSTEM* fs = nullptr;
    // 显式转 PWSTR：DeviceName 形参非 const，/Zc:strictStrings 下字面量是 const
    NTSTATUS st = FspFileSystemCreate(const_cast<PWSTR>(L"" FSP_FSCTL_DISK_DEVICE_NAME),
                                      &vol, &g_wf_iface, &fs);
    if (!NT_SUCCESS(st)) { fprintf(stderr, "[fe] FspFileSystemCreate failed 0x%08lX\n", (unsigned long)st); return st; }
    std::wstring mount_w = utf8_to_wide(g_svc_mp);
    st = FspFileSystemSetMountPoint(fs, (PWSTR)mount_w.c_str());
    if (!NT_SUCCESS(st)) { fprintf(stderr, "[fe] SetMountPoint(%s) failed 0x%08lX\n", g_svc_mp.c_str(), (unsigned long)st); FspFileSystemDelete(fs); return st; }
    if (g_svc_rw) g_wapi.mount_rw(g_wh, g_svc_mp.c_str());
    else          g_wapi.mount_readonly(g_wh, g_svc_mp.c_str());
    if (getenv("FE_MOUNT_DEBUG")) FspFileSystemSetDebugLog(fs, (UINT32)-1);
    st = FspFileSystemStartDispatcher(fs, 0);
    if (!NT_SUCCESS(st)) { FspFileSystemDelete(fs); return st; }
    g_wfs = fs; Service->UserContext = fs;
    printf("MOUNTED at %s (unlocked=%d)\n", g_svc_mp.c_str(), g_ipc_unlocked.load() ? 1 : 0); fflush(stdout);
    return STATUS_SUCCESS;
}
static NTSTATUS wf_SvcStop(FSP_SERVICE* Service) {
    FSP_FILE_SYSTEM* fs = (FSP_FILE_SYSTEM*)Service->UserContext;
    if (fs) { FspFileSystemStopDispatcher(fs); FspFileSystemDelete(fs); }
    g_ipc_stop = true;
    if (g_wv && g_wh) { g_wv->unmount(g_wh); g_wv->close(g_wh); g_wh = nullptr; }
    g_wfs = nullptr;
    return STATUS_SUCCESS;
}

int fe_winmount_service() {
    if (g_svc_mp.empty()) { fprintf(stderr, "[fe] winmount needs a drive letter\n"); return 1; }
    if (!NT_SUCCESS(FspLoad(nullptr))) { fprintf(stderr, "[fe] FspLoad failed: is the WinFSP driver running?\n"); return 8; }
    g_wf_iface.GetVolumeInfo = wf_GetVolumeInfo;
    g_wf_iface.GetSecurityByName = wf_GetSecurityByName;
    g_wf_iface.GetSecurity = wf_GetSecurity;
    g_wf_iface.SetSecurity = wf_SetSecurity;
    g_wf_iface.SetBasicInfo = wf_SetBasicInfo;
    g_wf_iface.Flush = wf_Flush;
    g_wf_iface.Create = wf_Create;   // 可写：不存在则创建；只读：不存在返 NOT_FOUND
    g_wf_iface.Open = wf_Open;
    g_wf_iface.Overwrite = wf_Overwrite;
    g_wf_iface.Cleanup = wf_Cleanup;
    g_wf_iface.Close = wf_Close;
    g_wf_iface.Read = wf_Read;
    g_wf_iface.Write = wf_Write;            // M6 写支持
    g_wf_iface.SetFileSize = wf_SetFileSize;
    g_wf_iface.GetFileInfo = wf_GetFileInfo;
    g_wf_iface.GetDirInfoByName = wf_GetDirInfoByName;
    g_wf_iface.ReadDirectory = wf_ReadDirectory;
    g_wf_iface.CanDelete = wf_CanDelete;   // 仅预检；实际删除在 Cleanup(FspCleanupDelete)
    g_wf_iface.SetVolumeLabel = wf_SetVolumeLabel;
    // 必须 FspServiceRun：控制台调试模式自动走 Mount Manager 全局盘符，跨窗口可见。
    // 不能换 FspServiceLoop——它只建会话盘符，其他窗口 I/O 在内核层即失败(0xC0000010)。
    // 显式转 PWSTR：FspServiceRun 收非 const 指针，字符串字面量在 /Zc:strictStrings 下是 const。
    FspServiceRun(const_cast<PWSTR>(L"FE-Mount"), wf_SvcStart, wf_SvcStop, nullptr);
    return 0;
}
#endif // FE_HAVE_WINFSP
