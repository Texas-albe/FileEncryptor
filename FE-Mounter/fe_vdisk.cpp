// fe_vdisk
#include "fe_common.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>     // O_NOFOLLOW
#ifndef _WIN32
#  include <unistd.h>   // access
#  include <signal.h>   // kill
#  include <errno.h>    // errno
#endif

#ifdef _WIN32
#  include <wintrust.h>     // WinVerifyTrust
#  include <softpub.h>
#  include <io.h>           // _open_osfhandle
#  pragma comment(lib, "wintrust.lib")
#endif

#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w; w.resize(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
std::string wide_to_utf8(const WCHAR* w) {
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s; s.resize(n);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}
std::string self_dir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring wp(buf, n);
    size_t pos = wp.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return ".";
    return wide_to_utf8(wp.substr(0, pos).c_str());
}
#else
std::string self_dir() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return ".";
    buf[n] = '\0';
    std::string p(buf);
    size_t pos = p.find_last_of('/');
    return (pos == std::string::npos) ? "." : p.substr(0, pos);
}
#endif

// 低危
FILE* fe_open_write_nofollow(const std::string& path, bool append) {
#ifdef _WIN32
    HANDLE h = CreateFileW(utf8_to_wide(path).c_str(), FILE_GENERIC_WRITE, 0, nullptr,
                           append ? OPEN_ALWAYS : CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return nullptr;
    // OPEN_REPARSE_POINT 下句柄指向重解
    // 能取回重解析数
    std::vector<BYTE> rp(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    DWORD got = 0;
    if (DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, nullptr, 0, rp.data(), (DWORD)rp.size(), &got, nullptr)) {
        CloseHandle(h);
        return nullptr;
    }
    if (append) SetFilePointer(h, 0, nullptr, FILE_END);
    int fd = _open_osfhandle((intptr_t)h, 0);
    if (fd < 0) { CloseHandle(h); return nullptr; }
    FILE* f = _fdopen(fd, append ? "ab" : "wb");
    if (!f) { _close(fd); return nullptr; }
    return f;
#else
    int flags = O_WRONLY | O_CREAT | O_NOFOLLOW | (append ? O_APPEND : O_TRUNC);
    int fd = open(path.c_str(), flags, 0600);
    if (fd < 0) return nullptr;
    FILE* f = fdopen(fd, append ? "ab" : "wb");
    if (!f) { close(fd); return nullptr; }
    return f;
#endif
}

// 低危
bool fe_pid_alive(long pid) {
    if (pid <= 0) return false;
#ifdef _WIN32
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED;   // 打不开≠不存
    DWORD rc = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return rc == WAIT_TIMEOUT;   // 句柄已触发即进
#else
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
#endif
}

std::string default_lib_path() {
#ifdef _WIN32
    return self_dir() + "/vdisk.dll";
#else
    // 发行包
    // 只认 exe 同目录
    if (const char* env = getenv("FE_VDISK_LIB")) {
        if (*env) return env;
    }
    std::vector<std::string> tries;
    tries.push_back(self_dir());
    tries.push_back("/usr/lib");
    tries.push_back("/usr/lib/x86_64-linux-gnu");
    tries.push_back("/usr/local/lib");
    tries.push_back("/usr/lib64");
    for (const auto& d : tries) {
        const std::string p = d + "/libvdisk.so";
        if (access(p.c_str(), R_OK) == 0) return p;
    }
    return self_dir() + "/libvdisk.so";   // 全都没有
#endif
}

#ifdef _WIN32
// Authenticode 签名校验。必须
// 策略
// 原型自行 typedef
// LPVOID 且带 C linkage），直接调/强转
// 第一参须 HANDLE
typedef LONG (WINAPI *WinVerifyTrustFn)(HANDLE, GUID*, LPVOID);

static bool verify_trusted(const std::wstring& path, std::string& err) {
    const char* skip = getenv("FE_VDISK_ALLOW_UNSIGNED");
    const char* must = getenv("FE_VDISK_REQUIRE_SIGNED");
    bool require = (must && *must == '1');
    if (!require && skip && *skip == '1') return true;
    HMODULE wt = LoadLibraryW(L"wintrust.dll");
    if (!wt) { if (require) { err = "wintrust.dll unavailable"; return false; } return true; }
    WinVerifyTrustFn fn = (WinVerifyTrustFn)GetProcAddress(wt, "WinVerifyTrust");
    if (!fn) { FreeLibrary(wt); if (require) { err = "WinVerifyTrust missing"; return false; } return true; }
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;              // 不弹 UI
    wd.fdwRevocationChecks = WTD_REVOKE_NONE; // 不查吊销列表
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;   // 局部副本
    LONG st = fn(INVALID_HANDLE_VALUE, &action, (LPVOID)&wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    fn(INVALID_HANDLE_VALUE, &action, (LPVOID)&wd);
    FreeLibrary(wt);
    if (st == ERROR_SUCCESS) return true;   // 签名有效
    // M3
    if (st == (LONG)TRUST_E_NOSIGNATURE || st == (LONG)TRUST_E_PROVIDER_UNKNOWN ||
        st == (LONG)TRUST_E_SUBJECT_FORM_UNKNOWN) {
        if (require) { err = "vdisk.dll is unsigned (FE_VDISK_REQUIRE_SIGNED=1)"; return false; }
        fprintf(stderr, "[fe] WARNING: vdisk.dll is unsigned; continuing (set FE_VDISK_REQUIRE_SIGNED=1 to enforce)\n");
        return true;
    }
    char b[180];
    snprintf(b, sizeof b, "vdisk.dll signature invalid (0x%08lX); refusing to load", (unsigned long)st);
    err = b;
    return false;
}

#else   // 非 Windows
static bool verify_trusted(const std::wstring&, std::string&) { return true; }
#endif

bool vdisk_load(VDiskApi& v, const std::string& path, std::string& err) {
#ifdef _WIN32
    // 绝对路径 +
    // System32 为 OS ACL 保护
    std::wstring wpath = utf8_to_wide(path);
    if (!verify_trusted(wpath, err)) return false;
    v.lib = (void*)LoadLibraryExW(wpath.c_str(), nullptr,
                                  LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!v.lib) { char b[64]; snprintf(b, sizeof b, "LoadLibraryExW err=%lu", GetLastError()); err = b; return false; }
    auto sym = [&](const char* n) { return (void*)GetProcAddress((HMODULE)v.lib, n); };
#else
    v.lib = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!v.lib) { const char* e = dlerror(); err = e ? e : "dlopen failed"; return false; }
    auto sym = [&](const char* n) { return dlsym(v.lib, n); };
#endif
    v.open            = (decltype(v.open))sym("vdisk_open");
    v.close           = (decltype(v.close))sym("vdisk_close");
    v.unlock          = (decltype(v.unlock))sym("vdisk_unlock");
    v.lock            = (decltype(v.lock))sym("vdisk_lock");
    v.purge_on_suspend= (decltype(v.purge_on_suspend))sym("vdisk_purge_on_suspend");
    v.reindex         = (decltype(v.reindex))sym("vdisk_reindex");
    v.mount_readonly  = (decltype(v.mount_readonly))sym("vdisk_mount_readonly");
    v.unmount         = (decltype(v.unmount))sym("vdisk_unmount");
    v.readdir         = (decltype(v.readdir))sym("vdisk_readdir");
    v.getattr         = (decltype(v.getattr))sym("vdisk_getattr");
    v.read_file       = (decltype(v.read_file))sym("vdisk_read_file");
    v.write_file      = (decltype(v.write_file))sym("vdisk_write_file");
    v.strerror        = (decltype(v.strerror))sym("vdisk_strerror");
    v.recovery_gen    = (decltype(v.recovery_gen))sym("vdisk_recovery_gen");
    v.recovery_create = (decltype(v.recovery_create))sym("vdisk_recovery_create");
    v.recovery_open   = (decltype(v.recovery_open))sym("vdisk_recovery_open");
    v.recovery_remove = (decltype(v.recovery_remove))sym("vdisk_recovery_remove");
    v.set_idle_timeout= (decltype(v.set_idle_timeout))sym("vdisk_set_idle_timeout");
    v.idle_remaining  = (decltype(v.idle_remaining))sym("vdisk_idle_remaining");
    v.set_read_cache  = (decltype(v.set_read_cache))sym("vdisk_set_read_cache");
    v.mount_rw        = (decltype(v.mount_rw))sym("vdisk_mount_rw");
    v.create_file     = (decltype(v.create_file))sym("vdisk_create_file");
    v.create_file_ex  = (decltype(v.create_file_ex))sym("vdisk_create_file_ex");
    v.delete_file     = (decltype(v.delete_file))sym("vdisk_delete_file");
    v.truncate_file   = (decltype(v.truncate_file))sym("vdisk_truncate_file");
    v.rename          = (decltype(v.rename))sym("vdisk_rename");
    v.stat_space      = (decltype(v.stat_space))sym("vdisk_stat_space");
    v.note_activity   = (decltype(v.note_activity))sym("vdisk_note_activity");
    v.index_stamp     = (decltype(v.index_stamp))sym("vdisk_index_stamp");
    v.is_unlocked     = (decltype(v.is_unlocked))sym("vdisk_is_unlocked");
    if (!v.open || !v.close || !v.unlock || !v.lock || !v.readdir ||
        !v.getattr || !v.read_file || !v.strerror) { err = "libvdisk missing required symbols"; return false; }
    // M5+/M8 依赖
    // 匿名 namespace 导出成 C++ 修饰
    if (!v.note_activity || !v.index_stamp || !v.is_unlocked)
        fprintf(stderr, "[fe] warn: libvdisk missing busy/lock-state ABI "
                "(note_activity=%d index_stamp=%d is_unlocked=%d); auto-lock hardening degraded\n",
                v.note_activity ? 1 : 0, v.index_stamp ? 1 : 0, v.is_unlocked ? 1 : 0);
    return true;
}

bool read_pass_file(const std::string& path, std::string& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';
    out = buf;
    return true;
}

uint64_t fnv1a64(const uint8_t* p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;          // FNV-1a 64 偏移基
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

// 统一内存清零
#include <sodium.h>
void secure_zero(void* p, size_t n) { if (p && n) sodium_memzero(p, n); }

// M5 多库注册表
std::string vaults_registry_path() {
    const char* home = getenv("USERPROFILE");
    if (!home) home = getenv("HOME");
    if (!home) home = ".";
    std::string base = std::string(home) + "/.fe-mounter";
#ifdef _WIN32
    CreateDirectoryW(utf8_to_wide(base).c_str(), nullptr);
#else
    mkdir(base.c_str(), 0700);
#endif
    return base + "/vaults.txt";
}

std::vector<std::string> vaults_list() {
    std::vector<std::string> out;
    FILE* f = fopen(vaults_registry_path().c_str(), "rb");
    if (!f) return out;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        std::string s = line;
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        if (!s.empty()) out.push_back(s);
    }
    fclose(f);
    return out;
}

bool vaults_add(const std::string& dir, std::string& err) {
    auto cur = vaults_list();
    for (auto& s : cur) if (s == dir) { err = "already registered"; return false; }
    FILE* f = fe_open_write_nofollow(vaults_registry_path().c_str(), true);
    if (!f) { err = "cannot open registry"; return false; }
    fprintf(f, "%s\n", dir.c_str());
    fclose(f);
    return true;
}

bool vaults_remove(const std::string& dir, std::string& err) {
    auto cur = vaults_list();
    bool found = false;
    std::vector<std::string> keep;
    for (auto& s : cur) { if (s == dir) found = true; else keep.push_back(s); }
    if (!found) { err = "not registered"; return false; }
    FILE* f = fopen(vaults_registry_path().c_str(), "wb");
    if (!f) { err = "cannot write registry"; return false; }
    for (auto& s : keep) fprintf(f, "%s\n", s.c_str());
    fclose(f);
    return true;
}

bool read_whole(const VDiskApi& v, VDiskHandle* h, const std::string& vpath,
                std::vector<uint8_t>& out, std::string& err) {
    uint64_t sz = 0, mt = 0; uint8_t isdir = 0;
    if (v.getattr(h, vpath.c_str(), &sz, &mt, &isdir) != VDISK_OK) { err = "getattr failed"; return false; }
    if (isdir) { err = "is a directory"; return false; }
    // M5
    if (sz > kFeMaxFileSize) { err = "file too large"; return false; }
    out.assign(sz ? (size_t)sz : 1, 0);
    uint64_t len = sz;
    VDiskStatus st = v.read_file(h, vpath.c_str(), 0, out.data(), &len);
    if (st != VDISK_OK) { err = v.strerror ? v.strerror(st) : "read failed"; return false; }
    out.resize((size_t)len);
    return true;
}

void walk(const VDiskApi& v, VDiskHandle* h, const std::string& vpath) {
    uint64_t n = 0;
    if (v.readdir(h, vpath.c_str(), nullptr, &n) != VDISK_OK) return;
    if (n > kFeMaxDirEntries) return;   // M5
    std::vector<VDiskEntry> ents((size_t)n);
    VDiskEntry* parr = ents.data();
    if (n > 0 && v.readdir(h, vpath.c_str(), &parr, &n) != VDISK_OK) return;
    for (uint64_t i = 0; i < n; i++) {
        std::string child = (vpath == "/") ? ("/" + std::string(ents[i].name))
                                            : (vpath + "/" + ents[i].name);
        if (ents[i].is_dir) {
            printf("DIR  %s\n", child.c_str());
            walk(v, h, child);
        } else {
            std::vector<uint8_t> buf; std::string err;
            if (read_whole(v, h, child, buf, err)) {
                printf("FILE %s size=%llu fnv=0x%016llx\n", child.c_str(),
                       (unsigned long long)buf.size(),
                       (unsigned long long)fnv1a64(buf.data(), buf.size()));
            } else {
                printf("FILE %s size=%llu  [read-err: %s]\n", child.c_str(),
                       (unsigned long long)ents[i].size, err.c_str());
            }
        }
    }
}
