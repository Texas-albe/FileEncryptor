#include "output_lock.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>
#include <sys/stat.h>

#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#endif

#include "FileEncryptor.hpp"   

// 跨进程输出锁

// 锁文件内容
// 只存 pid 有两个问题
// 回收
// nonce 用于回收
struct LockContent {
    uint32_t magic;
    uint32_t pid;
    uint64_t nonce;
    int64_t  created;
};

static const uint32_t kLockMagic = 0x46454C31u;   // 'FEL1'

static void fill_lock_content(LockContent& lc) {
    lc.magic = kLockMagic;
#ifdef _WIN32
    lc.pid = (uint32_t)GetCurrentProcessId();
#else
    lc.pid = (uint32_t)getpid();
#endif
    randombytes_buf(&lc.nonce, sizeof(lc.nonce));
    lc.created = (int64_t)time(nullptr);
}

static bool lock_content_equal(const LockContent& a, const LockContent& b) {
    return a.magic == b.magic && a.pid == b.pid &&
           a.nonce == b.nonce && a.created == b.created;
}

#ifdef _WIN32
static bool read_lock_handle(HANDLE h, LockContent& lc) {
    DWORD rd = 0;
    if (!ReadFile(h, &lc, sizeof(lc), &rd, NULL)) return false;
    return rd == sizeof(lc) && lc.magic == kLockMagic;
}
#else
static bool read_lock_fd(int fd, LockContent& lc) {
    return read(fd, &lc, sizeof(lc)) == (ssize_t)sizeof(lc) && lc.magic == kLockMagic;
}
#endif

bool fe_process_alive(int pid) {
#ifdef _WIN32
    if (pid <= 0) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return false;
    DWORD code = 0;
    bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
#else
    return pid > 0 && ::kill(pid, 0) == 0;
#endif
}

LockResult fe_acquire_output_lock(const std::string& out_path, std::string& lock_path) {
    lock_path = out_path + ".lock";
#ifdef _WIN32
    std::wstring w = utf8_to_wstring(lock_path);
    auto create_new_lock = [&]() -> bool {
        HANDLE h = CreateFileW(w.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return false;
        LockContent lc; fill_lock_content(lc);
        DWORD wr;
        WriteFile(h, &lc, sizeof(lc), &wr, NULL);
        CloseHandle(h);
        // P0-4
        tighten_file_permissions(lock_path);
        return true;
    };
    if (create_new_lock()) return LockResult::OK;

    // CREATE_NEW 失败
    HANDLE h = CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        LockContent lc;
        if (!read_lock_handle(h, lc)) { CloseHandle(h); return LockResult::CANNOT_CREATE; }
        const bool alive = fe_process_alive((int)lc.pid);
        CloseHandle(h);
        if (alive) return LockResult::LOCKED;   // 锁仍
        // 失效锁
        // 说明别
        h = CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        bool same = false;
        if (h != INVALID_HANDLE_VALUE) {
            LockContent lc2;
            same = read_lock_handle(h, lc2) && lock_content_equal(lc, lc2);
            CloseHandle(h);
        }
        if (!same) return LockResult::LOCKED;
        DeleteFileW(w.c_str());
        if (create_new_lock()) return LockResult::OK;
        // 回收
        if (create_new_lock()) return LockResult::OK;
        return LockResult::LOCKED;
    }
    // 连读取现有锁文
    return LockResult::CANNOT_CREATE;
#else
    auto create_new_lock = [&]() -> bool {
        int fd = open(lock_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return false;
        LockContent lc; fill_lock_content(lc);
        if (write(fd, &lc, sizeof(lc)) < 0) { /* 尽力写锁文件 */ }
        close(fd);
        return true;
    };
    if (create_new_lock()) return LockResult::OK;

    int fd = open(lock_path.c_str(), O_RDONLY, 0);
    if (fd >= 0) {
        LockContent lc;
        if (!read_lock_fd(fd, lc)) { close(fd); return LockResult::CANNOT_CREATE; }
        const bool alive = fe_process_alive((int)lc.pid);
        close(fd);
        if (alive) return LockResult::LOCKED;   // 锁被存活进程持
        // 失效锁
        fd = open(lock_path.c_str(), O_RDONLY, 0);
        bool same = false;
        if (fd >= 0) {
            LockContent lc2;
            same = read_lock_fd(fd, lc2) && lock_content_equal(lc, lc2);
            close(fd);
        }
        if (!same) return LockResult::LOCKED;
        unlink(lock_path.c_str());
        if (create_new_lock()) return LockResult::OK;
        // 回收竞争失败
        if (create_new_lock()) return LockResult::OK;
        return LockResult::LOCKED;
    }
    // 连读取
    return LockResult::CANNOT_CREATE;
#endif
}

// 防符号链接写穿

#if !defined(_WIN32)
bool fe_create_output_no_follow(const std::string& path) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC, 0600);
    if (fd < 0) {
        if (errno == ELOOP) fprintf(stderr, "Refusing to write through existing symlink: %s\n", path.c_str());
        return false;
    }
    ::close(fd);
    return true;
}
#else
// Windows
// 因此分两步
// 。只有已存
// 才用 OPEN_REPARSE_POINT
// 这样不存
bool fe_create_output_no_follow(const std::string& path) {
    const std::wstring wpath = utf8_to_wstring(path);
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    DWORD err = GetLastError();
    if (err != ERROR_FILE_EXISTS && err != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "Cannot create output file: %s\n", path.c_str());
        return false;
    }
    // 已存
    HANDLE lh = CreateFileW(wpath.c_str(), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (lh == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot create output file: %s\n", path.c_str());
        return false;
    }
    BY_HANDLE_FILE_INFORMATION fi;
    bool reparse = GetFileInformationByHandle(lh, &fi) &&
                   (fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    CloseHandle(lh);
    if (reparse) {
        fprintf(stderr, "Refusing to write through existing symlink: %s\n", path.c_str());
        return false;
    }
    h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot create output file: %s\n", path.c_str());
        return false;
    }
    CloseHandle(h);
    return true;
}
#endif

// 原子替换

// UTF-8 安全
bool replace_file_utf8(const std::string& from, const std::string& to) {
#ifdef _WIN32
    std::wstring wf = utf8_to_wstring(from);
    std::wstring wt = utf8_to_wstring(to);
    return MoveFileExW(wf.c_str(), wt.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    // M19
    // 两步
    // 已丢失
    return std::rename(from.c_str(), to.c_str()) == 0;
#endif
}

// 临时名
// 这样重跑才能复
// 对外导出
// 先算出这个路径
std::string atomic_output_tmp_path(const std::string& final_path) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : final_path) { h ^= c; h *= 1099511628211ull; }
    char buf[24];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return final_path + ".fe_tmp_" + buf;
}

AtomicOutput::AtomicOutput(const std::string& final_path)
    : final_(final_path), tmp_(atomic_output_tmp_path(final_path)) {}

AtomicOutput::~AtomicOutput() {
    if (!committed_) remove_file_utf8(tmp_);
}

bool AtomicOutput::commit() {
    if (committed_) return true;
    if (!replace_file_utf8(tmp_, final_)) {
        // 替换失败
        fprintf(stderr, "Error: cannot move temp output into place: %s\n", final_.c_str());
        remove_file_utf8(tmp_);
        committed_ = true;   // 视作已终结
        return false;
    }
    committed_ = true;
    return true;
}

// 权限

// UTF-8 安全
bool remove_file_utf8(const std::string& path) {
#ifdef _WIN32
    return _wremove(utf8_to_wstring(path).c_str()) == 0;
#else
    return std::remove(path.c_str()) == 0;
#endif
}

// 清掉只读属性
void clear_readonly_attribute(const std::string& path) {
#ifdef _WIN32
    const std::wstring w = utf8_to_wstring(path);
    DWORD a = GetFileAttributesW(w.c_str());
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY))
        SetFileAttributesW(w.c_str(), a & ~FILE_ATTRIBUTE_READONLY);
#else
    // POSIX 的只读
    struct stat st;
    if (::stat(path.c_str(), &st) == 0 && (st.st_mode & S_IWUSR) == 0)
        ::chmod(path.c_str(), st.st_mode | S_IWUSR);
#endif
}

// 收紧密钥文件权
// 阻断继承）
void tighten_file_permissions(const std::string& path) {
#ifdef _WIN32
    clear_readonly_attribute(path);
    const std::wstring w = utf8_to_wstring(path);

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

    PSID system_sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &system_sid)) system_sid = NULL;

    EXPLICIT_ACCESSW ea[2];
    memset(ea, 0, sizeof(ea));
    ea[0].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(tu->User.Sid);
    ea[1] = ea[0];
    ea[1].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system_sid);

    PACL new_dacl = NULL;
    DWORD rc = SetEntriesInAclW(system_sid ? 2 : 1, ea, NULL, &new_dacl);
    if (rc == ERROR_SUCCESS && new_dacl) {
        SetNamedSecurityInfoW(const_cast<LPWSTR>(w.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, new_dacl, NULL);
        LocalFree(new_dacl);
    }
    if (system_sid) FreeSid(system_sid);
#else
    chmod(path.c_str(), 0600);        // rw
#endif
}
