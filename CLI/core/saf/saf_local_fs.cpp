// 本地文件系统后端：逻辑根 + UTF-8 路径，读写列目录
#include "saf.hpp"

#include <cerrno>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

constexpr uint64_t kMaxChunk = 1u << 30;

#ifdef _WIN32
uint64_t filetime_to_unix(FILETIME ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart == 0) return 0;
    return (uint64_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}
// 权限位合成：Windows 仅只读属性有意义，映射为是否含用户写位
uint32_t local_mode_from_win(DWORD attr, bool is_dir) {
    uint32_t m = is_dir ? 0755u : 0644u;
    if (attr & FILE_ATTRIBUTE_READONLY) m &= ~0200u;
    return m;
}
#endif

// 本地文件流
class LocalFsStream final : public Stream {
public:
#ifdef _WIN32
    HANDLE h_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif

    SafStatus read(uint8_t* out, uint64_t* len) override {
        if (!out || !len) return SAF_E_BADARG;
        if (*len == 0) return SAF_OK;
        uint64_t want = (*len > kMaxChunk) ? kMaxChunk : *len;
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile(h_, out, (DWORD)want, &got, nullptr)) {
            if (GetLastError() == ERROR_HANDLE_EOF) { *len = 0; return SAF_OK; }
            return SAF_E_IO;
        }
        *len = got;
#else
        for (;;) {
            ssize_t n = ::read(fd_, out, (size_t)want);
            if (n < 0) { if (errno == EINTR) continue; return SAF_E_IO; }
            *len = (uint64_t)n;
            break;
        }
#endif
        return SAF_OK;
    }

    SafStatus write(const uint8_t* in, uint64_t len) override {
        if (len == 0) return SAF_OK;
        if (!in) return SAF_E_BADARG;
        uint64_t off = 0;
        while (off < len) {
            uint64_t chunk = (len - off > kMaxChunk) ? kMaxChunk : (len - off);
#ifdef _WIN32
            DWORD w = 0;
            if (!WriteFile(h_, in + off, (DWORD)chunk, &w, nullptr) || w == 0) return SAF_E_IO;
            off += w;
#else
            ssize_t n = ::write(fd_, in + off, (size_t)chunk);
            if (n < 0) { if (errno == EINTR) continue; return SAF_E_IO; }
            off += (uint64_t)n;
#endif
        }
        return SAF_OK;
    }

    SafStatus seek(uint64_t offset) override {
#ifdef _WIN32
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
        return SetFilePointerEx(h_, li, nullptr, FILE_BEGIN) ? SAF_OK : SAF_E_IO;
#else
        return (::lseek(fd_, (off_t)offset, SEEK_SET) < 0) ? SAF_E_IO : SAF_OK;
#endif
    }

    SafStatus tell(uint64_t* out_pos) override {
        if (!out_pos) return SAF_E_BADARG;
#ifdef _WIN32
        LARGE_INTEGER zero, cur; zero.QuadPart = 0;
        if (!SetFilePointerEx(h_, zero, &cur, FILE_CURRENT)) return SAF_E_IO;
        *out_pos = (uint64_t)cur.QuadPart;
#else
        off_t p = ::lseek(fd_, 0, SEEK_CUR);
        if (p < 0) return SAF_E_IO;
        *out_pos = (uint64_t)p;
#endif
        return SAF_OK;
    }

    SafStatus flush() override {
#ifdef _WIN32
        return FlushFileBuffers(h_) ? SAF_OK : SAF_E_IO;
#else
        return SAF_OK;   // POSIX 无缓冲，写即落
#endif
    }

    SafStatus close() override {
        bool ok = false;
#ifdef _WIN32
        if (h_ != INVALID_HANDLE_VALUE) { ok = CloseHandle(h_) != FALSE; h_ = INVALID_HANDLE_VALUE; }
#else
        if (fd_ >= 0) { ok = ::close(fd_) == 0; fd_ = -1; }
#endif
        return ok ? SAF_OK : SAF_E_IO;
    }
};

// 打开本机路径（不做逻辑根解析，绝对路径原样使用）
SafStatus open_native(const std::string& p, char mode, std::shared_ptr<Stream>& out) {
    out.reset();
    if (mode != 'r' && mode != 'w' && mode != 'a') return SAF_E_BADARG;
    auto st = std::make_shared<LocalFsStream>();
#ifdef _WIN32
    DWORD access = (mode == 'r') ? GENERIC_READ : GENERIC_WRITE;
    DWORD share = (mode == 'r') ? FILE_SHARE_READ : 0;
    DWORD disp = (mode == 'w') ? CREATE_NEW : ((mode == 'a') ? OPEN_ALWAYS : OPEN_EXISTING);
    // M32：FILE_FLAG_OPEN_REPARSE_POINT——打开重解析点本身而非其目标，配合下方 tag 复查（现在能真正看到链接自身的 tag）拒绝符号链接写穿/读穿
    HANDLE h = CreateFileW(saf_utf8_to_wide(p).c_str(), access, share,
                           nullptr, disp,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (mode == 'w' && e == ERROR_FILE_EXISTS) return SAF_E_EXIST;
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
        return SAF_E_IO;
    }
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof(tag)) && tag.ReparseTag != 0) {
        CloseHandle(h);
        return SAF_E_BADARG;
    }
    if (mode == 'a') SetFilePointer(h, 0, nullptr, FILE_END);
    st->h_ = h;
#else
    int flags = 0;
    if (mode == 'r') flags = O_RDONLY | O_NOFOLLOW;
    else if (mode == 'w') flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;
    else flags = O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW;
    int fd = ::open(p.c_str(), flags, 0600);
    if (fd < 0) {
        if (errno == EEXIST) return SAF_E_EXIST;
        if (errno == ENOENT || errno == ENOTDIR) return SAF_E_NOTFOUND;
        if (errno == ELOOP) return SAF_E_BADARG;
        return SAF_E_IO;
    }
    st->fd_ = fd;
#endif
    out = st;
    return SAF_OK;
}

// 本地目录后端
class LocalFsBackend final : public StorageBackend {
public:
    explicit LocalFsBackend(std::string root) : root_(std::move(root)) {}

    const char* scheme() const override { return "file"; }
    bool can_write() const override { return true; }
    bool can_list() const override { return true; }

    SafStatus stat(const std::string& vpath, uint64_t* out_size,
                   uint64_t* out_mtime, bool* out_is_dir,
                   bool* out_is_symlink = nullptr,
                   uint32_t* out_mode = nullptr) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
        if (vpath.empty()) {   // 根本身
            if (out_size) *out_size = 0;
            if (out_mtime) *out_mtime = 0;
            if (out_is_dir) *out_is_dir = true;
            if (out_is_symlink) *out_is_symlink = false;
            if (out_mode) *out_mode = 0;
            return SAF_OK;
        }
#ifdef _WIN32
        WIN32_FILE_ATTRIBUTE_DATA d{};
        if (!GetFileAttributesExW(saf_utf8_to_wide(p).c_str(), GetFileExInfoStandard, &d)) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
            return SAF_E_IO;
        }
        bool is_reparse = (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        if (out_is_symlink) *out_is_symlink = is_reparse;
        if (out_size) *out_size = ((uint64_t)d.nFileSizeHigh << 32) | (uint64_t)d.nFileSizeLow;
        if (out_mtime) *out_mtime = filetime_to_unix(d.ftLastWriteTime);
        bool is_dir = (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (out_is_dir) *out_is_dir = is_dir;
        if (out_mode) *out_mode = local_mode_from_win(d.dwFileAttributes, is_dir);
#else
        struct stat st{};
        if (::lstat(p.c_str(), &st) != 0) {
            if (errno == ENOENT || errno == ENOTDIR) return SAF_E_NOTFOUND;
            return SAF_E_IO;
        }
        bool is_link = S_ISLNK(st.st_mode) != 0;
        if (out_is_symlink) *out_is_symlink = is_link;
        if (out_size) *out_size = is_link ? 0 : (S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size);
        if (out_mtime) *out_mtime = (uint64_t)st.st_mtime;
        if (out_is_dir) *out_is_dir = S_ISDIR(st.st_mode) != 0;
        if (out_mode) *out_mode = (uint32_t)(st.st_mode & 07777);
#endif
        return SAF_OK;
    }

    SafStatus open(const std::string& vpath, char mode,
                   std::shared_ptr<Stream>& out) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
        return open_native(p, mode, out);
    }

    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        out.clear();
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
#ifdef _WIN32
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(saf_utf8_to_wide(p + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
            return SAF_E_IO;
        }
        do {
            std::string name = saf_wide_to_utf8(fd.cFileName);
            if (name == "." || name == "..") continue;
            bool is_reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            bool is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            SafEntry e;
            e.name = name;
            e.is_symlink = is_reparse;
            e.is_dir = is_dir;
            e.size = is_reparse ? 0 : (is_dir ? 0 : (((uint64_t)fd.nFileSizeHigh << 32) | (uint64_t)fd.nFileSizeLow));
            e.mtime = filetime_to_unix(fd.ftLastWriteTime);
            e.mode = local_mode_from_win(fd.dwFileAttributes, is_dir);
            out.push_back(std::move(e));
        } while (FindNextFileW(h, &fd));
        FindClose(h);
#else
        DIR* d = ::opendir(p.c_str());
        if (!d) return (errno == ENOENT || errno == ENOTDIR) ? SAF_E_NOTFOUND : SAF_E_IO;
        while (struct dirent* de = ::readdir(d)) {
            std::string name = de->d_name;
            if (name == "." || name == "..") continue;
            struct stat st{};
            if (::lstat((p + "/" + name).c_str(), &st) != 0) continue;
            bool is_link = S_ISLNK(st.st_mode) != 0;
            SafEntry e;
            e.name = name;
            e.is_symlink = is_link;
            e.is_dir = S_ISDIR(st.st_mode) != 0;
            e.size = is_link ? 0 : (e.is_dir ? 0 : (uint64_t)st.st_size);
            e.mtime = (uint64_t)st.st_mtime;
            e.mode = (uint32_t)(st.st_mode & 07777);
            out.push_back(std::move(e));
        }
        ::closedir(d);
#endif
        return SAF_OK;
    }

    SafStatus create_file(const std::string& vpath) override {
        std::shared_ptr<Stream> s;
        SafStatus st = open(vpath, 'w', s);
        if (st != SAF_OK) return st;
        return s->close();
    }

    SafStatus mkdir(const std::string& vpath) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
#ifdef _WIN32
        if (CreateDirectoryW(saf_utf8_to_wide(p).c_str(), nullptr)) return SAF_OK;
        DWORD e = GetLastError();
        if (e == ERROR_ALREADY_EXISTS) return SAF_E_EXIST;
        if (e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#else
        if (::mkdir(p.c_str(), 0700) == 0) return SAF_OK;
        if (errno == EEXIST) return SAF_E_EXIST;
        if (errno == ENOENT) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#endif
    }

    SafStatus delete_file(const std::string& vpath) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
        bool is_dir = false;
        SafStatus st = stat(vpath, nullptr, nullptr, &is_dir);
        if (st != SAF_OK) return st;
#ifdef _WIN32
        std::wstring w = saf_utf8_to_wide(p);
        bool ok = is_dir ? (RemoveDirectoryW(w.c_str()) != FALSE) : (DeleteFileW(w.c_str()) != FALSE);
        if (ok) return SAF_OK;
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#else
        int rc = is_dir ? ::rmdir(p.c_str()) : ::unlink(p.c_str());
        if (rc == 0) return SAF_OK;
        if (errno == ENOENT) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#endif
    }

    SafStatus truncate_file(const std::string& vpath, uint64_t new_size) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
#ifdef _WIN32
        HANDLE h = CreateFileW(saf_utf8_to_wide(p).c_str(), GENERIC_WRITE, 0,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
            return SAF_E_IO;
        }
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)new_size;
        bool ok = SetFilePointerEx(h, li, nullptr, FILE_BEGIN) && SetEndOfFile(h);
        CloseHandle(h);
        return ok ? SAF_OK : SAF_E_IO;
#else
        if (::truncate(p.c_str(), (off_t)new_size) == 0) return SAF_OK;
        if (errno == ENOENT) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#endif
    }

    SafStatus rename_file(const std::string& from, const std::string& to) override {
        std::string pf, pt;
        if (!resolve(from, pf) || !resolve(to, pt)) return SAF_E_BADARG;
#ifdef _WIN32
        if (MoveFileExW(saf_utf8_to_wide(pf).c_str(), saf_utf8_to_wide(pt).c_str(), 0)) return SAF_OK;
        DWORD e = GetLastError();
        if (e == ERROR_ALREADY_EXISTS || e == ERROR_FILE_EXISTS) return SAF_E_EXIST;
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#else
        if (::access(pt.c_str(), F_OK) == 0) return SAF_E_EXIST;
        if (::rename(pf.c_str(), pt.c_str()) == 0) return SAF_OK;
        if (errno == ENOENT) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#endif
    }

    // 符号链接：vpath（链接位置）指向 target（后端内相对/绝对路径，原样存为链接目标）
    SafStatus symlink(const std::string& target, const std::string& vpath) override {
        std::string pp;
        if (!resolve(vpath, pp)) return SAF_E_BADARG;
#ifdef _WIN32
        DWORD attr = GetFileAttributesW(saf_utf8_to_wide(pp).c_str());
        DWORD flags = (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
                          ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
        if (CreateSymbolicLinkW(saf_utf8_to_wide(pp).c_str(),
                                saf_utf8_to_wide(target).c_str(), flags))
            return SAF_OK;
        DWORD e = GetLastError();
        if (e == ERROR_ALREADY_EXISTS) return SAF_E_EXIST;
        return SAF_E_IO;
#else
        if (::symlink(target.c_str(), pp.c_str()) == 0) return SAF_OK;
        if (errno == EEXIST) return SAF_E_EXIST;
        if (errno == ENOENT) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#endif
    }

    // 读符号链接目标（近似：Windows 下取解析后的规范化绝对路径）
    SafStatus readlink(const std::string& vpath, std::string& out_target) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
#ifdef _WIN32
        HANDLE h = CreateFileW(saf_utf8_to_wide(p).c_str(), 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) return SAF_E_NOTFOUND;
        WCHAR tmp[MAX_PATH * 2] = {0};
        DWORD n = GetFinalPathNameByHandleW(h, tmp, _countof(tmp) - 1, FILE_NAME_NORMALIZED);
        CloseHandle(h);
        if (n == 0) return SAF_E_IO;
        out_target = saf_wide_to_utf8(std::wstring(tmp, n));
        return SAF_OK;
#else
        char buf[4096];
        ssize_t n = ::readlink(p.c_str(), buf, sizeof(buf) - 1);
        if (n < 0) { if (errno == ENOENT) return SAF_E_NOTFOUND; return SAF_E_IO; }
        out_target.assign(buf, (size_t)n);
        return SAF_OK;
#endif
    }

    // 权限位：Windows 仅映射用户写位（去写位 → 只读属性）
    SafStatus chmod(const std::string& vpath, uint32_t mode) override {
        std::string p;
        if (!resolve(vpath, p)) return SAF_E_BADARG;
#ifdef _WIN32
        DWORD attr = GetFileAttributesW(saf_utf8_to_wide(p).c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return SAF_E_NOTFOUND;
        bool want_write = (mode & 0200u) != 0;
        bool is_ro = (attr & FILE_ATTRIBUTE_READONLY) != 0;
        if (want_write == !is_ro) return SAF_OK;
        if (want_write) attr &= ~FILE_ATTRIBUTE_READONLY;
        else attr |= FILE_ATTRIBUTE_READONLY;
        return SetFileAttributesW(saf_utf8_to_wide(p).c_str(), attr) ? SAF_OK : SAF_E_IO;
#else
        if (::chmod(p.c_str(), (mode & 07777)) == 0) return SAF_OK;
        if (errno == ENOENT) return SAF_E_NOTFOUND;
        return SAF_E_IO;
#endif
    }

    bool can_symlink() const override { return true; }
    bool can_chmod()  const override { return true; }
    bool can_seek()   const override { return true; }

private:
    // 逻辑路径 → 本地路径（越界由 saf_path_normalize 拦截）
    bool resolve(const std::string& vpath, std::string& out) const {
        std::string rel;
        if (!saf_path_normalize(vpath, rel)) return false;
        out = root_.empty() ? "." : root_;
        if (!rel.empty()) {
#ifdef _WIN32
            out += "\\";
            for (char c : rel) out += (c == '/') ? '\\' : c;
#else
            out += "/" + rel;
#endif
        }
        return true;
    }

    std::string root_;
};

}  // namespace

std::shared_ptr<StorageBackend> saf_open_local_fs(const std::string& root) {
    std::string r = root;
    while (r.size() > 1 && (r.back() == '/' || r.back() == '\\')) r.pop_back();
    return std::make_shared<LocalFsBackend>(r);
}

SafStatus saf_open_native_file(const std::string& path, char mode,
                               std::shared_ptr<Stream>& out) {
    return open_native(path, mode, out);
}
