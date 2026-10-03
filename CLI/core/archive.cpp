#include "archive.hpp"
#include "FileEncryptor.hpp"   // create_directory_recursive / remove_file_utf8 / 路径工具
#include "util/byte_io.hpp"
#include "util/hex.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sodium.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#endif

#ifdef _WIN32
#include <direct.h>
#endif

using fe::util::put_le32;
using fe::util::put_le64;
using fe::util::get_le32;
using fe::util::get_le64;

const char ARCHIVE_MAGIC[8] = { 'F','E','P','K','1','\r','\n',0 };

namespace {

const unsigned char TRAILER[8] = { 'F','E','P','K','E','N','D','!' };
const size_t      kIoBuf = 1u << 20;
const int         kMaxDepth = 1024;

// 路径规范化：统一分隔符为 '/'，去掉重复与前导分隔符。
// 返回 false 表示路径本身非法（含 ".."、绝对路径、盘符、空组件）。
bool normalize_rel(const std::string& in, std::string& out) {
    std::string s;
    s.reserve(in.size());
    for (char c : in) s.push_back((c=='\\') ? '/' : c);
    // 绝对路径与盘符一律拒绝：归档内路径必须能安全地拼到输出目录下面
    if (!s.empty() && (s[0]=='/' || s[0]=='\\')) return false;
    if (s.size()>=2 && s[1]==':') return false;
    if (s.find('\0')!=std::string::npos) return false;

    std::vector<std::string> parts;
    size_t i = 0;
    while (i < s.size()) {
        size_t j = s.find('/', i);
        if (j == std::string::npos) j = s.size();
        std::string seg = s.substr(i, j - i);
        if (seg == "..") return false;             // 穿越
        if (!seg.empty() && seg != ".") parts.push_back(seg);
        i = j + 1;
    }
    if (parts.empty()) return false;
    for (const auto& p : parts) {
        if (p.size() > ARCHIVE_MAX_PATH) return false;
        // Windows 保留名与非法字符：解包端要能落地，打包端就先拒
        for (char c : p) {
            if ((unsigned char)c < 0x20) return false;
            if (c==':' || c=='*' || c=='?' || c=='"' || c=='<' || c=='>' || c=='|') return false;
        }
        std::string tail = p;
        for (auto& c : tail) c = (char)std::tolower((unsigned char)c);
        if (tail.size()>=4) {
            std::string stem = tail.substr(tail.find_last_of('.')==std::string::npos
                                           ? 0 : tail.find_last_of('.'));
            if (stem == "con" || stem == "prn" || stem == "aux" || stem == "nul") return false;
        }
    }
    out.clear();
    for (size_t k = 0; k < parts.size(); ++k) {
        if (k) out.push_back('/');
        out += parts[k];
    }
    return true;
}

std::string base_name_of(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    return (pos == std::string::npos) ? p : p.substr(pos + 1);
}

std::string parent_of(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    if (pos == std::string::npos) return ".";
    if (pos == 0) return p.substr(0, 1);
    return p.substr(0, pos);
}

std::string join_path(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    if (dir.back()=='/' || dir.back()=='\\') return dir + name;
    return dir + "/" + name;
}

bool is_dir_path(const std::string& p) {
#ifdef _WIN32
    struct _stat64 st;
    if (_wstat64(utf8_to_wstring(p).c_str(), &st) != 0) return false;
    return (st.st_mode & _S_IFDIR) != 0;
#else
    struct stat st;
    if (::stat(p.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
#endif
}

bool file_mode_time(const std::string& p, uint32_t& mode, int64_t& mtime, uint64_t& size) {
#ifdef _WIN32
    struct _stat64 st;
    if (_wstat64(utf8_to_wstring(p).c_str(), &st) != 0) return false;
    mode = (uint32_t)(st.st_mode & 0666);
    mtime = (int64_t)st.st_mtime;
    size  = (uint64_t)st.st_size;
#else
    struct stat st;
    if (::lstat(p.c_str(), &st) != 0) return false;
    mode = (uint32_t)(st.st_mode & 0777);
    mtime = (int64_t)st.st_mtime;
    size  = (uint64_t)st.st_size;
#endif
    return true;
}

// 目录递归：跳过符号链接与重解析点，避免循环与归档到目录外的东西。
// rel 是归档内相对路径前缀（含顶层目录名，末尾不带 '/'）。
bool walk_dir(const std::string& fs_path, const std::string& rel,
              const std::vector<std::string>& excludes,
              std::vector<ArchiveEntry>& out, std::string& err, int depth) {
    if (depth > kMaxDepth) {
        err = "directory nesting too deep: " + fs_path;
        return false;
    }
    if (out.size() >= ARCHIVE_MAX_ENTRIES) {
        err = "too many entries (limit " + std::to_string(ARCHIVE_MAX_ENTRIES) + ")";
        return false;
    }
    bool excluded = std::find(excludes.begin(), excludes.end(), fs_path) != excludes.end();

    uint32_t dmode = 0; int64_t dmtime = 0; uint64_t dsize = 0;
    if (!file_mode_time(fs_path, dmode, dmtime, dsize)) {
        err = "cannot stat " + fs_path;
        return false;
    }
    if (!excluded) {
        ArchiveEntry e;
        e.path = rel;
        e.is_dir = true;
        e.mode = dmode;
        e.mtime = dmtime;
        e.source = fs_path;
        out.push_back(std::move(e));
    }

#ifdef _WIN32
    std::wstring wpattern = utf8_to_wstring(fs_path + "\\*");
    struct _wfinddata_t fd;
    intptr_t h = _wfindfirst(wpattern.c_str(), &fd);
    if (h == -1) return true;                 // 空目录 / 不可读：不算失败
    std::vector<std::string> subdirs;
    do {
        if (wcscmp(fd.name, L".") == 0 || wcscmp(fd.name, L"..") == 0) continue;
        std::string name = wstring_to_utf8(fd.name);
        std::string child = fs_path + "\\" + name;
        std::string child_rel = rel + "/" + name;
        // 重解析点（junction / 符号链接目录，属性位 0x0400）一律跳过
        bool is_sub = (fd.attrib & _A_SUBDIR) != 0;
        bool reparse = (fd.attrib & 0x0400) != 0;
        if (is_sub) {
            if (!reparse && !excluded) subdirs.push_back(child);
            continue;
        }
        if (reparse) continue;                // 文件形态的重解析点也不收
        std::string norm;
        if (!normalize_rel(child_rel, norm)) continue;
        uint32_t m = 0; int64_t mt = 0; uint64_t sz = 0;
        if (!file_mode_time(child, m, mt, sz)) continue;
        ArchiveEntry e;
        e.path = norm; e.size = sz; e.mode = m; e.mtime = mt; e.source = child;
        out.push_back(std::move(e));
    } while (_wfindnext(h, &fd) == 0);
    _findclose(h);
    for (const auto& sub : subdirs) {
        std::string subname = base_name_of(sub);
        std::string norm;
        if (!normalize_rel(rel + "/" + subname, norm)) continue;
        if (!walk_dir(sub, norm, excludes, out, err, depth + 1)) return false;
    }
#else
    DIR* dp = opendir(fs_path.c_str());
    if (!dp) return true;
    std::vector<std::string> subdirs;
    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        std::string child = fs_path + "/" + de->d_name;
        std::string child_rel = rel + "/" + de->d_name;
        struct stat st;
        if (::lstat(child.c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;    // 符号链接不归档
        std::string norm;
        if (!normalize_rel(child_rel, norm)) continue;
        if (S_ISDIR(st.st_mode)) { subdirs.push_back(child); continue; }
        if (std::find(excludes.begin(), excludes.end(), child) != excludes.end()) continue;
        ArchiveEntry e;
        e.path = norm; e.size = (uint64_t)st.st_size;
        e.mode = (uint32_t)(st.st_mode & 0777);
        e.mtime = (int64_t)st.st_mtime; e.source = child;
        out.push_back(std::move(e));
    }
    closedir(dp);
    for (const auto& sub : subdirs) {
        std::string subname = base_name_of(sub);
        std::string norm;
        if (!normalize_rel(rel + "/" + subname, norm)) continue;
        if (!walk_dir(sub, norm, excludes, out, err, depth + 1)) return false;
    }
#endif
    return true;
}

// POSIX 叫 fdopen，MSVC 叫 _fdopen；这里收口，避免 Windows 专名漏到 POSIX 构建
static inline std::FILE* fdopen_compat(int fd, const char* mode) {
#ifdef _WIN32
    return _fdopen(fd, mode);
#else
    return ::fdopen(fd, mode);
#endif
}

// 独占创建的文件：O_EXCL 保证目标此前不存在，不跟随攻击者预置的符号链接。
class ExclFile {
public:
    explicit ExclFile(const std::string& path) {
#ifdef _WIN32
        std::wstring wpath = utf8_to_wstring(path);
        int fd = _wopen(wpath.c_str(), _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
                        _S_IREAD | _S_IWRITE);
#else
        int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
#endif
        if (fd < 0) { err_ = errno; return; }
        fp_ = fdopen_compat(fd, "wb");
        if (!fp_) {
            err_ = errno;
#ifdef _WIN32
            _close(fd);
#else
            ::close(fd);
#endif
        }
    }
    ~ExclFile() { if (fp_) std::fclose(fp_); }
    ExclFile(const ExclFile&) = delete;
    ExclFile& operator=(const ExclFile&) = delete;
    bool ok() const { return fp_ != nullptr; }
    int err() const { return err_; }
    bool raw(const void* p, size_t n) { return std::fwrite(p, 1, n, fp_) == n; }
private:
    std::FILE* fp_ = nullptr;
    int err_ = 0;
};

// 只读打开（宽字符安全），供解包时读源归档
std::FILE* open_read(const std::string& path) {
#ifdef _WIN32
    std::wstring wpath = utf8_to_wstring(path);
    return _wfopen(wpath.c_str(), L"rb");
#else
    return std::fopen(path.c_str(), "rb");
#endif
}

bool read_exact(std::FILE* f, void* p, size_t n) { return std::fread(p, 1, n, f) == n; }

void apply_mode_time(const std::string& path, uint32_t mode, int64_t mtime) {
#ifdef _WIN32
    // Windows 只落地只读位：权限模型与 POSIX 不同，强行套 0777 反而会去掉写权限
    if ((mode & 0200) == 0) _wchmod(utf8_to_wstring(path).c_str(), _S_IREAD);
    // 用 SetFileTime 而非 _utime 系列：后者的 _utim64 要看 _USE_32BIT_TIME_T
    // 宏与 CRT 版本，跨工具链不稳；Win32 这条路径没有这种依赖
    if (mtime > 0) {
        ULARGE_INTEGER ft;
        // Unix 秒 → Windows FILETIME（100ns 自 1601-01-01 起）
        ft.QuadPart = ((ULONGLONG)mtime - 11644473600ULL) * 10000000ULL;
        FILETIME t;
        t.dwLowDateTime  = ft.LowPart;
        t.dwHighDateTime = ft.HighPart;
        HANDLE h = CreateFileW(utf8_to_wstring(path).c_str(), FILE_WRITE_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            SetFileTime(h, &t, &t, &t);
            CloseHandle(h);
        }
    }
#else
    ::chmod(path.c_str(), (mode_t)(mode & 0777));
    struct utimbuf ut;
    ut.actime = (time_t)mtime;
    ut.modtime = (time_t)mtime;
    ::utime(path.c_str(), &ut);
#endif
}

}  // namespace

bool archive_collect(const std::vector<std::string>& inputs,
                     const std::vector<std::string>& excludes,
                     std::vector<ArchiveEntry>& out, std::string& err) {
    err.clear();
    out.clear();
    for (const auto& in : inputs) {
        if (is_dir_path(in)) {
            // 顶层保留目录名，解包出来仍是一棵完整的树
            std::string top = base_name_of(in);
            std::string norm;
            if (!normalize_rel(top, norm)) {
                err = "cannot use directory name in archive: " + top;
                return false;
            }
            if (std::find(excludes.begin(), excludes.end(), in) != excludes.end()) continue;
            if (!walk_dir(in, norm, excludes, out, err, 0)) return false;
        } else {
            std::string name = base_name_of(in);
            std::string norm;
            if (!normalize_rel(name, norm)) {
                err = "cannot use file name in archive: " + name;
                return false;
            }
            uint32_t m = 0; int64_t mt = 0; uint64_t sz = 0;
            if (!file_mode_time(in, m, mt, sz)) { err = "cannot stat " + in; return false; }
            ArchiveEntry e;
            e.path = norm; e.size = sz; e.mode = m; e.mtime = mt; e.source = in;
            out.push_back(std::move(e));
        }
        if (out.size() > ARCHIVE_MAX_ENTRIES) {
            err = "too many entries (limit " + std::to_string(ARCHIVE_MAX_ENTRIES) + ")";
            return false;
        }
    }
    if (out.empty()) { err = "nothing to archive"; return false; }
    // 同名条目会让解包端互相覆盖，打包端直接拒
    std::vector<std::string> seen;
    seen.reserve(out.size());
    for (const auto& e : out) {
        if (std::find(seen.begin(), seen.end(), e.path) != seen.end()) {
            err = "duplicate entry in archive: " + e.path;
            return false;
        }
        seen.push_back(e.path);
    }
    return true;
}

bool archive_write(const std::string& out_path,
                   const std::vector<ArchiveEntry>& entries, std::string& err) {
    err.clear();
    if (entries.empty()) { err = "nothing to archive"; return false; }
    if (entries.size() > ARCHIVE_MAX_ENTRIES) { err = "too many entries"; return false; }

    uint64_t total_raw = 0;
    for (const auto& e : entries)
        if (!e.is_dir) total_raw += e.size;

    ExclFile out(out_path);
    if (!out.ok()) {
        err = (out.err() == EEXIST)
            ? ("output already exists: " + out_path)
            : ("cannot write " + out_path);
        return false;
    }

    unsigned char head[ARCHIVE_HEADER_SIZE];
    std::memcpy(head, ARCHIVE_MAGIC, 8);
    put_le32(head + 8,  ARCHIVE_VERSION);
    put_le32(head + 12, (uint32_t)entries.size());
    put_le64(head + 16, total_raw);
    put_le64(head + 24, 0);
    if (!out.raw(head, sizeof(head))) { err = "write failed: " + out_path; return false; }

    std::vector<char> buf(kIoBuf);
    for (const auto& e : entries) {
        unsigned char rec[28];
        put_le32(rec + 0, (uint32_t)e.path.size());
        put_le32(rec + 4, e.is_dir ? ARCHIVE_FLAG_DIR : 0u);
        put_le64(rec + 8, e.is_dir ? 0ull : e.size);
        put_le32(rec + 16, e.mode & 0xFFFu);
        put_le64(rec + 20, (uint64_t)e.mtime);
        if (!out.raw(rec, sizeof(rec)) || !out.raw(e.path.data(), e.path.size())) {
            err = "write failed: " + out_path;
            return false;
        }
        if (e.is_dir) continue;
        std::ifstream in;
        if (!open_stream(in, e.source, std::ios::in | std::ios::binary)) {
            err = "cannot open " + e.source;
            return false;
        }
        uint64_t left = e.size;
        while (left > 0) {
            size_t want = (size_t)std::min<uint64_t>(left, buf.size());
            in.read(buf.data(), (std::streamsize)want);
            std::streamsize got = in.gcount();
            if (got <= 0) { err = "unexpected end of " + e.source; return false; }
            if (!out.raw(buf.data(), (size_t)got)) {
                err = "write failed: " + out_path;
                return false;
            }
            left -= (uint64_t)got;
        }
    }

    unsigned char tail[16];
    std::memcpy(tail, TRAILER, 8);
    put_le64(tail + 8, total_raw);
    if (!out.raw(tail, sizeof(tail))) { err = "write failed: " + out_path; return false; }
    return true;
}

bool archive_probe(const std::string& path) {
    std::FILE* f = open_read(path);
    if (!f) return false;
    unsigned char m[8];
    bool ok = read_exact(f, m, 8) && std::memcmp(m, ARCHIVE_MAGIC, 8) == 0;
    std::fclose(f);
    return ok;
}

bool archive_extract(const std::string& archive_path, const std::string& out_dir,
                     bool force_overwrite,
                     std::function<void(uint64_t, uint64_t)> progress,
                     std::string& err) {
    err.clear();
    std::FILE* f = open_read(archive_path);
    if (!f) { err = "cannot open " + archive_path; return false; }
    struct Closer { std::FILE* f; ~Closer(){ if (f) std::fclose(f); } } closer{f};

    unsigned char head[ARCHIVE_HEADER_SIZE];
    if (!read_exact(f, head, sizeof(head)) || std::memcmp(head, ARCHIVE_MAGIC, 8) != 0) {
        err = "not an archive container: " + archive_path;
        return false;
    }
    if (get_le32(head + 8) != ARCHIVE_VERSION) {
        err = "unsupported archive version " + std::to_string(get_le32(head + 8));
        return false;
    }
    uint32_t count = get_le32(head + 12);
    uint64_t total_raw = get_le64(head + 16);
    if (count > ARCHIVE_MAX_ENTRIES) { err = "archive declares too many entries"; return false; }

    if (!create_directory_recursive(out_dir)) {
        err = "cannot create output directory " + out_dir;
        return false;
    }

    std::string last_made;
    std::vector<char> buf(kIoBuf);
    uint64_t done = 0;

    struct Pending { std::string path; uint32_t mode; int64_t mtime; };
    std::vector<Pending> dirs;

    // 顺序处理：目录条目直接建，文件条目缺父目录时现补。
    // 目录的权限与时间统一留到最后 —— 建子目录会改写父目录的 mtime。
    for (uint32_t i = 0; i < count; ++i) {
        unsigned char rec[28];
        if (!read_exact(f, rec, sizeof(rec))) { err = "truncated archive"; return false; }
        uint32_t plen = get_le32(rec + 0);
        uint32_t flags = get_le32(rec + 4);
        uint64_t size = get_le64(rec + 8);
        uint32_t mode = get_le32(rec + 16);
        int64_t mtime = (int64_t)get_le64(rec + 20);
        if (plen == 0 || plen > ARCHIVE_MAX_PATH) { err = "corrupt archive entry"; return false; }
        std::string raw_path(plen, '\0');
        if (!read_exact(f, &raw_path[0], plen)) { err = "truncated archive"; return false; }
        std::string rel;
        if (!normalize_rel(raw_path, rel)) {
            err = "unsafe path in archive: " + raw_path;
            return false;
        }
        std::string target = join_path(out_dir, rel);

        if (flags & ARCHIVE_FLAG_DIR) {
            if (!create_directory_recursive(target)) {
                err = "cannot create directory " + target;
                return false;
            }
            dirs.push_back({target, mode, mtime});
            continue;
        }

        // 文件：父目录缺失就现补（归档里可能没显式收录空目录之外的父条目）
        std::string pd = parent_of(target);
        if (pd != last_made) {
            if (!create_directory_recursive(pd)) {
                err = "cannot create directory " + pd;
                return false;
            }
            last_made = pd;
        }

        // 已存在：-y 覆盖（先删再以 O_EXCL 建，删的是链接本身不跟到别处），
        // 否则跳过并保持原样
        bool exists = false;
        {
            std::ifstream t;
            exists = open_stream(t, target, std::ios::in | std::ios::binary) && t.good();
        }
        if (exists) {
            if (!force_overwrite) {
                fprintf(stderr, "Skipped (exists): %s\n", target.c_str());
                // 数据仍要读掉，保持流位置
                uint64_t left = size;
                while (left > 0) {
                    size_t want = (size_t)std::min<uint64_t>(left, buf.size());
                    if (!read_exact(f, buf.data(), want)) { err = "truncated archive"; return false; }
                    left -= want;
                    done += want;
                    if (progress) progress(done, total_raw);
                }
                continue;
            }
            remove_file_utf8(target);
        }

        ExclFile o(target);
        if (!o.ok()) { err = "cannot write " + target; return false; }
        uint64_t left = size;
        while (left > 0) {
            size_t want = (size_t)std::min<uint64_t>(left, buf.size());
            if (!read_exact(f, buf.data(), want)) { err = "truncated archive"; return false; }
            if (!o.raw(buf.data(), want)) { err = "write failed: " + target; return false; }
            left -= want;
            done += want;
            if (progress) progress(done, total_raw);
        }
        apply_mode_time(target, mode, mtime);
    }

    // 目录的属性放最后：建子目录时父目录的 mtime 会被改写
    for (const auto& d : dirs) apply_mode_time(d.path, d.mode, d.mtime);

    unsigned char tail[16];
    if (!read_exact(f, tail, sizeof(tail)) || std::memcmp(tail, TRAILER, 8) != 0) {
        err = "archive is truncated or corrupted (bad trailer)";
        return false;
    }
    if (get_le64(tail + 8) != total_raw || done != total_raw) {
        err = "archive size mismatch (expected " + std::to_string(total_raw) +
              " bytes, got " + std::to_string(done) + ")";
        return false;
    }
    return true;
}

bool archive_make_temp(const std::string& tag, std::string& out_path, std::string& err) {
    err.clear();
#ifdef _WIN32
    wchar_t wbuf[MAX_PATH + 1];
    DWORD n = GetTempPathW(MAX_PATH, wbuf);
    if (n == 0 || n > MAX_PATH) { err = "cannot locate temp directory"; return false; }
    std::string dir = wstring_to_utf8(wbuf);
#else
    const char* e = getenv("TMPDIR");
    std::string dir = (e && *e) ? e : "/tmp";
#endif
    while (!dir.empty() && (dir.back()=='/' || dir.back()=='\\')) dir.pop_back();

    // 名字可预测就能被抢先预置（符号链接 / 占位阻断），故用 16 字节随机量。
    // 占位文件必须先关闭再删：Windows 上 _wopen 不带 FILE_SHARE_DELETE，
    // 句柄还开着时删除会失败，于是 archive_write 的 O_EXCL 永远撞 EEXIST。
    for (int attempt = 0; attempt < 8; ++attempt) {
        unsigned char r[16];
        randombytes_buf(r, sizeof(r));
        std::string cand = join_path(dir, ".fearch-" + tag + "-" +
                                           fe::util::to_hex(r, sizeof(r)) + ".tmp");
        int e = 0;
        {
            ExclFile probe(cand);
            if (probe.ok()) e = 0;
            else e = probe.err();
        }
        if (e == 0) {
            remove_file_utf8(cand);   // 只用来证明这个名字此刻可用
            out_path = cand;
            return true;
        }
        if (e != EEXIST) { err = "cannot create a temp file in " + dir; return false; }
    }
    err = "cannot find a free temp file name in " + dir;
    return false;
}


// 列目录下一层条目名（不含 . 与 ..）
bool list_dir_names(const std::string& dir, std::vector<std::string>& out) {
    out.clear();
#ifdef _WIN32
    std::wstring wpat = utf8_to_wstring(dir + "\\*");
    struct _wfinddata_t fd;
    intptr_t h = _wfindfirst(wpat.c_str(), &fd);
    if (h == -1) return false;
    do {
        if (wcscmp(fd.name, L".") == 0 || wcscmp(fd.name, L"..") == 0) continue;
        out.push_back(wstring_to_utf8(fd.name));
    } while (_wfindnext(h, &fd) == 0);
    _findclose(h);
#else
    DIR* dp = opendir(dir.c_str());
    if (!dp) return false;
    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        out.push_back(de->d_name);
    }
    closedir(dp);
#endif
    return true;
}

bool merge_dir_into(const std::string& src_dir, const std::string& dst_dir,
                    bool force_overwrite, std::string& err) {
    err.clear();
    std::vector<std::string> names;
    if (!list_dir_names(src_dir, names)) { err = "cannot read " + src_dir; return false; }
    if (!create_directory_recursive(dst_dir)) { err = "cannot create " + dst_dir; return false; }
    for (const auto& n : names) {
        std::string from = join_path(src_dir, n);
        std::string to = join_path(dst_dir, n);
        bool fdir = is_dir_path(from);
        bool tdir = is_dir_path(to);
        if (fdir && tdir) {
            if (!merge_dir_into(from, to, force_overwrite, err)) return false;
            continue;
        }
        if (tdir) { remove_tree(to); }
        else if (!force_overwrite) {
            std::ifstream ex;
            if (open_stream(ex, to, std::ios::in | std::ios::binary) && ex.good()) continue;
        } else {
            remove_file_utf8(to);
        }
        if (!replace_file_utf8(from, to)) { err = "cannot move " + from; return false; }
    }
    return true;
}

bool remove_tree(const std::string& dir) {
    std::vector<std::string> names;
    if (!list_dir_names(dir, names)) return false;
    for (const auto& n : names) {
        std::string p = join_path(dir, n);
        // 只对真实目录递归；符号链接 / 重解析点删链接本身，
        // 跟进去就可能删到这棵树之外
        if (is_dir_path(p)) remove_tree(p);
        else remove_file_utf8(p);
    }
    // 目录不能用 remove_file_utf8：Windows 上 _wremove 删不了目录，
    // 少了这步会把空暂存目录留在输出目录里
#ifdef _WIN32
    return _wrmdir(utf8_to_wstring(dir).c_str()) == 0;
#else
    return ::rmdir(dir.c_str()) == 0;
#endif
}
