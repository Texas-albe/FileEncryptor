#include "fileio_util.hpp"

#include <cstdio>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

#include "FileEncryptor.hpp"   

bool fe_file_exists(const std::string& path) {
    std::ifstream f;
    return open_stream(f, path, std::ios::in | std::ios::binary);
}

int64_t fe_file_size(const std::string& path) {
#ifdef _WIN32
    struct _stat64 st;
    if (_wstat64(utf8_to_wstring(path).c_str(), &st) != 0) return -1;
    return st.st_size;
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return -1;
    return (int64_t)st.st_size;
#endif
}

bool fe_truncate_file(const std::string& path, uint64_t size) {
#ifdef _WIN32
    std::wstring wpath = utf8_to_wstring(path);
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)size;
    bool ok = true;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) ok = false;
    else if (!SetEndOfFile(h)) ok = false;
    CloseHandle(h);
    return ok;
#else
    return ::truncate(path.c_str(), (off_t)size) == 0;
#endif
}

bool create_directory_recursive(const std::string& path) {
    // 5.2 安全加固
    // SAF content
    if (path.rfind("content://", 0) != 0 && path_has_traversal(path)) return false;
    if (path.empty()) return true;
#ifdef _WIN32
    struct _stat64 st;
    if (_wstat64(utf8_to_wstring(path).c_str(), &st) == 0) {
        return (st.st_mode & S_IFDIR) != 0;
    }
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        std::string parent = path.substr(0, pos);
        // 盘符根
        // 盘可访问
        if (parent.size() == 2 && parent[1] == ':') {
            struct _stat64 rst;
            if (_wstat64(utf8_to_wstring(parent + "/").c_str(), &rst) != 0 ||
                (rst.st_mode & S_IFDIR) == 0) {
                return false;   // 盘不存
            }
            // 盘根存
        } else {
            if (!create_directory_recursive(parent)) return false;
        }
    }
    return _wmkdir(utf8_to_wstring(path).c_str()) == 0;
#else
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return (st.st_mode & S_IFDIR) != 0;
    }
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        if (!create_directory_recursive(path.substr(0, pos))) return false;
    }
    return mkdir(path.c_str(), 0755) == 0;
#endif
}

std::string fe_normalize_path_lexical(const std::string& p) {
    std::string s = p;
    bool had_long_prefix = false, had_unc_prefix = false;
#ifdef _WIN32
    // Windows 长路径 / 设备前缀：\\?\
    // 攻击者可能借
    for(char& ch : s) if(ch=='/') ch='\\';
    if(s.size()>=4 && s[0]=='\\' && s[1]=='\\' && s[2]=='?' && s[3]=='\\') {
        had_long_prefix = true;
        if(s.size()>=8 && s.compare(4,4,"UNC\\")==0) {
            had_unc_prefix = true;
            s = "\\" + s.substr(8);   
        } else {
            s = s.substr(4);          // \\?\C:\... -> C:\...
        }
    }
#endif
    // 注意
    // 须先 utf8_to_wstring
#ifdef _WIN32
    fs::path np = fs::path(utf8_to_wstring(s)).lexically_normal();
    if(np.empty()) np = fs::path(utf8_to_wstring(s));
    std::string out = wstring_to_utf8(np.make_preferred().wstring());
#else
    fs::path np = fs::path(s).lexically_normal();
    if(np.empty()) np = fs::path(s);
    std::string out = np.make_preferred().string();
#endif
#ifdef _WIN32
    // 还原长路径前缀
    if(had_unc_prefix && out.size()>=2) out = "\\\\?\\UNC\\" + out.substr(2);
    else if(had_long_prefix) out = "\\\\?\\" + out;
#endif
    return out;
}
