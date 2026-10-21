// SAF 公共实现：错误文本 / 路径工具 / URI 解析 / 编码 / 后端工厂
#include "saf.hpp"
#include "saf_archive.hpp"
#include "saf_vault.hpp"

#include <cctype>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

// 错误文本
const char* saf_strerror(SafStatus st) {
    switch (st) {
    case SAF_OK:         return "ok";
    case SAF_E_BADARG:   return "bad argument";
    case SAF_E_AUTH:     return "authentication failed (wrong passphrase)";
    case SAF_E_LOCKED:   return "backend is locked";
    case SAF_E_NOMEM:    return "out of memory";
    case SAF_E_IO:       return "io error";
    case SAF_E_NOTIMPL:  return "not implemented";
    case SAF_E_NOTFOUND: return "not found";
    case SAF_E_RO:       return "read-only backend";
    case SAF_E_EXIST:    return "already exists";
    case SAF_E_GONE:     return "mount point is gone";
    case SAF_E_INTERNAL: return "internal error";
    }
    return "unknown";
}

// 路径规范化
bool saf_path_normalize(const std::string& in, std::string& out) {
    out.clear();
    std::string seg;
    auto flush = [&]() -> bool {
        if (seg.empty()) return true;
        if (seg == ".") { seg.clear(); return true; }
        if (seg == "..") return false;              // 越界一律拒绝
        if (seg.find('\0') != std::string::npos) return false;
        if (!out.empty()) out += "/";
        out += seg;
        seg.clear();
        return true;
    };
    for (char c : in) {
        if (c == '\\') c = '/';                     // 统一分隔符
        if (c == '/') { if (!flush()) return false; continue; }
        seg.push_back(c);
    }
    return flush();
}

// URI 拆分
bool saf_uri_split(const std::string& uri, std::string& scheme, std::string& rest) {
    const std::string kSep = "://";
    size_t p = uri.find(kSep);
    if (p == std::string::npos) { scheme.clear(); rest = uri; return true; }
    if (p == 0) return false;
    for (size_t i = 0; i < p; ++i) {
        unsigned char c = (unsigned char)uri[i];
        if (!(std::isalnum(c) || c == '+' || c == '-' || c == '.')) return false;
    }
    scheme = uri.substr(0, p);
    rest = uri.substr(p + kSep.size());
    return true;
}

// 后端工厂
SafStatus saf_open_backend(const std::string& uri, std::shared_ptr<StorageBackend>& out) {
    std::string scheme, rest;
    if (!saf_uri_split(uri, scheme, rest)) return SAF_E_BADARG;
    out.reset();
    if (scheme.empty() || scheme == "file") {
        out = saf_open_local_fs(rest);
        return out ? SAF_OK : SAF_E_BADARG;
    }
    if (scheme == "archive") return saf_open_archive_file(rest, out);   // 阶段二：归档只读后端
    if (scheme == "vault") return SAF_E_LOCKED;                         // 需密码，走带密码重载
    return SAF_E_BADARG;
}

SafStatus saf_open_backend_with_password(const std::string& uri,
                                         const std::string& passphrase,
                                         std::shared_ptr<StorageBackend>& out) {
    std::string scheme, rest;
    if (!saf_uri_split(uri, scheme, rest)) return SAF_E_BADARG;
    if (scheme != "vault") return saf_open_backend(uri, out);           // 其余后端不认密码
    VaultVdiskOptions opt;
    return saf_open_vault_vdisk(rest, passphrase, opt, out);
}

// 编码转换
#ifdef _WIN32
std::wstring saf_utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

std::string saf_wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
#else
std::wstring saf_utf8_to_wide(const std::string& s) { return std::wstring(s.begin(), s.end()); }
std::string saf_wide_to_utf8(const std::wstring& w) { return std::string(w.begin(), w.end()); }
#endif
