// vdisk 宿主
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS   // getenv 在 MSVC 下告警，此处只
#endif

#include "saf_vault.hpp"
#include "vdisk.h"

#include <cstdlib>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
using LibHandle = HMODULE;
#ifndef LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 0x00000100
#endif
#ifndef LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x00001000
#endif
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif
#ifndef LOAD_WITH_ALTERED_SEARCH_PATH
#define LOAD_WITH_ALTERED_SEARCH_PATH 0x00000008
#endif
#else
#include <dlfcn.h>
using LibHandle = void*;
#endif

namespace {

// vdisk 符号表
struct VdiskSyms {
    VDiskHandle*  (*open)(const char*) = nullptr;
    void          (*close)(VDiskHandle*) = nullptr;
    VDiskStatus   (*unlock)(VDiskHandle*, const char*, int) = nullptr;
    VDiskStatus   (*lock)(VDiskHandle*) = nullptr;
    VDiskStatus   (*readdir)(VDiskHandle*, const char*, VDiskEntry**, uint64_t*) = nullptr;
    VDiskStatus   (*getattr)(VDiskHandle*, const char*, uint64_t*, uint64_t*, uint8_t*) = nullptr;
    VDiskStatus   (*read_file)(VDiskHandle*, const char*, uint64_t, uint8_t*, uint64_t*) = nullptr;
    VDiskStatus   (*write_file)(VDiskHandle*, const char*, uint64_t, const uint8_t*, uint64_t) = nullptr;
    VDiskStatus   (*mount_rw)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus   (*create_file)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus   (*delete_file)(VDiskHandle*, const char*) = nullptr;
    VDiskStatus   (*truncate_file)(VDiskHandle*, const char*, uint64_t) = nullptr;
    uint32_t      (*abi_version)() = nullptr;
};

SafStatus map_status(VDiskStatus s) {
    switch (s) {
    case VDISK_OK:         return SAF_OK;
    case VDISK_E_BADARG:   return SAF_E_BADARG;
    case VDISK_E_AUTH:     return SAF_E_AUTH;
    case VDISK_E_LOCKED:   return SAF_E_LOCKED;
    case VDISK_E_NOMEM:    return SAF_E_NOMEM;
    case VDISK_E_NOTIMPL:  return SAF_E_NOTIMPL;
    case VDISK_E_NOTFOUND: return SAF_E_NOTFOUND;
    case VDISK_E_RO:       return SAF_E_RO;
    case VDISK_E_INTERNAL: return SAF_E_INTERNAL;
    default:               return SAF_E_IO;
    }
}

// 密码用完即清零
void wipe(std::string& s) {
    if (s.empty()) return;
    volatile char* p = &s[0];
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
}

void* raw_sym(LibHandle h, const char* name) {
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(h, name));
#else
    return dlsym(h, name);
#endif
}

template <typename T>
void bind(LibHandle h, const char* name, T& fn) {
    fn = reinterpret_cast<T>(raw_sym(h, name));
}

void unload_lib(LibHandle h) {
    if (!h) return;
#ifdef _WIN32
    FreeLibrary(h);
#else
    dlclose(h);
#endif
}

LibHandle load_raw(const std::string& path, bool full_path) {
    if (path.empty()) return LibHandle();
#ifdef _WIN32
    std::wstring w = saf_utf8_to_wide(path);
    // 全路径只信该目
    DWORD flags = full_path ? (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
                            : LOAD_LIBRARY_SEARCH_SYSTEM32;
    HMODULE h = LoadLibraryExW(w.c_str(), nullptr, flags);
    if (!h && full_path) h = LoadLibraryExW(w.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);   // 老系统
    return h;
#else
    (void)full_path;
    return dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
}

std::string lib_name() {
#ifdef _WIN32
    return "vdisk.dll";
#else
    return "libvdisk.so";
#endif
}

// 候选顺序
bool load_vdisk(const std::string& explicit_path, const std::string& library_dir,
                LibHandle& out_lib, VdiskSyms& out_syms, bool& out_full_path) {
    std::vector<std::pair<std::string, bool>> cands;   
    if (!explicit_path.empty()) cands.push_back({ explicit_path, true });
    if (const char* env = std::getenv("FE_VDISK_LIB")) {
        if (env && *env) cands.push_back({ std::string(env), true });
    }
    if (!library_dir.empty()) {
        std::string d = library_dir;
        char last = d.empty() ? '\0' : d.back();
        std::string sep = (last == '/' || last == '\\') ? std::string() : "/";
        cands.push_back({ d + sep + lib_name(), true });
    }
    cands.push_back({ lib_name(), false });

    for (const auto& c : cands) {
        LibHandle h = load_raw(c.first, c.second);
        if (!h) continue;
        VdiskSyms s;
        bind(h, "vdisk_open", s.open);
        bind(h, "vdisk_close", s.close);
        bind(h, "vdisk_unlock", s.unlock);
        bind(h, "vdisk_lock", s.lock);
        bind(h, "vdisk_readdir", s.readdir);
        bind(h, "vdisk_getattr", s.getattr);
        bind(h, "vdisk_read_file", s.read_file);
        bind(h, "vdisk_write_file", s.write_file);
        bind(h, "vdisk_mount_rw", s.mount_rw);
        bind(h, "vdisk_create_file", s.create_file);
        bind(h, "vdisk_delete_file", s.delete_file);
        bind(h, "vdisk_truncate_file", s.truncate_file);
        bind(h, "vdisk_abi_version", s.abi_version);
        if (!s.open || !s.close || !s.unlock || !s.readdir || !s.getattr || !s.read_file ||
            !s.abi_version) {
            unload_lib(h);
            continue;
        }
        if (s.abi_version() != VDISK_ABI_VERSION) {   // 符号齐全但 ABI 版本
            unload_lib(h);
            continue;
        }
        out_lib = h;
        out_syms = s;
        out_full_path = c.second;
        return true;
    }
    return false;
}

class VdiskVaultHost final : public VaultHost {
public:
    VdiskVaultHost(LibHandle lib, const VdiskSyms& syms, VDiskHandle* h, bool writable)
        : lib_(lib), s_(syms), h_(h), writable_(writable) {}

    ~VdiskVaultHost() override {
        if (!h_) return;
        if (s_.lock) s_.lock(h_);
        s_.close(h_);
        h_ = nullptr;
        unload_lib(lib_);
        lib_ = LibHandle();
    }

    bool writable() const override { return writable_; }

    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        out.clear();
        uint64_t n = 0;
        VDiskStatus st = s_.readdir(h_, vpath.c_str(), nullptr, &n);   // 第一段
        if (st != VDISK_OK) return map_status(st);
        if (n == 0) return SAF_OK;
        std::vector<VDiskEntry> arr(n);
        VDiskEntry* base = arr.data();
        uint64_t cap = n;
        st = s_.readdir(h_, vpath.c_str(), &base, &cap);                // 第二段
        if (st != VDISK_OK) return map_status(st);
        for (uint64_t i = 0; i < n; ++i) {
            SafEntry e;
            e.name = arr[i].name ? arr[i].name : "";
            e.is_dir = arr[i].is_dir != 0;
            e.size = arr[i].size;
            e.mtime = arr[i].mtime;
            out.push_back(std::move(e));
        }
        return SAF_OK;
    }

    SafStatus getattr(const std::string& vpath, uint64_t* out_size,
                      uint64_t* out_mtime, bool* out_is_dir) override {
        uint8_t dir = 0;
        VDiskStatus st = s_.getattr(h_, vpath.c_str(), out_size, out_mtime, &dir);
        if (st != VDISK_OK) return map_status(st);
        if (out_is_dir) *out_is_dir = dir != 0;
        return SAF_OK;
    }

    SafStatus read(const std::string& vpath, uint64_t offset,
                   uint8_t* out, uint64_t* len) override {
        VDiskStatus st = s_.read_file(h_, vpath.c_str(), offset, out, len);
        return map_status(st);
    }

    SafStatus write(const std::string& vpath, uint64_t offset,
                    const uint8_t* in, uint64_t len) override {
        if (!s_.write_file) return SAF_E_NOTIMPL;
        return map_status(s_.write_file(h_, vpath.c_str(), offset, in, len));
    }

    SafStatus create_file(const std::string& vpath) override {
        if (!s_.create_file) return SAF_E_NOTIMPL;
        return map_status(s_.create_file(h_, vpath.c_str()));
    }

    SafStatus delete_file(const std::string& vpath) override {
        if (!s_.delete_file) return SAF_E_NOTIMPL;
        return map_status(s_.delete_file(h_, vpath.c_str()));
    }

    SafStatus truncate_file(const std::string& vpath, uint64_t new_size) override {
        if (!s_.truncate_file) return SAF_E_NOTIMPL;
        return map_status(s_.truncate_file(h_, vpath.c_str(), new_size));
    }

    SafStatus lock() override {
        if (!s_.lock) return SAF_E_NOTIMPL;
        return map_status(s_.lock(h_));
    }

private:
    LibHandle   lib_;
    VdiskSyms   s_;
    VDiskHandle* h_;
    bool        writable_;
};

}  // namespace

SafStatus saf_open_vault_vdisk(const std::string& library_dir,
                               const std::string& passphrase,
                               const VaultVdiskOptions& opt,
                               std::shared_ptr<StorageBackend>& out) {
    out.reset();
    if (passphrase.empty()) return SAF_E_BADARG;

    LibHandle lib = LibHandle();
    VdiskSyms syms;
    bool full_path = false;
    if (!load_vdisk(opt.lib_path, library_dir, lib, syms, full_path)) return SAF_E_NOTFOUND;

    VDiskHandle* h = syms.open(library_dir.c_str());
    if (!h) { unload_lib(lib); return SAF_E_IO; }

    std::string pw = passphrase;                       // 拷一份
    VDiskStatus st = syms.unlock(h, pw.c_str(), opt.use_recovery ? 1 : 0);
    wipe(pw);
    if (st != VDISK_OK) { syms.close(h); unload_lib(lib); return map_status(st); }

    if (opt.writable) {
        // 只置可写标志
        st = syms.mount_rw(h, "");
        if (st != VDISK_OK) { syms.close(h); unload_lib(lib); return map_status(st); }
    }

    out = saf_open_vault(std::make_shared<VdiskVaultHost>(lib, syms, h, opt.writable));
    return out ? SAF_OK : SAF_E_NOMEM;
}
