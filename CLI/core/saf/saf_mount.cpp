// 挂载点后端：底层仍是本地 fs，但打开前校验挂载、打开时复查存活
#include "saf_mount.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace {

std::string parent_dir(const std::string& p) {
    std::string s = p;
    while (s.size() > 1 && (s.back() == '/' || s.back() == '\\')) s.pop_back();
    size_t pos = s.find_last_of("/\\");
    if (pos == std::string::npos) return std::string();
    if (pos == 0) return std::string(1, s[0]);        // "/xxx" → "/"
#ifdef _WIN32
    if (pos == 2 && s.size() == 3 && s[1] == ':') return std::string();   // "C:\" 盘根无父
#endif
    return s.substr(0, pos);
}

bool dev_id(const std::string& p, uint64_t& out) {
#ifdef _WIN32
    std::wstring w = saf_utf8_to_wide(p);
    HANDLE h = CreateFileW(w.c_str(), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION fi;
    ZeroMemory(&fi, sizeof(fi));
    BOOL ok = GetFileInformationByHandle(h, &fi);
    CloseHandle(h);
    if (!ok) return false;
    out = fi.dwVolumeSerialNumber;
    return true;
#else
    struct stat st;
    if (::stat(p.c_str(), &st) != 0) return false;
    out = (uint64_t)st.st_dev;
    return true;
#endif
}

class MountBackend : public StorageBackend {
public:
    MountBackend(std::shared_ptr<StorageBackend> inner, std::string point,
                 bool writable, bool require)
        : inner_(std::move(inner)), point_(std::move(point)),
          writable_(writable), require_(require) {}

    const char* scheme() const override { return "mount"; }
    bool can_write() const override { return writable_ && inner_->can_write(); }
    bool can_list()  const override { return inner_->can_list(); }

    SafStatus stat(const std::string& vpath, uint64_t* s, uint64_t* m, bool* d,
                   bool* sl = nullptr, uint32_t* mo = nullptr) override {
        return inner_->stat(vpath, s, m, d, sl, mo);
    }
    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        return inner_->readdir(vpath, out);
    }
    SafStatus open(const std::string& vpath, char mode, std::shared_ptr<Stream>& out) override {
        uint64_t d = 0;
        if (!dev_id(point_, d)) return SAF_E_GONE;                     // 挂载点已不存在
        if (require_ && !saf_is_mount_point(point_)) return SAF_E_GONE; // 已卸载，别往空目录写
        if (mode != 'r' && !writable_) return SAF_E_RO;   // M33：写模式打开同样要求后端可写（与 delete_file 一致）
        return inner_->open(vpath, mode, out);
    }
    SafStatus create_file(const std::string& v) override {
        if (!writable_) return SAF_E_RO;   // M33：只读挂载点后端拒绝建文件（与 delete_file 一致）
        return inner_->create_file(v);
    }
    SafStatus mkdir(const std::string& v) override {
        if (!writable_) return SAF_E_RO;   // M33：只读挂载点后端拒绝建目录
        return inner_->mkdir(v);
    }
    SafStatus delete_file(const std::string& v) override {
        if (!writable_) return SAF_E_RO;
        return inner_->delete_file(v);
    }
    SafStatus truncate_file(const std::string& v, uint64_t n) override {
        if (!writable_) return SAF_E_RO;   // M33：只读挂载点后端拒绝截断
        return inner_->truncate_file(v, n);
    }
    SafStatus rename_file(const std::string& a, const std::string& b) override {
        if (!writable_) return SAF_E_RO;   // M33：只读挂载点后端拒绝改名
        return inner_->rename_file(a, b);
    }
    SafStatus symlink(const std::string& target, const std::string& vpath) override {
        uint64_t d = 0;
        if (!dev_id(point_, d)) return SAF_E_GONE;
        return inner_->symlink(target, vpath);
    }
    SafStatus readlink(const std::string& vpath, std::string& out_target) override {
        uint64_t d = 0;
        if (!dev_id(point_, d)) return SAF_E_GONE;
        return inner_->readlink(vpath, out_target);
    }
    SafStatus chmod(const std::string& vpath, uint32_t mode) override {
        uint64_t d = 0;
        if (!dev_id(point_, d)) return SAF_E_GONE;
        return inner_->chmod(vpath, mode);
    }
    bool can_symlink() const override { return inner_->can_symlink(); }
    bool can_chmod()  const override { return inner_->can_chmod(); }
    bool can_seek()   const override { return inner_->can_seek(); }

private:
    std::shared_ptr<StorageBackend> inner_;
    std::string point_;
    bool writable_;
    bool require_;
};

} // namespace

bool saf_is_mount_point(const std::string& path) {
    if (path.empty()) return false;
    uint64_t self = 0;
    if (!dev_id(path, self)) return false;
    std::string par = parent_dir(path);
    if (par.empty()) return true;                 // 盘根 / 无父目录
    uint64_t pdev = 0;
    if (!dev_id(par, pdev)) return false;
    return self != pdev;
}

bool saf_mount_alive(const std::string& path) {
    uint64_t d = 0;
    return dev_id(path, d);            // 只判能否访问，是否仍挂载由 saf_is_mount_point 复查
}

SafStatus saf_open_mount_fs(const std::string& mount_point,
                            const SafMountOptions& opt,
                            std::shared_ptr<StorageBackend>& out) {
    out.reset();
    if (mount_point.empty()) return SAF_E_BADARG;
    if (opt.require_mount && !saf_is_mount_point(mount_point)) return SAF_E_BADARG;
    auto inner = saf_open_local_fs(mount_point);
    if (!inner) return SAF_E_BADARG;
    out = std::make_shared<MountBackend>(inner, mount_point, opt.writable, opt.require_mount);
    return SAF_OK;
}
