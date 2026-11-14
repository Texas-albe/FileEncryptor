// 加密盘后端
#include "saf_vault.hpp"
#include "saf_secure.hpp"

#include <cstring>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace {

constexpr uint64_t kMaxChunk = 1u << 30;

// 读流
class VaultReadStream final : public Stream {
public:
    VaultReadStream(std::shared_ptr<VaultHost> host, std::string vpath)
        : host_(std::move(host)), vpath_(std::move(vpath)) {}

    SafStatus read(uint8_t* out, uint64_t* len) override {
        if (!out || !len) return SAF_E_BADARG;
        if (*len == 0) return SAF_OK;
        host_->note_activity();                       // M5 续期下沉
        uint64_t remaining = *len;
        uint64_t written = 0;
        constexpr uint64_t kW = 1u << 20;             // 锁定窗口 1MiB
        SecureBuf buf(kW);
        while (remaining > 0) {
            uint64_t chunk = (remaining > kW) ? kW : remaining;
            uint64_t got = chunk;
            SafStatus st = host_->read(vpath_, off_ + written, buf.data(), &got);
            if (st != SAF_OK) { buf.zero(); *len = written; return st; }
            if (got == 0) { buf.zero(); *len = written; return SAF_OK; }   // EOF
            if (got > chunk) { buf.zero(); *len = written; return SAF_E_IO; }  // 宿主越界写=内部
            std::memcpy(out + written, buf.data(), (size_t)got);
            buf.zero();
            written += got;
            off_ += got;
            remaining -= got;
            if (got < chunk) { *len = written; return SAF_OK; }            // 短读=末块/EOF
        }
        *len = written;
        return SAF_OK;
    }

    SafStatus write(const uint8_t*, uint64_t) override { return SAF_E_RO; }
    SafStatus seek(uint64_t offset) override { off_ = offset; return SAF_OK; }

    SafStatus tell(uint64_t* out_pos) override {
        if (!out_pos) return SAF_E_BADARG;
        *out_pos = off_;
        return SAF_OK;
    }

    SafStatus flush() override { return SAF_OK; }
    SafStatus close() override { return SAF_OK; }

private:
    std::shared_ptr<VaultHost> host_;
    std::string                vpath_;
    uint64_t                   off_ = 0;
};

// 写流
class VaultWriteStream final : public Stream {
public:
    VaultWriteStream(std::shared_ptr<VaultHost> host, std::string vpath, uint64_t off)
        : host_(std::move(host)), vpath_(std::move(vpath)), off_(off) {}

    SafStatus read(uint8_t*, uint64_t*) override { return SAF_E_BADARG; }

    SafStatus write(const uint8_t* in, uint64_t len) override {
        if (len == 0) return SAF_OK;
        if (!in) return SAF_E_BADARG;
        SafStatus st = host_->write(vpath_, off_, in, len);
        if (st != SAF_OK) return st;
        off_ += len;
        return SAF_OK;
    }

    SafStatus seek(uint64_t offset) override { off_ = offset; return SAF_OK; }

    SafStatus tell(uint64_t* out_pos) override {
        if (!out_pos) return SAF_E_BADARG;
        *out_pos = off_;
        return SAF_OK;
    }

    SafStatus flush() override { return SAF_OK; }
    SafStatus close() override { return SAF_OK; }

private:
    std::shared_ptr<VaultHost> host_;
    std::string                vpath_;
    uint64_t                   off_ = 0;
};

class VaultBackend final : public StorageBackend {
public:
    explicit VaultBackend(std::shared_ptr<VaultHost> host) : host_(std::move(host)) {}

    const char* scheme() const override { return "vault"; }
    bool can_write() const override { return host_->writable(); }
    bool can_list() const override { return true; }
    bool can_integrity_check() const override { return true; }    // 底层 AEAD 逐块校验
    bool can_secure_wipe() const override { return false; }        // 明文擦除语义

    SafStatus stat(const std::string& vpath, uint64_t* out_size,
                   uint64_t* out_mtime, bool* out_is_dir,
                   bool* out_is_symlink = nullptr,
                   uint32_t* out_mode = nullptr) override {
        std::string p;
        if (!norm(vpath, p)) return SAF_E_BADARG;
        if (out_is_symlink) *out_is_symlink = false;   // 加密盘无符号链
        if (out_mode) *out_mode = 0;
        return host_->getattr(p, out_size, out_mtime, out_is_dir);
    }

    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        out.clear();
        std::string p;
        if (!norm(vpath, p)) return SAF_E_BADARG;
        std::vector<SafEntry> raw;
        SafStatus st = host_->readdir(p, raw);
        if (st != SAF_OK) return st;
        // 纵深防御
        for (auto& e : raw) {
            if (e.name.empty()) continue;
            if (e.name.find('/') != std::string::npos) continue;
            if (e.name.find('\\') != std::string::npos) continue;
            if (e.name == "." || e.name == "..") continue;
            out.push_back(std::move(e));
        }
        return SAF_OK;
    }

    SafStatus open(const std::string& vpath, char mode,
                   std::shared_ptr<Stream>& out) override {
        out.reset();
        std::string p;
        if (!norm(vpath, p)) return SAF_E_BADARG;
        if (p.empty()) return SAF_E_BADARG;                 // 盘根不能当文件

        if (mode == 'r') {
            bool is_dir = false;
            SafStatus st = host_->getattr(p, nullptr, nullptr, &is_dir);
            if (st != SAF_OK) return st;
            if (is_dir) return SAF_E_BADARG;
            out = std::make_shared<VaultReadStream>(host_, p);
            return SAF_OK;
        }
        if (mode != 'w' && mode != 'a') return SAF_E_BADARG;
        if (!host_->writable()) return SAF_E_RO;

        uint64_t size = 0;
        bool is_dir = false;
        bool exists = (host_->getattr(p, &size, nullptr, &is_dir) == SAF_OK);
        if (exists && is_dir) return SAF_E_BADARG;
        if (mode == 'w' && exists) return SAF_E_EXIST;      // 独占创建
        if (!exists) {
            SafStatus st = host_->create_file(p);
            if (st != SAF_OK) return st;
        }
        out = std::make_shared<VaultWriteStream>(host_, p, (mode == 'a') ? size : 0);
        return SAF_OK;
    }

    SafStatus create_file(const std::string& vpath) override {
        std::string p;
        if (!norm(vpath, p) || p.empty()) return SAF_E_BADARG;
        if (!host_->writable()) return SAF_E_RO;
        return host_->create_file(p);
    }

    SafStatus mkdir(const std::string&) override { return SAF_E_NOTIMPL; }   // 盘内目录随条目

    SafStatus delete_file(const std::string& vpath) override {
        std::string p;
        if (!norm(vpath, p) || p.empty()) return SAF_E_BADARG;
        if (!host_->writable()) return SAF_E_RO;
        return host_->delete_file(p);
    }

    SafStatus truncate_file(const std::string& vpath, uint64_t new_size) override {
        std::string p;
        if (!norm(vpath, p) || p.empty()) return SAF_E_BADARG;
        if (!host_->writable()) return SAF_E_RO;
        return host_->truncate_file(p, new_size);
    }

    SafStatus rename_file(const std::string&, const std::string&) override {
        return SAF_E_NOTIMPL;                               // vdisk ABI 无重命名
    }

    bool can_seek() const override { return true; }   // VaultWriteStream/VaultReadStream 支持 seek

private:
    static bool norm(const std::string& vpath, std::string& out) {
        return saf_path_normalize(vpath, out);
    }

    std::shared_ptr<VaultHost> host_;
};

}  // namespace

std::shared_ptr<StorageBackend> saf_open_vault(std::shared_ptr<VaultHost> host) {
    if (!host) return nullptr;
    return std::make_shared<VaultBackend>(std::move(host));
}
