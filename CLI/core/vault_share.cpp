// Vault entry share implementation
#define _CRT_SECURE_NO_WARNINGS
#include "vault_share.hpp"

#include "vdisk.h"
#include "FileEncryptor.hpp"
#include "fileio_util.hpp"

#include <algorithm>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

namespace {

// Pull model streambuf: each underflow reads one chunk via vdisk_read_file.
// Seekable on purpose: encrypt_file probes seekg(0, cur) and buffers the
// whole input in memory when the stream is not seekable.
class VdiskStreambuf : public std::streambuf {
public:
    VdiskStreambuf(VDiskHandle* h, std::string vp, std::string& err)
        : h_(h), vp_(std::move(vp)), err_(err), buf_(1u << 20), off_(0),
          size_(0), eof_(false) {
        uint64_t mt = 0;
        uint8_t is_dir = 0;
        VDiskStatus rc = vdisk_getattr(h_, vp_.c_str(), &size_, &mt, &is_dir);
        if (rc != VDISK_OK || is_dir) {
            err_ = "entry not found in vault: '" + vp_ + "'";
            eof_ = true;
            return;
        }
    }

    bool fatal() const { return !err_.empty() && size_ == 0 && off_ == 0 && eof_; }
    bool valid() const { return !eof_ || size_ > 0; }

protected:
    int underflow() override {
        if (eof_ || off_ >= size_) { eof_ = true; return traits_type::eof(); }
        // *len is in/out: capacity in, bytes read out
        uint64_t got = std::min<uint64_t>(buf_.size(), size_ - off_);
        VDiskStatus rc = vdisk_read_file(h_, vp_.c_str(), off_,
                                         reinterpret_cast<uint8_t*>(buf_.data()), &got);
        if (rc != VDISK_OK || got == 0) {
            err_ = "read failed at offset " + std::to_string((unsigned long long)off_) +
                   " (code " + std::to_string((int)rc) + ")";
            eof_ = true;
            return traits_type::eof();
        }
        off_ += got;
        setg(buf_.data(), buf_.data(), buf_.data() + (size_t)got);
        return traits_type::to_int_type((unsigned char)*gptr());
    }

    std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way,
                           std::ios_base::openmode) override {
        std::streamoff cur = off_ - (std::streamoff)(egptr() - gptr());
        std::streamoff target =
            (way == std::ios_base::beg) ? off
            : (way == std::ios_base::cur) ? cur + off
            : (std::streamoff)size_;
        if (target < 0 || (uint64_t)target > size_) return -1;
        off_ = (uint64_t)target;
        eof_ = off_ >= size_;
        setg(nullptr, nullptr, nullptr);
        return target;
    }

    std::streampos seekpos(std::streampos sp, std::ios_base::openmode which) override {
        return seekoff((std::streamoff)sp, std::ios_base::beg, which);
    }

private:
    VDiskHandle* h_;
    std::string vp_;
    std::string& err_;
    std::vector<char> buf_;
    uint64_t off_;
    uint64_t size_;
    bool eof_;
};

}  // namespace

bool vault_share_file(const std::string& vault_dir_in, const std::string& vpath,
                      const std::string& out_ptd_in, const std::string& vault_password,
                      const std::vector<std::string>& recipients, std::string& err) {
    std::string vault_dir = vault_dir_in;
    while (!vault_dir.empty() && (vault_dir.back() == '/' || vault_dir.back() == '\\'))
        vault_dir.pop_back();
    std::string out_ptd = out_ptd_in;
    if (vpath.empty() || out_ptd.empty() || vault_dir.empty()) {
        err = "empty path"; return false;
    }
    if (recipients.empty()) { err = "no recipients"; return false; }

    VDiskHandle* h = vdisk_open(vault_dir.c_str());
    if (!h) { err = "cannot open vault: " + vault_dir; return false; }
    VDiskStatus rc = vdisk_unlock(h, vault_password.c_str(), 0);
    if (rc != VDISK_OK) {
        vdisk_close(h);
        err = rc == VDISK_E_AUTH ? "vault password wrong" : "vault unlock failed";
        return false;
    }

    std::string base = vpath;
    size_t pos = base.find_last_of('/');
    if (pos != std::string::npos) base = base.substr(pos + 1);
    if (base.empty()) base = "shared";

    {
        VdiskStreambuf sb(h, vpath, err);
        if (!err.empty()) {
            vdisk_close(h);
            return false;
        }
        std::istream in(&sb);
        bool ok = encrypt_file(std::string(), out_ptd, SecureBuffer(),
                               CryptoMode::XCHACHA20, nullptr, false, 0,
                               true, &recipients, nullptr, nullptr, nullptr, 0,
                               &in, nullptr, &base);
        if (!ok && err.empty()) err = "re-encryption failed";
        if (ok) {
            std::cout << "Shared: " << vpath << " -> " << out_ptd
                      << " (" << recipients.size() << " recipient(s))\n";
        }
    }
    vdisk_close(h);
    return err.empty();
}
