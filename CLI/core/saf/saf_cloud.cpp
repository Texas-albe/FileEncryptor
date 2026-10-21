// 对象存储后端：key 前缀模拟目录，写流缓冲后整对象 put
#include "saf_cloud.hpp"

#include <algorithm>

namespace {

std::string key_of(const std::string& prefix, const std::string& vpath) {
    std::string v;
    if (!saf_path_normalize(vpath, v)) v.clear();
    if (prefix.empty()) return v;
    std::string p = prefix;
    while (!p.empty() && p.back() == '/') p.pop_back();
    if (p.empty()) return v;
    return v.empty() ? p : p + "/" + v;
}

std::string dir_prefix(const std::string& prefix, const std::string& vpath) {
    std::string k = key_of(prefix, vpath);
    return k.empty() ? std::string() : k + "/";
}

class CloudWriteStream : public Stream {
public:
    CloudWriteStream(std::shared_ptr<SafObjectStore> store, std::string key,
                     std::vector<uint8_t> seed)
        : store_(std::move(store)), key_(std::move(key)), buf_(std::move(seed)) {}

    SafStatus read(uint8_t*, uint64_t* len) override { *len = 0; return SAF_E_RO; }
    SafStatus write(const uint8_t* in, uint64_t len) override {
        if (!in && len) return SAF_E_BADARG;
        buf_.insert(buf_.end(), in, in + len);
        return SAF_OK;
    }
    SafStatus seek(uint64_t) override { return SAF_E_NOTIMPL; }
    SafStatus tell(uint64_t* out_pos) override { *out_pos = buf_.size(); return SAF_OK; }
    SafStatus flush() override { return put_now(); }
    SafStatus close() override { return put_now(); }

private:
    SafStatus put_now() {
        if (closed_) return SAF_OK;
        closed_ = true;
        return store_->put(key_, buf_);
    }
    std::shared_ptr<SafObjectStore> store_;
    std::string key_;
    std::vector<uint8_t> buf_;
    bool closed_ = false;
};

class CloudReadStream : public Stream {
public:
    CloudReadStream(std::shared_ptr<SafObjectStore> store, std::string key,
                    uint64_t size, uint64_t chunk)
        : store_(std::move(store)), key_(std::move(key)),
          size_(size), chunk_(chunk ? chunk : (1u << 20)) {}

    SafStatus read(uint8_t* out, uint64_t* len) override {
        if (!out || !len) return SAF_E_BADARG;
        if (pos_ >= size_) { *len = 0; return SAF_OK; }
        uint64_t want = *len ? *len : (size_ - pos_);
        if (want > size_ - pos_) want = size_ - pos_;
        if (want > chunk_) want = chunk_;
        std::vector<uint8_t> tmp;
        uint64_t got = 0;
        SafStatus st = store_->get(key_, pos_, want, tmp, &got);
        if (st != SAF_OK) return st;
        if (got == 0) { *len = 0; return SAF_OK; }
        std::copy(tmp.begin(), tmp.begin() + (ptrdiff_t)got, out);
        pos_ += got;
        *len = got;
        return SAF_OK;
    }
    SafStatus write(const uint8_t*, uint64_t) override { return SAF_E_RO; }
    SafStatus tell(uint64_t* out_pos) override { *out_pos = pos_; return SAF_OK; }
    SafStatus close() override { return SAF_OK; }

private:
    std::shared_ptr<SafObjectStore> store_;
    std::string key_;
    uint64_t size_ = 0, chunk_ = 0, pos_ = 0;
};

class CloudBackend : public StorageBackend {
public:
    CloudBackend(std::shared_ptr<SafObjectStore> store, SafCloudOptions opt)
        : store_(std::move(store)), opt_(std::move(opt)) {}

    const char* scheme() const override { return "cloud"; }
    bool can_write() const override { return store_->writable(); }
    bool can_list()  const override { return true; }

    SafStatus stat(const std::string& vpath, uint64_t* out_size,
                   uint64_t* out_mtime, bool* out_is_dir,
                   bool* out_is_symlink = nullptr,
                   uint32_t* out_mode = nullptr) override {
        std::string k = key_of(opt_.prefix, vpath);
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = 0;
        if (out_is_dir) *out_is_dir = false;
        if (out_is_symlink) *out_is_symlink = false;   // 对象存储无符号链接
        if (out_mode) *out_mode = 0;

        if (k.empty()) { if (out_is_dir) *out_is_dir = true; return SAF_OK; }

        std::vector<std::pair<std::string, uint64_t>> all;
        SafStatus st = store_->list(k, all);          // 只列该前缀，不拉全桶
        if (st != SAF_OK) return st;
        bool exact = false, dir = false;
        uint64_t sz = 0;
        for (const auto& kv : all) {
            if (kv.first == k) { exact = true; sz = kv.second; break; }
            if (kv.first.size() > k.size() && kv.first.compare(0, k.size(), k) == 0 &&
                kv.first[k.size()] == '/') dir = true;
        }
        if (!exact && !dir) return SAF_E_NOTFOUND;
        if (out_size) *out_size = sz;
        if (out_is_dir) *out_is_dir = dir;
        return SAF_OK;
    }

    SafStatus open(const std::string& vpath, char mode,
                   std::shared_ptr<Stream>& out) override {
        out.reset();
        std::string k = key_of(opt_.prefix, vpath);
        if (k.empty()) return SAF_E_BADARG;

        std::vector<std::pair<std::string, uint64_t>> all;
        SafStatus st = store_->list(k, all);
        if (st != SAF_OK) return st;

        bool exists = false;
        uint64_t size = 0;
        for (const auto& kv : all) if (kv.first == k) { exists = true; size = kv.second; break; }

        if (mode == 'r') {
            if (!exists) return SAF_E_NOTFOUND;
            out = std::make_shared<CloudReadStream>(store_, k, size, opt_.chunk);
            return SAF_OK;
        }
        if (!can_write()) return SAF_E_RO;
        if (mode == 'w') {
            if (exists) return SAF_E_EXIST;
            out = std::make_shared<CloudWriteStream>(store_, k, std::vector<uint8_t>());
            return SAF_OK;
        }
        if (mode == 'a') {
            std::vector<uint8_t> seed;
            if (exists) {
                uint64_t got = 0;
                st = store_->get(k, 0, 0, seed, &got);
                if (st != SAF_OK) return st;
            }
            out = std::make_shared<CloudWriteStream>(store_, k, std::move(seed));
            return SAF_OK;
        }
        return SAF_E_BADARG;
    }

    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        out.clear();
        std::string pfx = dir_prefix(opt_.prefix, vpath);
        std::vector<std::pair<std::string, uint64_t>> all;
        SafStatus st = store_->list(pfx, all);
        if (st != SAF_OK) return st;

        std::vector<std::string> seen;
        for (const auto& kv : all) {
            std::string rest = kv.first.substr(pfx.size());
            if (rest.empty()) continue;
            size_t slash = rest.find('/');
            std::string name = (slash == std::string::npos) ? rest : rest.substr(0, slash);
            if (slash == std::string::npos) {
                SafEntry e;
                e.name = name; e.is_dir = false; e.size = kv.second;
                out.push_back(e);
            } else {
                if (std::find(seen.begin(), seen.end(), name) != seen.end()) continue;
                seen.push_back(name);
                SafEntry e;
                e.name = name; e.is_dir = true;
                out.push_back(e);
            }
        }
        return SAF_OK;
    }

    SafStatus delete_file(const std::string& vpath) override {
        if (!can_write()) return SAF_E_RO;
        return store_->remove(key_of(opt_.prefix, vpath));
    }

    SafStatus truncate_file(const std::string&, uint64_t) override { return SAF_E_NOTIMPL; }
    SafStatus rename_file(const std::string&, const std::string&) override { return SAF_E_NOTIMPL; }
    SafStatus mkdir(const std::string&) override { return SAF_E_NOTIMPL; }   // 无空目录对象

private:
    std::shared_ptr<SafObjectStore> store_;
    SafCloudOptions opt_;
};

} // namespace

std::shared_ptr<StorageBackend> saf_open_cloud(std::shared_ptr<SafObjectStore> store,
                                               const SafCloudOptions& opt) {
    if (!store) return nullptr;
    return std::make_shared<CloudBackend>(std::move(store), opt);
}
