// 归档后端
#include "saf_archive.hpp"

#include <algorithm>
#include <cstring>
#include <map>

namespace {

// 归档布局常量
const char kMagic[8] = {'F', 'E', 'P', 'K', '1', '\r', '\n', 0};
const char kTrailer[8] = {'F', 'E', 'P', 'K', 'E', 'N', 'D', '!'};
constexpr uint32_t kFlagDir = 1u;
constexpr uint32_t kMaxEntries = 1000000;
constexpr uint32_t kMaxPath = 4096;
constexpr size_t kCopyBuf = 64u * 1024u;
constexpr size_t kEntryHead = 28;   

void put_u32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
void put_u64(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
uint32_t get_u32(const uint8_t* p) { uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (8 * i); return v; }
uint64_t get_u64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i); return v; }

// 归档成员索引项
struct Member {
    std::string path;
    bool is_dir = false;
    uint64_t size = 0;
    uint64_t mtime = 0;
    uint32_t mode = 0;
    uint64_t data_off = 0;
};

// 打包待写条目
struct PackEnt {
    std::string path;
    bool is_dir = false;
    uint64_t size = 0;
    uint64_t mtime = 0;
    uint32_t mode = 0;
};

// 顺序扫描建成员
SafStatus scan_index(Stream& s, std::vector<Member>& out) {
    uint8_t magic[8];   // 先单独验魔数
    uint64_t got = sizeof(magic);
    if (s.seek(0) != SAF_OK) return SAF_E_IO;
    if (s.read(magic, &got) != SAF_OK || got != sizeof(magic)) return SAF_E_IO;
    if (std::memcmp(magic, kMagic, 8) != 0) return SAF_E_BADARG;
    uint8_t hdr[24];    
    got = sizeof(hdr);
    if (s.read(hdr, &got) != SAF_OK || got != sizeof(hdr)) return SAF_E_IO;
    uint32_t ver = get_u32(hdr);
    uint32_t count = get_u32(hdr + 4);
    if (ver != 1 || count > kMaxEntries) return SAF_E_BADARG;
    uint64_t off = 32;
    out.clear();
    for (uint32_t i = 0; i < count; ++i) {
        if (s.seek(off) != SAF_OK) return SAF_E_IO;
        uint8_t eh[kEntryHead];
        got = sizeof(eh);
        if (s.read(eh, &got) != SAF_OK || got != sizeof(eh)) return SAF_E_IO;
        uint32_t plen = get_u32(eh);
        uint32_t flags = get_u32(eh + 4);
        uint64_t size = get_u64(eh + 8);
        uint32_t mode = get_u32(eh + 16);
        uint64_t mtime = get_u64(eh + 20);
        if (plen == 0 || plen > kMaxPath) return SAF_E_BADARG;
        std::string path((size_t)plen, '\0');
        got = plen;
        if (s.read((uint8_t*)path.data(), &got) != SAF_OK || got != plen) return SAF_E_IO;
        std::string norm;
        if (!saf_path_normalize(path, norm) || norm.empty()) return SAF_E_BADARG;
        Member m;
        m.path = norm;
        m.is_dir = (flags & kFlagDir) != 0;
        m.size = m.is_dir ? 0 : size;
        m.mtime = mtime;
        m.mode = mode;
        m.data_off = off + kEntryHead + plen;
        out.push_back(std::move(m));
        off += kEntryHead + plen + m.size;
    }
    return SAF_OK;
}

// 递归收集目录树
SafStatus collect_tree(StorageBackend& be, const std::string& dir, std::vector<PackEnt>& out) {
    std::vector<SafEntry> es;
    SafStatus st = be.readdir(dir, es);
    if (st != SAF_OK) return st;
    for (const auto& e : es) {
        std::string p = dir.empty() ? e.name : dir + "/" + e.name;
        uint64_t size = 0, mt = 0;
        bool isdir = false;
        if (be.stat(p, &size, &mt, &isdir) != SAF_OK) continue;
        PackEnt en;
        en.path = p;
        en.is_dir = isdir;
        en.size = isdir ? 0 : size;
        en.mtime = mt;
        en.mode = isdir ? 0755 : 0644;
        out.push_back(en);
        if (isdir) {
            st = collect_tree(be, p, out);
            if (st != SAF_OK) return st;
        }
    }
    return SAF_OK;
}

// 区间流
class BoundStream final : public Stream {
public:
    BoundStream(std::shared_ptr<Stream> base, uint64_t begin, uint64_t len)
        : base_(std::move(base)), begin_(begin), len_(len) {}

    SafStatus read(uint8_t* out, uint64_t* len) override {
        if (!len) return SAF_E_BADARG;
        uint64_t remain = len_ - pos_;
        if (remain == 0) { *len = 0; return SAF_OK; }
        uint64_t want = (*len < remain) ? *len : remain;
        if (base_->seek(begin_ + pos_) != SAF_OK) return SAF_E_IO;   // 共享底层流
        uint64_t got = want;
        if (base_->read(out, &got) != SAF_OK) return SAF_E_IO;
        pos_ += got;
        *len = got;
        return SAF_OK;
    }

    SafStatus write(const uint8_t*, uint64_t) override { return SAF_E_RO; }
    SafStatus seek(uint64_t offset) override {
        if (offset > len_) return SAF_E_BADARG;
        pos_ = offset;
        return SAF_OK;
    }
    SafStatus tell(uint64_t* out_pos) override {
        if (!out_pos) return SAF_E_BADARG;
        *out_pos = pos_;
        return SAF_OK;
    }
    SafStatus close() override { return SAF_OK; }

private:
    std::shared_ptr<Stream> base_;
    uint64_t begin_, len_, pos_ = 0;
};

// 归档只读后端
class ArchiveBackend final : public StorageBackend {
public:
    explicit ArchiveBackend(std::shared_ptr<Stream> raw) : raw_(std::move(raw)) {}
    SafStatus init() { return scan_index(*raw_, members_); }

    const char* scheme() const override { return "archive"; }
    bool can_write() const override { return false; }   // 改写 = 整体重打
    bool can_list() const override { return true; }

    SafStatus stat(const std::string& vpath, uint64_t* out_size,
                   uint64_t* out_mtime, bool* out_is_dir,
                   bool* out_is_symlink = nullptr,
                   uint32_t* out_mode = nullptr) override {
        std::string rel;
        if (!saf_path_normalize(vpath, rel)) return SAF_E_BADARG;
        if (out_is_symlink) *out_is_symlink = false;
        if (out_mode) *out_mode = 0;
        if (rel.empty()) {   
            if (out_size) *out_size = 0;
            if (out_mtime) *out_mtime = 0;
            if (out_is_dir) *out_is_dir = true;
            return SAF_OK;
        }
        for (const auto& m : members_) {
            if (m.path == rel) {
                if (out_size) *out_size = m.size;
                if (out_mtime) *out_mtime = m.mtime;
                if (out_is_dir) *out_is_dir = m.is_dir;
                if (out_mode) *out_mode = m.mode;
                return SAF_OK;
            }
        }
        std::string pfx = rel + "/";   // 无精确匹配但有
        for (const auto& m : members_) {
            if (m.path.size() > pfx.size() && m.path.compare(0, pfx.size(), pfx) == 0) {
                if (out_size) *out_size = 0;
                if (out_mtime) *out_mtime = 0;
                if (out_is_dir) *out_is_dir = true;
                return SAF_OK;
            }
        }
        return SAF_E_NOTFOUND;
    }

    SafStatus open(const std::string& vpath, char mode, std::shared_ptr<Stream>& out) override {
        out.reset();
        if (mode != 'r') return SAF_E_RO;
        std::string rel;
        if (!saf_path_normalize(vpath, rel)) return SAF_E_BADARG;
        for (const auto& m : members_) {
            if (m.path != rel) continue;
            if (m.is_dir) return SAF_E_BADARG;
            out = std::make_shared<BoundStream>(raw_, m.data_off, m.size);
            return SAF_OK;
        }
        return SAF_E_NOTFOUND;
    }

    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        out.clear();
        std::string rel;
        if (!saf_path_normalize(vpath, rel)) return SAF_E_BADARG;
        std::string pfx = rel.empty() ? "" : rel + "/";
        std::map<std::string, SafEntry> acc;   // 目录条目
        for (const auto& m : members_) {
            if (m.path.size() <= pfx.size()) continue;
            if (m.path.compare(0, pfx.size(), pfx) != 0) continue;
            std::string rest = m.path.substr(pfx.size());
            size_t slash = rest.find('/');
            if (slash == std::string::npos) {
                SafEntry e;
                e.name = rest;
                e.is_dir = m.is_dir;
                e.size = m.size;
                e.mtime = m.mtime;
                auto it = acc.find(rest);
                if (it == acc.end()) acc.emplace(rest, std::move(e));
            } else {
                SafEntry e;
                e.name = rest.substr(0, slash);
                e.is_dir = true;                 // 目录优先
                acc[e.name] = std::move(e);
            }
        }
        for (auto& kv : acc) out.push_back(std::move(kv.second));
        return SAF_OK;
    }

    bool can_seek() const override { return true; }   // BoundStream 支持随机读

private:
    std::shared_ptr<Stream> raw_;
    std::vector<Member> members_;
};

// 递归展开归档条
SafStatus unpack_dir(StorageBackend& arc, StorageBackend& dst, const std::string& dir) {
    std::vector<SafEntry> es;
    SafStatus st = arc.readdir(dir, es);
    if (st != SAF_OK) return st;
    for (const auto& e : es) {
        std::string p = dir.empty() ? e.name : dir + "/" + e.name;
        if (e.is_dir) {
            st = dst.mkdir(p);
            if (st != SAF_OK && st != SAF_E_EXIST) return st;
            st = unpack_dir(arc, dst, p);
            if (st != SAF_OK) return st;
            continue;
        }
        std::shared_ptr<Stream> in, os;
        st = arc.open(p, 'r', in);
        if (st != SAF_OK) return st;
        st = dst.open(p, 'w', os);
        if (st != SAF_OK) { in->close(); return st; }
        std::vector<uint8_t> buf(kCopyBuf);
        bool ok = true;
        for (;;) {
            uint64_t got = buf.size();
            if (in->read(buf.data(), &got) != SAF_OK) { ok = false; break; }
            if (got == 0) break;
            if (os->write(buf.data(), got) != SAF_OK) { ok = false; break; }
        }
        in->close();
        os->close();
        if (!ok) return SAF_E_IO;
    }
    return SAF_OK;
}

}  // namespace

SafStatus saf_archive_pack(StorageBackend& src, Stream& out) {
    std::vector<PackEnt> ents;
    SafStatus st = collect_tree(src, "", ents);
    if (st != SAF_OK) return st;
    if (ents.size() > kMaxEntries) return SAF_E_BADARG;
    uint64_t total = 0;
    for (const auto& e : ents) total += e.size;

    uint8_t hdr[32] = {0};
    std::memcpy(hdr, kMagic, 8);
    put_u32(hdr + 8, 1);
    put_u32(hdr + 12, (uint32_t)ents.size());
    put_u64(hdr + 16, total);
    put_u64(hdr + 24, 0);
    if (out.write(hdr, sizeof(hdr)) != SAF_OK) return SAF_E_IO;

    std::vector<uint8_t> buf(kCopyBuf);
    for (const auto& e : ents) {
        uint8_t eh[kEntryHead] = {0};
        put_u32(eh, (uint32_t)e.path.size());
        put_u32(eh + 4, e.is_dir ? kFlagDir : 0u);
        put_u64(eh + 8, e.size);
        put_u32(eh + 16, e.mode);
        put_u64(eh + 20, e.mtime);
        if (out.write(eh, sizeof(eh)) != SAF_OK) return SAF_E_IO;
        if (out.write((const uint8_t*)e.path.data(), e.path.size()) != SAF_OK) return SAF_E_IO;
        if (e.is_dir) continue;

        std::shared_ptr<Stream> in;
        st = src.open(e.path, 'r', in);
        if (st != SAF_OK) return st;
        uint64_t left = e.size;
        bool ok = true;
        while (left > 0) {
            uint64_t want = std::min<uint64_t>(left, buf.size());
            uint64_t got = want;
            if (in->read(buf.data(), &got) != SAF_OK || got == 0) { ok = false; break; }
            if (out.write(buf.data(), got) != SAF_OK) { ok = false; break; }
            left -= got;
        }
        in->close();
        if (!ok || left != 0) return SAF_E_IO;   // 源文件
    }

    uint8_t tr[16] = {0};
    std::memcpy(tr, kTrailer, 8);
    put_u64(tr + 8, total);
    return out.write(tr, sizeof(tr));
}

SafStatus saf_archive_unpack(StorageBackend& arc, StorageBackend& dst) {
    return unpack_dir(arc, dst, "");
}

SafStatus saf_open_archive_stream(std::shared_ptr<Stream> raw, std::shared_ptr<StorageBackend>& out) {
    out.reset();
    if (!raw) return SAF_E_BADARG;
    auto be = std::make_shared<ArchiveBackend>(raw);
    SafStatus st = be->init();
    if (st != SAF_OK) return st;
    out = be;
    return SAF_OK;
}

SafStatus saf_open_archive_file(const std::string& path, std::shared_ptr<StorageBackend>& out) {
    out.reset();
    std::shared_ptr<Stream> raw;
    SafStatus st = saf_open_native_file(path, 'r', raw);
    if (st != SAF_OK) return st;
    return saf_open_archive_stream(raw, out);
}
