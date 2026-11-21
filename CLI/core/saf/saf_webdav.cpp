// WebDAV cloud backend (libcurl based, read paths only)
#include "saf_webdav.hpp"

#ifdef FE_WITH_CURL

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {

// ---- diagnostics ----

thread_local std::string t_last_err;

std::string set_err(std::string s) {
    t_last_err = std::move(s);
    return t_last_err;
}

// ---- small helpers ----

std::string lower_copy(const std::string& s) {
    std::string o(s);
    for (auto& c : o) c = (char)std::tolower((unsigned char)c);
    return o;
}

bool ieq(const std::string& a, const std::string& b) { return lower_copy(a) == lower_copy(b); }

std::string url_decode(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit((unsigned char)s[i+1]) &&
            std::isxdigit((unsigned char)s[i+2])) {
            auto hv = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return c - 'A' + 10;
            };
            o.push_back((char)((hv(s[i+1]) << 4) | hv(s[i+2])));
            i += 2;
        } else {
            o.push_back(s[i]);
        }
    }
    return o;
}

// days from civil (Howard Hinnant algorithm)
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

// RFC1123: "Wed, 15 Nov 2026 12:00:00 GMT"
uint64_t parse_http_date(const std::string& s) {
    static const char* mon[12] = {"Jan","Feb","Mar","Apr","May","Jun",
                                  "Jul","Aug","Sep","Oct","Nov","Dec"};
    size_t p = s.find(", ");
    if (p == std::string::npos) return 0;
    p += 2;
    auto num_at = [&](size_t& q) -> long {
        long v = 0;
        while (q < s.size() && s[q] >= '0' && s[q] <= '9') { v = v*10 + (s[q]-'0'); ++q; }
        return v;
    };
    long day = num_at(p);
    if (p >= s.size() || s[p] != ' ') return 0;
    ++p;
    if (p + 3 > s.size()) return 0;
    std::string mo = s.substr(p, 3);
    int mi = -1;
    for (int k = 0; k < 12; ++k) if (mo == mon[k]) { mi = k; break; }
    if (mi < 0) return 0;
    p += 3;
    if (p >= s.size() || s[p] != ' ') return 0;
    ++p;
    long year = num_at(p);
    if (p >= s.size() || s[p] != ' ') return 0;
    ++p;
    long hh = num_at(p);
    if (p >= s.size() || s[p] != ':') return 0;
    ++p;
    long mm = num_at(p);
    if (p >= s.size() || s[p] != ':') return 0;
    ++p;
    long ss = num_at(p);
    int64_t days = days_from_civil(year, (unsigned)mi + 1, (unsigned)day);
    return (uint64_t)(days * 86400 + hh * 3600 + mm * 60 + ss);
}

// ---- curl glue ----

std::once_flag g_curl_once;
void curl_global_once() {
    std::call_once(g_curl_once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

struct CurlEasy {
    CURL* h = nullptr;
    CurlEasy() { curl_global_once(); h = curl_easy_init(); }
    ~CurlEasy() { if (h) curl_easy_cleanup(h); }
    explicit operator bool() const { return h != nullptr; }
};

std::string url_encode_seg(const std::string& s) {
    CurlEasy ce;
    if (!ce) return s;
    char* e = curl_easy_escape(ce.h, s.c_str(), (int)s.size());
    std::string o = e ? e : s;
    if (e) curl_free(e);
    return o;
}

size_t body_cb(char* ptr, size_t sz, size_t nm, void* ud) {
    auto* out = static_cast<std::vector<uint8_t>*>(ud);
    size_t n = sz * nm;
    out->insert(out->end(), ptr, ptr + n);
    return n;
}

struct PutReader {
    const std::string& data;
    size_t off = 0;
};

size_t put_read_cb(char* ptr, size_t sz, size_t nm, void* ud) {
    auto* r = static_cast<PutReader*>(ud);
    size_t want = sz * nm;
    if (r->off >= r->data.size()) return 0;
    size_t n = (std::min)(want, r->data.size() - r->off);
    std::memcpy(ptr, r->data.data() + r->off, n);
    r->off += n;
    return n;
}

size_t hdr_cb(char* ptr, size_t sz, size_t nm, void* ud) {
    auto* out = static_cast<std::string*>(ud);   // raw headers, keep all
    out->append(ptr, sz * nm);
    return sz * nm;
}

struct DavResult {
    long status = 0;
    std::vector<uint8_t> body;
    std::string raw_headers;
    std::string err;
};

// one HTTP request, method kept verbatim
DavResult dav_req(const SafWebDavOptions& opt, const char* method, const std::string& url,
                  const std::string& body, const std::vector<std::string>& hdrs) {
    DavResult r;
    CurlEasy ce;
    if (!ce) { r.err = set_err("curl init failed"); return r; }
    curl_easy_setopt(ce.h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(ce.h, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(ce.h, CURLOPT_CONNECTTIMEOUT, opt.timeout_sec);
    // stall detection: <1 byte/s for 30s aborts (no total timeout: large transfers)
    curl_easy_setopt(ce.h, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(ce.h, CURLOPT_LOW_SPEED_TIME, 30L);
    curl_easy_setopt(ce.h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ce.h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(ce.h, CURLOPT_SSL_VERIFYPEER, opt.verify_tls ? 1L : 0L);
    curl_easy_setopt(ce.h, CURLOPT_SSL_VERIFYHOST, opt.verify_tls ? 2L : 0L);
    if (!opt.user.empty() || !opt.pass.empty()) {
        curl_easy_setopt(ce.h, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
        curl_easy_setopt(ce.h, CURLOPT_USERPWD, (opt.user + ":" + opt.pass).c_str());
    }
    curl_slist* hl = nullptr;
    for (const auto& h : hdrs) hl = curl_slist_append(hl, h.c_str());
    // drop Expect: 100-continue (avoids body/retry interleaving on 401 auth dance)
    hl = curl_slist_append(hl, "Expect:");
    if (hl) curl_easy_setopt(ce.h, CURLOPT_HTTPHEADER, hl);
    if (!body.empty()) {
        curl_easy_setopt(ce.h, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(ce.h, CURLOPT_POSTFIELDSIZE, (long)body.size());
    }
    curl_easy_setopt(ce.h, CURLOPT_WRITEFUNCTION, body_cb);
    curl_easy_setopt(ce.h, CURLOPT_WRITEDATA, &r.body);
    curl_easy_setopt(ce.h, CURLOPT_HEADERFUNCTION, hdr_cb);
    curl_easy_setopt(ce.h, CURLOPT_HEADERDATA, &r.raw_headers);
    CURLcode rc = curl_easy_perform(ce.h);
    if (hl) curl_slist_free_all(hl);
    if (rc != CURLE_OK) {
        r.err = set_err(std::string("curl: ") + curl_easy_strerror(rc));
        return r;
    }
    curl_easy_getinfo(ce.h, CURLINFO_RESPONSE_CODE, &r.status);
    return r;
}

// retry once on 3xx keeping the method (curl FOLLOWLOCATION would turn PROPFIND into GET)
DavResult dav_req_follow(const SafWebDavOptions& opt, const char* method, const std::string& url,
                         const std::string& body, const std::vector<std::string>& hdrs) {
    DavResult r = dav_req(opt, method, url, body, hdrs);
    if ((r.status == 301 || r.status == 302 || r.status == 307 || r.status == 308) &&
        r.err.empty()) {
        // locate Location header
        std::string loc;
        std::string lh = lower_copy(r.raw_headers);
        size_t p = lh.find("location:");
        if (p != std::string::npos) {
            p += 9;
            size_t e = r.raw_headers.find('\n', p);
            if (e == std::string::npos) e = r.raw_headers.size();
            loc = r.raw_headers.substr(p, e - p);
            // trim
            while (!loc.empty() && (loc.front() == ' ' || loc.front() == '\r')) loc.erase(loc.begin());
            while (!loc.empty() && (loc.back() == ' ' || loc.back() == '\r')) loc.pop_back();
        }
        if (!loc.empty()) {
            std::string abs = loc;
            if (abs.rfind("http", 0) != 0) {
                // relative: scheme+host from original url
                size_t sp = url.find("://");
                size_t hs = (sp == std::string::npos) ? 0 : url.find('/', sp + 3);
                abs = (hs == std::string::npos) ? url + loc : url.substr(0, hs) + loc;
            }
            r = dav_req(opt, method, abs, body, hdrs);
        }
    }
    return r;
}

// ---- minimal XML scan (namespace agnostic, case-insensitive) ----

// next start tag whose local name matches; *after_gt = offset past '>'
size_t find_tag(const std::string& s, size_t from, const std::string& name, size_t* after_gt) {
    size_t p = from;
    while ((p = s.find('<', p)) != std::string::npos) {
        if (p + 1 < s.size() && (s[p+1] == '/' || s[p+1] == '?' || s[p+1] == '!')) {
            ++p;
            continue;
        }
        size_t e = p + 1;
        while (e < s.size() && s[e] != '>' && s[e] != ' ' && s[e] != '/' &&
               s[e] != '\t' && s[e] != '\n' && s[e] != '\r') ++e;
        std::string tag = s.substr(p + 1, e - (p + 1));
        size_t col = tag.rfind(':');
        if (col != std::string::npos) tag = tag.substr(col + 1);
        if (ieq(tag, name)) {
            size_t gt = s.find('>', e);
            if (gt == std::string::npos) return std::string::npos;
            if (after_gt) *after_gt = gt + 1;
            return p;
        }
        p = e;
    }
    return std::string::npos;
}

size_t find_close(const std::string& s, size_t from, const std::string& name) {
    size_t p = from;
    while ((p = s.find("</", p)) != std::string::npos) {
        size_t e = p + 2;
        while (e < s.size() && s[e] != '>' && s[e] != ' ' && s[e] != '/') ++e;
        std::string tag = s.substr(p + 2, e - (p + 2));
        size_t col = tag.rfind(':');
        if (col != std::string::npos) tag = tag.substr(col + 1);
        if (ieq(tag, name)) return p;
        p = e;
    }
    return std::string::npos;
}

bool tag_text(const std::string& xml, size_t from, const std::string& name,
              std::string& out, size_t* next) {
    size_t after = 0;
    size_t t = find_tag(xml, from, name, &after);
    if (t == std::string::npos) return false;
    // self-closing?
    if (after >= 2 && xml[after - 2] == '/') {
        out.clear();
        if (next) *next = after;
        return true;
    }
    size_t close = find_close(xml, after, name);
    if (close == std::string::npos) return false;
    out = xml.substr(after, close - after);
    if (next) *next = close;
    return true;
}

bool has_tag_ci(const std::string& s, const std::string& name) {
    size_t p = 0;
    while ((p = s.find('<', p)) != std::string::npos) {
        size_t e = p + 1;
        while (e < s.size() && s[e] != '>' && s[e] != ' ' && s[e] != '/' &&
               s[e] != '\t' && s[e] != '\n' && s[e] != '\r') ++e;
        std::string tag = s.substr(p + 1, e - (p + 1));
        size_t col = tag.rfind(':');
        if (col != std::string::npos) tag = tag.substr(col + 1);
        if (ieq(tag, name)) return true;
        p = e;
    }
    return false;
}

const char k_allprop[] =
    "<?xml version=\"1.0\"?>"
    "<d:propfind xmlns:d=\"DAV:\"><d:prop>"
    "<d:resourcetype/><d:getcontentlength/><d:getlastmodified/>"
    "</d:prop></d:propfind>";

std::string strip_host(const std::string& url_or_path) {
    size_t pp = url_or_path.find("://");
    if (pp == std::string::npos) return url_or_path;
    size_t sl = url_or_path.find('/', pp + 3);
    return (sl == std::string::npos) ? std::string("/") : url_or_path.substr(sl);
}

std::string canon_href(const std::string& href) {
    std::string s = url_decode(strip_host(href));
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

// ---- backend ----

class WebDavBackend;

class WebDavReadStream : public Stream {
public:
    WebDavReadStream(std::shared_ptr<WebDavBackend> be, std::string vpath, uint64_t size)
        : be_(std::move(be)), vpath_(std::move(vpath)), size_(size) {}

    SafStatus read(uint8_t* out, uint64_t* len) override;
    SafStatus write(const uint8_t*, uint64_t) override { return SAF_E_RO; }
    SafStatus seek(uint64_t pos) override { pos_ = pos; return SAF_OK; }
    SafStatus tell(uint64_t* out_pos) override { *out_pos = pos_; return SAF_OK; }
    SafStatus close() override { return SAF_OK; }

private:
    SafStatus copy_from_full(const std::vector<uint8_t>& full, uint8_t* out, uint64_t want, uint64_t* got);
    std::shared_ptr<WebDavBackend> be_;
    std::string vpath_;
    uint64_t size_ = 0, pos_ = 0;
    std::vector<uint8_t> full_;   // fallback when server ignores Range
};

class WebDavBackend : public StorageBackend,
                      public std::enable_shared_from_this<WebDavBackend> {
public:
    explicit WebDavBackend(SafWebDavOptions opt) : opt_(std::move(opt)) {}

    const char* scheme() const override { return "webdav"; }
    bool can_write() const override { return false; }   // read-only by design
    bool can_list() const override { return true; }
    bool can_seek() const override { return true; }

    SafStatus stat(const std::string& vpath, uint64_t* out_size, uint64_t* out_mtime,
                   bool* out_is_dir, bool* out_is_symlink = nullptr,
                   uint32_t* out_mode = nullptr) override {
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = 0;
        if (out_is_dir) *out_is_dir = false;
        if (out_is_symlink) *out_is_symlink = false;
        if (out_mode) *out_mode = 0;
        std::string url = url_for(vpath);
        DavResult r = dav_req_follow(opt_, "PROPFIND", url, k_allprop,
                                     {"Depth: 0", "Content-Type: application/xml"});
        if (!r.err.empty()) return SAF_E_IO;
        if (r.status == 401 || r.status == 403) return set_err_status(r, SAF_E_AUTH);
        if (r.status == 404) return SAF_E_NOTFOUND;
        if (r.status != 207) return set_err_status(r, SAF_E_IO);
        std::string xml(r.body.begin(), r.body.end());
        std::string href;
        size_t next = 0;
        if (!tag_text(xml, 0, "href", href, &next)) return set_err_status(r, SAF_E_IO);
        if (has_tag_ci(xml, "collection")) {
            if (out_is_dir) *out_is_dir = true;
        } else {
            std::string len_s;
            if (tag_text(xml, next, "getcontentlength", len_s, &next))
                if (out_size) *out_size = strtoull(len_s.c_str(), nullptr, 10);
            std::string date_s;
            if (tag_text(xml, next, "getlastmodified", date_s, &next))
                if (out_mtime) *out_mtime = parse_http_date(date_s);
        }
        return SAF_OK;
    }

    SafStatus open(const std::string& vpath, char mode,
                   std::shared_ptr<Stream>& out) override {
        out.reset();
        if (mode != 'r') return SAF_E_RO;
        uint64_t size = 0, mt = 0;
        bool is_dir = false;
        SafStatus st = stat(vpath, &size, &mt, &is_dir);
        if (st != SAF_OK) return st;
        if (is_dir) return SAF_E_BADARG;
        out = std::make_shared<WebDavReadStream>(shared_from_this(), vpath, size);
        return SAF_OK;
    }

    SafStatus readdir(const std::string& vpath, std::vector<SafEntry>& out) override {
        out.clear();
        std::string url = url_for(vpath);
        DavResult r = dav_req_follow(opt_, "PROPFIND", url, k_allprop,
                                     {"Depth: 1", "Content-Type: application/xml"});
        if (!r.err.empty()) return SAF_E_IO;
        if (r.status == 401 || r.status == 403) return set_err_status(r, SAF_E_AUTH);
        if (r.status == 404) return SAF_E_NOTFOUND;
        if (r.status != 207) return set_err_status(r, SAF_E_IO);
        std::string xml(r.body.begin(), r.body.end());
        std::string self = canon_href(strip_host(url));
        size_t rs = 0, after = 0;
        while ((rs = find_tag(xml, rs, "response", &after)) != std::string::npos) {
            size_t close = find_close(xml, after, "response");
            if (close == std::string::npos) break;
            std::string block = xml.substr(after, close - after);
            rs = close;
            std::string href;
            if (!tag_text(block, 0, "href", href, &after)) continue;
            std::string hp = canon_href(href);
            if (hp == self) continue;                       // skip the directory itself
            SafEntry e;
            size_t slash = hp.rfind('/');
            e.name = (slash == std::string::npos) ? hp : hp.substr(slash + 1);
            if (e.name.empty()) continue;
            e.is_dir = has_tag_ci(block, "collection");
            if (!e.is_dir) {
                std::string len_s;
                if (tag_text(block, 0, "getcontentlength", len_s, &after))
                    e.size = strtoull(len_s.c_str(), nullptr, 10);
                std::string date_s;
                if (tag_text(block, 0, "getlastmodified", date_s, &after))
                    e.mtime = parse_http_date(date_s);
            }
            out.push_back(std::move(e));
        }
        return SAF_OK;
    }

    // Build the full URL for a vault-relative path
    std::string url_for(const std::string& vpath) const {
        std::string v;
        if (!saf_path_normalize(vpath, v)) v.clear();
        std::string base = opt_.base_url;
        while (!base.empty() && base.back() == '/') base.pop_back();
        if (v.empty()) return base;
        std::string u = base;
        size_t p = 0;
        while (p < v.size()) {
            size_t q = v.find('/', p);
            if (q == std::string::npos) q = v.size();
            u += "/" + url_encode_seg(v.substr(p, q - p));
            p = q + 1;
        }
        return u;
    }

    // GET one byte range
    DavResult dav_get_range(const std::string& vpath, uint64_t lo, uint64_t hi) {
        std::string rng = "Range: bytes=" + std::to_string(lo) + "-" + std::to_string(hi);
        return dav_req(opt_, "GET", url_for(vpath), std::string(), {rng});
    }

    const SafWebDavOptions& options() const { return opt_; }

private:
    SafStatus set_err_status(const DavResult& r, SafStatus st) {
        set_err("HTTP " + std::to_string(r.status));
        return st;
    }
    SafWebDavOptions opt_;
};

SafStatus WebDavReadStream::read(uint8_t* out, uint64_t* len) {
    if (!out || !len) return SAF_E_BADARG;
    if (pos_ >= size_) { *len = 0; return SAF_OK; }
    uint64_t want = *len ? *len : (1u << 20);
    if (want > (1u << 20)) want = 1u << 20;
    want = std::min<uint64_t>(want, size_ - pos_);
    if (!full_.empty()) {
        uint64_t got = 0;
        SafStatus st = copy_from_full(full_, out, want, &got);
        if (st != SAF_OK) return st;
        *len = got;
        return SAF_OK;
    }
    DavResult r = be_->dav_get_range(vpath_, pos_, pos_ + want - 1);
    if (!r.err.empty()) return SAF_E_IO;
    if (r.status == 200) {                      // server ignored Range: cache whole body
        full_ = std::move(r.body);
        size_ = std::max<uint64_t>(size_, full_.size());
        uint64_t got = 0;
        SafStatus st = copy_from_full(full_, out, want, &got);
        if (st != SAF_OK) return st;
        *len = got;
        return SAF_OK;
    }
    if (r.status == 416) { *len = 0; return SAF_OK; }
    if (r.status == 401 || r.status == 403) return SAF_E_AUTH;
    if (r.status == 404) return SAF_E_NOTFOUND;
    if (r.status != 206) { set_err("HTTP " + std::to_string(r.status)); return SAF_E_IO; }
    uint64_t n = std::min<uint64_t>((uint64_t)r.body.size(), want);
    if (n) std::memcpy(out, r.body.data(), (size_t)n);
    pos_ += n;
    *len = n;
    return SAF_OK;
}

SafStatus WebDavReadStream::copy_from_full(const std::vector<uint8_t>& full, uint8_t* out,
                                           uint64_t want, uint64_t* got) {
    if (pos_ >= full.size()) { *got = 0; return SAF_OK; }
    uint64_t n = std::min<uint64_t>(want, (uint64_t)full.size() - pos_);
    if (n) std::memcpy(out, full.data() + pos_, (size_t)n);
    pos_ += n;
    *got = n;
    return SAF_OK;
}

} // namespace

std::shared_ptr<StorageBackend> saf_open_webdav(const SafWebDavOptions& opt) {
    if (opt.base_url.empty()) { set_err("empty base url"); return nullptr; }
    return std::make_shared<WebDavBackend>(opt);
}

bool saf_webdav_parse_uri(const std::string& uri, SafWebDavOptions& opt, std::string& err) {
    std::string scheme, rest;
    if (!saf_uri_split(uri, scheme, rest) || scheme.empty()) {
        err = "invalid uri";
        return false;
    }
    bool tls;
    if (scheme == "webdav" || scheme == "dav") tls = false;
    else if (scheme == "webdavs" || scheme == "davs") tls = true;
    else { err = "scheme must be webdav:// or webdavs://"; return false; }
    std::string hostpart = rest;
    while (!hostpart.empty() && hostpart.front() == '/') hostpart.erase(hostpart.begin());
    size_t at = hostpart.rfind('@');
    if (at != std::string::npos) {
        std::string ui = hostpart.substr(0, at);
        hostpart = hostpart.substr(at + 1);
        size_t colon = ui.find(':');
        if (colon != std::string::npos) {
            opt.user = url_decode(ui.substr(0, colon));
            opt.pass = url_decode(ui.substr(colon + 1));
        } else {
            opt.user = url_decode(ui);
        }
    }
    if (opt.user.empty() && opt.pass.empty()) {
        const char* eu = std::getenv("FE_WEBDAV_USER");
        const char* ep = std::getenv("FE_WEBDAV_PASS");
        if (eu) opt.user = eu;
        if (ep) opt.pass = ep;
    }
    if (hostpart.empty()) { err = "missing host"; return false; }
    opt.base_url = std::string(tls ? "https://" : "http://") + hostpart;
    return true;
}

bool saf_webdav_append_text(const SafWebDavOptions& opt, const std::string& rel,
                            const std::string& text, std::string& err) {
    if (opt.base_url.empty()) { err = set_err("empty base url"); return false; }
    std::string base = opt.base_url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    std::string url = base;
    size_t p = 0;
    while (p < rel.size()) {
        size_t q = rel.find('/', p);
        if (q == std::string::npos) q = rel.size();
        url += "/" + url_encode_seg(rel.substr(p, q - p));
        p = q + 1;
    }
    DavResult old = dav_req(opt, "GET", url, std::string(), {});
    if (!old.err.empty() && old.status != 404) { err = old.err; return false; }
    std::string all(old.body.begin(), old.body.end());
    all += text;

    CurlEasy ce;
    if (!ce) { err = set_err("curl init failed"); return false; }
    PutReader reader{all, 0};
    std::vector<uint8_t> sink;
    curl_easy_setopt(ce.h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(ce.h, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(ce.h, CURLOPT_READFUNCTION, put_read_cb);
    curl_easy_setopt(ce.h, CURLOPT_READDATA, &reader);
    curl_easy_setopt(ce.h, CURLOPT_INFILESIZE_LARGE, (curl_off_t)all.size());
    curl_easy_setopt(ce.h, CURLOPT_CONNECTTIMEOUT, opt.timeout_sec);
    curl_easy_setopt(ce.h, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(ce.h, CURLOPT_LOW_SPEED_TIME, 30L);
    curl_easy_setopt(ce.h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ce.h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(ce.h, CURLOPT_SSL_VERIFYPEER, opt.verify_tls ? 1L : 0L);
    curl_easy_setopt(ce.h, CURLOPT_SSL_VERIFYHOST, opt.verify_tls ? 2L : 0L);
    if (!opt.user.empty() || !opt.pass.empty()) {
        curl_easy_setopt(ce.h, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
        curl_easy_setopt(ce.h, CURLOPT_USERPWD, (opt.user + ":" + opt.pass).c_str());
    }
    curl_slist* hl = nullptr;
    hl = curl_slist_append(hl, "Content-Type: application/x-ndjson");
    hl = curl_slist_append(hl, "Expect:");
    if (hl) curl_easy_setopt(ce.h, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(ce.h, CURLOPT_WRITEFUNCTION, body_cb);
    curl_easy_setopt(ce.h, CURLOPT_WRITEDATA, &sink);
    CURLcode rc = curl_easy_perform(ce.h);
    if (hl) curl_slist_free_all(hl);
    if (rc != CURLE_OK) { err = set_err(std::string("curl: ") + curl_easy_strerror(rc)); return false; }
    long st = 0;
    curl_easy_getinfo(ce.h, CURLINFO_RESPONSE_CODE, &st);
    if (st < 200 || st >= 300) {
        err = set_err("WebDAV PUT status " + std::to_string(st));
        return false;
    }
    return true;
}

std::string saf_webdav_last_error() { return t_last_err; }

#else // !FE_WITH_CURL

std::shared_ptr<StorageBackend> saf_open_webdav(const SafWebDavOptions&) {
    return nullptr;
}

bool saf_webdav_parse_uri(const std::string&, SafWebDavOptions&, std::string& err) {
    err = "built without curl support";
    return false;
}

bool saf_webdav_append_text(const SafWebDavOptions&, const std::string&,
                            const std::string&, std::string& err) {
    err = "built without curl support";
    return false;
}

std::string saf_webdav_last_error() { return std::string("built without curl support"); }

#endif // FE_WITH_CURL
