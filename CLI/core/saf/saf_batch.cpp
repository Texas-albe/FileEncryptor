// 通用批量层
#include "saf_batch.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>

namespace {

uint64_t now_sec() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string join_path(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    return a + "/" + b;
}

std::string num(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    return std::string(buf);
}


SafAuditLog g_audit_log;
SafAuditHook g_audit_hook;
std::mutex g_audit_mutex;

std::string json_escape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
            else o += (char)c;
        }
    }
    return o;
}

// 逐段切分读取一
bool next_line(const std::string& s, size_t& pos, std::string& out) {
    if (pos >= s.size()) return false;
    size_t e = s.find('\n', pos);
    if (e == std::string::npos) { out = s.substr(pos); pos = s.size(); }
    else { out = s.substr(pos, e - pos); pos = e + 1; }
    return true;
}

} // namespace

// 递归枚举
SafStatus saf_walk(StorageBackend& be, const std::string& root,
                   std::vector<SafWalkItem>& out) {
    std::string r;
    if (!saf_path_normalize(root, r)) return SAF_E_BADARG;

    uint64_t size = 0, mtime = 0;
    bool is_dir = false;
    SafStatus st = be.stat(r, &size, &mtime, &is_dir);
    if (st != SAF_OK) return st;
    if (!is_dir) {
        SafWalkItem it;
        it.path = r; it.is_dir = false; it.size = size; it.mtime = mtime;
        out.push_back(it);
        return SAF_OK;
    }
    if (!be.can_list()) return SAF_E_NOTIMPL;

    std::vector<SafEntry> ents;
    st = be.readdir(r, ents);
    if (st != SAF_OK) return st;
    for (const auto& e : ents) {
        std::string child;
        if (!saf_path_normalize(join_path(r, e.name), child)) continue;
        if (e.is_dir) {
            SafWalkItem it;
            it.path = child; it.is_dir = true;
            out.push_back(it);
            SafStatus sub = saf_walk(be, child, out);
            if (sub != SAF_OK && sub != SAF_E_NOTIMPL) return sub;
        } else {
            SafWalkItem it;
            it.path = child; it.is_dir = false; it.size = e.size; it.mtime = e.mtime;
            out.push_back(it);
        }
    }
    return SAF_OK;
}

// 单文件流式搬运
SafStatus saf_transfer_file(StorageBackend& src, const std::string& src_path,
                            StorageBackend& dst, const std::string& dst_path,
                            uint64_t skip_bytes,
                            const SafTransferProgress& prog,
                            uint64_t* out_copied) {
    if (out_copied) *out_copied = 0;
    struct AuditGuard {
        std::string key;
        std::chrono::steady_clock::time_point t0;
        uint64_t copied = 0;
        SafStatus st = SAF_OK;
        ~AuditGuard() {
            SafAuditEvent e;
            e.op = "transfer_file";
            e.key = key;
            e.status = st;
            e.bytes = copied;
            e.elapsed_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            e.error_code = (int)st;
            saf_audit_log().append(e);
        }
    } audit{src_path, std::chrono::steady_clock::now(), 0, SAF_OK};
    auto done = [&](SafStatus s) -> SafStatus { audit.st = s; return s; };

    std::string sp, dp;
    if (!saf_path_normalize(src_path, sp)) return done(SAF_E_BADARG);
    if (!saf_path_normalize(dst_path, dp)) return done(SAF_E_BADARG);

    std::shared_ptr<Stream> rs;
    SafStatus st = src.open(sp, 'r', rs);
    if (st != SAF_OK) return done(st);

    std::shared_ptr<Stream> ws;
    if (skip_bytes > 0) {
        st = dst.open(dp, 'a', ws);
        if (st == SAF_E_NOTIMPL) return done(SAF_E_NOTIMPL);   // 目标不支持追加 =
    } else {
        st = dst.open(dp, 'w', ws);
    }
    if (st != SAF_OK) return done(st);

    // 搬运循环统一走 saf_pump
    SafPumpProgress pp;
    pp.on_bytes = prog.on_bytes;
    pp.cancelled = prog.cancelled;
    pp.chunk = prog.chunk;
    uint64_t copied = 0;
    SafStatus pr = saf_pump(*rs, *ws, skip_bytes, pp, &copied);
    SafStatus fc = ws->close();
    rs->close();
    if (pr != SAF_OK) return done(pr);
    if (fc != SAF_OK) return done(fc);
    audit.copied = copied;
    if (out_copied) *out_copied = copied;
    return done(SAF_OK);
}

// 续传簿记
void SafResumeBook::mark_done(const std::string& key) {
    for (auto& kv : items_) {
        if (kv.first == key) { kv.second.done = true; kv.second.bytes = 0; return; }
    }
    SafResumeEntry e; e.done = true; e.bytes = 0;
    items_.emplace_back(key, e);
}

void SafResumeBook::set_bytes(const std::string& key, uint64_t n) {
    for (auto& kv : items_) {
        if (kv.first == key) { kv.second.done = false; kv.second.bytes = n; return; }
    }
    SafResumeEntry e; e.done = false; e.bytes = n;
    items_.emplace_back(key, e);
}

const SafResumeEntry* SafResumeBook::find(const std::string& key) const {
    for (const auto& kv : items_) if (kv.first == key) return &kv.second;
    return nullptr;
}

size_t SafResumeBook::size() const { return items_.size(); }
void SafResumeBook::clear() { items_.clear(); }

std::string SafResumeBook::escape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        if (c == '\\') o += "\\\\";
        else if (c == '\t') o += "\\t";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o.push_back((char)c);
    }
    return o;
}

bool SafResumeBook::unescape(const std::string& s, std::string& out) {
    out.clear();
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c != '\\') { out.push_back(c); continue; }
        if (++i >= s.size()) return false;
        switch (s[i]) {
        case '\\': out.push_back('\\'); break;
        case 't':  out.push_back('\t'); break;
        case 'n':  out.push_back('\n'); break;
        case 'r':  out.push_back('\r'); break;
        default:   return false;
        }
    }
    return true;
}

std::string SafResumeBook::serialize() const {
    std::string o = "saf-resume-v1\n";
    for (const auto& kv : items_) {
        o += escape(kv.first);
        o += " ";
        o += kv.second.done ? "1" : "0";
        o += " ";
        o += num(kv.second.bytes);
        o += "\n";
    }
    return o;
}

bool SafResumeBook::deserialize(const std::string& text) {
    items_.clear();
    size_t pos = 0;
    std::string line, first;
    if (!next_line(text, pos, first)) return false;
    if (first != "saf-resume-v1") return false;
    while (next_line(text, pos, line)) {
        if (line.empty()) continue;
        size_t p1 = line.find(' ');
        if (p1 == std::string::npos) return false;
        size_t p2 = line.find(' ', p1 + 1);
        if (p2 == std::string::npos) return false;
        std::string key;
        if (!unescape(line.substr(0, p1), key)) return false;
        SafResumeEntry e;
        e.done = (line.substr(p1 + 1, p2 - p1 - 1) == "1");
        e.bytes = std::strtoull(line.substr(p2 + 1).c_str(), nullptr, 10);
        items_.emplace_back(key, e);
    }
    return true;
}

// 整树搬运
SafStatus saf_transfer_tree(StorageBackend& src, const std::string& src_root,
                            StorageBackend& dst, const std::string& dst_root,
                            const std::function<std::string(const std::string&)>& name_map,
                            SafResumeBook& book, const std::string& key_prefix,
                            const SafTransferProgress& prog,
                            SafTransferStats& out_stats) {
    struct TreeAudit {
        std::string key;
        std::chrono::steady_clock::time_point t0;
        uint64_t bytes = 0;
        SafStatus st = SAF_OK;
        ~TreeAudit() {
            SafAuditEvent e;
            e.op = "transfer_tree";
            e.key = key;
            e.status = st;
            e.bytes = bytes;
            e.elapsed_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            e.error_code = (int)st;
            saf_audit_log().append(e);
        }
    } audit{src_root, std::chrono::steady_clock::now(), 0, SAF_OK};
    auto done = [&](SafStatus s) -> SafStatus { audit.st = s; return s; };
    std::vector<SafWalkItem> items;
    SafStatus st = saf_walk(src, src_root, items);
    if (st != SAF_OK) return done(st);

    std::string sr, dr;
    if (!saf_path_normalize(src_root, sr)) return done(SAF_E_BADARG);
    if (!saf_path_normalize(dst_root, dr)) return done(SAF_E_BADARG);

    for (const auto& it : items) {
        if (prog.cancelled && prog.cancelled()) return done(SAF_E_BADARG);

        std::string rel = it.path;                 // 相对 src_root
        if (!sr.empty()) {
            if (rel.size() > sr.size() && rel.compare(0, sr.size(), sr) == 0 &&
                rel[sr.size()] == '/') rel = rel.substr(sr.size() + 1);
            else if (rel == sr) rel.clear();
        }
        if (rel.empty()) continue;

        std::string dst_rel = name_map ? name_map(rel) : rel;
        if (dst_rel.empty()) continue;

        std::string key = key_prefix + "|" + rel;

        if (it.is_dir) {
            if (dst.can_write()) dst.mkdir(join_path(dr, dst_rel));   // 不支持
            continue;
        }

        if (const SafResumeEntry* e = book.find(key)) {
            if (e->done) { out_stats.files_skip++; continue; }
        }

        uint64_t skip = 0;
        if (const SafResumeEntry* e = book.find(key)) skip = e->bytes;

        // 目标子目录
        size_t slash = dst_rel.find_last_of('/');
        if (slash != std::string::npos && dst.can_write())
            dst.mkdir(join_path(dr, dst_rel.substr(0, slash)));

        uint64_t copied = 0;
        st = saf_transfer_file(src, it.path, dst, join_path(dr, dst_rel), skip, prog, &copied);
        if (st == SAF_OK && skip + copied != it.size) {
            // 低危
            std::string dfull = join_path(dr, dst_rel);
            SafStatus dr_st = dst.delete_file(dfull);
            if (dr_st == SAF_OK || dr_st == SAF_E_NOTFOUND) {
                skip = 0;
                st = saf_transfer_file(src, it.path, dst, dfull, 0, prog, &copied);
            } else {
                st = SAF_E_IO;   // 半成品删不掉
            }
        }
        if (st != SAF_OK) {
            if (st == SAF_E_BADARG && prog.cancelled && prog.cancelled()) return done(st);   // 中止
            out_stats.files_fail++;
            continue;
        }
        if (skip + copied != it.size) {   // 重做后仍不符
            out_stats.files_fail++;
            continue;
        }
        book.mark_done(key);
        out_stats.files_done++;
        out_stats.bytes += copied + skip;
    }
    audit.bytes = out_stats.bytes;
    return done(SAF_OK);
}

// 审计日志
void SafAuditLog::append(const SafAuditEvent& ev) {
    SafAuditEvent e = ev;
    if (e.ts == 0) e.ts = now_sec();
    SafAuditHook hook;
    {
        std::lock_guard<std::mutex> lk(g_audit_mutex);
        evs_.push_back(e);
        hook = g_audit_hook;
    }
    if (hook) hook(e);   // 解锁
}

const std::vector<SafAuditEvent>& SafAuditLog::events() const { return evs_; }
size_t SafAuditLog::size() const { return evs_.size(); }
void SafAuditLog::clear() { evs_.clear(); }

std::string SafAuditLog::serialize() const {
    std::string o = "saf-audit-v1\n";
    for (const auto& e : evs_) {
        o += SafResumeBook::escape(e.op);
        o += " ";
        o += SafResumeBook::escape(e.key);
        o += " ";
        long long st = (long long)e.status;
        char sbuf[32];
        std::snprintf(sbuf, sizeof(sbuf), "%lld", st);
        o += sbuf;
        o += " ";
        o += num(e.bytes);
        o += " ";
        o += num(e.ts);
        o += "\n";
    }
    return o;
}


std::string SafAuditLog::to_jsonl() const {
    std::string o;
    for (const auto& e : evs_) {
        o += "{\"schema\":1,\"ts\":" + num(e.ts)
           + ",\"op\":\"" + json_escape(e.op)
           + "\",\"key\":\"" + json_escape(e.key)
           + "\",\"status\":" + num((uint64_t)e.status)
           + ",\"bytes\":" + num(e.bytes)
           + ",\"elapsed_ms\":" + num(e.elapsed_ms)
           + ",\"error_code\":" + std::to_string(e.error_code)
           + ",\"device_id\":\"" + json_escape(e.device_id)
           + "\"}\n";
    }
    return o;
}

SafAuditLog& saf_audit_log() { return g_audit_log; }

void saf_set_audit_hook(SafAuditHook hook) {
    std::lock_guard<std::mutex> lk(g_audit_mutex);
    g_audit_hook = std::move(hook);
}

bool SafAuditLog::deserialize(const std::string& text) {
    evs_.clear();
    size_t pos = 0;
    std::string line, first;
    if (!next_line(text, pos, first)) return false;
    if (first != "saf-audit-v1") return false;
    while (next_line(text, pos, line)) {
        if (line.empty()) continue;
        size_t p[4];
        size_t from = 0;
        for (int i = 0; i < 4; ++i) {
            p[i] = line.find(' ', from);
            if (p[i] == std::string::npos) return false;
            from = p[i] + 1;
        }
        SafAuditEvent e;
        if (!SafResumeBook::unescape(line.substr(0, p[0]), e.op)) return false;
        if (!SafResumeBook::unescape(line.substr(p[0] + 1, p[1] - p[0] - 1), e.key)) return false;
        e.status = (SafStatus)std::strtoll(line.substr(p[1] + 1, p[2] - p[1] - 1).c_str(), nullptr, 10);
        e.bytes = std::strtoull(line.substr(p[2] + 1, p[3] - p[2] - 1).c_str(), nullptr, 10);
        e.ts = std::strtoull(line.substr(p[3] + 1).c_str(), nullptr, 10);
        evs_.push_back(e);
    }
    return true;
}
