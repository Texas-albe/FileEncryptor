#include "split_volumes.hpp"

#include "FileEncryptor.hpp"   // remove_file_utf8 / write_sha256_sidecar

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>

namespace {

// 尺寸后缀→乘数。用 1024 进制（与 FAT32 限值、邮件附件的惯用口径一致），
// KiB/MiB 写法也接受，免得用户以为是 1000 进制。
struct Unit { const char* suffix; uint64_t mul; };

const Unit kUnits[] = {
    {"KIB", 1ull << 10}, {"MIB", 1ull << 20}, {"GIB", 1ull << 30}, {"TIB", 1ull << 40},
    {"KB",  1ull << 10}, {"MB",  1ull << 20}, {"GB",  1ull << 30}, {"TB",  1ull << 40},
    {"K",   1ull << 10}, {"M",   1ull << 20}, {"G",   1ull << 30}, {"T",   1ull << 40},
    {"B",   1ull},
};

// 单卷下限：容器头约 256 字节，再加至少一个数据块。
const uint64_t kMinVolume = 1ull << 20;      // 1 MiB
const uint32_t kMaxVolumes = 99999;          // 枚举兜底
const size_t   kIoBufMax  = 16u << 20;      // 16 MiB

bool file_exists(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return f.good();
}

std::string strip_ptd(const std::string& p) {
    if (p.size() < 4) return p;
    std::string tail = p.substr(p.size() - 4);
    for (auto& c : tail) c = (char)std::tolower((unsigned char)c);
    return (tail == ".ptd") ? p.substr(0, p.size() - 4) : p;
}

std::string upper(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)std::toupper((unsigned char)c);
    return r;
}

std::string join(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    if (dir.back() == '/' || dir.back() == '\\') return dir + name;
    return dir + "/" + name;
}

std::string dir_of(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    if (pos == std::string::npos) return ".";
    if (pos == 0) return p.substr(0, 1);
    return p.substr(0, pos);
}

std::string base_name_of(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    return (pos == std::string::npos) ? p : p.substr(pos + 1);
}

}  // namespace

std::string volume_path(const std::string& ptd_path, uint32_t index) {
    char idx[16];
    std::snprintf(idx, sizeof(idx), ".%03u", index);
    return strip_ptd(ptd_path) + idx + ".ptd";
}

std::string base_ptd_of(const std::string& volume_file) {
    if (strip_ptd(volume_file).size() == volume_file.size()) return "";   // 无 .ptd 后缀
    std::string stem = strip_ptd(volume_file);                           // foo.003
    size_t dot = stem.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= stem.size()) return "";

    std::string digits = stem.substr(dot + 1);
    if (digits.size() < 3) return "";                 // 序号至少 3 位
    for (char c : digits)
        if (!std::isdigit((unsigned char)c)) return "";
    // 只认规范宽度：3 位（001~999）或 4 位起的自然数（1000~）。
    // "01"、"007" 这类一律不算，否则 foo.007.txt 之类会被误判成卷。
    if (digits.size() > 3 && digits[0] == '0') return "";
    return stem.substr(0, dot) + ".ptd";
}

bool parse_split_size(const std::string& spec, uint64_t& out_bytes, std::string& err) {
    out_bytes = 0;
    err.clear();

    size_t b = spec.find_first_not_of(" \t");
    if (b == std::string::npos) { err = "empty size"; return false; }
    size_t e = spec.find_last_not_of(" \t");
    std::string s = spec.substr(b, e - b + 1);

    size_t i = 0;
    while (i < s.size() && (std::isdigit((unsigned char)s[i]) || s[i] == '.')) ++i;
    std::string num = s.substr(0, i);
    std::string suf = upper(s.substr(i));
    if (num.empty()) { err = "no number in \"" + spec + "\""; return false; }
    if (num.find('.') != num.rfind('.')) { err = "bad number \"" + num + "\""; return false; }

    uint64_t mul = 1;
    if (!suf.empty()) {
        bool hit = false;
        for (const auto& u : kUnits)
            if (suf == u.suffix) { mul = u.mul; hit = true; break; }
        if (!hit) {
            err = "unknown unit \"" + suf + "\" (use KB/MB/GB/TB or K/M/G/T)";
            return false;
        }
    }

    // 手算定点数，避开 strtod 的 locale 与精度问题
    uint64_t whole = 0, frac_num = 0, frac_den = 1;
    size_t dot = num.find('.');
    auto parse_uint = [](const std::string& t, uint64_t& v) -> bool {
        if (t.empty()) return true;
        uint64_t r = 0;
        for (char c : t) {
            if (!std::isdigit((unsigned char)c)) return false;
            if (r > (UINT64_MAX - (uint64_t)(c - '0')) / 10) return false;
            r = r * 10 + (uint64_t)(c - '0');
        }
        v = r;
        return true;
    };
    if (!parse_uint(num.substr(0, dot), whole)) { err = "bad number \"" + num + "\""; return false; }
    if (dot != std::string::npos) {
        std::string fr = num.substr(dot + 1);
        if (fr.size() > 9) fr.resize(9);              // 纳级精度足够
        if (!parse_uint(fr, frac_num)) { err = "bad number \"" + num + "\""; return false; }
        for (size_t k = 0; k < fr.size(); ++k) frac_den *= 10;
    }

    if (whole == 0 && frac_num == 0) { err = "size must be greater than zero"; return false; }
    if (whole > UINT64_MAX / mul) { err = "size overflow"; return false; }
    if (frac_num > UINT64_MAX / mul) { err = "size overflow"; return false; }

    uint64_t base = whole * mul;
    uint64_t extra = (frac_num * mul + frac_den - 1) / frac_den;   // 向上取整
    if (base > UINT64_MAX - extra) { err = "size overflow"; return false; }

    out_bytes = base + extra;
    if (out_bytes == 0) { err = "size must be greater than zero"; return false; }
    return true;
}

bool split_file(const std::string& src, uint64_t volume_bytes,
                uint32_t& out_count, std::string& err) {
    out_count = 0;
    err.clear();

    if (volume_bytes < kMinVolume) { err = "split size must be at least 1MB"; return false; }
    std::ifstream in(src, std::ios::binary);
    if (!in.good()) { err = "cannot open " + src; return false; }

    std::string dir = dir_of(src);
    std::string base = base_name_of(strip_ptd(src));
    std::vector<char> buf((size_t)std::min<uint64_t>(volume_bytes, kIoBufMax));

    uint32_t idx = 0;
    for (;;) {
        std::string vp = join(dir, volume_path(base + ".ptd", idx + 1));
        std::ofstream out(vp, std::ios::binary | std::ios::trunc);
        if (!out.good()) { err = "cannot write " + vp; return false; }

        uint64_t written = 0;
        while (written < volume_bytes) {
            size_t want = (size_t)std::min<uint64_t>(buf.size(), volume_bytes - written);
            in.read(buf.data(), (std::streamsize)want);
            std::streamsize got = in.gcount();
            if (got <= 0) break;
            out.write(buf.data(), got);
            if (!out.good()) { err = "write failed: " + vp; return false; }
            written += (uint64_t)got;
        }
        out.close();

        ++idx;
        if (written < volume_bytes) break;          // 最后一卷通常不满
        if (idx >= kMaxVolumes) { err = "too many volumes"; return false; }
    }

    if (idx == 0) { err = "nothing to write"; return false; }
    out_count = idx;
    return true;
}

std::vector<std::string> find_volumes(const std::string& base_ptd,
                                      std::vector<uint32_t>* out_missing) {
    if (out_missing) out_missing->clear();
    std::vector<std::string> out;
    uint32_t stop = 1;
    for (; stop <= kMaxVolumes; ++stop) {
        std::string p = volume_path(base_ptd, stop);
        if (!file_exists(p)) break;
        out.push_back(p);
    }
    // 首个缺号之后再往外看 100 卷：命中就说明是「中间少了几卷」
    // 而不是「本来就到这儿为止」。报的是空洞区间，不是命中的卷号——
    // 用户要知道的是「我少了哪几卷」，不是「后面还剩哪几卷」。
    if (out_missing) {
        uint32_t last_found = stop - 1;
        for (uint32_t k = stop; k < stop + 100 && k <= kMaxVolumes; ++k) {
            if (file_exists(volume_path(base_ptd, k))) last_found = k;
        }
        for (uint32_t k = stop; k <= last_found; ++k)
            if (!file_exists(volume_path(base_ptd, k))) out_missing->push_back(k);
    }
    return out;
}

bool merge_volumes(const std::string& base_ptd, const std::string& merged_path,
                   std::string& err) {
    err.clear();
    std::vector<uint32_t> missing;
    std::vector<std::string> vols = find_volumes(base_ptd, &missing);
    if (vols.empty()) { err = "no volumes found for " + base_ptd; return false; }
    if (!missing.empty()) {
        std::string list;
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i) list += ", ";
            char b[16];
            std::snprintf(b, sizeof(b), "%03u", missing[i]);
            list += b;
        }
        err = "volume set incomplete (expected at least " +
              std::to_string(missing.back() + 1) + " volumes), missing: " + list;
        return false;
    }

    std::ofstream out(merged_path, std::ios::binary | std::ios::trunc);
    if (!out.good()) { err = "cannot write " + merged_path; return false; }

    std::vector<char> buf(kIoBufMax);
    for (const auto& v : vols) {
        std::ifstream in(v, std::ios::binary);
        if (!in.good()) { err = "cannot open " + v; return false; }
        for (;;) {
            in.read(buf.data(), (std::streamsize)buf.size());
            std::streamsize got = in.gcount();
            if (got <= 0) break;
            out.write(buf.data(), got);
            if (!out.good()) { err = "write failed: " + merged_path; return false; }
        }
    }
    out.close();
    return true;
}

bool finish_encrypt_split(const std::string& ptd_path, uint64_t volume_bytes,
                          bool sha_sidecar, std::string& err) {
    err.clear();
    uint32_t n = 0;
    if (!split_file(ptd_path, volume_bytes, n, err)) return false;
    for (uint32_t i = 1; i <= n; ++i) {
        if (sha_sidecar) write_sha256_sidecar(volume_path(ptd_path, i));
    }
    remove_file_utf8(ptd_path);   // 留着就等于分卷没生效
    // 整文件 sidecar 随原件一起失效，否则会指向一个不存在的文件
    remove_file_utf8(ptd_path + ".sha256");
    return true;
}

bool resolve_decrypt_input(const std::string& in_path, SplitPlan& plan, std::string& err) {
    err.clear();
    plan = SplitPlan();
    plan.real_input = in_path;

    // 输入是 foo.003.ptd → 同组是 foo.*.ptd；输入本身就是 foo.ptd 也一样。
    // 完整件同时存在时优先用它（分卷多半是残留副本）；否则合并分卷。
    // 都没有就原样返回，让后续按「打不开文件」报错。
    std::string base = base_ptd_of(in_path);
    if (base.empty()) base = in_path;
    if (file_exists(base)) return true;

    plan.volumes = find_volumes(base);
    if (plan.volumes.empty()) return true;        // 没有分卷，原样返回

    plan.merged_path = base + ".merge.ptd";
    if (!merge_volumes(base, plan.merged_path, err)) {
        remove_file_utf8(plan.merged_path);
        plan = SplitPlan();
        plan.real_input = in_path;
        return false;
    }
    plan.real_input = plan.merged_path;
    plan.from_volumes = true;
    return true;
}

MergedTemp::~MergedTemp() {
    if (!path.empty()) remove_file_utf8(path);
}
