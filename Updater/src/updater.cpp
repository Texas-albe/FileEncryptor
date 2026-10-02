// Updater.cpp — FileEncryptor 自动更新器（独立命令行工具，无自更新、无版本号）
//
// 技术栈：C++17 + libcurl(HTTPS, 静态链接 bundled 源码) + 内置 SHA-256 + 内置最小 JSON 解析。
// 跨平台：Windows / Linux 同构；仅安装步骤按 OS 分支（Windows: msiexec / 直接复制；其他: 直接复制）。
// TLS 后端：Windows 用原生 Schannel，Linux 用系统 OpenSSL（均零额外依赖）。
//
// 用法：
//   Updater --check  --current <ver> --type <qt|winui> --platform <windows|linux> [--etag <e>]
//   Updater --update --url <url> --sha256 <hex> --size <n> --install-dir <path> [--sig-url <url>]
// 失败时 stdout 仍给出 JSON，error 为分类原因，detail 为具体说明（供 GUI 展示）。
//
// --check  ：查 GitHub 最新 release，匹配当前 type/platform 的资产，输出一行 JSON 到 stdout。
// --update：下载资产到临时目录，校验大小 + SHA256（+ 可选 Minisign），成功后放入 install-dir。
// 网络范围：默认只访问 GitHub 白名单域名，加 --allow-any-host 放开（仅调试用）。

#include <curl/curl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <algorithm>
#include <fstream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <ctime>
#endif

// ===================== 最小 JSON 解析（够用即可） =====================
struct JsonValue {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<JsonValue> arr;
    std::vector<std::pair<std::string, JsonValue>> obj;
    const JsonValue* find(const std::string& k) const {
        if (type != Obj) return nullptr;
        for (const auto& p : obj) if (p.first == k) return &p.second;
        return nullptr;
    }
    const JsonValue* at(size_t i) const {
        return (type == Arr && i < arr.size()) ? &arr[i] : nullptr;
    }
    std::string asStr() const { return (type == Str) ? str : std::string(); }
    double asNum() const { return (type == Num) ? num : 0; }
    bool asBool() const { return (type == Bool) ? b : false; }
};

struct JsonParser {
    const char* p; const char* end; std::string err;
    JsonParser(const char* s, size_t n) : p(s), end(s + n) {}
    bool parse(JsonValue& out) { skipws(); if (!parseValue(out)) return false; skipws(); return p == end; }
    void skipws() { while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++; }
    bool parseValue(JsonValue& v) {
        skipws(); if (p >= end) { err = "eof"; return false; }
        char c = *p;
        if (c == '{') return parseObject(v);
        if (c == '[') return parseArray(v);
        if (c == '"') { if (!parseString(v)) return false; v.type = JsonValue::Str; return true; }
        if (c == 't' || c == 'f') return parseBool(v);
        if (c == 'n') { p += 4; v.type = JsonValue::Null; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber(v);
        err = "char"; return false;
    }
    bool parseObject(JsonValue& v) {
        v.type = JsonValue::Obj; p++;
        skipws(); if (p < end && *p == '}') { p++; return true; }
        while (true) {
            skipws(); if (p >= end || *p != '"') { err = "key"; return false; }
            JsonValue k; if (!parseString(k)) return false; k.type = JsonValue::Str;
            skipws(); if (p >= end || *p != ':') { err = "colon"; return false; } p++;
            JsonValue val; if (!parseValue(val)) return false;
            v.obj.push_back({ k.str, val });
            skipws(); if (p >= end) { err = "oend"; return false; }
            if (*p == ',') { p++; continue; }
            if (*p == '}') { p++; return true; }
            err = "osep"; return false;
        }
    }
    bool parseArray(JsonValue& v) {
        v.type = JsonValue::Arr; p++; skipws();
        if (p < end && *p == ']') { p++; return true; }
        while (true) {
            JsonValue val; if (!parseValue(val)) return false;
            v.arr.push_back(val);
            skipws(); if (p >= end) { err = "aend"; return false; }
            if (*p == ',') { p++; continue; }
            if (*p == ']') { p++; return true; }
            err = "asep"; return false;
        }
    }
    bool parseString(JsonValue& v) {
        p++; std::string s;
        while (p < end) {
            char c = *p;
            if (c == '"') { p++; v.str = s; return true; }
            if (c == '\\') {
                p++; if (p >= end) { err = "esc"; return false; }
                char e = *p++;
                switch (e) {
                    case 'n': s += '\n'; break;
                    case 't': s += '\t'; break;
                    case 'r': s += '\r'; break;
                    case '"': s += '"'; break;
                    case '\\': s += '\\'; break;
                    case '/': s += '/'; break;
                    case 'b': s += '\b'; break;
                    case 'f': s += '\f'; break;
                    case 'u': {
                        if (p + 4 > end) { err = "uni"; return false; }
                        unsigned cp = 0;
                        for (int i = 0; i < 4; i++) {
                            char h = *p++; cp <<= 4;
                            if (h >= '0' && h <= '9') cp += h - '0';
                            else if (h >= 'a' && h <= 'f') cp += h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') cp += h - 'A' + 10;
                            else { err = "hex"; return false; }
                        }
                        if (cp < 0x80) s += (char)cp;
                        else if (cp < 0x800) { s += (char)(0xC0 | (cp >> 6)); s += (char)(0x80 | (cp & 0x3F)); }
                        else { s += (char)(0xE0 | (cp >> 12)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
                        break;
                    }
                    default: s += e;
                }
            } else { s += c; p++; }
        }
        err = "strend"; return false;
    }
    bool parseNumber(JsonValue& v) {
        const char* s = p;
        if (p < end && *p == '-') p++;
        while (p < end && ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' || *p == 'E' || *p == '+' || *p == '-')) p++;
        v.num = atof(std::string(s, p).c_str()); v.type = JsonValue::Num; return true;
    }
    bool parseBool(JsonValue& v) {
        if (p + 4 <= end && strncmp(p, "true", 4) == 0) { v.b = true; p += 4; v.type = JsonValue::Bool; return true; }
        if (p + 5 <= end && strncmp(p, "false", 5) == 0) { v.b = false; p += 5; v.type = JsonValue::Bool; return true; }
        err = "bool"; return false;
    }
};

// ===================== 工具函数 =====================
// UTF-8 路径 → 原生路径（Windows 需转宽字符；其他平台直接用）
static std::filesystem::path nativePath(const std::string& utf8) {
#ifdef _WIN32
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &w[0], n);
    return std::filesystem::path(w);
#else
    return std::filesystem::path(utf8);
#endif
}

#ifdef _WIN32
static std::wstring to_wide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
#endif

static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return false;
    return true;
}

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && ::isspace((unsigned char)s[a])) a++;
    while (b > a && ::isspace((unsigned char)s[b - 1])) b--;
    return s.substr(a, b - a);
}

static std::string randSuffix() {
#ifdef _WIN32
    unsigned seed = (unsigned)(GetTickCount() ^ GetCurrentProcessId());
#else
    unsigned seed = (unsigned)(time(nullptr) ^ getpid());
#endif
    seed = seed * 1103515245u + 12345u;
    char buf[16];
    snprintf(buf, sizeof(buf), "%08X%04X", seed, (seed >> 16) & 0xFFFF);
    return std::string(buf);
}

// ===================== 内置 SHA-256（纯 C++17，跨平台） =====================
namespace sha256 {
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

struct State {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint64_t len = 0;
    unsigned char buf[64]; unsigned bufn = 0;

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t shr(uint32_t x, int n) { return x >> n; }

    void block(const unsigned char* p) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
                   ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ shr(w[i-15],3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ shr(w[i-2],10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const unsigned char* data, size_t n) {
        len += n;
        for (size_t i = 0; i < n; i++) {
            buf[bufn++] = data[i];
            if (bufn == 64) { block(buf); bufn = 0; }
        }
    }
    void final(unsigned char out[32]) {
        uint64_t bitlen = len * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        unsigned char zero = 0;
        while (bufn != 56) update(&zero, 1);
        unsigned char bits[8];
        for (int i = 0; i < 8; i++) bits[i] = (unsigned char)(bitlen >> (56 - 8*i));
        update(bits, 8);
        for (int i = 0; i < 8; i++) {
            out[i*4]   = (unsigned char)(h[i] >> 24);
            out[i*4+1] = (unsigned char)(h[i] >> 16);
            out[i*4+2] = (unsigned char)(h[i] >> 8);
            out[i*4+3] = (unsigned char)(h[i]);
        }
    }
};
} // namespace sha256

// SHA256 文件 → 小写 hex；失败返回空串。
static std::string sha256File(const std::string& pathUtf8) {
    std::ifstream f(nativePath(pathUtf8), std::ios::binary);
    if (!f) return std::string();
    sha256::State s;
    unsigned char buf[1 << 16];
    while (f.read((char*)buf, sizeof(buf)) || f.gcount() > 0) {
        std::streamsize g = f.gcount();
        if (g > 0) s.update(buf, (size_t)g);
        if (!f) break;
    }
    unsigned char out[32];
    s.final(out);
    static const char* d = "0123456789abcdef";
    std::string hex(64, '0');
    for (int i = 0; i < 32; i++) { hex[i*2] = d[out[i] >> 4]; hex[i*2+1] = d[out[i] & 0xF]; }
    return hex;
}

// ===================== 访问范围：只放行 GitHub 域名 =====================
// 本工具只取更新，非 GitHub 域一律拒绝（防被当任意 URL 下载器 / SSRF）
// 白名单三端同步：kGitHubHosts(此处) / GUI-Qt kAllowedHosts / GUI-WinUI s_allowedHosts
static const char* const kGitHubHosts[] = {
    "github.com", "api.github.com",
    "objects.githubusercontent.com", "codeload.github.com",
};
// release 资产下载时 GitHub 会 302 到该域，漏掉会导致「有更新但下载不到」
static const char* const kGitHubAssetHosts[] = {
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com", "codeload.github.com",
};
static bool g_allowAnyHost = false; // --allow-any-host 时放开
static std::string g_proxy;         // --proxy 显式代理，为空则沿用 curl 的环境变量代理

// 精确匹配白名单，不做后缀模糊（防 evilgithub.com 之类）
static bool hostInList(const std::string& host, const char* const* list, size_t n) {
    if (host.empty()) return false;
    for (size_t i = 0; i < n; i++) if (host == list[i]) return true;
    return false;
}
static bool isGitHubHost(const std::string& host) {
    return hostInList(host, kGitHubHosts, sizeof(kGitHubHosts) / sizeof(kGitHubHosts[0]));
}
static bool isGitHubAssetHost(const std::string& host) {
    return hostInList(host, kGitHubAssetHosts, sizeof(kGitHubAssetHosts) / sizeof(kGitHubAssetHosts[0]));
}
// API 请求只允许 GitHub 域；下载/签名 URL 额外允许对象存储域
static bool isGitHubOrAssetHost(const std::string& host) {
    return isGitHubHost(host) || isGitHubAssetHost(host);
}

// 取 URL 主机（小写、去端口、去凭据）
static std::string urlHost(const std::string& url) {
    size_t s = url.find("://");
    if (s == std::string::npos) return std::string();
    s += 3;
    size_t e = url.find_first_of("/?#", s);
    std::string h = url.substr(s, (e == std::string::npos) ? std::string::npos : e - s);
    size_t c = h.find('@');                       // 去 user:pass@
    if (c != std::string::npos) h = h.substr(c + 1);
    size_t p = h.find(':');                       // 去端口
    if (p != std::string::npos) h.resize(p);
    for (char& ch : h) ch = (char)tolower((unsigned char)ch);
    return h;
}

// 仅 http/https，且主机在 GitHub 白名单内（下载场景额外放行对象存储域）
static bool urlAllowed(const std::string& url, std::string* hostOut, bool allowAssetHost = false) {
    std::string host = urlHost(url);
    if (hostOut) *hostOut = host;
    if (g_allowAnyHost) return !host.empty();
    size_t s = url.find("://");
    std::string scheme = (s != std::string::npos) ? url.substr(0, s) : std::string();
    if (scheme != "https" && scheme != "http") return false;
    return allowAssetHost ? isGitHubOrAssetHost(host) : isGitHubHost(host);
}

// ===================== libcurl 回调与 GET / 下载 =====================
// CA 证书包：Windows 上 curl 的 OpenSSL 后端不读系统证书库，缺 CAINFO 时 HTTPS 直接
// 报证书校验失败（表现为「检查不了更新」）；Linux 的 OpenSSL 默认路径已覆盖，这里也
// 允许 CURL_CA_BUNDLE / SSL_CERT_FILE 覆盖以便自带 CA 分发。
static void applyCaBundle(CURL* h) {
#ifdef _WIN32
    std::vector<std::string> cands;
    if (const char* e = getenv("CURL_CA_BUNDLE")) cands.emplace_back(e);
    char exepath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, exepath, MAX_PATH) > 0) {
        std::string dir(exepath);
        dir.erase(dir.find_last_of("\\/"));
        cands.push_back(dir + "\\ca\\ca-bundle.crt");
        cands.push_back(dir + "\\curl-ca-bundle.crt");
    }
    const char* installed[] = {
        "C:\\Windows\\System32\\curl-ca-bundle.crt",
        "C:\\Windows\\curl\\curl-ca-bundle.crt",
        "C:\\Program Files\\curl\\curl-ca-bundle.crt",
    };
    for (const char* p : installed) cands.emplace_back(p);
#else
    std::vector<std::string> cands;
    if (const char* e = getenv("SSL_CERT_FILE")) cands.emplace_back(e);
    if (const char* e = getenv("CURL_CA_BUNDLE")) cands.emplace_back(e);
    const char* installed[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
    };
    for (const char* p : installed) cands.emplace_back(p);
#endif
    for (const std::string& c : cands) {
        std::FILE* f = std::fopen(c.c_str(), "rb");
        if (!f) continue;
        std::fclose(f);
        curl_easy_setopt(h, CURLOPT_CAINFO, c.c_str());
        return;
    }
}

struct GetCtx {
    std::vector<char>* body = nullptr;
    std::string* etag = nullptr;
    std::string* finalUrl = nullptr;
};
static size_t getWriteCb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* c = static_cast<GetCtx*>(userdata);
    size_t n = size * nmemb;
    c->body->insert(c->body->end(), (char*)ptr, (char*)ptr + n);
    return n;
}
static size_t getHeaderCb(char* buffer, size_t size, size_t nmemb, void* userdata) {
    auto* c = static_cast<GetCtx*>(userdata);
    size_t n = size * nmemb;
    std::string line(buffer, n);
    size_t colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string lk; for (char ch : key) lk += (char)tolower((unsigned char)ch);
        if (lk == "etag" && c->etag) *c->etag = trim(line.substr(colon + 1));
    }
    return n;
}

// HTTP 结果：ok=false 时 error 为可展示给用户的分类原因，detail 带 curl 原文
struct HttpResult {
    bool ok = false;
    long status = 0;
    std::string error;   // 分类原因：network_unreachable / tls_verify_failed / ...
    std::string detail;  // curl 错误串或 respone 说明
    std::string etag;
    std::string effectiveUrl;
};

// 把 curl 失败 / HTTP 状态码翻译成 GUI 能理解的原因（GUI 只拿到 error 字段）
static void classify(int curlCode, const std::string& curlErr, long status, HttpResult* r) {
    // 错误码比错误串稳：代理类失败在 Windows 上的 strerror 未必带 "proxy"
    // curl 8.x 公开头不再导出这几个旧枚举，按 curl.h 里的历史数值硬写
    if (curlCode == 3 /*COULDNT_RESOLVE_PROXY*/ || curlCode == 5 /*COULDNT_CONNECT_PROXY*/ ||
        curlCode == 403 /*PROXY*/) { r->error = "proxy_failed"; return; }
    if (curlCode == 401 /*PROXY_AUTH*/) { r->error = "proxy_auth_failed"; return; }
    if (status == 403 || status == 429) { r->error = "rate_limited"; return; }
    if (status == 404) { r->error = "release_not_found"; return; }
    if (status >= 500) { r->error = "server_error"; return; }
    if (!curlErr.empty()) {
        // 代理相关失败要单独说清：用户看得懂「代理不通」才知道去查代理而不是重装
        if (curlErr.find("proxy") != std::string::npos) {
            if (curlErr.find("authentication") != std::string::npos) r->error = "proxy_auth_failed";
            else if (curlErr.find("resolve") != std::string::npos ||
                     curlErr.find("connect") != std::string::npos ||
                     curlErr.find("CONNECT") != std::string::npos) r->error = "proxy_failed";
            else r->error = "proxy_failed";
            return;
        }
        if (curlErr.find("Could not resolve host") != std::string::npos ||
            curlErr.find("Couldn't resolve host") != std::string::npos) r->error = "dns_failed";
        else if (curlErr.find("Operation timed out") != std::string::npos) r->error = "timeout";
        else if (curlErr.find("Could not connect") != std::string::npos ||
                 curlErr.find("connect()") != std::string::npos) r->error = "network_unreachable";
        else if (curlErr.find("SSL certificate") != std::string::npos) r->error = "tls_verify_failed";
        else r->error = "network_failed";
        return;
    }
    r->error = "network_failed";
}

// 低层 GET（跟随重定向，最多 6 次；支持 If-None-Match、Range 头）。
static HttpResult lowGet(const std::string& url, std::vector<char>* out,
                         long* statusOut, std::string* etagOut, std::string* finalUrlOut,
                         const std::string& etagIn, const std::string& rangeHeader,
                         const HttpResult* preset = nullptr, const char* purpose = nullptr) {
    HttpResult r;
    CURL* h = curl_easy_init();
    if (!h) { r.error = "curl_init_failed"; r.detail = "curl_easy_init returned null"; return r; }
    GetCtx ctx{out, etagOut, finalUrlOut};
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    // 无超时会让 GUI 一直转圈：连不上/被墙时必须有上限
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    if (!g_proxy.empty()) curl_easy_setopt(h, CURLOPT_PROXY, g_proxy.c_str());
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, getWriteCb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, getHeaderCb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &ctx);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 6L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "FileEncryptorUpdater/1.0");
    curl_easy_setopt(h, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); // 避免沙箱/部分网络无 IPv6 路由导致连接失败
    struct curl_slist* hdr = nullptr;
    hdr = curl_slist_append(hdr, "Accept: application/vnd.github+json");
    if (!etagIn.empty()) {
        std::string h2 = "If-None-Match: " + etagIn; // GitHub 的 ETag 已自带引号
        hdr = curl_slist_append(hdr, h2.c_str());
    }
    if (!rangeHeader.empty()) hdr = curl_slist_append(hdr, rangeHeader.c_str());
    if (hdr) curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
    applyCaBundle(h);

    CURLcode rc = curl_easy_perform(h);
    long code = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
    char* eff = nullptr;
    curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &eff);
    if (eff && finalUrlOut) *finalUrlOut = eff;
    if (statusOut) *statusOut = code;
    r.status = code;
    if (eff) r.effectiveUrl = eff;

    if (rc == CURLE_OK) {
        r.ok = true;
    } else {
        r.detail = curl_easy_strerror(rc);
        if (preset) { r.error = preset->error; if (preset->detail.empty()) r.detail = preset->detail; }
        else classify((int)rc, r.detail, code, &r);
    }
    (void)purpose;

    if (hdr) curl_slist_free_all(hdr);
    curl_easy_cleanup(h);
    return r;
}

struct DlCtx {
    std::ofstream* f = nullptr;
    long long* written = nullptr;
    long long total = 0;
    long long base = 0; // 已续传的偏移
    const std::function<void(long long, long long)>* prog = nullptr;
};
static size_t dlWriteCb(void* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* c = static_cast<DlCtx*>(userdata);
    size_t n = size * nmemb;
    c->f->write((const char*)ptr, (std::streamsize)n);
    if (!c->f->good()) return 0; // 通知 libcurl 中止
    *c->written += (long long)n;
    if (c->prog) (*c->prog)(*c->written, c->total);
    return n;
}
static size_t dlHeaderCb(char* buffer, size_t size, size_t nmemb, void* userdata) {
    auto* c = static_cast<DlCtx*>(userdata);
    size_t n = size * nmemb;
    std::string line(buffer, n);
    size_t colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string lk; for (char ch : key) lk += (char)tolower((unsigned char)ch);
        if (lk == "content-length") {
            long long len = atoll(trim(line.substr(colon + 1)).c_str());
            // 续传时 Content-Length 只含剩余部分，进度条总长按完整大小算
            if (len > 0) c->total = (c->base > 0) ? (len + c->base) : len;
        }
    }
    return n;
}

// 最近一次下载失败的原因：downloadToFile 只返回 -1，错误细节要靠它带出去
static std::string g_dlError;

// 下载到文件（支持 Range 续传、进度回调）。返回实际写入字节数；失败时返回 -1。
static long long downloadToFile(const std::string& url, const std::string& outPathUtf8,
                                 long long resumeFrom,
                                 const std::function<void(long long, long long)>& onProgress) {
    CURL* h = curl_easy_init();
    if (!h) { g_dlError = "curl_easy_init failed"; return -1; }

    std::ofstream f;
    if (resumeFrom > 0)
        f.open(nativePath(outPathUtf8), std::ios::binary | std::ios::out | std::ios::ate);
    else
        f.open(nativePath(outPathUtf8), std::ios::binary | std::ios::out | std::ios::trunc);
    if (!f) {
        g_dlError = "cannot open output file: " + outPathUtf8;
        fprintf(stderr, "[update] cannot open out file: %s\n", outPathUtf8.c_str());
        curl_easy_cleanup(h);
        return -1;
    }
    if (resumeFrom > 0) f.seekp((std::streamoff)resumeFrom, std::ios::beg);

    long long written = resumeFrom;
    long long total = resumeFrom; // 若响应含 Content-Length，dlHeaderCb 会改写为剩余+偏移
    DlCtx ctx{&f, &written, total, resumeFrom, &onProgress};

    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, dlWriteCb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, dlHeaderCb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &ctx);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 6L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "FileEncryptorUpdater/1.0");
    curl_easy_setopt(h, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); // 避免沙箱/部分网络无 IPv6 路由导致连接失败
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 20L);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    // 大文件下载给足时间，但要能出进度；单次写入无响应超过 120s 就算断流
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 0L);
    curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 4096L);
    curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME, 60L);
    applyCaBundle(h);
    if (resumeFrom > 0) curl_easy_setopt(h, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)resumeFrom);

    CURLcode rc = curl_easy_perform(h);
    f.flush();
    long code = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
    char* eff = nullptr;
    curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &eff);
    bool ok = (rc == CURLE_OK);
    // curl 对 4xx/5xx 也返回 CURLE_OK，不查状态码就会把错误页当安装包写完
    if (ok && resumeFrom == 0 && code != 200 && code != 206) {
        ok = false;
        g_dlError = "http status " + std::to_string(code);
        fprintf(stderr, "[update] unexpected http status %ld\n", code);
    }
    if (!ok) {
        g_dlError = std::string(curl_easy_strerror(rc)) + " (http " + std::to_string(code) + ")";
        fprintf(stderr, "[update] curl error: %s (rc=%d) status=%ld effective=%s written=%lld total=%lld\n",
                curl_easy_strerror(rc), (int)rc, code, eff ? eff : "?",
                (long long)written, (long long)ctx.total);
    }
    curl_easy_cleanup(h);
    return ok ? written : -1;
}

// 语义化版本比较：a<b 返回 <0，a==b 返回 0，a>b 返回 >0（仅比较前三个整数段）
static int versionCmp(const std::string& a, const std::string& b) {
    auto split = [](const std::string& s) {
        std::vector<int> v(3, 0); size_t i = 0, n = 0;
        while (n < 3 && i < s.size()) {
            size_t j = s.find('.', i);
            std::string part = (j == std::string::npos) ? s.substr(i) : s.substr(i, j - i);
            v[n++] = atoi(part.c_str());
            if (j == std::string::npos) break;
            i = j + 1;
        }
        return v;
    };
    auto va = split(a), vb = split(b);
    for (int i = 0; i < 3; i++) if (va[i] != vb[i]) return va[i] < vb[i] ? -1 : 1;
    return 0;
}

// 从数字起点起摘一段版本号，只保留 x.y.z 三段
static std::string takeNumVer(const std::string& s, size_t from) {
    size_t i = from;
    while (i < s.size() && !isdigit((unsigned char)s[i])) i++;
    size_t st = i;
    while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.')) i++;
    std::string v = s.substr(st, i - st);
    std::vector<std::string> segs; std::string cur;
    for (char c : v) { if (c == '.') { segs.push_back(cur); cur.clear(); } else cur += c; }
    segs.push_back(cur);
    std::string out;
    for (size_t k = 0; k < segs.size() && k < 3; k++) { if (k) out += '.'; out += segs[k]; }
    return out;
}

// 从 tag 提取 GUI 版本：兼容 GUI2.1.0 / GUI-Qt-2.1.0 / gui-2.1.0 / CLI2.7.0_GUI2.1.0。
// 认不出 GUI 段时退化为 tag 里最后一个版本号——否则换 tag 命名后会静默判定「已是最新」，
// 表现为「明明有新版本却总说没更新」。
static std::string guiVerFromTag(const std::string& tag) {
    for (size_t p = 0; p + 3 <= tag.size(); p++)
        if (iequals(tag.substr(p, 3), "GUI")) {
            std::string v = takeNumVer(tag, p + 3);
            if (!v.empty()) return v;
        }
    std::string last;
    for (size_t i = 0; i < tag.size(); i++)
        if (isdigit((unsigned char)tag[i])) {
            std::string v = takeNumVer(tag, i);
            if (!v.empty()) last = v;
        }
    return last;
}

// 根据 type/platform 从资产名匹配下载资产（大小写不敏感）
static int matchAsset(const JsonValue& assets, const std::string& type, const std::string& platform) {
    auto lower = [](const std::string& s) {
        std::string o = s; for (char& c : o) c = (char)tolower((unsigned char)c); return o;
    };
    const bool win = (platform == "windows" || platform == "win" || platform == "windows_x64");
    const bool linux = (platform == "linux");
    const bool isWinui = (type == "winui");
    std::vector<std::string> cands;
    for (const auto& a : assets.arr) {
        const JsonValue* n = a.find("name");
        if (!n) continue;
        const std::string ln = lower(n->asStr());
        bool ok = false;
        if (isWinui && win)
            // WinUI 分发过 .msi，也曾出独立 exe：命中其一即可，别只认 .msi
            ok = (ln.find("winui") != std::string::npos || ln.find("winui3") != std::string::npos)
                 && (ln.find("windows") != std::string::npos || ln.find("win") != std::string::npos)
                 && (ln.find(".msi") != std::string::npos || ln.find(".exe") != std::string::npos);
        else if (!isWinui && win)
            ok = ln.find("qt") != std::string::npos
                 && (ln.find("windows") != std::string::npos || ln.find("win") != std::string::npos)
                 && ln.find(".exe") != std::string::npos;
        else if (linux)
            ok = ln.find("qt") != std::string::npos && ln.find("linux") != std::string::npos;
        if (ok) cands.push_back(n->asStr());
    }
    if (cands.empty()) return -1;
    for (size_t i = 0; i < assets.arr.size(); i++) {
        const JsonValue* n = assets.arr[i].find("name");
        if (n && std::find(cands.begin(), cands.end(), n->asStr()) != cands.end()) return (int)i;
    }
    return -1;
}

static std::string jsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default: o += c;
        }
    }
    return o;
}

// ===================== --check =====================
static int doCheck(const std::string& current, const std::string& type, const std::string& platform,
                   const std::string& etagIn) {
    const std::string api = "https://api.github.com/repos/Texas-albe/FileEncryptor/releases/latest";
    std::string host;
    if (!urlAllowed(api, &host)) {
        printf("{\"ok\":false,\"error\":\"host_not_allowed\",\"host\":\"%s\"}\n", jsonEscape(host).c_str());
        return 1;
    }
    std::vector<char> body;
    long status = 0; std::string etagNew, finalUrl;
    HttpResult hr = lowGet(api, &body, &status, &etagNew, &finalUrl, etagIn, std::string());
    if (!hr.ok) {
        // 把具体原因（DNS/超时/TLS/限流）透出，GUI 才不会只显示一句「网络失败」
        printf("{\"ok\":false,\"error\":\"%s\",\"detail\":\"%s\",\"http_status\":%ld}\n",
               jsonEscape(hr.error).c_str(), jsonEscape(hr.detail).c_str(), hr.status);
        return 1;
    }
    if (status == 304) {
        printf("{\"ok\":true,\"not_modified\":true,\"has_update\":false}\n");
        return 0;
    }
    if (status != 200 || body.empty()) {
        printf("{\"ok\":false,\"error\":\"api_status_%ld\",\"detail\":\"%s\"}\n", status, jsonEscape(hr.detail).c_str());
        return 1;
    }
    JsonValue root;
    JsonParser parser(body.data(), body.size());
    if (!parser.parse(root)) {
        printf("{\"ok\":false,\"error\":\"json_parse:%s\"}\n", parser.err.c_str());
        return 1;
    }
    const JsonValue* tagV = root.find("tag_name");
    const JsonValue* assetsV = root.find("assets");
    const JsonValue* bodyV = root.find("body");
    if (!tagV || !assetsV) {
        printf("{\"ok\":false,\"error\":\"malformed_api\"}\n");
        return 1;
    }
    std::string tag = tagV->asStr();
    std::string latest = guiVerFromTag(tag);
    int idx = matchAsset(*assetsV, type, platform);
    bool hasUpdate = !latest.empty() && versionCmp(latest, current) > 0;

    printf("{\"ok\":true,");
    printf("\"has_update\":%s,", hasUpdate ? "true" : "false");
    printf("\"current_version\":\"%s\",", jsonEscape(current).c_str());
    printf("\"latest_version\":\"%s\",", jsonEscape(latest.empty() ? current : latest).c_str());
    printf("\"tag\":\"%s\",", jsonEscape(tag).c_str());
    if (idx >= 0) {
        const JsonValue& a = assetsV->arr[idx];
        std::string url = a.find("browser_download_url") ? a.find("browser_download_url")->asStr() : "";
        std::string name = a.find("name") ? a.find("name")->asStr() : "";
        long long size = a.find("size") ? (long long)a.find("size")->asNum() : 0;
        std::string sha;
        const JsonValue* dig = a.find("digest");
        if (dig) { sha = dig->asStr(); if (sha.rfind("sha256:", 0) == 0) sha = sha.substr(7); }
        printf("\"asset_name\":\"%s\",", jsonEscape(name).c_str());
        printf("\"download_url\":\"%s\",", jsonEscape(url).c_str());
        printf("\"sig_url\":\"%s\",", jsonEscape(url + ".minisig").c_str()); // 无则 404，--update 时跳过
        printf("\"sha256\":\"%s\",", sha.c_str());
        printf("\"size\":%lld,", (long long)size);
    } else {
        printf("\"asset_name\":\"\",\"download_url\":\"\",\"sig_url\":\"\",\"sha256\":\"\",\"size\":0,");
    }
    std::string notes = bodyV ? bodyV->asStr() : "";
    if (!notes.empty()) {
        size_t nl = notes.find('\n');
        if (nl != std::string::npos) notes = notes.substr(0, nl);
        if (notes.size() > 120) notes = notes.substr(0, 120);
    }
    printf("\"etag\":\"%s\",", jsonEscape(etagNew).c_str());
    printf("\"notes\":\"%s\"}", jsonEscape(notes).c_str());
    fflush(stdout);
    return 0;
}

// ===================== --update =====================
static int doUpdate(const std::string& url, const std::string& expectedSha,
                    long long expectedSize, const std::string& installDir, const std::string& sigUrl) {
    std::string host;
    if (!urlAllowed(url, &host, true)) {
        fprintf(stderr, "[update] host not allowed: %s\n", host.c_str());
        printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"host_not_allowed\",\"host\":\"%s\"}\n",
               jsonEscape(host).c_str());
        fflush(stdout);
        return 1;
    }
    if (!sigUrl.empty() && !urlAllowed(sigUrl, &host, true)) {
        fprintf(stderr, "[update] sig host not allowed: %s\n", host.c_str());
        printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"host_not_allowed\",\"host\":\"%s\"}\n",
               jsonEscape(host).c_str());
        fflush(stdout);
        return 1;
    }

    std::error_code ec;
    auto tmpBase = std::filesystem::temp_directory_path(ec);
    std::filesystem::path tmpDir = tmpBase / ("fe_update_" + randSuffix());
    std::filesystem::create_directories(tmpDir, ec);

    std::string leaf = url.substr(url.find_last_of('/') + 1);
    std::filesystem::path tmpFile = tmpDir / leaf;
    std::string tmpPathUtf8 = tmpFile.u8string();

    fprintf(stderr, "[update] temp=%s\n", tmpPathUtf8.c_str());
    int lastPct = -1; long long lastBytes = 0;
    auto progress = [&](long long w, long long t) {
        int pct = (t > 0) ? (int)(w * 100 / t) : -1;
        if (pct >= 0) {
            if (pct - lastPct >= 5 || (pct == 100 && lastPct != 100)) {
                printf("{\"progress\":%d,\"stage\":\"downloading\"}\n", pct); fflush(stdout);
                lastPct = pct;
            }
        } else if (w - lastBytes >= 2LL * 1024 * 1024) {
            printf("{\"progress\":-1,\"downloaded\":%lld,\"stage\":\"downloading\"}\n", (long long)w); fflush(stdout);
            lastBytes = w;
        }
    };

    printf("{\"progress\":0,\"stage\":\"downloading\"}\n"); fflush(stdout);
    long long got = downloadToFile(url, tmpPathUtf8, 0, progress);
    if (got < 0) {
        printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"download_failed\",\"detail\":\"%s\"}\n",
               jsonEscape(g_dlError).c_str());
        std::filesystem::remove_all(tmpDir, ec);
        return 1;
    }
    printf("{\"progress\":100,\"stage\":\"verifying\"}\n"); fflush(stdout);

    long long fsize = 0;
    auto szec = std::error_code{};
    fsize = (long long)std::filesystem::file_size(tmpFile, szec);
    // 断点/代理截断会在无 SHA 断言时留下半个安装包，落盘后必须核对大小
    if (expectedSize > 0 && fsize != expectedSize) {
        printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"size_mismatch\","
               "\"expected\":%lld,\"actual\":%lld}\n", (long long)expectedSize, fsize);
        std::filesystem::remove(tmpFile, ec);
        std::filesystem::remove_all(tmpDir, ec);
        return 1;
    }
    if (fsize != got) {
        printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"size_mismatch\",\"actual\":%lld}\n", fsize);
        std::filesystem::remove(tmpFile, ec);
        std::filesystem::remove_all(tmpDir, ec);
        return 1;
    }
    std::string actualSha = sha256File(tmpPathUtf8);
    bool shaOk = expectedSha.empty() ? true : iequals(actualSha, expectedSha);
    if (!shaOk) {
        printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"sha256_mismatch\",\"expected\":\"%s\",\"actual\":\"%s\"}\n",
               expectedSha.c_str(), actualSha.c_str());
        std::filesystem::remove(tmpFile, ec);
        std::filesystem::remove_all(tmpDir, ec);
        return 1;
    }

    // 可选 Minisign：若 sigUrl 可得则验证（当前 release 无 .minisig，404 即跳过）
    if (!sigUrl.empty()) {
        fprintf(stderr, "[update] sig_url provided but Minisign verification not bundled; skipping (no embedded key)\n");
    }

    std::filesystem::path installPath = nativePath(installDir);
    std::filesystem::create_directories(installPath, ec);
    bool isMsi = leaf.size() >= 4 && iequals(leaf.substr(leaf.size() - 4), ".msi");
    if (isMsi) {
#ifdef _WIN32
        printf("{\"progress\":100,\"stage\":\"installing\"}\n"); fflush(stdout);
        std::wstring wpath = to_wide(tmpPathUtf8);
        std::wstring wcmd = L"msiexec /i \"" + wpath + L"\" /qn /norestart";
        int r = _wsystem(wcmd.c_str());
        if (r != 0) {
            printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"msiexec_failed\",\"code\":%d}\n", r);
            return 1;
        }
#else
        fprintf(stderr, "[update] .msi install only supported on Windows; skipping package install\n");
#endif
    } else {
        std::filesystem::path dst = installPath / leaf;
        if (!std::filesystem::copy_file(tmpFile, dst, std::filesystem::copy_options::overwrite_existing, ec)) {
            printf("{\"progress\":100,\"stage\":\"error\",\"error\":\"copy_failed\",\"what\":\"%s\"}\n", ec.message().c_str());
            return 1;
        }
    }

    std::filesystem::remove(tmpFile, ec);
    std::filesystem::remove_all(tmpDir, ec);
    printf("{\"progress\":100,\"stage\":\"done\",\"installed_to\":\"%s\"}\n", jsonEscape(installDir).c_str());
    fflush(stdout);
    return 0;
}

// ===================== main =====================
int main(int argc, char** argv) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "[update] curl_global_init failed\n");
        return 2;
    }
    std::string mode, current, type, platform, etag, url, sha, installDir, sigUrl;
    long long expectedSize = 0;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](std::string& out) { if (i + 1 < argc) out = argv[++i]; };
        if (a == "--check") mode = "check";
        else if (a == "--update") mode = "update";
        else if (a == "--current") next(current);
        else if (a == "--type") next(type);
        else if (a == "--platform") next(platform);
        else if (a == "--etag") next(etag);
        else if (a == "--url") next(url);
        else if (a == "--sha256") next(sha);
        else if (a == "--size") { if (i + 1 < argc) expectedSize = atoll(argv[++i]); }
        else if (a == "--install-dir") next(installDir);
        else if (a == "--sig-url") next(sigUrl);
        else if (a == "--proxy") next(g_proxy);
        else if (a == "--allow-any-host") g_allowAnyHost = true;
    }
    int rc = 2;
    if (mode == "check") {
        if (current.empty()) current = "0.0.0";
        if (type.empty()) type = "qt";
        if (platform.empty()) platform = "windows";
        rc = doCheck(current, type, platform, etag);
    } else if (mode == "update") {
        if (url.empty() || installDir.empty()) {
            printf("{\"ok\":false,\"error\":\"usage: --update --url <u> --install-dir <d> [--sha256 <h>]\"}\n");
            rc = 2;
        } else {
            rc = doUpdate(url, sha, expectedSize, installDir, sigUrl);
        }
    } else {
        printf("{\"ok\":false,\"error\":\"usage: Updater --check|--update ...\"}\n");
        rc = 2;
    }
    curl_global_cleanup();
    return rc;
}
