#define _CRT_SECURE_NO_WARNINGS
#include "FileEncryptor.hpp"
#ifdef FE_WITH_ZSTD
#include "zstd.h"   // 仅当构建集成了 zstd 预编译库时引入（third_party/zstd/include）
#endif
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <string>
#include <chrono>
#include <iostream>
#include <functional>
#include <cctype>
#include <sys/stat.h>
#include <sodium.h>
#include "config.hpp"
#include "progress_frame.hpp"
#include "ptd_format.hpp"
#include "kdf.hpp"
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <filesystem>

#ifdef _WIN32
#include <io.h>      // _isatty / _fileno
#else
#include <unistd.h> // isatty
#endif

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>    // _aligned_malloc / _aligned_free（输入侧页对齐大缓冲）
#include <debugapi.h>
#include <shlobj.h>
#include <aclapi.h>       // SetEntriesInAclW / SetNamedSecurityInfoW（密钥文件 DACL 收紧）
#include <direct.h>
#include <io.h>
#include <process.h>
#pragma comment(lib, "shell32.lib")   // SHFileOperationW（回收站）
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>     // chmod（密钥文件 0600）
#include <pwd.h>
#include <dirent.h>
#include <fcntl.h>
#include <cerrno>
#include <signal.h>
#endif

namespace fs = std::filesystem;

#ifdef __linux__
#include <signal.h>
#include <unistd.h>
#endif
// ---------- 常量 ----------
static constexpr size_t CHUNK_SIZE=1*1024*1024;
static constexpr size_t PASSWORD_MIN_LEN=6;

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;
static constexpr size_t XCHACHA20_IV_LEN=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t AEGIS256_IV_LEN=crypto_aead_aegis256_NPUBBYTES;
static constexpr size_t AEGIS256_TAG_SIZE=crypto_aead_aegis256_ABYTES;
static constexpr size_t TAG_SIZE=16;
static constexpr size_t MAX_TAG_SIZE=AEGIS256_TAG_SIZE;

static const uint32_t PROGRESS_MAGIC=0x504F5247;
static const uint32_t PROGRESS_VERSION=2;
// v2：新增 HMAC 认证，防续传劫持

// 压缩帧最大缓冲：每块原始明文最多压缩到 ZSTD_compressBound(CHUNK_SIZE) 字节
#ifdef FE_WITH_ZSTD
static const size_t COMP_BUF_MAX = ZSTD_compressBound(CHUNK_SIZE);
#else
static const size_t COMP_BUF_MAX = CHUNK_SIZE;
#endif

// 断点进度结构（v2：带 HMAC 认证，防续传劫持）
// HMAC（crypto_auth = HMAC-SHA512/256，32 字节）覆盖前 24 字节（magic+version+chunks+bytes）
#pragma pack(push, 1)
struct ProgressInfo {
    uint32_t magic;
    uint32_t version;
    uint64_t processed_chunks;
    uint64_t processed_bytes;
    unsigned char hmac[crypto_auth_BYTES];
};
#pragma pack(pop)
static constexpr size_t PROGRESS_SIZE=sizeof(ProgressInfo);

// ---------- 辅助：模式查询 ----------
static size_t tag_size_for_mode(CryptoMode m) {
    return (m==CryptoMode::AEGIS256) ? AEGIS256_TAG_SIZE : TAG_SIZE;
}

// ---------- 认证失败信息泄露防护 ----------
// 非详细模式下认证失败只输出通用错误，不暴露密码错误/头篡改等可枚举或侧信道探测细节。
static bool g_verbose=false;
void set_verbose(bool v) { g_verbose=v; }

// mlock 失败告警（SecureBuffer 构造时调用）：内存页未能锁定，敏感密钥可能被换出到
// swap / 落进 core dump。首次失败时提示一次（stderr + 结构化日志），不重复刷屏。
void fe_report_mlock_warning_once() {
    static std::atomic<bool> warned{false};
    if(!warned.exchange(true)) {
        fprintf(stderr,"Warning: sodium_mlock failed; sensitive key material may be swappable.\n");
        log_event(LOG_WARN,"mlock_failed",
            {{"detail","memory pages could not be locked; keys may be written to swap"}});
    }
}

static void report_auth_error(bool silent, const std::string& detail) {
    if(silent) return;
    const Config& cfg=global_config();
    bool detailed = g_verbose || cfg.log_level>=LOG_DEBUG;
    if(detailed) fprintf(stderr, "%s\n", detail.c_str());
    else fprintf(stderr, "Error: Decryption failed. (Invalid key or corrupted file)\n");
}

// ---------- 路径规范化（防别名绕过） ----------
// lexically_normal 解析 . 与 ..，make_preferred 统一分隔符，堵住路径别名绕过。
static std::string normalize_path_lexical(const std::string& p) {
    std::string s = p;
    bool had_long_prefix = false, had_unc_prefix = false;
#ifdef _WIN32
    // Windows 长路径 / 设备前缀：\\?\ 与 \\?\UNC\ 会改变 '..' 的解析语义，
    // 攻击者可能借此绕过路径穿越 / 白名单检查。统一先剥离前缀再做逻辑规范化。
    for(char& ch : s) if(ch=='/') ch='\\';
    if(s.size()>=4 && s[0]=='\\' && s[1]=='\\' && s[2]=='?' && s[3]=='\\') {
        had_long_prefix = true;
        if(s.size()>=8 && s.compare(4,4,"UNC\\")==0) {
            had_unc_prefix = true;
            s = "\\" + s.substr(8);   // \\?\UNC\server\share\... -> \\server\share\...
        } else {
            s = s.substr(4);          // \\?\C:\... -> C:\...
        }
    }
#endif
    // 注意：fs::path 窄字符串按 ACP(GBK) 解释，含中文/Emoji 的 UTF-8 路径往返会崩溃；
    // 须先 utf8_to_wstring 再构造 path，规范化后 wstring_to_utf8 取回，编码无损。
#ifdef _WIN32
    fs::path np = fs::path(utf8_to_wstring(s)).lexically_normal();
    if(np.empty()) np = fs::path(utf8_to_wstring(s));
    std::string out = wstring_to_utf8(np.make_preferred().wstring());
#else
    fs::path np = fs::path(s).lexically_normal();
    if(np.empty()) np = fs::path(s);
    std::string out = np.make_preferred().string();
#endif
#ifdef _WIN32
    // 还原长路径前缀（规范化后已无 '..'，可安全保留长路径支持）。
    if(had_unc_prefix && out.size()>=2) out = "\\\\?\\UNC\\" + out.substr(2);
    else if(had_long_prefix) out = "\\\\?\\" + out;
#endif
    return out;
}

// ---------- 续传进度绑定（防重放） ----------
// 源路径+大小+mtime 纳入 .prs 的 HMAC，旧 .prs 无法重放到不同文件。
static int64_t get_file_size_utf8(const std::string& path);
// 前向声明：is_complete_output / decrypt_file 需要提前获知尾部（加密名）长度做文件大小校验。
static bool peek_name_footer_len(const std::string& ptd_path, uint64_t& footer_len);

// 内容令牌：对源文件头部64KB+尾部64KB+总大小求 Blake2b 作指纹，防 mtime 复刻重放；
// 小文件(<128KB)直接全文哈希，大文件不读全文，开销恒定。
static std::string file_content_token(const std::string& path) {
    int64_t sz = get_file_size_utf8(path);
    if(sz < 0) return std::string();
    const size_t kHead = 1u << 16, kTail = 1u << 16;
    std::ifstream f;
    if(!open_stream(f,path,std::ios::binary)) return std::string();
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, 16);
    std::vector<unsigned char> buf(kHead);
    size_t to_read = (size_t)std::min<int64_t>(kHead, sz);
    if(to_read > 0) {
        f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)to_read);
        crypto_generichash_update(&st, buf.data(), (size_t)f.gcount());
    }
    if(sz > (int64_t)(kHead + kTail)) {
        f.seekg(-(std::streamoff)kTail, std::ios::end);
        if(f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)kTail))
            crypto_generichash_update(&st, buf.data(), (size_t)f.gcount());
    }
    f.close();
    unsigned char out[16];
    crypto_generichash_final(&st, out, 16);
    char hex[33];
    sodium_bin2hex(hex, sizeof(hex), out, 16);
    char sizeb[24];
    snprintf(sizeb, sizeof(sizeb), "%llx", (unsigned long long)sz);
    return std::string(hex) + std::string(sizeb);
}

static std::string compute_progress_binding(const std::string& in_path) {
    // 同 normalize_path_lexical：宽字符往返，避免 fs::path 的 ACP 编码损失对
    // 含中文/Emoji 的 UTF-8 路径抛异常（历史缺陷：中文路径加密必崩溃）。
#ifdef _WIN32
    fs::path np = fs::path(utf8_to_wstring(in_path)).lexically_normal();
    if(np.empty()) np = fs::path(utf8_to_wstring(in_path));
    std::string norm = wstring_to_utf8(np.make_preferred().wstring());
#else
    fs::path np = fs::path(in_path).lexically_normal();
    if(np.empty()) np = fs::path(in_path);
    std::string norm = np.make_preferred().string();
#endif
    int64_t sz = get_file_size_utf8(in_path);
    int64_t mt = 0;
#ifdef _WIN32
    struct _stat64 st;
    if(_wstat64(utf8_to_wstring(in_path).c_str(),&st)==0) mt=(int64_t)st.st_mtime;
#else
    struct stat st;
    if(stat(in_path.c_str(),&st)==0) mt=(int64_t)st.st_mtime;
#endif
    std::string token = file_content_token(in_path);
    // 用 std::string 拼接，避免 snprintf 返回超长时按返回值构造 std::string 的越界读。
    return "|" + norm + "|" + std::to_string(sz) + "|" + std::to_string(mt) + "|" + token;
}

// ---------- 明文 Blake2b 哈希（完整性校验） ----------
static bool file_blake2b(const std::string& path, unsigned char out[HASH_SIZE]) {
    std::ifstream f;
    if(!open_stream(f,path,std::ios::binary)) return false;
    crypto_generichash_state st;
    crypto_generichash_init(&st,nullptr,0,HASH_SIZE);
    std::vector<unsigned char> buf(1<<20);
    while(true) {
        f.read(reinterpret_cast<char*>(buf.data()),(std::streamsize)buf.size());
        std::streamsize n=f.gcount();
        if(n>0) crypto_generichash_update(&st,buf.data(),(size_t)n);
        if(f.eof()) break;
        if(!f.good()) { f.close(); return false; }
    }
    f.close();
    crypto_generichash_final(&st,out,HASH_SIZE);
    return true;
}

// ---------- 4 MiB 聚合写出缓冲 ----------
// 块密文/明文攒满 4 MiB 再一次性写盘，合并小 syscall；verify_only 下不绑定输出流。
struct AggWriter {
    std::ostream* os=nullptr;
    std::vector<unsigned char> buf;
    static constexpr size_t CAP=4*1024*1024;
    void bind(std::ostream& s){ os=&s; buf.reserve(CAP); }
    bool put(const unsigned char* p, size_t n){
        if(!os) return true;                  // verify_only：空操作
        if(buf.size()+n > CAP) { if(!flush()) return false; }
        buf.insert(buf.end(), p, p+n);
        return true;
    }
    bool flush(){
        if(!os) return true;
        if(!buf.empty()){
            os->write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)buf.size());
            buf.clear();
            if(!os->good()) return false;
        }
        os->flush();
        return os->good();
    }
};

// ---------- 输入侧 4 MiB 页对齐大缓冲 ----------
// 缓冲从 4 KiB 扩到 4 MiB 页对齐，每块读取压到约 1 次内核读；须先于流声明（逆序析构）。
struct InputBuffer {
    unsigned char* buf=nullptr;
    static constexpr size_t CAP=4*1024*1024;
    bool attach(std::istream& s){
#ifdef _WIN32
        buf=(unsigned char*)_aligned_malloc(CAP,4096);
#else
        void* p=nullptr;
        if(posix_memalign(&p,4096,CAP)!=0) buf=nullptr; else buf=(unsigned char*)p;
#endif
        if(!buf) return false;
        s.rdbuf()->pubsetbuf(reinterpret_cast<char*>(buf),(std::streamsize)CAP);
        return true;
    }
    ~InputBuffer(){
#ifdef _WIN32
        if(buf) _aligned_free(buf);
#else
        if(buf) free(buf);
#endif
    }
};

// ---------- SHA-256 校验单（功能10） ----------
// 加密后生成 <file>.sha256（<hex>  <基名>），供外部工具链校验传输完整性。
static std::atomic<bool> g_write_sha256{false};
void set_write_sha256(bool b) { g_write_sha256.store(b); }
bool write_sha256_enabled() { return g_write_sha256.load(); }

static bool file_sha256(const std::string& path, unsigned char out[crypto_hash_sha256_BYTES]) {
    std::ifstream f;
    if(!open_stream(f,path,std::ios::binary)) return false;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    std::vector<unsigned char> buf(1<<20);
    while(true) {
        f.read(reinterpret_cast<char*>(buf.data()),(std::streamsize)buf.size());
        std::streamsize n=f.gcount();
        if(n>0) crypto_hash_sha256_update(&st,buf.data(),(size_t)n);
        if(f.eof()) break;
        if(!f.good()) { f.close(); return false; }
    }
    f.close();
    crypto_hash_sha256_final(&st,out);
    return true;
}

void write_sha256_sidecar(const std::string& file) {
    unsigned char h[crypto_hash_sha256_BYTES];
    if(!file_sha256(file,h)) return;
    char hex[(crypto_hash_sha256_BYTES*2)+1];
    sodium_bin2hex(hex,sizeof(hex),h,crypto_hash_sha256_BYTES);
    std::string base=file;
    size_t bs=base.find_last_of("/\\");
    std::string name=(bs!=std::string::npos)?base.substr(bs+1):base;
    std::string sidecar=file+".sha256";
    std::ofstream of;
    if(!open_stream(of,sidecar,std::ios::out|std::ios::trunc)) return;
    of<<hex<<"  "<<name<<"\n";
    of.close();
    log_event(LOG_INFO,"sha256_written",{{"path",sidecar}});
}

// ---------- AEGIS-256 可用性探测（缺 AES-NI 不可用） ----------
// magic static 局部初始化保证线程安全（历史 static int cached 非线程安全）。
bool aegis256_supported() {
    static const bool s_supported = []() -> bool {
        unsigned char k[32],npub[32],m[16],c[64],m2[16];
        unsigned long long clen=0,mlen=0;
        randombytes_buf(k,32);
        randombytes_buf(npub,32);
        memset(m,0xAB,sizeof(m));
        int e=crypto_aead_aegis256_encrypt(c,&clen,m,sizeof(m),nullptr,0,nullptr,npub,k);
        int d=(e==0)?crypto_aead_aegis256_decrypt(m2,&mlen,nullptr,c,clen,nullptr,0,npub,k):-1;
        return (e==0&&d==0&&mlen==sizeof(m)&&memcmp(m,m2,sizeof(m))==0);
    }();
    return s_supported;
}

bool stdin_is_interactive() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

// 解析加密模式：AEGIS-256 需 AES-NI。交互终端询问后默认降级 XChaCha20；
// 非交互禁止自动降级（refuse=true），由调用方中止/告警。
CryptoMode resolve_encrypt_mode(CryptoMode requested, bool interactive,
    bool& refuse, std::string& message) {
    refuse=false;
    message.clear();
    if(requested!=CryptoMode::AEGIS256 || aegis256_supported()) return requested;

    if(interactive) {
        std::cout<<"Warning: AEGIS-256 is not available on this CPU (AES-NI required).\n"
                 <<"Switch to XChaCha20-Poly1305 (recommended)? (Y/n): ";
        char ch='y';
        std::cin>>ch;
        if(ch=='n'||ch=='N') {
            std::cerr<<"Continuing with AEGIS-256 (will likely fail or be very slow on this CPU).\n";
            return CryptoMode::AEGIS256;
        }
        std::cerr<<"Selected XChaCha20-Poly1305 based on hardware capability.\n";
        return CryptoMode::XCHACHA20;
    }

    // 非交互：明确拒绝，绝不自动降级（否则自动化任务会在不知情下行为突变）。
    refuse=true;
    message="AEGIS-256 requires AES-NI hardware support, which is not available on this CPU.\n"
            "Using AEGIS-256 here is extremely slow and not side-channel resistant.\n"
            "Switch to XChaCha20-Poly1305 (-m xchacha20) for secure, fast encryption.";
    return requested;
}

// ---------- AAD 构建（元数据） ----------
// 传入头部原始字节（对于 v3 不含末尾 32 字节 plaintext_hash）与块元数据。
static std::vector<unsigned char> build_aad_with_metadata(
    const unsigned char* hdr_ptr, size_t hdr_len,
    uint32_t chunk_size,
    uint32_t total_chunks,
    uint64_t orig_size) {
    std::vector<unsigned char> aad;
    aad.insert(aad.end(),hdr_ptr,hdr_ptr+hdr_len);

    for(int i=0; i<4; ++i) aad.push_back((chunk_size>>(i*8))&0xFF);
    for(int i=0; i<4; ++i) aad.push_back((total_chunks>>(i*8))&0xFF);
    for(int i=0; i<8; ++i) aad.push_back((orig_size>>(i*8))&0xFF);
    return aad;
}

// ---------- 文件系统辅助（UTF-8 安全） ----------
static bool file_exists(const std::string& path) {
    std::ifstream f;
    return open_stream(f,path,std::ios::in|std::ios::binary);
}

// 返回 >=0 的文件大小，不存在返回 -1
static int64_t get_file_size_utf8(const std::string& path) {
#ifdef _WIN32
    struct _stat64 st;
    if(_wstat64(utf8_to_wstring(path).c_str(),&st)!=0) return -1;
    return st.st_size;
#else
    struct stat st;
    if(stat(path.c_str(),&st)!=0) return -1;
    return (int64_t)st.st_size;
#endif
}

// 将文件截断到指定字节数（续传时丢弃未记账的残片）
static bool truncate_file(const std::string& path,uint64_t size) {
#ifdef _WIN32
    std::wstring wpath=utf8_to_wstring(path);
    HANDLE h=CreateFileW(wpath.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li; li.QuadPart=(LONGLONG)size;
    bool ok=true;
    if(!SetFilePointerEx(h,li,NULL,FILE_BEGIN)) ok=false;
    else if(!SetEndOfFile(h)) ok=false;
    CloseHandle(h);
    return ok;
#else
    return ::truncate(path.c_str(),(off_t)size)==0;
#endif
}

// 判断路径是否为符号链接 / 重解析点（已存在才报告，不存在返回 false）。
// v2.1.2：去掉 static —— `-m rage` 分支（run_asym）需要同样的守卫。
bool path_is_symlink(const std::string& path) {
#ifdef _WIN32
    std::wstring w=utf8_to_wstring(path);
    DWORD attr=GetFileAttributesW(w.c_str());
    if(attr==INVALID_FILE_ATTRIBUTES) return false;
    return (attr&FILE_ATTRIBUTE_REPARSE_POINT)!=0;
#else
    struct stat st;
    if(lstat(path.c_str(),&st)!=0) return false;
    return S_ISLNK(st.st_mode);
#endif
}

// 组件法而非子串匹配：覆盖前缀 “..” 与中间 “/..”，同时不会把 "a..b" 误判为穿越
bool path_has_traversal(const std::string& p) {
    std::string n=p;
    for(char& c:n) if(c=='\\') c='/';
    size_t start=0;
    while(true) {
        size_t pos=n.find('/',start);
        std::string comp=(pos==std::string::npos) ? n.substr(start) : n.substr(start,pos-start);
        if(comp=="..") return true;
        if(pos==std::string::npos) break;
        start=pos+1;
    }
    return false;
}

// 依据 YAML 配置校验输入输出路径（长度上限/白名单根目录）；true 允许，false 拒绝。
// v2.1.2 去掉 static，供非对称（rage）分支复用。
bool validate_io_paths(const std::string& in_path,const std::string& out_path,bool silent) {
    const Config& cfg=global_config();
    // 1.5.2：原始路径含 ".." 组件一律拒绝（须在规范化前检查，否则 lexically_normal
    // 会折叠 ".." 而漏掉 "C:/allowed/../../outside/x" 类绕过）。
    if(path_has_traversal(in_path)||path_has_traversal(out_path)) {
        if(!silent) fprintf(stderr,"Path contains directory traversal (..): in=%s out=%s\n",
            in_path.c_str(),out_path.c_str());
        return false;
    }
    // 规范化（解析 . 与 ..、统一分隔符）后的路径用于白名单前缀比较与长度上限，
    // 堵住基于路径别名的绕过（如 "C:/allowed/./x"、"C:/allowed//x" 等）。
    const std::string in_norm = normalize_path_lexical(in_path);
    const std::string out_norm = normalize_path_lexical(out_path);
    if(cfg.max_path_length>0) {
        if(in_norm.size()>cfg.max_path_length) {
            if(!silent) fprintf(stderr,"Input path too long (%zu > %zu bytes).\n",in_norm.size(),cfg.max_path_length);
            return false;
        }
        if(out_norm.size()>cfg.max_path_length) {
            if(!silent) fprintf(stderr,"Output path too long (%zu > %zu bytes).\n",out_norm.size(),cfg.max_path_length);
            return false;
        }
    }
    if(cfg.path_whitelist_enabled && !cfg.path_whitelist.empty()) {
        auto under=[&](const std::string& p,const std::string& root) {
            if(p.length()<root.length()) return false;
            if(p.compare(0,root.length(),root)!=0) return false;
            return (p.length()==root.length()) ||
                   (p[root.length()]=='/'||p[root.length()]=='\\');
        };
        bool in_ok=false,out_ok=false;
        for(const auto& r:cfg.path_whitelist) {
            const std::string rnorm = normalize_path_lexical(r);
            if(!in_ok&&under(in_norm,rnorm))  in_ok=true;
            if(!out_ok&&under(out_norm,rnorm)) out_ok=true;
        }
        if(!in_ok)  { if(!silent) fprintf(stderr,"Input path not in whitelist: %s\n",in_path.c_str());  return false; }
        if(!out_ok) { if(!silent) fprintf(stderr,"Output path not in whitelist: %s\n",out_path.c_str()); return false; }
    }
    return true;
}

// 收紧新建输出文件的权限（避免半截明文被其他用户读取）；
static void restrict_permissions(const std::string& path) {
#ifndef _WIN32
    chmod(path.c_str(),0600);
#endif
}

// ---------- 跨进程输出锁 ----------
static bool process_alive_pid(int pid) {
#ifdef _WIN32
    if(pid<=0) return false;
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,(DWORD)pid);
    if(!h) return false;
    DWORD code=0;
    bool alive=GetExitCodeProcess(h,&code)&&code==STILL_ACTIVE;
    CloseHandle(h);
    return alive;
#else
    return pid>0&&::kill(pid,0)==0;
#endif
}

enum class LockResult { OK, LOCKED, CANNOT_CREATE };

// 锁结果：OK 成功；LOCKED 被存活进程持有；CANNOT_CREATE 无法创建（权限/路径问题）。
static LockResult acquire_output_lock(const std::string& out_path,std::string& lock_path) {
    lock_path=out_path+".lock";
#ifdef _WIN32
    std::wstring w=utf8_to_wstring(lock_path);
    HANDLE h=CreateFileW(w.c_str(),GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h!=INVALID_HANDLE_VALUE) {
        DWORD pid=GetCurrentProcessId(),wr;
        WriteFile(h,&pid,sizeof(pid),&wr,NULL);
        CloseHandle(h);
        return LockResult::OK;
    }
    // CREATE_NEW 失败：要么“真被占用”，要么“无法创建（权限/路径）”，需要区分
    h=CreateFileW(w.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(h!=INVALID_HANDLE_VALUE) {
        DWORD pid=0,rd=0;
        ReadFile(h,&pid,sizeof(pid),&rd,NULL);
        CloseHandle(h);
        if(rd==sizeof(pid)&&!process_alive_pid((int)pid)) {
            // 失效锁（持有进程已退出）：回收后重试
            DeleteFileW(w.c_str());
            h=CreateFileW(w.c_str(),GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
            if(h!=INVALID_HANDLE_VALUE) {
                DWORD p2=GetCurrentProcessId(),wr;
                WriteFile(h,&p2,sizeof(p2),&wr,NULL);
                CloseHandle(h);
                return LockResult::OK;
            }
            // 回收后仍无法创建：权限 / 路径问题
            return LockResult::CANNOT_CREATE;
        }
        // 锁仍被存活进程持有
        return LockResult::LOCKED;
    }
    // 连读取现有锁文件都失败：权限 / 路径问题
    return LockResult::CANNOT_CREATE;
#else
    int fd=open(lock_path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd>=0) {
        int pid=getpid();
        if(write(fd,&pid,sizeof(pid))<0) { /* best-effort lock write */ }
        close(fd);
        return LockResult::OK;
    }
    fd=open(lock_path.c_str(),O_RDONLY,0);
    if(fd>=0) {
        int pid=0; bool stolen=false;
        if(read(fd,&pid,sizeof(pid))==sizeof(pid)&&!process_alive_pid(pid)) {
            close(fd);
            unlink(lock_path.c_str());
            fd=open(lock_path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
            if(fd>=0) {
                int p2=getpid();
                if(write(fd,&p2,sizeof(p2))<0) { /* best-effort lock write */ }
                close(fd);
                stolen=true;
            }
        }
        else {
            close(fd);
        }
        if(stolen) return LockResult::OK;
        // 锁被存活进程持有
        return LockResult::LOCKED;
    }
    // 连读取都失败：权限 / 路径问题
    return LockResult::CANNOT_CREATE;
#endif
}

struct OutputLockGuard {
    std::string path;
    bool owned;
    ~OutputLockGuard() {
        if(owned&&!path.empty()) remove_file_utf8(path);
    }
};

// UTF-8 安全的原子替换
// v2.1.2：去掉 static —— run_asym 用「先写 .prt 再原子替换」实现 rage 输出落盘。
bool replace_file_utf8(const std::string& from,const std::string& to) {
#ifdef _WIN32
    std::wstring wf=utf8_to_wstring(from);
    std::wstring wt=utf8_to_wstring(to);
    return MoveFileExW(wf.c_str(),wt.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
#else
    std::remove(to.c_str());
    return std::rename(from.c_str(),to.c_str())==0;
#endif
}

// Windows：清掉只读属性位（密钥文件覆盖写入前的准备；POSIX 无此概念）
void clear_readonly_attribute(const std::string& path) {
#ifdef _WIN32
    const std::wstring w=utf8_to_wstring(path);
    DWORD a=GetFileAttributesW(w.c_str());
    if(a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_READONLY))
        SetFileAttributesW(w.c_str(),a&~FILE_ATTRIBUTE_READONLY);
#else
    (void)path;
#endif
}

// 收紧密钥文件权限（0600）。Windows 写真正 DACL（当前用户+SYSTEM，PROTECTED_DACL
// 阻断继承）；旧 _chmod 只读位并非访问控制。ACL 失败静默回退。
void tighten_file_permissions(const std::string& path) {
#ifdef _WIN32
    clear_readonly_attribute(path);
    const std::wstring w=utf8_to_wstring(path);

    // 当前进程的令牌用户 SID
    HANDLE tok=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&tok)) return;
    DWORD need=0;
    GetTokenInformation(tok,TokenUser,NULL,0,&need);
    std::vector<unsigned char> buf(need?need:256);
    TOKEN_USER* tu=reinterpret_cast<TOKEN_USER*>(buf.data());
    BOOL got=GetTokenInformation(tok,TokenUser,buf.data(),(DWORD)buf.size(),&need);
    CloseHandle(tok);
    if(!got||!tu->User.Sid) return;

    PSID system_sid=NULL;
    SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;
    if(!AllocateAndInitializeSid(&nt,1,SECURITY_LOCAL_SYSTEM_RID,
                                 0,0,0,0,0,0,0,&system_sid)) system_sid=NULL;

    EXPLICIT_ACCESSW ea[2];
    memset(ea,0,sizeof(ea));
    ea[0].grfAccessPermissions=FILE_ALL_ACCESS;
    ea[0].grfAccessMode=SET_ACCESS;
    ea[0].grfInheritance=NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm=TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType=TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName=reinterpret_cast<LPWSTR>(tu->User.Sid);
    ea[1]=ea[0];
    ea[1].grfAccessPermissions=FILE_ALL_ACCESS;
    ea[1].Trustee.TrusteeType=TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName=reinterpret_cast<LPWSTR>(system_sid);

    PACL new_dacl=NULL;
    DWORD rc=SetEntriesInAclW(system_sid?2:1,ea,NULL,&new_dacl);
    if(rc==ERROR_SUCCESS&&new_dacl) {
        SetNamedSecurityInfoW(const_cast<LPWSTR>(w.c_str()),SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
            NULL,NULL,new_dacl,NULL);
        LocalFree(new_dacl);
    }
    if(system_sid) FreeSid(system_sid);
#else
    chmod(path.c_str(), 0600);        // rw-------，仅拥有者可读写
#endif
}

// ---------- 反调试 ----------
// 检测到调试器会 exit(1)，只能在 main() 启动期、工作线程创建前调用，切勿移入并发 worker。
void anti_debug_check() {
#ifdef _WIN32
    if(IsDebuggerPresent()) {
        fprintf(stderr,"Debugger detected, exiting.\n");
        exit(1);
    }
#else
    // 在缺少 ptrace 权限的环境（容器/沙箱）下 ptrace 会失败，但这并不等于“被调试”。仅当“已被其它 tracer 占用”(EBUSY) 时才视为被调试，避免在普通受限环境中误退出（此前会因权限不足直接 exit(1)）。
    if(ptrace(PTRACE_TRACEME,0,0,0)==-1) {
        if(errno==EBUSY) {
            fprintf(stderr,"Debugger detected, exiting.\n");
            exit(1);
        }
    }
#endif
}

static void disable_core_dump() {
#ifdef _WIN32
    SetErrorMode(SEM_NOGPFAULTERRORBOX);
#else
    struct rlimit rl;
    if(getrlimit(RLIMIT_CORE,&rl)==0) {
        rl.rlim_cur=0;
        setrlimit(RLIMIT_CORE,&rl);
    }
#endif
}

// ---------- 辅助 ----------
template<typename T>
static void secure_clear(T& v) {
    if(v.empty()) return;
    sodium_memzero(v.data(),v.size());
    v.clear();
    v.shrink_to_fit();
}

// ---------- 目录创建 ----------
bool create_directory_recursive(const std::string& path) {
    // 1.5.2 安全加固：拒绝包含 ".." 的输出目录，避免越权创建目录
    //（如 -o "a/out/../../ESCAPE_X" 会在父级目录外建出 ESCAPE_X）。
    if(path_has_traversal(path)) return false;
    if(path.empty()) return true;
#ifdef _WIN32
    struct _stat64 st;
    if(_wstat64(utf8_to_wstring(path).c_str(),&st)==0) {
        return (st.st_mode&S_IFDIR)!=0;
    }
    size_t pos=path.find_last_of("/\\");
    if(pos!=std::string::npos) {
        std::string parent=path.substr(0,pos);
        // 盘符根("H:")的 stat/_wmkdir 不可靠，改用绝对根 "H:/" 探测：
        // 盘可访问则继续创建剩余分量，否则失败。
        if(parent.size()==2 && parent[1]==':') {
            struct _stat64 rst;
            if(_wstat64(utf8_to_wstring(parent+"/").c_str(),&rst)!=0 ||
               (rst.st_mode&S_IFDIR)==0) {
                return false;   // 盘不存在或不可访问
            }
            // 盘根存在 → 落到下方 _wmkdir 创建剩余分量
        } else {
            if(!create_directory_recursive(parent)) return false;
        }
    }
    return _wmkdir(utf8_to_wstring(path).c_str())==0;
#else
    struct stat st;
    if(stat(path.c_str(),&st)==0) {
        return (st.st_mode&S_IFDIR)!=0;
    }
    size_t pos=path.find_last_of("/\\");
    if(pos!=std::string::npos) {
        if(!create_directory_recursive(path.substr(0,pos))) return false;
    }
    return mkdir(path.c_str(),0755)==0;
#endif
}

// ---------- 文件有效性检查 ----------
static bool is_file_valid(const std::string& path) {
    std::ifstream f;
    if(!open_stream(f,path,std::ios::binary)) return false;
    unsigned char hbuf[HEADER_SIZE_V6];
    f.read(reinterpret_cast<char*>(hbuf),HEADER_SIZE_V6);
    if(f.gcount()<5) return false;
    unsigned char ver=hbuf[4];
    uint64_t need=header_size_for_version(ver);
    if((uint64_t)f.gcount()<need) return false;
    return (memcmp(hbuf,MAGIC,4)==0&&(ver==1||ver==2||ver==3||ver==5||ver==VERSION));
}

// 判断已存在的输出是否“完整且有效”，可安全跳过
static bool is_complete_output(const std::string& out_path, bool encrypt, const std::string& in_path) {
    int64_t cur=get_file_size_utf8(out_path);
    if(cur<0) return false;
    if(encrypt) {
        int64_t in_sz=get_file_size_utf8(in_path);
        if(in_sz<0) return false;
        // 读取输出头部的 version / mode 以确定头部大小与 tag 长度
        std::ifstream hf;
        unsigned char ver=0; CryptoMode m=CryptoMode::XCHACHA20;
        if(open_stream(hf,out_path,std::ios::binary)) {
            unsigned char h5[6];
            if(hf.read(reinterpret_cast<char*>(h5),6)&&memcmp(h5,MAGIC,4)==0) {
                ver=h5[4]; m=static_cast<CryptoMode>(h5[5]);
            }
            hf.close();
        }
        uint64_t hdr=header_size_for_version(ver);
        size_t tag=tag_size_for_mode(m);
        uint64_t cs=CHUNK_SIZE;
        uint64_t expected;
        if(in_sz==0) {
            expected=hdr+4+4+8;
        }
        else {
            uint64_t tc=((uint64_t)in_sz+cs-1)/cs;
            uint64_t last=(uint64_t)in_sz-(tc-1)*cs;
            expected=hdr+4+4+8+(tc-1)*(cs+tag)+(last+tag);
        }
        uint64_t fl=0;
        peek_name_footer_len(out_path, fl);   // 新格式总带加密名尾部
        expected += fl;
        return (uint64_t)cur==expected;
    }
    else {
        // 解密产物：从源 .ptd 头读取 orig_size 与当前输出尺寸比较
        std::ifstream f;
        if(!open_stream(f,in_path,std::ios::binary)) return false;
        unsigned char verbuf[5];
        if(!f.read(reinterpret_cast<char*>(verbuf),5)) return false;
        unsigned char ver=verbuf[4];
        uint64_t hdr_size=header_size_for_version(ver);
        uint64_t orig=0;
        f.seekg((std::streamoff)(hdr_size+4+4),std::ios::beg);
        if(!f.read(reinterpret_cast<char*>(&orig),8)) return false;
        return (uint64_t)cur==orig;
    }
}

// ---------- 进度 ----------
// 仅读取并校验结构（magic / version），HMAC 认证需密钥，由调用方在派生密钥后验证。
static bool load_progress_raw(const std::string& out_path,ProgressInfo& info) {
    std::string prog_path=out_path+".prs";
    std::ifstream f;
    if(!open_stream(f,prog_path,std::ios::binary)) return false;
    f.read(reinterpret_cast<char*>(&info),sizeof(info));
    if(f.gcount()!=sizeof(info)) return false;
    if(info.magic!=PROGRESS_MAGIC||info.version!=PROGRESS_VERSION) {
        return false;
    }
    return true;
}

// 校验 .prs 的 HMAC（防续传劫持 + 防重放）：覆盖前 24 字节
// （magic+version+chunks+bytes）外加源文件绑定标识（规范化路径 + 大小 + mtime）。
static bool verify_progress_hmac(const ProgressInfo& info,const unsigned char* auth_key,
    const std::string& binding) {
    std::vector<unsigned char> msg;
    msg.reserve(24+binding.size());
    msg.insert(msg.end(), reinterpret_cast<const unsigned char*>(&info),
        reinterpret_cast<const unsigned char*>(&info)+24);
    msg.insert(msg.end(), binding.begin(), binding.end());
    return crypto_auth_verify(info.hmac, msg.data(), msg.size(), auth_key)==0;
}

// 计算并写入带 HMAC 的进度（先落盘再返回；success 时调用方再记账 HMAC 之前已 flush 密文）。
// HMAC 输入含源文件绑定标识，使该进度无法被重放到其它文件（防重放攻击）。
static bool save_progress(const std::string& out_path,
    uint64_t processed_chunks,uint64_t processed_bytes,
    const unsigned char* auth_key,const std::string& binding) {
    ProgressInfo info;
    info.magic=PROGRESS_MAGIC;
    info.version=PROGRESS_VERSION;
    info.processed_chunks=processed_chunks;
    info.processed_bytes=processed_bytes;
    std::vector<unsigned char> msg;
    msg.reserve(24+binding.size());
    msg.insert(msg.end(), reinterpret_cast<const unsigned char*>(&info),
        reinterpret_cast<const unsigned char*>(&info)+24);
    msg.insert(msg.end(), binding.begin(), binding.end());
    crypto_auth(info.hmac, msg.data(), msg.size(), auth_key);

    std::string prog_path=out_path+".prs";
    std::string temp_prog=prog_path+".tmp";
    // temp 用 trunc 打开即可覆盖残留（上次 rename 失败遗留的 tmp 会作为本次源被重写），
    // 无需逐次 unlink 预清理——每省一次元数据操作，对每 0.5s 一次的节流保存更友好。

    std::ofstream f;
    if(!open_stream(f,temp_prog,std::ios::binary|std::ios::trunc)) return false;
    f.write(reinterpret_cast<const char*>(&info),sizeof(info));
    if(!f.good()) {
        f.close();
        remove_file_utf8(temp_prog);
        return false;
    }
    f.close();
    // 关键修复：Windows std::rename 目标已存在即失败(EEXIST)，改用 replace_file_utf8()
    // (MoveFileExW 替换写) 保证每块后都能覆盖更新进度文件。
    if(!replace_file_utf8(temp_prog,prog_path)) {
        remove_file_utf8(temp_prog);
        return false;
    }
    return true;
}

static void remove_progress(const std::string& out_path) {
    std::string prog_path=out_path+".prs";
    remove_file_utf8(prog_path);
}

// ---------- 进程级限速器（令牌桶，v1.7.2） ----------
// 主循环按已处理字节数记账，超 max_bytes_per_sec 则休眠，覆盖全部并发线程。
static uint64_t g_rl_max_bps = 0;          // 0 = 不限速
static std::mutex g_rl_mutex;
static int64_t  g_rl_allowance = 0;        // 当前窗口允许的剩余字节
static std::chrono::steady_clock::time_point g_rl_last;

void init_rate_limiter(uint64_t max_bytes_per_sec) {
    std::lock_guard<std::mutex> lock(g_rl_mutex);
    g_rl_max_bps = max_bytes_per_sec;
    g_rl_allowance = (int64_t)max_bytes_per_sec; // 起始满桶
    g_rl_last = std::chrono::steady_clock::now();
}

static void throttle_consume(uint64_t n) {
    if (g_rl_max_bps == 0) return;          // 不限速
    std::lock_guard<std::mutex> lock(g_rl_mutex);
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - g_rl_last).count();
    if (elapsed > 0) {
        int64_t refill = (int64_t)(elapsed * (double)g_rl_max_bps);
        g_rl_allowance += refill;
        if (g_rl_allowance > (int64_t)g_rl_max_bps) g_rl_allowance = (int64_t)g_rl_max_bps;
        g_rl_last = now;
    }
    g_rl_allowance -= (int64_t)n;
    if (g_rl_allowance < 0) {
        // 透支：休眠补足（最小 1ms，避免忙等抖动）
        double deficit = (double)(-g_rl_allowance) / (double)g_rl_max_bps;
        if (deficit > 0) {
            std::this_thread::sleep_for(std::chrono::duration<double>(deficit));
            g_rl_last = std::chrono::steady_clock::now();
            g_rl_allowance = 0;
        }
    }
}

static void print_progress(size_t processed,size_t total,
    std::chrono::steady_clock::time_point start,
    bool finish=false) {
    static std::mutex print_mutex;
    std::lock_guard<std::mutex> lock(print_mutex);

    if(total==0) return;

    const int bar_width=40;
    double fraction=static_cast<double>(processed)/total;
    int pos=static_cast<int>(bar_width*fraction);
    if(pos>bar_width) pos=bar_width;

    int pct=static_cast<int>(fraction*100.0 + 1e-9);
    static int last_pct=-1;
    // 非帧（纯 CLI）进度条：仅当整数百分比变化时刷新，避免每块都重算 format_size 与重绘
    if(!finish && pct==last_pct) return;
    last_pct=pct;

    auto now=std::chrono::steady_clock::now();
    double elapsed=std::chrono::duration<double>(now-start).count();
    double speed=(elapsed>0) ? (processed/1048576.0)/elapsed : 0.0; // MB/s（1024 进制）
    int eta=(speed>0) ? static_cast<int>((total-processed)/1048576.0/speed) : 0;

    std::string bar;
    bar.reserve(bar_width+2);
    bar+='[';
    for(int i=0; i<bar_width; ++i) {
        if(i<pos) bar+='=';
        else if(i==pos) bar+='>';
        else bar+=' ';
    }
    bar+=']';

    char buf[128];
    snprintf(buf,sizeof(buf),"\r%s %s/%s | %.2f MB/s | %d:%02d",
        bar.c_str(),format_size((uint64_t)processed).c_str(),format_size((uint64_t)total).c_str(),
        speed,eta/60,eta%60);

    if(finish) {
        last_pct=-1;   // 复位，下一文件从 0% 重新开始
        std::cout<<buf<<'\n';
    }
    else {
        std::cout<<buf<<std::flush;
    }
}

// ---------- 文件名 / 扩展名混淆（v1.7.0） ----------
// 输出 <16hex>.<混淆扩展名>.ptd；混淆名=Blake2b(Blake2b(口令),路径) 确定性，续传命中同一文件且不泄露原名。
static const char* const OBFUSCATED_EXTS[] = {
    "png","jpg","jpeg","apng","mp4","mp3","aac","avi","bmp","txt","yaml",
    "json","js","cpp","hpp","c","md","pdf","doc","docx","ppt","pptx","xls",
    "xlsx","gif","zip","rar","iso","htm","html","css"
};
static constexpr size_t OBFUSCATED_EXT_COUNT=sizeof(OBFUSCATED_EXTS)/sizeof(OBFUSCATED_EXTS[0]);

// ---------- 原始文件名加密存储（v1.7.1） ----------
// 原名以 XChaCha20-Poly1305 信封追加密文末尾；尾部 [加密名 n+16B][magic "FENX"][len 4B]，最末 8 字节可直接定位；兼容旧 FENM 读取。
static constexpr char NAME_FOOTER_MAGIC[4]     = {'F','E','N','M'}; // 旧版明文尾部（仅兼容读取）
static constexpr char NAME_FOOTER_MAGIC_ENC[4] = {'F','E','N','X'}; // 新版加密尾部
static constexpr size_t NAME_FOOTER_HDR = 8;                 // magic(4) + name_len(4)
static constexpr uint32_t NAME_FOOTER_MAX_NAME = 1024;
static constexpr size_t NAME_ENV_TAG = crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

// 由主密钥派生"文件名加密"子密钥（与主密文密钥域分离，杜绝密钥复用）
static void derive_name_key(const unsigned char* master_key,
    unsigned char name_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    const char tag[]="FE_name_v4";
    std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
    in.insert(in.end(), master_key, master_key+ARGON2_OUTPUT_LEN);
    crypto_generichash(name_key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        in.data(), in.size(), nullptr, 0);
}

// 由文件 salt 派生"文件名加密"nonce（每文件唯一，杜绝 nonce 复用）
static void derive_name_nonce(const unsigned char* salt, size_t salt_len,
    unsigned char nonce[XCHACHA20_IV_LEN]) {
    const char tag[]="FE_name_nonce_v4";
    std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
    in.insert(in.end(), salt, salt+salt_len);
    crypto_generichash(nonce, XCHACHA20_IV_LEN, in.data(), in.size(), nullptr, 0);
}

static std::string path_basename_utf8(const std::string& p) {
    size_t pos=p.find_last_of("/\\");
    return (pos!=std::string::npos) ? p.substr(pos+1) : p;
}

std::string replace_basename(const std::string& p,const std::string& newbase) {
    size_t pos=p.find_last_of("/\\");
    if(pos==std::string::npos) return newbase;
    return p.substr(0,pos+1)+newbase;
}

std::string make_obfuscated_basename(const std::string& in_path,const SecureBuffer& password) {
    unsigned char key[32];
    crypto_generichash(key,sizeof(key),password.data(),password.size(),nullptr,0);
    unsigned char seed[32];
    crypto_generichash(seed,sizeof(seed),
        reinterpret_cast<const unsigned char*>(in_path.data()),in_path.size(),
        key,sizeof(key));
    static const char hexd[]="0123456789abcdef";
    char name[17];
    for(int i=0; i<8; ++i) {
        name[i*2]=hexd[seed[i]>>4];
        name[i*2+1]=hexd[seed[i]&0x0F];
    }
    name[16]='\0';
    return std::string(name)+"."+OBFUSCATED_EXTS[seed[8]%OBFUSCATED_EXT_COUNT];
}

// 用与主密文相同的 XChaCha20-Poly1305 加密原始文件名，写入文件末尾加密信封。
// master_key 为 Argon2 派生主密钥；salt 取自文件头，用于派生独立 nonce。
static bool append_encrypted_name_footer(std::fstream& fout,
    const std::string& in_path,
    const unsigned char* master_key,
    const unsigned char* salt) {
    std::string base=path_basename_utf8(in_path);
    if(base.empty()||base.size()>NAME_FOOTER_MAX_NAME) return true; // 跳过则解密走文件名回退
    unsigned char name_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[XCHACHA20_IV_LEN];
    derive_name_key(master_key, name_key);
    derive_name_nonce(salt, ARGON2_SALT_LEN, nonce);
    std::vector<unsigned char> env(base.size()+NAME_ENV_TAG);
    unsigned long long envlen=0;
    // AAD 绑定本文件 salt，防止尾部被挪用到其他文件
    int rc=crypto_aead_xchacha20poly1305_ietf_encrypt(
        env.data(), &envlen,
        reinterpret_cast<const unsigned char*>(base.data()), base.size(),
        salt, ARGON2_SALT_LEN, nullptr, nonce, name_key);
    if(rc!=0||envlen!=(unsigned long long)env.size()) return false;
    unsigned char tail[NAME_FOOTER_HDR];
    memcpy(tail,NAME_FOOTER_MAGIC_ENC,4);
    uint32_t n=(uint32_t)base.size();
    for(int i=0; i<4; ++i) tail[4+i]=(unsigned char)((n>>(i*8))&0xFF);
    fout.seekp(0,std::ios::end);
    fout.write(reinterpret_cast<const char*>(env.data()), (std::streamsize)envlen);
    fout.write(reinterpret_cast<const char*>(tail),NAME_FOOTER_HDR);
    fout.flush();
    return fout.good();
}

// 尾部元数据未认证，还原前须净化防越权路径；Windows 保留设备名
// (CON/PRN/AUX/NUL/COMx/LPTx) 命中即拒绝，避免指向设备。
static bool is_windows_reserved_name(const std::string& name) {
#ifdef _WIN32
    // 取基名（去目录），再剥扩展名得到待比较的"名"
    std::string base=name;
    size_t bs=base.find_last_of("/\\");
    if(bs!=std::string::npos) base=base.substr(bs+1);
    size_t dot=base.find('.');
    std::string stem=(dot!=std::string::npos)?base.substr(0,dot):base;
    // 转大写比较（保留名大小写不敏感）
    std::string up;
    up.reserve(stem.size());
    for(unsigned char c: stem) up.push_back((char)std::toupper(c));
    if(up=="CON"||up=="PRN"||up=="AUX"||up=="NUL") return true;
    auto is_num=[&](const std::string& pre){
        if(up.size()<=pre.size()) return false;
        if(up.compare(0,pre.size(),pre)!=0) return false;
        for(size_t i=pre.size();i<up.size();++i)
            if(!std::isdigit((unsigned char)up[i])) return false;
        return true;
    };
    for(int i=1;i<=9;++i) {
        if(is_num("COM"+std::to_string(i))) return true;
        if(is_num("LPT"+std::to_string(i))) return true;
    }
#else
    (void)name;
#endif
    return false;
}

static bool sanitize_restored_name(const std::string& n) {
    if(n.empty()||n.size()>255) return false;
    if(n[0]=='.') return false;                       // 隐藏文件（"." 开头）
    if(n.find("..")!=std::string::npos) return false; // 路径穿越组件
    for(unsigned char c : n) {
        if(c<0x20||c==0x7F) return false;            // 控制字符
        if(c=='/'||c=='\\'||c==':') return false;     // 路径分隔符 / 盘符冒号
    }
#ifdef _WIN32
    // Windows 会静默剥离结尾的 '.' 与空格，造成"CON.ptd"被当成"CON"、
    // "a. .txt" 与 "a.txt" 撞名。拒绝此类名字，避免还原后覆盖或设备指向。
    if(n.back()=='.'||n.back()==' ') return false;
    if(is_windows_reserved_name(n)) return false;     // CON/PRN/AUX/NUL/COMx/LPTx
#endif
    return true;
}

// 仅读取尾部结构长度（无需密钥），供解密时的文件大小校验使用；
// 兼容加密尾部(FENX, 含 16 字节 tag)与旧版明文尾部(FENM)。
static bool peek_name_footer_len(const std::string& ptd_path, uint64_t& footer_len) {
    footer_len=0;
    int64_t sz=get_file_size_utf8(ptd_path);
    if(sz<(int64_t)(NAME_FOOTER_HDR+16)) return false;
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    f.seekg(-(std::streamoff)NAME_FOOTER_HDR, std::ios::end);
    unsigned char tail[NAME_FOOTER_HDR];
    if(!f.read(reinterpret_cast<char*>(tail), NAME_FOOTER_HDR)) return false;
    bool enc = (memcmp(tail, NAME_FOOTER_MAGIC_ENC,4)==0);
    bool plain = (memcmp(tail, NAME_FOOTER_MAGIC,4)==0);
    if(!enc && !plain) return false;
    uint32_t n=0;
    for(int i=0;i<4;++i) n|=((uint32_t)tail[4+i])<<(i*8);
    if(n==0||n>NAME_FOOTER_MAX_NAME) return false;
    uint64_t env = enc ? (uint64_t)n + NAME_ENV_TAG : (uint64_t)n;
    uint64_t total = env + NAME_FOOTER_HDR;
    if((uint64_t)sz < total) return false;
    footer_len=total;
    return true;
}

// 解密尾部（需主密钥 + salt）。成功返回原始文件名；失败（密钥错/被篡改/无尾部）返回 false。
static bool decrypt_name_footer(const std::string& ptd_path,
    std::string& out_name,
    const unsigned char* master_key,
    const unsigned char* salt) {
    out_name.clear();
    int64_t sz=get_file_size_utf8(ptd_path);
    if(sz<(int64_t)(NAME_FOOTER_HDR+16)) return false;
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    f.seekg(-(std::streamoff)NAME_FOOTER_HDR, std::ios::end);
    unsigned char tail[NAME_FOOTER_HDR];
    if(!f.read(reinterpret_cast<char*>(tail), NAME_FOOTER_HDR)) return false;
    bool enc = (memcmp(tail, NAME_FOOTER_MAGIC_ENC,4)==0);
    bool plain = (memcmp(tail, NAME_FOOTER_MAGIC,4)==0);
    if(!enc && !plain) return false;
    uint32_t n=0;
    for(int i=0;i<4;++i) n|=((uint32_t)tail[4+i])<<(i*8);
    if(n==0||n>NAME_FOOTER_MAX_NAME) return false;
    uint64_t env_len = enc ? (uint64_t)n + NAME_ENV_TAG : (uint64_t)n;
    uint64_t total = env_len + NAME_FOOTER_HDR;
    if((uint64_t)sz < total) return false;
    f.seekg(-(std::streamoff)total, std::ios::end);
    if(plain) {
        // 旧版明文尾部：直接读取（仍做净化防越权输出）
        std::string raw((size_t)n,'\0');
        if(!f.read(&raw[0],(std::streamsize)n)) return false;
        if(!sanitize_restored_name(raw)) return false;
        out_name=raw;
        return true;
    }
    std::vector<unsigned char> env((size_t)env_len);
    if(!f.read(reinterpret_cast<char*>(env.data()),(std::streamoff)env_len)) return false;
    unsigned char name_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[XCHACHA20_IV_LEN];
    derive_name_key(master_key, name_key);
    derive_name_nonce(salt, ARGON2_SALT_LEN, nonce);
    std::vector<unsigned char> plain_out((size_t)n);
    unsigned long long mlen=0;
    int rc=crypto_aead_xchacha20poly1305_ietf_decrypt(
        plain_out.data(), &mlen, nullptr,
        env.data(), env_len, salt, ARGON2_SALT_LEN, nonce, name_key);
    if(rc!=0) return false;            // 密钥错或被篡改
    if(mlen!=(unsigned long long)n) return false;
    std::string raw(reinterpret_cast<char*>(plain_out.data()), (size_t)mlen);
    if(!sanitize_restored_name(raw)) return false;
    out_name=raw;
    return true;
}

// 公开接口：从密文末尾的加密信封恢复原始文件名。需口令以派生主密钥并解密尾部。
// 解密失败（密钥错/无尾部）返回 false，调用方回退到基于 .ptd 文件名的命名。
bool read_original_name(const std::string& ptd_path, std::string& out_name,
    const SecureBuffer& password,
    const unsigned char* pre_kek, size_t pre_kek_len,
    std::vector<unsigned char>* out_kek) {
    out_name.clear();
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdrbuf[320];
    if(!f.read(reinterpret_cast<char*>(hdrbuf),5)) return false;
    if(memcmp(hdrbuf,MAGIC,4)!=0) return false;
    unsigned char ver=hdrbuf[4];
    if(ver!=1&&ver!=2&&ver!=3&&ver!=VERSION&&ver!=5&&ver!=6) return false;
    size_t hdr_size=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdrbuf+5),(std::streamoff)(hdr_size-5))) return false;
    unsigned char salt_buf[ARGON2_SALT_LEN];
    const unsigned char* salt_ptr=nullptr;
    unsigned int kdf_ops=ARGON2_OPS_LEGACY;
    size_t kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    if(ver==1)      { FileHeaderV1 h=load_header<FileHeaderV1>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; }
    else if(ver==2) { FileHeaderV2 h=load_header<FileHeaderV2>(hdrbuf);  memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else if(ver==3) { FileHeaderV3 h=load_header<FileHeaderV3>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else if(ver==5) { FileHeaderV5 h=load_header<FileHeaderV5>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else if(ver==6) { FileHeaderV6 h=load_header<FileHeaderV6>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    else            { FileHeaderV4 h=load_header<FileHeaderV4>(hdrbuf); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; kdf_ops=h.opslimit; kdf_mem=(size_t)h.memlimit_kb*1024; }
    SecureBuffer kek(ARGON2_OUTPUT_LEN);
    if(pre_kek && pre_kek_len >= ARGON2_OUTPUT_LEN) {
        std::memcpy(kek.data(), pre_kek, ARGON2_OUTPUT_LEN);
    } else if(!derive_key(password.data(),password.size(),salt_ptr,kek.data(),kdf_ops,kdf_mem)) {
        return false;
    }
    if(out_kek) out_kek->assign(kek.data(), kek.data()+ARGON2_OUTPUT_LEN);

    // v6 容器：文件名信封由 DEK 加密（与载荷一致），KEK 仅用于解裹 DEK。
    // 故 v6 须先解裹出 DEK，再以 DEK 还原文件名；v1-v5 直接以 KEK（载荷密钥）解密。
    if(ver==6) {
        FileHeaderV6 h6=load_header<FileHeaderV6>(hdrbuf);
        unsigned char dek[32];
        if(!unwrap_dek(h6.dek_box, kek.data(), h6.dek_nonce, dek)) return false;
        bool ok=decrypt_name_footer(ptd_path, out_name, dek, salt_ptr);
        sodium_memzero(dek, sizeof(dek));
        return ok;
    }
    return decrypt_name_footer(ptd_path, out_name, kek.data(), salt_ptr);
}

// ---------- 只读元数据预览（功能2：文件头信息查看器） ----------
// 不派生密钥、不解密任何内容，仅解析公开头部与尾部信封标志。
bool read_ptd_metadata(const std::string& ptd_path, PtdMeta& meta) {
    meta=PtdMeta{};
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdr[HEADER_SIZE_V6];
    if(!f.read(reinterpret_cast<char*>(hdr),5)) return false;
    if(memcmp(hdr,MAGIC,4)!=0) return false;
    unsigned char ver=hdr[4];
    if(ver!=1&&ver!=2&&ver!=3&&ver!=VERSION&&ver!=5&&ver!=6) return false;
    meta.version=ver;
    meta.valid=true;
    size_t need=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdr+5),(std::streamoff)(need-5))) return false;
    unsigned char salt_buf[ARGON2_SALT_LEN];
    const unsigned char* salt_ptr=nullptr;
    size_t iv_len=0;
    if(ver==1)      { FileHeaderV1 h=load_header<FileHeaderV1>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,std::min<size_t>(h.iv_len,24)); meta.iv_hex=hex; }
    else if(ver==2) { FileHeaderV2 h=load_header<FileHeaderV2>(hdr);  memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,std::min<size_t>(h.iv_len,24)); meta.iv_hex=hex; }
    else if(ver==3) { FileHeaderV3 h=load_header<FileHeaderV3>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,std::min<size_t>(h.iv_len,32)); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2;
                     int64_t sz=get_file_size_utf8(ptd_path); (void)sz; }
    else if(ver==5) { FileHeaderV5 h=load_header<FileHeaderV5>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     meta.compression=h.compression; meta.comp_level=h.comp_level;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,32); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2; }
    else if(ver==6) { FileHeaderV6 h=load_header<FileHeaderV6>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     meta.compression=h.compression; meta.comp_level=h.comp_level;
                     meta.dek_wrapped=true; meta.key_version=get_be32(reinterpret_cast<const unsigned char*>(&h.key_version));
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,32); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2; }
    else            { FileHeaderV4 h=load_header<FileHeaderV4>(hdr); memcpy(salt_buf,h.salt,ARGON2_SALT_LEN); salt_ptr=salt_buf; meta.mode=static_cast<CryptoMode>(h.mode); meta.opslimit=h.opslimit; meta.memlimit_kb=h.memlimit_kb; iv_len=h.iv_len;
                     char hex[65]; sodium_bin2hex(hex,sizeof(hex),h.iv,32); meta.iv_hex=hex;
                     char hx2[65]; sodium_bin2hex(hx2,sizeof(hx2),h.plaintext_hash,HASH_SIZE); meta.plaintext_hash_hex=hx2; }
    // 头部之后紧随 16 字节块元数据：chunk_size(4) + total_chunks(4) + orig_size(8)
    // （不在任何版本的头部结构内，故需单独读取）
    uint32_t meta_chunk=0, meta_chunks=0;
    uint64_t meta_orig=0;
    if(f.read(reinterpret_cast<char*>(&meta_chunk),4)&&
       f.read(reinterpret_cast<char*>(&meta_chunks),4)&&
       f.read(reinterpret_cast<char*>(&meta_orig),8)) {
        meta.chunk_size=meta_chunk;
        meta.total_chunks=meta_chunks;
        meta.orig_size=meta_orig;
    }
    if(salt_ptr) {
        char hex[65]; sodium_bin2hex(hex,sizeof(hex),salt_ptr,ARGON2_SALT_LEN); meta.salt_hex=hex;
    }
    // 尾部文件名信封：仅 v1.7.1+ 写入（FENX 加密 / FENM 明文）；旧格式无。
    uint64_t fl=0;
    meta.has_name_footer = peek_name_footer_len(ptd_path, fl);
    return true;
}

// ---------- 完整性校验（功能3：只验不解） ----------
bool verify_ptd(const std::string& ptd_path, const SecureBuffer& password) {
    // 自校验：直接流式解密并计算明文哈希，不再落盘 .verify.tmp（消除 4 倍 I/O）。
    // decrypt_file 在 verify_only 模式下当且仅当明文长度与存储哈希均匹配时返回 true。
    return decrypt_file(ptd_path, ptd_path, password,
        nullptr, false, false, nullptr, nullptr, 0, true);
}

// ---------- 密钥轮换 / rewrap（v6 容器） ----------
// old_password 解出 wrapped DEK，new_password 派生新 KEK 重裹（key_version 自增），重写头部容器区与 hmac，载荷不动；仅 v6+。
bool rewrap_file(const std::string& ptd_path,
    const SecureBuffer& old_password,
    const std::string& new_key_path,
    bool new_key_from_stdin) {
    // 读取新口令（与 CLI 密钥源约定一致：密钥文件原始字节 / 整段 stdin）
    SecureBuffer new_pw;
    if(!new_key_path.empty()) {
        std::ifstream kf;
        if(!open_stream(kf,new_key_path,std::ios::binary)) {
            fprintf(stderr,"Cannot open new key file: %s\n",new_key_path.c_str());
            return false;
        }
        std::vector<char> kbuf((std::istreambuf_iterator<char>(kf)),
                               std::istreambuf_iterator<char>());
        kf.close();
        if(kbuf.empty()) { fprintf(stderr,"New key file is empty: %s\n",new_key_path.c_str()); return false; }
        new_pw=SecureBuffer(kbuf.data(),kbuf.size());
        sodium_memzero(kbuf.data(),kbuf.size()); kbuf.clear();
    } else if(new_key_from_stdin) {
        std::vector<char> sbuf((std::istreambuf_iterator<char>(std::cin)),
                               std::istreambuf_iterator<char>());
        if(sbuf.empty()) { fprintf(stderr,"No new key material received from stdin.\n"); return false; }
        new_pw=SecureBuffer(sbuf.data(),sbuf.size());
        sodium_memzero(sbuf.data(),sbuf.size()); sbuf.clear();
    } else {
        fprintf(stderr,"rewrap requires a new key source (--new-key-file <file> or --new-key-stdin).\n");
        return false;
    }

    // 只读方式打开，先校验 magic / 版本
    std::fstream f;
    if(!open_stream(f,ptd_path,std::ios::in|std::ios::out|std::ios::binary)) {
        fprintf(stderr,"Cannot open container for rewrap: %s\n",ptd_path.c_str());
        return false;
    }
    unsigned char hdr[HEADER_SIZE_V6];
    if(!f.read(reinterpret_cast<char*>(hdr),HEADER_SIZE_V6) || f.gcount()!=HEADER_SIZE_V6) {
        fprintf(stderr,"Container too small or unreadable: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    if(memcmp(hdr,MAGIC,4)!=0) { fprintf(stderr,"Invalid magic (not a FileEncryptor file).\n"); f.close(); return false; }
    FileHeaderV6 h=load_header<FileHeaderV6>(hdr);
    if(h.version!=6) {
        fprintf(stderr,"rewrap requires a v6 container; file version=%u (re-encrypt instead).\n",(unsigned)h.version);
        f.close(); return false;
    }

    // 跨进程锁：避免与其他进程（如加密中）并发写同一文件
    std::string lock_path;
    LockResult lr=acquire_output_lock(ptd_path,lock_path);
    if(lr!=LockResult::OK) {
        fprintf(stderr,"Cannot acquire lock for rewrap: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    OutputLockGuard lock_guard{lock_path,true};

    // 用旧口令派生 KEK，解开 DEK（同时校验旧口令正确性）
    SecureBuffer old_kek(ARGON2_OUTPUT_LEN);
    if(!derive_key(old_password.data(),old_password.size(),h.salt,old_kek.data(),
            h.opslimit,(size_t)h.memlimit_kb*1024)) {
        fprintf(stderr,"Key derivation failed (old password).\n");
        f.close(); return false;
    }
    // DEK 以 SecureBuffer 持有（析构自动清零 + 解锁），保留至 header_hmac 重算完成
    SecureBuffer dek(32);
    if(!unwrap_dek(h.dek_box, old_kek.data(), h.dek_nonce, dek.data())) {
        report_auth_error(false, "Failed to unwrap DEK (wrong old password or corrupted container).");
        f.close(); return false;
    }
    sodium_memzero(old_kek.data(),old_kek.size());

    // 用新口令派生新 KEK，重裹 DEK（重新随机 nonce + box）。DEK 保持不变。
    SecureBuffer new_kek(ARGON2_OUTPUT_LEN);
    if(!derive_key(new_pw.data(),new_pw.size(),h.salt,new_kek.data(),
            h.opslimit,(size_t)h.memlimit_kb*1024)) {
        fprintf(stderr,"Key derivation failed (new password).\n");
        f.close(); return false;
    }
    if(!wrap_dek(dek.data(), new_kek.data(), h.dek_nonce, h.dek_box)) {
        fprintf(stderr,"DEK rewrap failed.\n");
        f.close(); return false;
    }
    sodium_memzero(new_kek.data(),new_kek.size());

    // 写回容器区：key_version 自增（大端）。DEK 不变，故 header_hmac 仍由 DEK 派生密钥计算，
    // 重算整头 HMAC（覆盖至 reserved 区，含新容器）后仍自洽。
    uint32_t kv=get_be32(reinterpret_cast<const unsigned char*>(&h.key_version))+1;
    put_be32(reinterpret_cast<unsigned char*>(&h.key_version), kv);
    // 局部 h 的容器区改动（dek_box / nonce / key_version）须先写回原始字节缓冲，
    // header_hmac 的覆盖与整头落盘都以该缓冲为基准（h 是 memcpy 出的副本）。
    memcpy(hdr, &h, HEADER_SIZE_V6);
    {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(dek.data(), hdr_auth);
        crypto_auth(hdr + (HEADER_SIZE_V6 - HEADER_HMAC_SIZE), hdr, HEADER_HMAC_COVER_V6, hdr_auth);
    }

    // 落盘：从头写回完整 256 字节头部（plaintext_hash 保持原值不变）
    f.seekp(0,std::ios::beg);
    if(!f.write(reinterpret_cast<const char*>(hdr),HEADER_SIZE_V6)) {
        fprintf(stderr,"Failed to write rewrapped header: %s\n",ptd_path.c_str());
        f.close(); return false;
    }
    f.flush();
    f.close();
    printf("rewrap: container '%s' rotated to key_version=%u (payload ciphertext untouched).\n",
        ptd_path.c_str(), kv);
    return true;
}


bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback,
    bool resume,
    int compress_level) {

    disable_core_dump();

    // 依据 YAML 配置校验输入/输出路径（长度上限 / 白名单）
    if(!validate_io_paths(in_path,out_path,false)) {
        fprintf(stderr,"Path validation failed (config policy)\n");
        return false;
    }

    // 防路径穿越：输出路径若含未解析的 ".." 分量则拒绝
    if(path_has_traversal(out_path)) {
        fprintf(stderr,"Output path contains directory traversal\n");
        return false;
    }
    if(password.size()<PASSWORD_MIN_LEN) {
        fprintf(stderr,"Password too short (min %zu characters)\n",PASSWORD_MIN_LEN);
        return false;
    }

    // 输入侧 4 MiB 页对齐大缓冲（先于 fin 声明，析构时 fin 先销毁，缓冲存活期覆盖流）
    InputBuffer fin_buf;
    std::ifstream fin;
    if(!open_stream(fin,in_path,std::ios::binary)) {
        fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }
    fin_buf.attach(fin);
    fin.seekg(0,std::ios::end);
    uint64_t total_size=static_cast<uint64_t>(fin.tellg());
    fin.seekg(0,std::ios::beg);
    auto start_time=std::chrono::steady_clock::now();
    // .prs 节流基点：进度文件只服务"进程被强杀后的断点续传"，无需逐块落盘。
    // （声明在所有 goto cleanup 之前，避免 C4533 跳过初始化。）
    auto last_prs_save=std::chrono::steady_clock::now();

    uint32_t chunk_size=CHUNK_SIZE;
    uint64_t total_chunks_64=(total_size+chunk_size-1)/chunk_size;
    if(total_chunks_64>UINT32_MAX) {
        fprintf(stderr,"File too large: %llu chunks exceeds uint32_t limit (%u).\n",
            (unsigned long long)total_chunks_64,UINT32_MAX);
        return false;
    }
    uint32_t total_chunks=static_cast<uint32_t>(total_chunks_64);
    uint64_t orig_size=total_size;

    size_t iv_len=(mode==CryptoMode::AES_GCM)?AES_GCM_IV_LEN
                 :(mode==CryptoMode::AEGIS256)?AEGIS256_IV_LEN:XCHACHA20_IV_LEN;
    size_t tag_size=tag_size_for_mode(mode);

    // ---- 续传检测：先读已存在输出的头部获取 salt，派生密钥后才能验证 .prs 的 HMAC ----
    ProgressInfo prog_info{0,0,0,0,{0}};
    bool has_progress=false;
    bool out_exists=file_exists(out_path);
    bool prog_present=file_exists(out_path+".prs");
    FileHeaderV3 existing_v3{};   // 复用 v3 前缀结构读取前 109 字节（v3 / v4 / v5 通用）
    FileHeaderV6 existing_v6{};   // v6 容器头（含 DEK 包裹区）
    bool existing_is_v3=false;   // 现有输出为 v3 / v4 / v5
    bool existing_is_v4=false;
    bool existing_is_v5=false;
    bool existing_is_v6=false;   // 现有输出为 v6 容器
    unsigned char existing_mode=0; // 现有输出的加密模式（含 v6）
    unsigned char existing_compression=0;  // v5 压缩标记
    int existing_comp_level=0;             // v5 压缩级别（按有符号解释，支持 zstd 负快速档）
    unsigned char existing_hdr_hmac[HEADER_HMAC_SIZE]={0};
    if(out_exists) {
        std::ifstream fhex;
        if(open_stream(fhex,out_path,std::ios::binary)) {
            unsigned char ehbuf[HEADER_SIZE_V6];
            if(fhex.read(reinterpret_cast<char*>(ehbuf),5) && fhex.gcount()==5
                && memcmp(ehbuf,MAGIC,4)==0) {
                unsigned char ver=ehbuf[4];
                size_t remaining=0;
                if(ver==6)      remaining=HEADER_SIZE_V6-5;
                else if(ver==5) remaining=HEADER_SIZE_V5-5;
                else if(ver==3||ver==4) remaining=HEADER_SIZE_V4-5;
                if(remaining>0 && fhex.read(reinterpret_cast<char*>(ehbuf+5),(std::streamoff)remaining)
                    && fhex.gcount()==(std::streamsize)remaining) {
                    if(ver==6) {
                        existing_is_v6=true;
                        memcpy(&existing_v6,ehbuf,HEADER_SIZE_V6);
                        existing_mode=existing_v6.mode;
                        memcpy(existing_hdr_hmac,ehbuf+HEADER_SIZE_V6-HEADER_HMAC_SIZE,HEADER_HMAC_SIZE);
                        existing_compression=existing_v6.compression;
                        existing_comp_level=(int)(signed char)existing_v6.comp_level;
                    }
                    else if(ver==5) {
                        memcpy(&existing_v3,ehbuf,HEADER_SIZE_V3);
                        existing_is_v3=true; existing_mode=existing_v3.mode;
                        existing_is_v5=true;
                        memcpy(existing_hdr_hmac,ehbuf+HEADER_SIZE_V5-HEADER_HMAC_SIZE,HEADER_HMAC_SIZE);
                        existing_compression=ehbuf[HEADER_SIZE_V3];
                        existing_comp_level=(int)(signed char)ehbuf[HEADER_SIZE_V3+1];
                    }
                    else if(ver==4) {
                        memcpy(&existing_v3,ehbuf,HEADER_SIZE_V3);
                        existing_is_v3=true; existing_mode=existing_v3.mode;
                        existing_is_v4=true;
                        memcpy(existing_hdr_hmac,ehbuf+HEADER_SIZE_V3,HEADER_HMAC_SIZE);
                    }
                    else if(ver==3) {
                        memcpy(&existing_v3,ehbuf,HEADER_SIZE_V3);
                        existing_is_v3=true; existing_mode=existing_v3.mode;
                    }
                }
            }
            fhex.close();
        }
    }

    SecureBuffer key(ARGON2_OUTPUT_LEN);
    SecureBuffer auth_key(crypto_auth_KEYBYTES);
    std::string prog_binding = compute_progress_binding(in_path);

    if(resume && prog_present && load_progress_raw(out_path,prog_info)) {
        if(existing_is_v3) {
            if(!derive_key(password.data(),password.size(),existing_v3.salt,key.data(),
                    existing_v3.opslimit,(size_t)existing_v3.memlimit_kb*1024)) {
                fprintf(stderr,"Key derivation failed for resume\n");
            } else {
                derive_progress_auth_key(key.data(),auth_key.data());
                // v4 / v5 输出：先校验文件头 HMAC（防文件头被篡改后重放旧 .prs）
                bool hdr_ok=true;
                if(existing_is_v4 || existing_is_v5) {
                    unsigned char hdr_auth[HEADER_HMAC_SIZE];
                    derive_header_auth_key(key.data(),hdr_auth);
                    size_t cover = existing_is_v5 ? HEADER_HMAC_COVER_V5 : HEADER_HMAC_COVER;
                    hdr_ok=(crypto_auth_verify(existing_hdr_hmac,
                        reinterpret_cast<const unsigned char*>(&existing_v3),cover,hdr_auth)==0);
                }
                if(hdr_ok && verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
                    && prog_info.processed_chunks<=total_chunks
                    && prog_info.processed_bytes<=total_size) {
                    has_progress=true;
                }
            }
        }
        else if(existing_is_v6) {
            // v6 续传：口令派生 KEK，解开 wrapped DEK（同时校验口令正确性），DEK 即载荷密钥
            FileHeaderV6* h=&existing_v6;
            SecureBuffer kek(ARGON2_OUTPUT_LEN);
            if(!derive_key(password.data(),password.size(),h->salt,kek.data(),
                    h->opslimit,(size_t)h->memlimit_kb*1024)) {
                fprintf(stderr,"Key derivation failed for resume\n");
            } else {
                unsigned char dek[32];
                if(unwrap_dek(h->dek_box,kek.data(),h->dek_nonce,dek)) {
                    memcpy(key.data(),dek,32);
                    sodium_memzero(dek,sizeof(dek));
                    derive_progress_auth_key(key.data(),auth_key.data());
                    unsigned char hdr_auth[HEADER_HMAC_SIZE];
                    derive_header_auth_key(key.data(),hdr_auth);
                    bool hdr_ok=(crypto_auth_verify(existing_hdr_hmac,
                        reinterpret_cast<const unsigned char*>(h),HEADER_HMAC_COVER_V6,hdr_auth)==0);
                    if(hdr_ok && verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
                        && prog_info.processed_chunks<=total_chunks
                        && prog_info.processed_bytes<=total_size) {
                        has_progress=true;
                    }
                } else {
                    fprintf(stderr,"Failed to unwrap DEK on resume (wrong password?)\n");
                }
                sodium_memzero(kek.data(),kek.size());
            }
        }
        // 注意：此处不能 key.clear()——提前 clear 会使后续 derive_key 写入已释放缓冲。
        // 保留 key 的有效 32 字节缓冲，函数返回时 SecureBuffer 析构自动清零。
    }

    // .prs 无法认证时，若原输出已存在则禁止从头覆盖（否则会静默抹掉正确密文、
    // 造成数据永久丢失）；仅当输出不存在（孤立 .prs）才安全重做。
    if(resume && prog_present && !has_progress) {
        if(out_exists) {
            fprintf(stderr,"Refusing to overwrite existing output '%s': progress authentication failed "
                "(likely wrong password or corrupt .prs). Use a different output path, or delete "
                "the file and its .prs first if you intend to restart.\n", out_path.c_str());
            log_event(LOG_ERROR,"refuse_overwrite_existing",{{"path",out_path}});
            return false;
        }
        if(existing_is_v3) {
            fprintf(stderr,"Progress authentication failed / corrupt, restarting from beginning.\n");
        } else {
            fprintf(stderr,"Cannot authenticate legacy progress file, restarting from beginning.\n");
        }
        log_event(LOG_WARN,"progress_auth_failed",{{"path",out_path}});
        prog_info={0,0,0,0,{0}};
    }

    uint64_t start_chunk=has_progress?prog_info.processed_chunks:0;
    uint64_t start_bytes=has_progress?prog_info.processed_bytes:0;

    // 压缩决策：未集成 zstd 时强制关闭；续传已存在的 v5 压缩文件时继续压缩（沿用其级别）
    bool do_compress;
#ifdef FE_WITH_ZSTD
    do_compress = (compress_level != 0) || (has_progress && existing_is_v5 && existing_compression==1);
    if(do_compress && has_progress && existing_is_v5 && existing_compression==1 && compress_level==0)
        compress_level = existing_comp_level;
#else
    do_compress = false;
    (void)compress_level;
#endif
    // v6：默认写 v6（随机 DEK，KEK 包裹）。header_hmac 覆盖整段前缀（含容器，rewrap 后重算）；
    // 载荷 AAD 只覆盖稳定前缀（不含容器），保证密钥轮换零重加密。
    const bool use_v6 = true;
    const size_t hdr_cover = use_v6 ? HEADER_HMAC_COVER_V6
                          : (do_compress ? HEADER_HMAC_COVER_V5 : HEADER_HMAC_COVER);
    const size_t aad_cover = use_v6 ? HEADER_AAD_COVER_V6 : hdr_cover;
    const bool resume_compressed = (has_progress && existing_is_v5 && existing_compression==1);

    size_t existing_hdr_size = existing_is_v6 ? HEADER_SIZE_V6
                              : (existing_is_v5 ? HEADER_SIZE_V5
                                : (existing_is_v4 ? HEADER_SIZE_V4 : HEADER_SIZE_V3));
    uint64_t trunc_pos;
    if(resume_compressed && start_chunk>0) {
        // v5 压缩文件：每块带 4 字节压缩帧长度前缀，磁盘为变长，需扫描前缀求断点偏移
        uint64_t off=0; bool scan_ok=true;
        std::ifstream ef;
        if(open_stream(ef,out_path,std::ios::binary) && ef.seekg((std::streamoff)(existing_hdr_size+12))) {
            for(uint32_t i=0;i<start_chunk;++i) {
                uint32_t cl=0;
                if(!ef.read(reinterpret_cast<char*>(&cl),4) || ef.gcount()!=4) { scan_ok=false; break; }
                // 前缀 4 字节 = 本块 AEAD 密文长度（已含 tag），故记录 = 4 + cl
                uint64_t rec=4+(uint64_t)cl;
                off+=rec;
                if(i+1<start_chunk) {
                    if(!ef.seekg((std::streamoff)rec,std::ios::cur)) { scan_ok=false; break; }
                }
            }
            ef.close();
        } else scan_ok=false;
        trunc_pos = scan_ok ? (existing_hdr_size+12+off)
                             : (existing_hdr_size+12+(uint64_t)start_chunk*(chunk_size+tag_size));
    } else {
        trunc_pos=(uint64_t)existing_hdr_size+4+4+8+(uint64_t)start_chunk*(chunk_size+tag_size);
    }

    // 跨进程锁：在打开/截断输出之前获取，防止两个进程同时写同一输出导致损坏
    std::string lock_path;
    LockResult lr=acquire_output_lock(out_path,lock_path);
    if(lr!=LockResult::OK) {
        if(lr==LockResult::LOCKED)
            fprintf(stderr,"Output file is locked by another process: %s\n",out_path.c_str());
        else
            fprintf(stderr,"Cannot create output lock file (permission or path issue): %s\n",lock_path.c_str());
        return false;
    }
    OutputLockGuard lock_guard{lock_path,true};

    // 防符号链接劫持
    if(path_is_symlink(out_path)) {
        fprintf(stderr,"Refusing to write through existing symlink: %s\n",out_path.c_str());
        return false;
    }

    // 续传一致性校验必须在 truncate_file 之前完成：否则失败时输出已截断，
    // cleanup 会删 .ptd/.prs，用户可用正确 -m 重跑、断点不丢。
    if(has_progress&&start_chunk>0) {
        if(existing_mode!=static_cast<unsigned char>(mode)) {
            fprintf(stderr,"Output file was created with a different encryption mode "
                "(existing=%d, requested=%d); cannot resume. Use the same -m mode, "
                "or delete the output file first.\n",
                (int)existing_mode,(int)mode);
            return false;
        }
        uint32_t st_chunk=0,st_total=0; uint64_t st_orig=0;
        {
            std::ifstream fhex;
            if(!open_stream(fhex,out_path,std::ios::binary)
                || !fhex.seekg(existing_hdr_size,std::ios::beg)
                || !fhex.read(reinterpret_cast<char*>(&st_chunk),4)
                || !fhex.read(reinterpret_cast<char*>(&st_total),4)
                || !fhex.read(reinterpret_cast<char*>(&st_orig),8)) {
                fprintf(stderr,"Cannot read metadata from existing file\n");
                return false;
            }
        }
        if(st_chunk!=CHUNK_SIZE||st_total!=total_chunks||st_orig!=orig_size) {
            fprintf(stderr,"Metadata mismatch: file may be corrupted\n");
            return false;
        }
    }

    std::fstream fout;
    if(has_progress&&start_chunk>0) {
        // 续传：先丢弃中断瞬间落盘但未记账的密文残片，再从断点继续写入
        if(!truncate_file(out_path,trunc_pos)) {
            fprintf(stderr,"Failed to truncate output for resume: %s\n",out_path.c_str());
            return false;
        }
        if(!open_stream(fout,out_path,std::ios::in|std::ios::out|std::ios::binary)) {
            fprintf(stderr,"Cannot open output file for resume: %s\n",out_path.c_str());
            return false;
        }
        fout.seekp((std::streamoff)trunc_pos,std::ios::beg);
    }
    else {
        if(!open_stream(fout,out_path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(out_path);
        remove_progress(out_path);
    }

    bool header_written=has_progress&&start_chunk>0;

    FileHeaderV6 header{};
    bool ok=true;
    std::vector<unsigned char> aad;
    std::vector<unsigned char> plaintext_chunk(CHUNK_SIZE);
    // 压缩帧缓冲（仅压缩模式使用，固定上界 ZSTD_compressBound(CHUNK_SIZE)；无 zstd 时退化为 CHUNK_SIZE）
    std::vector<unsigned char> comp_chunk(COMP_BUF_MAX);
    std::vector<unsigned char> ciphertext_chunk(COMP_BUF_MAX+MAX_TAG_SIZE);
    unsigned char nonce[32]={0};
    uint64_t processed_bytes=start_bytes;

    // 小于 64 MiB 的文件跳过进度文件写入：小文件重跑成本极低，省去每次 500ms 节流的
    // .prs 写穿（MoveFileExW + 多元数据操作），批量小文件场景下收益明显。
    bool persistent_progress=(total_size>=64ULL*1024*1024);

    // 4 MiB 聚合写出缓冲：后续密文块写入 outbuf 而非直接 fout，攒满 4 MiB 再写盘
    AggWriter outbuf;
    outbuf.bind(fout);

    if(!header_written) {
        memcpy(header.magic,MAGIC,4);
        header.version = use_v6 ? 6 : (do_compress ? 5 : VERSION);   // v6 容器默认；压缩时保留压缩标记
        header.mode=static_cast<unsigned char>(mode);
        header.iv_len=static_cast<unsigned char>(iv_len);
        header.opslimit=ARGON2_OPS_DEFAULT;
        header.memlimit_kb=ARGON2_MEM_DEFAULT_KB;
        {   // 功能14：按 YAML kdf_preset 覆盖默认值（仅新建头时生效，续传沿用既有参数）
            unsigned int pops=ARGON2_OPS_DEFAULT, pmem=ARGON2_MEM_DEFAULT_KB;
            kdf_preset_params(global_config().kdf_preset, pops, pmem);
            header.opslimit=pops;
            header.memlimit_kb=pmem;
        }
        randombytes_buf(header.salt,ARGON2_SALT_LEN);
        randombytes_buf(header.iv,iv_len);
        header.compression = do_compress ? 1 : 0;
        header.comp_level   = do_compress ? (unsigned char)(int)compress_level : 0;
        sodium_memzero(header.plaintext_hash,HASH_SIZE);
        sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);

        // v6 容器：派生 KEK（Argon2id(password,salt)），生成随机 DEK，以德克包裹进容器；
        // 载荷 AEAD 密钥 = DEK，KEK 仅用于包裹/解裹（密钥轮换零重加密的基础）。
        SecureBuffer kek(ARGON2_OUTPUT_LEN);
        if(!derive_key(password.data(),password.size(),header.salt,kek.data(),
                header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false; goto cleanup;
        }
        if(use_v6) {
            unsigned char dek[32];
            randombytes_buf(dek,sizeof(dek));
            put_be32(reinterpret_cast<unsigned char*>(&header.container_len), V6_CONTAINER_LEN);
            if(!wrap_dek(dek, kek.data(), header.dek_nonce, header.dek_box)) {
                fprintf(stderr,"DEK wrap failed\n"); ok=false; goto cleanup;
            }
            put_be32(reinterpret_cast<unsigned char*>(&header.key_version), 0);
            sodium_memzero(header.reserved, sizeof(header.reserved));
            memcpy(key.data(), dek, 32);          // 载荷密钥 = DEK
            sodium_memzero(dek, sizeof(dek));
        } else {
            memcpy(key.data(), kek.data(), ARGON2_OUTPUT_LEN);   // 旧格式：KEK 即载荷密钥
        }
        sodium_memzero(kek.data(), kek.size());
        derive_progress_auth_key(key.data(),auth_key.data());

        // 载荷 AAD 只覆盖稳定前缀（v6 不含容器区，v5 含压缩标记，v4 到 iv）
        aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
            aad_cover, chunk_size,total_chunks,orig_size);

        // 文件头 HMAC 写头时即计算落盘（覆盖对应前缀，不含 plaintext_hash/hmac 自身）：
        // 半成品 .ptd 也带合法 hmac 供续传校验，并防替换 salt/iv/mode 后重放旧 .prs。
        {
            unsigned char hdr_auth[HEADER_HMAC_SIZE];
            derive_header_auth_key(key.data(),hdr_auth);
            crypto_auth(header.header_hmac,
                reinterpret_cast<const unsigned char*>(&header),hdr_cover,hdr_auth);
        }

        if(!fout.write(reinterpret_cast<const char*>(&header),
                use_v6 ? HEADER_SIZE_V6 : (do_compress?HEADER_SIZE_V5:HEADER_SIZE_V4))) {
            fprintf(stderr,"Write header failed\n"); ok=false; goto cleanup;
        }
        if(!fout.write(reinterpret_cast<const char*>(&chunk_size),4)||
            !fout.write(reinterpret_cast<const char*>(&total_chunks),4)||
            !fout.write(reinterpret_cast<const char*>(&orig_size),8)) {
            fprintf(stderr,"Write metadata failed\n"); ok=false; goto cleanup;
        }
    }
    else {
        if(existing_is_v6) {
            // v6 续传：完整拷贝既有 v6 头，派生 KEK 后解开 DEK 作为载荷密钥
            header = existing_v6;
            SecureBuffer kek(ARGON2_OUTPUT_LEN);
            if(!derive_key(password.data(),password.size(),header.salt,kek.data(),
                    header.opslimit,(size_t)header.memlimit_kb*1024)) {
                ok=false; goto cleanup;
            }
            unsigned char dek[32];
            if(!unwrap_dek(header.dek_box, kek.data(), header.dek_nonce, dek)) {
                fprintf(stderr,"Failed to unwrap DEK on resume (wrong password?)\n");
                ok=false; goto cleanup;
            }
            memcpy(key.data(), dek, 32);
            sodium_memzero(dek, sizeof(dek));
            sodium_memzero(kek.data(), kek.size());
            sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);
            derive_progress_auth_key(key.data(),auth_key.data());
            aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
                aad_cover, chunk_size,total_chunks,orig_size);
        } else {
            memcpy(&header,&existing_v3,HEADER_SIZE_V3);
            if(existing_is_v5) {
                header.compression=existing_compression;
                header.comp_level=(unsigned char)(int)existing_comp_level;
            } else {
                header.compression=0;
                header.comp_level=0;
            }
            sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);
            if(!derive_key(password.data(),password.size(),header.salt,key.data(),
                    header.opslimit,(size_t)header.memlimit_kb*1024)) {
                ok=false; goto cleanup;
            }
            derive_progress_auth_key(key.data(),auth_key.data());
            aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
                hdr_cover, chunk_size,total_chunks,orig_size);
        }
    }

    // 明文 Blake2b 流式哈希；续传时先回放输入前缀 [0,start_bytes) 以补齐哈希状态
    crypto_generichash_state hstate;
    crypto_generichash_init(&hstate,nullptr,0,HASH_SIZE);
    if(start_bytes>0) {
        fin.seekg(0,std::ios::beg);
        uint64_t remain=start_bytes;
        std::vector<unsigned char> tmp(CHUNK_SIZE);
        while(remain>0) {
            size_t n=(size_t)std::min<uint64_t>(CHUNK_SIZE,remain);
            fin.read(reinterpret_cast<char*>(tmp.data()),n);
            if(fin.gcount()!=(std::streamsize)n) {
                fprintf(stderr,"Read error during hash catch-up\n");
                ok=false; break;
            }
            crypto_generichash_update(&hstate,tmp.data(),n);
            remain-=n;
        }
        if(!ok) goto cleanup;
        fin.seekg((std::streamoff)start_bytes,std::ios::beg);
    }

    // nonce 基值 = header.iv；按块索引用 sodium_increment 递增（消除 nonce 碰撞理论风险）
    memcpy(nonce,header.iv,iv_len);
    for(uint32_t k=0;k<start_chunk;++k) sodium_increment(nonce,iv_len);

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
        if(processed_bytes>=total_size) break;
        size_t chunk_len=std::min<size_t>(chunk_size,(size_t)(total_size-processed_bytes));
        fin.read(reinterpret_cast<char*>(plaintext_chunk.data()),chunk_len);
        if(fin.gcount()!=(std::streamsize)chunk_len) {
            fprintf(stderr,"Read error at chunk %u\n",i);
            ok=false; break;
        }

        crypto_generichash_update(&hstate,plaintext_chunk.data(),chunk_len);

        // v5+压缩：先 zstd 压缩明文，再对压缩帧做 AEAD 加密（仅 do_compress 时）
        const unsigned char* aead_in=plaintext_chunk.data();
        size_t aead_in_len=chunk_len;
        if(do_compress) {
#ifdef FE_WITH_ZSTD
            size_t cflen=ZSTD_compress(comp_chunk.data(),COMP_BUF_MAX,
                plaintext_chunk.data(),chunk_len,(int)(signed char)compress_level);
            if(ZSTD_isError(cflen)) {
                fprintf(stderr,"zstd compress failed (chunk %u): %s\n",i,ZSTD_getErrorName(cflen));
                ok=false; break;
            }
            aead_in=comp_chunk.data();
            aead_in_len=cflen;
#else
            fprintf(stderr,"Compression requested but zstd not linked (chunk %u)\n",i);
            ok=false; break;
#endif
        }

        unsigned long long ciphertext_len=0;
        int rc;
        if(mode==CryptoMode::AES_GCM) {
            rc=crypto_aead_aes256gcm_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                aead_in,aead_in_len,aad.data(),aad.size(),NULL,nonce,key.data());
            if(rc!=0) fprintf(stderr,"AES-GCM encryption failed at chunk %u\n",i);
        }
        else if(mode==CryptoMode::AEGIS256) {
            rc=crypto_aead_aegis256_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                aead_in,aead_in_len,aad.data(),aad.size(),NULL,nonce,key.data());
            if(rc!=0) fprintf(stderr,"AEGIS-256 encryption failed at chunk %u\n",i);
        }
        else {
            rc=crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                aead_in,aead_in_len,aad.data(),aad.size(),NULL,nonce,key.data());
            if(rc!=0) fprintf(stderr,"XChaCha20 encryption failed at chunk %u\n",i);
        }
        if(rc!=0) { ok=false; break; }

        if(do_compress) {
            unsigned char lenbuf[4];
            put_le32(lenbuf,(uint32_t)ciphertext_len);
            if(!outbuf.put(lenbuf,4)) {
                fprintf(stderr,"Write compressed length prefix failed at chunk %u\n",i);
                ok=false; break;
            }
        }
        if(!outbuf.put(ciphertext_chunk.data(),ciphertext_len)) {
            fprintf(stderr,"Write ciphertext failed at chunk %u\n",i);
            ok=false; break;
        }

        processed_bytes+=chunk_len;
        throttle_consume(chunk_len);
        // 逐块 save_progress 曾拖垮吞吐，改为按 500ms 节流：先 flush 密文再记账，
        // 保持「磁盘 .prt ≥ .prs 记账」不变式；强杀时截断到记账处重算。
        auto prs_now=std::chrono::steady_clock::now();
        if(persistent_progress && prs_now-last_prs_save>=std::chrono::milliseconds(500)) {
            outbuf.flush();   // 先落盘密文再记账进度（带 HMAC），保持「磁盘 .prt ≥ .prs」不变式
            if(!save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
                fprintf(stderr,"Failed to save progress at chunk %u\n",i);
            }
            last_prs_save=prs_now;
        }

        if(progress_callback) progress_callback(processed_bytes,total_size);
        else print_progress(processed_bytes,total_size,start_time);

        if(i+1<total_chunks) sodium_increment(nonce,iv_len);
    }

    if(ok) {
        // 结束哈希并回填 plaintext_hash；文件头 HMAC 已在写头瞬间算好（覆盖区由 hdr_cover 决定，
        // v6=192 / v5=63 / v4=61 字节），此处仅重算一遍（前缀未变，结果一致）后随 plaintext_hash 写回。
        crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(key.data(),hdr_auth);
        crypto_auth(header.header_hmac,
            reinterpret_cast<const unsigned char*>(&header),hdr_cover,hdr_auth);
        outbuf.flush();   // 先把缓冲的密文落盘，再回头写头部哈希 / HMAC
        size_t hdr_size = use_v6 ? HEADER_SIZE_V6
                        : (do_compress?HEADER_SIZE_V5:HEADER_SIZE_V4);
        fout.seekp((std::streamoff)(hdr_size-HASH_SIZE-HEADER_HMAC_SIZE),std::ios::beg);
        fout.write(reinterpret_cast<const char*>(header.plaintext_hash),HASH_SIZE);
        fout.write(reinterpret_cast<const char*>(header.header_hmac),HEADER_HMAC_SIZE);
        fout.flush();
        if(!append_encrypted_name_footer(fout,in_path,key.data(),header.salt)) {
            fprintf(stderr,"Failed to append encrypted original-name footer.\n");
            ok=false;
        }
    }
    else {
        crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
    }

cleanup:
    secure_clear(plaintext_chunk);
    secure_clear(ciphertext_chunk);

    fin.close();
    if(fout.is_open()) { outbuf.flush(); fout.close(); }

    if(ok) {
        remove_progress(out_path);
        if(!progress_callback) print_progress(total_size,total_size,start_time,true);

        // 自解密验证：复用本次已派生的密钥（key），边解密边计算明文哈希，
        // 不再落盘 .verify.tmp，消除 4 倍 I/O（写明文 + 读回 + 哈希 + 删除）。
        bool verify_ok=decrypt_file(out_path, out_path, password,
            [](size_t,size_t){}, true, false, key.data(), nullptr, 0, true);
        if(!verify_ok) {
            ok=false;
            remove_file_utf8(out_path);
            remove_progress(out_path);
            fprintf(stderr,"Self-decrypt verification failed, output removed.\n");
        }
    }
    else {
        remove_file_utf8(out_path);
        remove_progress(out_path);
        fprintf(stderr,"Encryption failed, output removed.\n");
    }

    // 自校验已结束（期间复用了派生密钥 key）。密钥与认证密钥均由 SecureBuffer 持有，
    // 函数返回时析构自动 sodium_memzero + sodium_munlock，无需手动清零。
    return ok;
}

// ---------- 解密 ----------
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    std::function<void(size_t,size_t)> progress_callback,
    bool silent,
    bool resume,
    const unsigned char* ext_key,
    const unsigned char* ext_kek, size_t ext_kek_len,
    bool verify_only) {
    disable_core_dump();

    // 依据 YAML 配置校验输入/输出路径（长度上限 / 白名单）
    if(!validate_io_paths(in_path,out_path,silent)) {
        if(!silent) fprintf(stderr,"Path validation failed (config policy)\n");
        return false;
    }

    // 防路径穿越：输出路径若含未解析的 ".." 分量则拒绝
    if(path_has_traversal(out_path)) {
        if(!silent) fprintf(stderr,"Output path contains directory traversal\n");
        return false;
    }
    if(password.size()<PASSWORD_MIN_LEN) {
        if(!silent) fprintf(stderr,"Password too short (min %zu characters)\n",PASSWORD_MIN_LEN);
        return false;
    }

    // 输入侧 4 MiB 页对齐大缓冲（先于 fin 声明，析构时 fin 先销毁，缓冲存活期覆盖流）
    InputBuffer fin_buf;
    std::ifstream fin;
    if(!open_stream(fin,in_path,std::ios::binary)) {
        if(!silent) fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }
    fin_buf.attach(fin);
    fin.seekg(0,std::ios::end);
    auto file_size=fin.tellg();
    fin.seekg(0,std::ios::beg);

    // 版本感知的头部解析：先读 magic+version，再按版本读取剩余头部。
    // 缓冲须容纳最大头部（v6 = 256 字节）
    unsigned char hdrbuf[320];
    size_t hdr_size=0;
    unsigned int kdf_ops=ARGON2_OPS_LEGACY;
    size_t kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    CryptoMode mode=CryptoMode::AES_GCM;
    size_t iv_len=0;
    const unsigned char* salt_ptr=nullptr;
    const unsigned char* iv_ptr=nullptr;
    unsigned char stored_hash[HASH_SIZE]={0};
    bool have_hash=false;
    unsigned char hdr_hmac[HEADER_HMAC_SIZE]={0};
    bool is_v4=false;
    bool is_v5=false;          // v5 头部（含压缩标记）
    bool is_v6=false;          // v6 容器头部（DEK 由 KEK 包裹）
    bool comp_on=false;        // 本文件已启用 zstd 压缩（v5 + compression==1）
    int comp_level_val=0;      // 已编码的 zstd 压缩级别（有符号，支持负快速档）
    uint32_t v6_key_version=0; // v6 密钥版本（仅 is_v6 时有效）

    // strict-aliasing 安全：头部由字节缓冲 memcpy 到函数级局部结构再读字段；
    // salt/iv 指针指向这些结构（生命周期覆盖整个函数，避免分支作用域悬挂指针）。
    FileHeaderV1 hv1{}; FileHeaderV2 hv2{}; FileHeaderV3 hv3{};
    FileHeaderV4 hv4{}; FileHeaderV5 hv5{}; FileHeaderV6 hv6{};

    // 密钥相关缓冲区提前声明，供异常跳转（dec_cleanup）安全清理
    SecureBuffer key(ARGON2_OUTPUT_LEN);
    SecureBuffer auth_key(crypto_auth_KEYBYTES);

    if(!fin.read(reinterpret_cast<char*>(hdrbuf),5)) {
        if(!silent) fprintf(stderr,"Read header failed\n");
        return false;
    }
    if(memcmp(hdrbuf,MAGIC,4)!=0) {
        if(!silent) fprintf(stderr,"Invalid magic\n");
        return false;
    }
    unsigned char ver=hdrbuf[4];
    if(ver==1) {
        hdr_size=HEADER_SIZE_V1;
        if(file_size<(std::streampos)(hdr_size+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
            return false;
        }
        if(!fin.read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
            if(!silent) fprintf(stderr,"Read header failed\n");
            return false;
        }
        hv1=load_header<FileHeaderV1>(hdrbuf);
        mode=static_cast<CryptoMode>(hv1.mode);
        iv_len=hv1.iv_len;
        salt_ptr=hv1.salt;
        iv_ptr=hv1.iv;
        kdf_ops=ARGON2_OPS_LEGACY;
        kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    }
    else if(ver==2) {
        hdr_size=HEADER_SIZE_V2;
        if(file_size<(std::streampos)(hdr_size+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
            return false;
        }
        if(!fin.read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
            if(!silent) fprintf(stderr,"Read header failed\n");
            return false;
        }
        hv2=load_header<FileHeaderV2>(hdrbuf);
        mode=static_cast<CryptoMode>(hv2.mode);
        iv_len=hv2.iv_len;
        salt_ptr=hv2.salt;
        iv_ptr=hv2.iv;
        kdf_ops=hv2.opslimit;
        kdf_mem=(size_t)hv2.memlimit_kb*1024;
    }
    else if(ver==3) {
        hdr_size=HEADER_SIZE_V3;
        if(file_size<(std::streampos)(hdr_size+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
            return false;
        }
        if(!fin.read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
            if(!silent) fprintf(stderr,"Read header failed\n");
            return false;
        }
        hv3=load_header<FileHeaderV3>(hdrbuf);
        mode=static_cast<CryptoMode>(hv3.mode);
        iv_len=hv3.iv_len;
        salt_ptr=hv3.salt;
        iv_ptr=hv3.iv;
        kdf_ops=hv3.opslimit;
        kdf_mem=(size_t)hv3.memlimit_kb*1024;
        memcpy(stored_hash,hv3.plaintext_hash,HASH_SIZE);
        have_hash=true;
    }
    else if(ver==VERSION) {
        // v4：v3 前缀 + 32 字节 header_hmac（独立密钥认证文件头，防篡改）
        hdr_size=HEADER_SIZE_V4;
        if(file_size<(std::streampos)(hdr_size+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
            return false;
        }
        if(!fin.read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
            if(!silent) fprintf(stderr,"Read header failed\n");
            return false;
        }
        hv4=load_header<FileHeaderV4>(hdrbuf);
        mode=static_cast<CryptoMode>(hv4.mode);
        iv_len=hv4.iv_len;
        salt_ptr=hv4.salt;
        iv_ptr=hv4.iv;
        kdf_ops=hv4.opslimit;
        kdf_mem=(size_t)hv4.memlimit_kb*1024;
        memcpy(stored_hash,hv4.plaintext_hash,HASH_SIZE);
        memcpy(hdr_hmac,hv4.header_hmac,HEADER_HMAC_SIZE);
        have_hash=true;
        is_v4=true;
    }
    else if(ver==5) {
        // v5：v4 基础上追加 2 字节压缩描述（compression / comp_level），磁盘为变长块
        hdr_size=HEADER_SIZE_V5;
        if(file_size<(std::streampos)(hdr_size+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
            return false;
        }
        if(!fin.read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
            if(!silent) fprintf(stderr,"Read header failed\n");
            return false;
        }
        hv5=load_header<FileHeaderV5>(hdrbuf);
        mode=static_cast<CryptoMode>(hv5.mode);
        iv_len=hv5.iv_len;
        salt_ptr=hv5.salt;
        iv_ptr=hv5.iv;
        kdf_ops=hv5.opslimit;
        kdf_mem=(size_t)hv5.memlimit_kb*1024;
        memcpy(stored_hash,hv5.plaintext_hash,HASH_SIZE);
        memcpy(hdr_hmac,hv5.header_hmac,HEADER_HMAC_SIZE);
        have_hash=true;
        is_v5=true;
        comp_on=(hv5.compression==1);
        comp_level_val=(int)(signed char)hv5.comp_level;
    }
    else if(ver==6) {
        // v6 容器：前缀与 v5 完全一致（magic..comp_level），其后是 DEK 包裹容器区
        hdr_size=HEADER_SIZE_V6;
        if(file_size<(std::streampos)(hdr_size+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
            return false;
        }
        if(!fin.read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
            if(!silent) fprintf(stderr,"Read header failed\n");
            return false;
        }
        hv6=load_header<FileHeaderV6>(hdrbuf);
        mode=static_cast<CryptoMode>(hv6.mode);
        iv_len=hv6.iv_len;
        salt_ptr=hv6.salt;
        iv_ptr=hv6.iv;
        kdf_ops=hv6.opslimit;
        kdf_mem=(size_t)hv6.memlimit_kb*1024;
        memcpy(stored_hash,hv6.plaintext_hash,HASH_SIZE);
        memcpy(hdr_hmac,hv6.header_hmac,HEADER_HMAC_SIZE);
        have_hash=true;
        is_v6=true;
        comp_on=(hv6.compression==1);
        comp_level_val=(int)(signed char)hv6.comp_level;
        v6_key_version=get_be32(reinterpret_cast<const unsigned char*>(&hv6.key_version));
    }
    else {
        if(!silent) fprintf(stderr,"Unsupported file version: %u\n",ver);
        return false;
    }

    // 严格校验加密模式：仅允许已知枚举值，未知值直接拒绝（否则后续的 IV 长度校验会被整体短路跳过）
    if(mode!=CryptoMode::AES_GCM&&mode!=CryptoMode::XCHACHA20&&mode!=CryptoMode::AEGIS256) {
        if(!silent) fprintf(stderr,"Invalid encryption mode in header\n");
        return false;
    }
    // 兜底：IV 长度不得超过缓冲区，防止后续 memcpy(nonce, iv_ptr, iv_len) 越界读取
    size_t tag_size=tag_size_for_mode(mode);
    if(iv_len>32) {
        if(!silent) fprintf(stderr,"Invalid IV length (too large)\n");
        return false;
    }
    // 旧格式（v1/v2）头部 iv 字段仅 24 字节；若文件声称更大，后续 memcpy(nonce,iv,iv_len)
    // 会越界读到相邻未初始化栈区。直接拒绝，避免按越界长度拷贝（此类文件本就无法解密）。
    if((ver==1||ver==2) && iv_len>24) {
        if(!silent) fprintf(stderr,"Invalid IV length for legacy header\n");
        return false;
    }
    if((mode==CryptoMode::AES_GCM&&iv_len!=AES_GCM_IV_LEN)||
        (mode==CryptoMode::XCHACHA20&&iv_len!=XCHACHA20_IV_LEN)||
        (mode==CryptoMode::AEGIS256&&iv_len!=AEGIS256_IV_LEN)) {
        if(!silent) fprintf(stderr,"Invalid IV length\n");
        return false;
    }

    uint32_t chunk_size=0,total_chunks=0;
    uint64_t orig_size=0;
    if(!fin.read(reinterpret_cast<char*>(&chunk_size),4)||
        !fin.read(reinterpret_cast<char*>(&total_chunks),4)||
        !fin.read(reinterpret_cast<char*>(&orig_size),8)) {
        if(!silent) fprintf(stderr,"Read metadata failed\n");
        return false;
    }

    if(chunk_size!=CHUNK_SIZE) {
        if(!silent) {
            fprintf(stderr,"Invalid chunk_size: %u (expected %zu). File may be corrupted.\n",
                chunk_size,CHUNK_SIZE);
        }
        return false;
    }

    // 派生密钥（提前到空文件短路之前，以便 v4 文件头 HMAC 校验对空文件也生效）。
    // 同时计算源文件绑定标识，供 .prs 防重放校验使用。
    std::string prog_binding = compute_progress_binding(in_path);
    // ext_kek：外部已派生 KEK（批量复用，跳过 Argon2id）；非 v6 即载荷密钥，v6 需解裹 DEK。
    // ext_key：外部最终密钥（自校验用），直接复用跳过 KDF 与解裹。
    const bool have_kek = (ext_kek && ext_kek_len >= ARGON2_OUTPUT_LEN);
    if(is_v6) {
        // v6 容器：KEK 解裹 DEK（同时校验口令正确性），DEK 即载荷密钥。
        if(have_kek) {
            unsigned char dek[32];
            if(!unwrap_dek(hv6.dek_box, ext_kek, hv6.dek_nonce, dek)) {
                report_auth_error(silent, "Failed to unwrap DEK (wrong password or corrupted container).");
                return false;
            }
            memcpy(key.data(), dek, 32);
            sodium_memzero(dek, sizeof(dek));
        } else if(ext_key) {
            memcpy(key.data(), ext_key, ARGON2_OUTPUT_LEN);   // 自校验：ext_key 即 DEK
        } else {
            SecureBuffer kek(ARGON2_OUTPUT_LEN);
            if(!derive_key(password.data(),password.size(),salt_ptr,kek.data(),kdf_ops,kdf_mem)) {
                if(!silent) fprintf(stderr,"Key derivation failed\n");
                return false;
            }
            unsigned char dek[32];
            if(!unwrap_dek(hv6.dek_box, kek.data(), hv6.dek_nonce, dek)) {
                report_auth_error(silent, "Failed to unwrap DEK (wrong password or corrupted container).");
                sodium_memzero(kek.data(), kek.size());
                return false;
            }
            memcpy(key.data(), dek, 32);
            sodium_memzero(dek, sizeof(dek));
            sodium_memzero(kek.data(), kek.size());
        }
        derive_progress_auth_key(key.data(), auth_key.data());
    } else if(have_kek || ext_key) {
        // 非 v6：外部密钥即载荷密钥，直接复用
        if(ext_key) memcpy(key.data(), ext_key, ARGON2_OUTPUT_LEN);
        else        memcpy(key.data(), ext_kek, ARGON2_OUTPUT_LEN);
        derive_progress_auth_key(key.data(), auth_key.data());
    } else if(!derive_key(password.data(),password.size(),salt_ptr,key.data(),kdf_ops,kdf_mem)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    } else {
        derive_progress_auth_key(key.data(), auth_key.data());
    }

    // v4/v5/v6 文件头 HMAC 校验：独立于 AEAD，防文件头被篡改（替换 salt/iv/mode 后重放）。
    // v6 由 DEK 派生密钥、覆盖至 reserved 区，须在解裹 DEK 后、明文输出前完成（失败只给通用错误）。
    if(is_v4 || is_v5 || is_v6) {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(key.data(), hdr_auth);
        if(crypto_auth_verify(hdr_hmac, hdrbuf, header_hmac_cover(ver), hdr_auth)!=0) {
            report_auth_error(silent, "Header authentication failed (file tampered or wrong key).");
            return false;
        }
    }

    // 跨进程锁 + 临时文件：解密先将明文写入 <out>.prt，全部校验通过后再原子重命名
    std::string part_path=out_path+".prt";
    // 防符号链接劫持：若 .prt 半成品已存在且为符号链接/重解析点，拒绝写入，避免清空被指向的敏感文件
    if(!verify_only && path_is_symlink(part_path)) {
        if(!silent) fprintf(stderr,"Refusing to write through existing symlink: %s\n",part_path.c_str());
        return false;
    }
    std::string lock_path;
    OutputLockGuard lock_guard;   // 函数作用域 RAII；verify_only 下不取锁、不写文件
    if(!verify_only) {
        LockResult lr=acquire_output_lock(out_path,lock_path);
        if(lr!=LockResult::OK) {
            if(!silent) {
                if(lr==LockResult::LOCKED)
                    fprintf(stderr,"Output file is locked by another process: %s\n",out_path.c_str());
                else
                    fprintf(stderr,"Cannot create output lock file (permission or path issue): %s\n",lock_path.c_str());
            }
            return false;
        }
        lock_guard.path=lock_path;
        lock_guard.owned=true;
    }

    // 密文末尾可能附加加密的原始文件名信封，大小校验必须把它计入
    uint64_t footer_len=0;
    peek_name_footer_len(in_path, footer_len);

    uint64_t total_size=orig_size;
    if(total_chunks==0) {
        if((size_t)file_size!=hdr_size+4+4+8+footer_len) {
            if(!silent) fprintf(stderr,"File size mismatch for empty file.\n");
            return false;
        }
        if(verify_only) {
            // 自校验空文件：不落盘，仅比对空哈希（无明文内容）
            if(have_hash) {
                unsigned char empty_hash[HASH_SIZE];
                crypto_generichash(empty_hash,HASH_SIZE,nullptr,0,nullptr,0);
                if(memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) return false;
            }
            return true;
        }
        std::ofstream fout;
        if(!open_stream(fout,part_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(part_path);
        fout.close();
        remove_progress(out_path);
        // 空文件无明文内容，直接原子落盘
        if(!replace_file_utf8(part_path,out_path)) {
            if(!silent) fprintf(stderr,"Failed to finalize output file: %s\n",out_path.c_str());
            remove_file_utf8(part_path);
            return false;
        }
        // 空文件完整性校验（v3）
        if(have_hash) {
            unsigned char empty_hash[HASH_SIZE];
            crypto_generichash(empty_hash,HASH_SIZE,nullptr,0,nullptr,0);
            if(memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) {
                report_auth_error(silent, "Plaintext integrity check failed (empty file).");
                remove_file_utf8(out_path);
                return false;
            }
        }
        return true;
    }

    uint64_t last_chunk_len=orig_size-(uint64_t)(total_chunks-1)*chunk_size;
    // 压缩文件（v5+压缩）为变长块，无法在解密前从文件头推断总密文长度，跳过此固定校验
    if(!comp_on) {
        uint64_t expected_size=(uint64_t)hdr_size+4+4+8
            +(uint64_t)(total_chunks-1)*(uint64_t)(chunk_size+tag_size)
            +(uint64_t)last_chunk_len+tag_size+footer_len;
        if((uint64_t)file_size!=expected_size) {
            if(!silent) {
                fprintf(stderr,"File size mismatch: expected %llu, got %llu. File corrupted.\n",
                    (unsigned long long)expected_size,(unsigned long long)file_size);
            }
            return false;
        }
    }

    ProgressInfo prog_info={0,0,0,0,{0}};
    // 续传需要“进度文件”与“对应的 .prt 半成品”同时齐备，否则视为全新开始
    bool has_progress=false;
    if(resume && load_progress_raw(out_path,prog_info) && file_exists(part_path)) {
        // 密钥与进度 HMAC 密钥已在前面（空文件短路之前）派生到 key / auth_key，此处直接复用，
        // 并把源文件绑定标识（规范化路径 + 大小 + mtime）纳入 HMAC 校验，防重放。
        if(verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
            && prog_info.processed_chunks<=total_chunks
            && prog_info.processed_bytes<=total_size) {
            has_progress=true;
        } else {
            if(!silent) fprintf(stderr,"Corrupted progress file detected, restarting from beginning.\n");
        }
    }
    uint64_t start_chunk=has_progress ? prog_info.processed_chunks : 0;
    uint64_t start_bytes=has_progress ? prog_info.processed_bytes : 0;

    // 解密续传：明文半成品（.prt）可能残留未完成块的残片，截断到已确认写入的明文长度
    std::fstream fout;
    if(verify_only) {
        // 自校验模式：不创建/写入任何明文文件，仅流式计算哈希
    }
    else if(has_progress&&start_chunk>0) {
        if(!truncate_file(part_path,start_bytes)) {
            if(!silent) fprintf(stderr,"Failed to truncate partial output for resume: %s\n",part_path.c_str());
            return false;
        }
        if(!open_stream(fout,part_path,std::ios::in|std::ios::out|std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot open output file for resume: %s\n",out_path.c_str());
            return false;
        }
        fout.seekp((std::streamoff)start_bytes,std::ios::beg);
    }
    else {
        if(!open_stream(fout,part_path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(part_path);
        remove_progress(out_path);
    }

    // 4 MiB 聚合写出缓冲：明文块写入 outbuf，攒满 4 MiB 再写盘（verify_only 下不绑定，空操作）
    AggWriter outbuf;
    if(!verify_only) outbuf.bind(fout);

    // 密钥已在前面（空文件短路之前）派生到 key / auth_key，此处无需重复派生。

    // AAD 须严格复刻加密端构造：v5 覆盖到压缩标记，v4/v3 到 iv；
    // v6 只到稳定前缀（不含容器区，rewrap 改写容器不使载荷 AAD 失效）。
    size_t aad_hdr_len=(ver==6) ? HEADER_AAD_COVER_V6 : header_hmac_cover(ver);
    std::vector<unsigned char> aad=build_aad_with_metadata(hdrbuf,aad_hdr_len,chunk_size,total_chunks,orig_size);

    auto start_time=std::chrono::steady_clock::now();
    // .prs 节流基点：进度文件只服务"进程被强杀后的断点续传"，无需逐块落盘。
    auto last_prs_save=std::chrono::steady_clock::now();
    // 压缩块密文上界为 ZSTD_compressBound(CHUNK_SIZE)+tag；未压缩块为 CHUNK_SIZE+tag
    std::vector<unsigned char> ciphertext_chunk((comp_on?COMP_BUF_MAX:chunk_size)+MAX_TAG_SIZE);
    std::vector<unsigned char> plaintext_chunk(COMP_BUF_MAX);  // AEAD 输出暂存（压缩帧，上界 COMP_BUF_MAX）
    std::vector<unsigned char> dec_chunk(chunk_size);          // zstd 解压后的最终明文（仅压缩模式使用）
    unsigned char nonce[32]={0};
    bool ok=true;
    uint64_t processed_bytes=start_bytes;
    // 小于 64 MiB 的文件跳过进度文件写入（见 encrypt_file 同款说明）
    bool persistent_progress=(total_size>=64ULL*1024*1024);

    // 提前声明，避免 goto dec_cleanup 跨过带初始化的变量
    bool use_increment=(ver==VERSION || ver==5 || ver==6);
    size_t input_offset=0;

    // 防整数溢出 / 越界：input_offset 来自文件头（v3 未被 HMAC 认证）或续传进度，
    // 须边界校验后再 seekg。先以 uint64_t 做乘法溢出检查，再确认落在文件范围内。
    {
        const uint64_t base = (uint64_t)hdr_size + 4 + 4 + 8;
        if(comp_on && start_chunk>0) {
            // 变长块（v5+压缩）：扫描每块的 4 字节压缩帧长度前缀求断点偏移
            uint64_t off=0; bool scan_ok=true;
            std::ifstream ef;
            if(open_stream(ef,in_path,std::ios::binary) && ef.seekg((std::streamoff)base)) {
                for(uint32_t i=0;i<start_chunk;++i) {
                    uint32_t cl=0;
                    if(!ef.read(reinterpret_cast<char*>(&cl),4) || ef.gcount()!=4) { scan_ok=false; break; }
                    off += 4 + (uint64_t)cl;
                }
                ef.close();
            } else scan_ok=false;
            if(!scan_ok) { if(!silent) fprintf(stderr,"Resume scan failed (corrupted file?)\n"); ok=false; goto dec_cleanup; }
            uint64_t off_total = base + off;
            if(off_total > (uint64_t)file_size) { if(!silent) fprintf(stderr,"Seek offset out of range (corrupted header?)\n"); ok=false; goto dec_cleanup; }
            input_offset=(size_t)off_total;
        } else {
            const uint64_t stride = (uint64_t)chunk_size + (uint64_t)tag_size;
            uint64_t off = base;
            if(stride != 0 && start_chunk > ((uint64_t)-1 - base) / stride) {
                if(!silent) fprintf(stderr,"Seek offset overflow (corrupted header?)\n");
                ok=false; goto dec_cleanup;
            }
            off += (uint64_t)start_chunk * stride;
            if(off > (uint64_t)file_size) {
                if(!silent) fprintf(stderr,"Seek offset out of range (corrupted header?)\n");
                ok=false; goto dec_cleanup;
            }
            input_offset = (size_t)off;
        }
    }

    // 明文 Blake2b 流式哈希（续传时先回放 .prt 前缀）
    crypto_generichash_state hstate;
    if(have_hash || verify_only) crypto_generichash_init(&hstate,nullptr,0,HASH_SIZE);
    if((have_hash || verify_only) && start_bytes>0) {
        std::ifstream pin;
        if(!open_stream(pin,part_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot open .prt for hash catch-up\n");
            ok=false;
        }
        else {
            uint64_t remain=start_bytes;
            std::vector<unsigned char> tmp(CHUNK_SIZE);
            while(remain>0 && ok) {
                size_t n=(size_t)std::min<uint64_t>(CHUNK_SIZE,remain);
                pin.read(reinterpret_cast<char*>(tmp.data()),n);
                if(pin.gcount()!=(std::streamsize)n) {
                    if(!silent) fprintf(stderr,"Read .prt for hash catch-up failed\n");
                    ok=false; break;
                }
                crypto_generichash_update(&hstate,tmp.data(),n);
                remain-=n;
            }
            pin.close();
        }
        if(!ok) goto dec_cleanup;
    }

    fin.seekg(input_offset,std::ios::beg);

    // 初始化 nonce：v3 用 sodium_increment 递增；旧格式用 iv XOR 块索引
    memcpy(nonce,iv_ptr,iv_len);
    if(use_increment) {
        for(uint32_t k=0;k<start_chunk;++k) sodium_increment(nonce,iv_len);
    }
    else {
        uint64_t idx=start_chunk;
        for(int j=0; j<8&&j<(int)iv_len; ++j) nonce[iv_len-1-j]^=(unsigned char)((idx>>(j*8))&0xFF);
    }

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
        if(processed_bytes>=total_size) break;
        size_t chunk_len=std::min<size_t>(chunk_size,(size_t)(total_size-processed_bytes));
        // 读本块密文：压缩块（v5+压缩）带 4 字节长度前缀，前缀值 = 本块 AEAD 密文长度（含 tag），
        // 故记录为 4 + cl；未压缩块为固定块长 chunk_len + tag_size。
        size_t expected_cipher_len;
        if(comp_on) {
            uint32_t cl=0;
            if(!fin.read(reinterpret_cast<char*>(&cl),4) || fin.gcount()!=4) {
                if(!silent) fprintf(stderr,"Read compressed length prefix failed at chunk %u\n",i);
                ok=false; break;
            }
            expected_cipher_len=(size_t)cl;
        } else {
            expected_cipher_len=chunk_len+tag_size;
        }
        if(expected_cipher_len > ciphertext_chunk.size()) {
            if(!silent) fprintf(stderr,"Ciphertext length overflow at chunk %u\n",i);
            ok=false; break;
        }
        fin.read(reinterpret_cast<char*>(ciphertext_chunk.data()),expected_cipher_len);
        if(fin.gcount()!=(std::streamsize)expected_cipher_len) {
            if(!silent) fprintf(stderr,"Read ciphertext chunk %u failed\n",i);
            ok=false;
            break;
        }

        if(!use_increment) {
            // 旧格式：每块重算 nonce = iv XOR i
            memcpy(nonce,iv_ptr,iv_len);
            uint64_t idx=i;
            for(int j=0; j<8&&j<(int)iv_len; ++j) nonce[iv_len-1-j]^=(unsigned char)((idx>>(j*8))&0xFF);
        }

        unsigned long long frame_len=0;   // AEAD 输出长度（压缩帧或未压缩明文）
        int rc;
        if(mode==CryptoMode::AES_GCM) {
            rc=crypto_aead_aes256gcm_decrypt(plaintext_chunk.data(),&frame_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key.data());
            if(rc!=0) report_auth_error(silent, "AES-GCM decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        }
        else if(mode==CryptoMode::AEGIS256) {
            rc=crypto_aead_aegis256_decrypt(plaintext_chunk.data(),&frame_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key.data());
            if(rc!=0) report_auth_error(silent, "AEGIS-256 decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        }
        else {
            rc=crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext_chunk.data(),&frame_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key.data());
            if(rc!=0) report_auth_error(silent, "XChaCha20 decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        }
        if(rc!=0) { ok=false; break; }

        // 解压（仅压缩块）：zstd 解压后的长度应等于本块明文长度 chunk_len
        const unsigned char* out_ptr=plaintext_chunk.data();
        size_t out_len=(size_t)frame_len;
        if(comp_on) {
#ifdef FE_WITH_ZSTD
            unsigned long long dl=ZSTD_decompress(dec_chunk.data(),chunk_len,plaintext_chunk.data(),frame_len);
            if(ZSTD_isError(dl)) {
                report_auth_error(silent, "zstd decompression failed at chunk " + std::to_string(i) + ".");
                ok=false; break;
            }
            if((size_t)dl!=chunk_len) {
                report_auth_error(silent, "Decompressed size mismatch at chunk " + std::to_string(i) + ".");
                ok=false; break;
            }
            out_ptr=dec_chunk.data();
            out_len=chunk_len;
#else
            report_auth_error(silent, "This file uses zstd compression but the binary was built without zstd.");
            ok=false; break;
#endif
        }

        if(!verify_only && !outbuf.put(out_ptr,out_len)) {
            if(!silent) fprintf(stderr,"Write plaintext chunk %u failed\n",i);
            ok=false;
            break;
        }
        if(have_hash || verify_only) crypto_generichash_update(&hstate,out_ptr,out_len);

        processed_bytes+=out_len;
        throttle_consume(out_len);
        // 逐块 save_progress 曾拖垮吞吐，改为 500ms 节流：先 flush 明文再记账，
        // 保持「磁盘 .prt ≥ .prs」不变式；verify_only 不落盘不写进度。
        if(!verify_only && persistent_progress) {
            auto prs_now=std::chrono::steady_clock::now();
            if(prs_now-last_prs_save>=std::chrono::milliseconds(500)) {
                outbuf.flush();   // 先落盘明文再记账进度（带 HMAC）
                if(!save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
                    if(!silent) fprintf(stderr,"Failed to save progress at chunk %u\n",i);
                }
                last_prs_save=prs_now;
            }
        }

        if(progress_callback) {
            progress_callback(processed_bytes,total_size);
        }
        else {
            print_progress(processed_bytes,total_size,start_time);
        }

        if(use_increment) {
            if(i+1<total_chunks) sodium_increment(nonce,iv_len);
        }
    }

    // 明文完整性校验：恢复的明文 Blake2b 必须与存储哈希一致
    if(have_hash || verify_only) {
        unsigned char final_hash[HASH_SIZE];
        crypto_generichash_final(&hstate,final_hash,HASH_SIZE);
        if(ok && have_hash && sodium_memcmp(final_hash,stored_hash,HASH_SIZE)!=0) {
            report_auth_error(silent, "Plaintext integrity check failed: recovered data does not match original.");
            ok=false;
        }
        // 自校验模式：无存储哈希可比对（理论上恒为 have_hash）时，至少核对总长度
        if(ok && verify_only && (uint64_t)processed_bytes!=(uint64_t)total_size) {
            if(!silent) fprintf(stderr,"Self-verify size mismatch.\n");
            ok=false;
        }
    }

dec_cleanup:
    // key / auth_key 由 SecureBuffer 持有，函数返回时析构自动 sodium_memzero + sodium_munlock，
    // 任何 return / goto 路径都已安全清理，无需在此手动清零。
    secure_clear(ciphertext_chunk);
    secure_clear(plaintext_chunk);

    fin.close();
    outbuf.flush();   // 把缓冲的明文落盘（verify_only 下为空操作）
    fout.close();

    if(verify_only) {
        // 自校验模式：不落盘、不替换、不删除任何文件，仅返回校验结果
        return ok;
    }
    if(ok) {
        remove_progress(out_path);
        // 防符号链接劫持
        if(path_is_symlink(out_path)) {
            if(!silent) fprintf(stderr,"Refusing to overwrite existing symlink: %s\n",out_path.c_str());
            ok=false;
            remove_file_utf8(part_path);
        }
        else if(!replace_file_utf8(part_path,out_path)) {
            ok=false;
            if(!silent) fprintf(stderr,"Failed to finalize output file: %s\n",out_path.c_str());
        }
        if(ok&&!progress_callback) {
            print_progress(total_size,total_size,start_time,true);
        }
    }
    if(!ok) {
        // 失败时只删除半成品（.prt），最终输出路径不写入任何明文
        remove_file_utf8(part_path);
        remove_progress(out_path);
        if(!silent) {
            fprintf(stderr,"Decryption failed, partial output removed.\n");
        }
    }
    return ok;
}

// ---------- 目录遍历 ----------
#ifdef _WIN32
#include <io.h>
#else
#include <dirent.h>
#endif

static bool is_directory(const std::string& path) {
#ifdef _WIN32
    struct _stat64 st;
    if(_wstat64(utf8_to_wstring(path).c_str(),&st)!=0) return false;
    return (st.st_mode&S_IFDIR)!=0;
#else
    struct stat st;
    if(stat(path.c_str(),&st)!=0) return false;
    return (st.st_mode&S_IFDIR)!=0;
#endif
}

bool fe_path_is_directory(const std::string& path) { return is_directory(path); }

static void collect_files_from_dir(const std::string& dir,std::vector<std::string>& out_files,int depth=0) {
    // 防御：极端深的目录嵌套（>1024 层）会耗尽调用栈导致崩溃（DoS）。
    // 超过深度上限时跳过该子树并发出告警，而非继续递归。
    if(depth>1024) {
        std::cerr<<"Warning: directory nesting too deep, skipping: "<<dir<<"\n";
        return;
    }
#ifdef _WIN32
    std::wstring wpattern=utf8_to_wstring(dir+"\\*");
    struct _wfinddata_t fd;
    intptr_t handle=_wfindfirst(wpattern.c_str(),&fd);
    if(handle==-1) return;
    do {
        if(wcscmp(fd.name,L".")==0||wcscmp(fd.name,L"..")==0) continue;
        std::string name=wstring_to_utf8(fd.name);
        std::string full=dir+"\\"+name;
        // 跳过重解析点（junction/符号链接目录，属性位 0x0400），避免目录循环导致死递归
        if((fd.attrib&_A_SUBDIR)&&!(fd.attrib&0x0400)) {
            collect_files_from_dir(full,out_files,depth+1);
        }
        else {
            out_files.push_back(full);
        }
    } while(_wfindnext(handle,&fd)==0);
    _findclose(handle);
#else
    DIR* dp=opendir(dir.c_str());
    if(!dp) return;
    struct dirent* entry;
    while((entry=readdir(dp))!=nullptr) {
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0) continue;
        std::string full=dir+"/"+entry->d_name;
        struct stat st;
        if(lstat(full.c_str(),&st)==0) {
            if(S_ISLNK(st.st_mode)) {
                continue; // 跳过符号链接，避免目录循环
            }
            if(S_ISDIR(st.st_mode)) {
                collect_files_from_dir(full,out_files,depth+1);
            }
            else {
                out_files.push_back(full);
            }
        }
    }
    closedir(dp);
#endif
}

// ---------- 批量处理 ----------
static std::string build_batch_out_path(const std::string& in_path,
    const std::string& out_dir_clean,
    const std::vector<std::string>& input_paths, bool include_root_name) {
    std::string out_path=out_dir_clean+"/";
    std::string best_root;
    for(const auto& root:input_paths) {
        // 前缀匹配需带边界：root 后须紧跟分隔符或与 in_path 相同，
        // 否则 "D:\data" 会误匹配 "D:\database\x"。
        if(is_directory(root)&&in_path.length()>=root.length()&&
           in_path.compare(0,root.length(),root)==0&&
           (in_path.length()==root.length()||
            in_path[root.length()]=='/'||in_path[root.length()]=='\\')) {
            if(root.length()>best_root.length()) best_root=root;
        }
    }
    if(!best_root.empty()) {
        std::string suffix=in_path.substr(best_root.length());
        if(!suffix.empty()&&(suffix[0]=='/'||suffix[0]=='\\')) suffix.erase(0,1);
        // 加密保留输入根目录名作顶层；解密默认不附加（多输入根时即使解密也附加），
        // 避免多 -i 同名冲突。
        bool need_root_name=include_root_name||input_paths.size()>1;
        if(need_root_name) {
            size_t root_pos=best_root.find_last_of("/\\");
            std::string root_name=(root_pos!=std::string::npos) ? best_root.substr(root_pos+1) : best_root;
            if(!root_name.empty()) out_path+=root_name+"/";
        }
        out_path+=suffix;
    }
    else {
        size_t pos=in_path.find_last_of("/\\");
        std::string fname=(pos!=std::string::npos) ? in_path.substr(pos+1) : in_path;
        out_path+=fname;
    }
    // 路径穿越防御：复用 path_has_traversal 的组件法（覆盖前缀 “..” 与中间 “/..”，
    if(path_has_traversal(out_path)) return "";
    return out_path;
}

bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const SecureBuffer& password,
    CryptoMode mode,    bool encrypt,
    int source_action,
    bool force_overwrite,
    int num_threads,
    bool restore_name,
    int compress_level) {
    // 批量入口兜底：main.cpp 已处理 AEGIS-256 缺 AES-NI 的降级；若仍直达传入，
    // 不自动降级仅警告，交由调用方显式决定（避免自动化任务静默行为变更）。
    if(encrypt&&mode==CryptoMode::AEGIS256&&!aegis256_supported()) {
        fprintf(stderr,"Warning: AEGIS-256 unavailable on this CPU (AES-NI required); "
                       "proceeding as requested (will be very slow / side-channel weak). "
                       "Consider -m xchacha20.\n");
    }

    std::string out_dir_clean=out_dir;
    while(!out_dir_clean.empty()&&(out_dir_clean.back()=='/'||out_dir_clean.back()=='\\')) {
        out_dir_clean.pop_back();
    }
    // 非 ASCII（UTF-8 多字节）字节必须转成 unsigned char 再传给 isalpha，
    // 否则负 char 传入 C 字符分类函数是未定义行为（glibc 下可能越界查表）。
    if(out_dir_clean.size()==2&&isalpha((unsigned char)out_dir_clean[0])&&out_dir_clean[1]==':') {
        out_dir_clean+='\\';
    }
    if(!out_dir_clean.empty()&&!create_directory_recursive(out_dir_clean)) {
        fprintf(stderr,"Cannot create output directory: %s\n",out_dir_clean.c_str());
        return false;
    }

    std::vector<std::string> all_files;
    for(const auto& path:input_paths) {
        if(is_directory(path)) {
            collect_files_from_dir(path,all_files);
        }
        else {
            all_files.push_back(path);
        }
    }

    size_t non_ptd_skipped=0;   // 批量解密中被过滤掉的非 .ptd 文件数（计入 SKIP）
    // restore_name 批量解密：预扫描派生 KEK 后缓存，worker 复用（避免每文件 3 次 Argon2id → 1 次）
    std::unordered_map<std::string, std::vector<unsigned char>> kek_cache;
    if(!encrypt) {
        // 批量解密只处理 .ptd 文件，与单文件 -d 强制 .ptd 保持一致
        std::vector<std::string> filtered;
        size_t skipped=0;
        for(const auto& f:all_files) {
            std::string lower=f;
            // 仅对 ASCII 字节转小写：中文等 UTF-8 多字节字节值为负，
            // 直接传给 ::tolower 是未定义行为（Windows/Linux 均可能越界查表）。
            std::transform(lower.begin(),lower.end(),lower.begin(),
                [](unsigned char c){ return (char)std::tolower(c); });
            if(lower.size()>=4&&lower.compare(lower.size()-4,4,".ptd")==0) {
                filtered.push_back(f);
            } else {
                ++skipped;
            }
        }
        all_files=std::move(filtered);
        non_ptd_skipped=skipped;
        if(skipped>0) {
            fprintf(stderr,"Skipped %zu non-.ptd file(s) in batch decrypt.\n",skipped);
            log_event(LOG_WARN,"batch_skipped_non_ptd",{{"count",std::to_string(skipped)}});
        }
    }

    if(all_files.empty()) {
        fprintf(stderr,"No files found to process.\n");
        return false;
    }

    size_t total_bytes=0;
    // 预扫描尺寸缓存：worker 成功补进度时复用，免去每文件二次 stat（超大批量省 syscall）
    std::unordered_map<std::string,int64_t> size_cache;
    size_cache.reserve(all_files.size());
    for(const auto& f:all_files) {
        int64_t s=get_file_size_utf8(f);
        if(s>=0) { total_bytes+=(size_t)s; size_cache.emplace(f,s); }
    }

    printf("Total files: %zu, Total size: %s\n",all_files.size(),format_size((uint64_t)total_bytes).c_str());

    // 并发线程数优先取自 YAML 配置（worker_threads），否则回退到 CLI/自动
    int cfg_threads=global_config().worker_threads;
    if(cfg_threads>0) num_threads=cfg_threads;
    if(num_threads<=0) {
        num_threads=std::thread::hardware_concurrency();
        if(num_threads<=0) num_threads=4;
    }
    // 资源耗尽防御：限制同时打开的文件数。每个线程约持有 2 个句柄（输入 + 输出），
    // 故并发线程数不超过 max_open_files/3，避免批量/高并发场景句柄耗尽导致 DoS。
    if(global_config().max_open_files>0) {
        int cap=(int)(global_config().max_open_files/3);
        if(cap<1) cap=1;
        if(num_threads>cap) num_threads=cap;
    }
    printf("Using %d thread(s)\n",num_threads);
    log_event(LOG_INFO,"batch_start",
        {{"mode",encrypt?"encrypt":"decrypt"},
         {"files",std::to_string(all_files.size())},
         {"threads",std::to_string(num_threads)},
         {"total_bytes",std::to_string(total_bytes)}});

    std::vector<std::string> files_to_process;
    bool pre_scan_ok=true;   // 预扫描阶段的源处理失败，稍后并入 all_ok
    // 预扫描优化：单线程循环内可安全缓存"上次已确保存在的输出子目录"，
    // 避免数万文件逐个递归 stat 各级目录（此阶段在任何帧输出之前，曾表现为 GUI"进度停滞"）。
    std::string last_mkdir;
    size_t scan_idx=0;
    for(const auto& in_path:all_files) {
        if((++scan_idx%2000)==0) {
            fprintf(stderr,"Pre-scanning: %zu/%zu files\n",scan_idx,all_files.size());
        }
        std::string out_path;
        if(!out_dir_clean.empty()) {
            out_path=build_batch_out_path(in_path,out_dir_clean,input_paths,encrypt);
            if(out_path.empty()) {
                fprintf(stderr,"Skipping %s: output path escapes output directory.\n",in_path.c_str());
                continue;
            }
        }
        else {
            out_path=in_path;
        }

        if(encrypt) {
            if(global_config().obfuscate_names) {
                out_path=replace_basename(out_path,
                    make_obfuscated_basename(in_path,password));
            }
            out_path+=".ptd";
        }
        else {
            if(out_path.size()>=4&&
                (out_path.substr(out_path.size()-4)==".ptd"||
                    out_path.substr(out_path.size()-4)==".PTD")) {
                out_path=out_path.substr(0,out_path.size()-4);
            }
            // 文件名还原默认关闭：开启需每文件多跑一次 Argon2id KDF，性能较差
            if(restore_name) {
                std::vector<unsigned char> kek(ARGON2_OUTPUT_LEN);
                std::string orig_name;
                if(read_original_name(in_path,orig_name,password,nullptr,0,&kek)) {
                    kek_cache[in_path]=kek;   // 缓存 KEK，worker 复用（3× → 1× Argon2id）
                    if(!orig_name.empty()) out_path=replace_basename(out_path,orig_name);
                }
            }
        }

        size_t dirpos=out_path.find_last_of("/\\");
        if(dirpos!=std::string::npos) {
            std::string out_subdir=out_path.substr(0,dirpos);
            if(out_subdir!=last_mkdir) {
                create_directory_recursive(out_subdir);
                last_mkdir=std::move(out_subdir);
            }
        }

        bool skip=false;
        if(!force_overwrite && file_exists(out_path)) {
            // 先 stat 判存在再打开：对不存在的输出逐文件做失败的 CreateFile
            // 也会经过过滤驱动（AV 实时扫描），大目录下是无谓的开销。
            if(!is_file_valid(out_path)) {
                fprintf(stderr,"Existing file %s is corrupted, will overwrite.\n",out_path.c_str());
            }
            else if(file_exists(out_path+".prs")) {
                fprintf(stderr,"Existing file %s has unfinished progress, will resume.\n",out_path.c_str());
            }
            else if(is_complete_output(out_path,encrypt,in_path)) {
                // 头部有效、无 .prs、尺寸完整即已完成，安全跳过；
                // 但解密若带源处置(-de/--wipe-source/--recycle-source)仍须移除源 .ptd。
                skip=true;
                printf("Skipped: %s (already done)\n",in_path.c_str());
                if(!encrypt && source_action!=0) {
                    if(!secure_handle_source(in_path,static_cast<SourceDisposition>(source_action))) {
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        pre_scan_ok=false;
                    }
                }
            }
            else {
                // 头部有效但尺寸不完整且无 .prs：多半是上一轮在首个 save_progress 前被强杀，
                // 残留下“仅头部”的半截 .ptd。当作未完成重新加密，避免解密字节不一致。
                fprintf(stderr,"Existing file %s is incomplete (no progress), will re-encrypt.\n",out_path.c_str());
            }
        }
        if(!skip) {
            files_to_process.push_back(in_path);
        }
    }

    if(files_to_process.empty()) {
        printf("No files to process (all already exist and valid, -y not specified).\n");
        return true;
    }

    printf("Processing %zu files (skipped %zu valid existing).\n",
        files_to_process.size(),all_files.size()-files_to_process.size());

    // ---- 帧式进度显示（v2.3.0）：1 行汇总 + 每线程 1 行，按帧原地刷新 ----
    // use_frame=false 时（输出被重定向到文件/管道且宿主未显式开启）回退旧的单行 \r 进度条。
    feui::BatchProgress progress_ui;
    const bool use_frame=progress_ui.begin(num_threads,total_bytes);

    std::atomic<size_t> file_index{0};
    std::atomic<size_t> global_processed{0};
    // 文件级计数：帧末行 FILES ... 实时反映 完成/跳过/失败，供 GUI 等宿主解析
    std::atomic<size_t> files_done{0};
    std::atomic<size_t> files_failed{0};
    std::atomic<size_t> skipped_not_ptd{0};   // worker 魔数预检发现的伪 .ptd（非加密文件）
    const size_t files_skipped=(all_files.size()-files_to_process.size())+non_ptd_skipped;
    std::mutex error_mutex;
    std::vector<std::string> error_files;
    std::chrono::steady_clock::time_point start_time=std::chrono::steady_clock::now();
    std::atomic<bool> all_ok{pre_scan_ok};
    std::atomic<bool> display_stop{false};

    // 显示线程：每 40ms 推一帧，使空闲线程行稳定刷新，不依赖 worker 回调频率。
    std::thread display_thread;
    if(use_frame) {
        display_thread=std::thread([&]{
            while(!display_stop.load(std::memory_order_relaxed)) {
                progress_ui.setProcessed(global_processed.load(std::memory_order_relaxed));
                progress_ui.setFileStats(files_done.load(std::memory_order_relaxed),
                                         files_failed.load(std::memory_order_relaxed),
                                         files_skipped+skipped_not_ptd.load(std::memory_order_relaxed),
                                         files_to_process.size());
                progress_ui.render();
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
            }
        });
    }

    auto worker=[&](int slot) {
        // 线程结束时清空自己的槽位（置空闲），避免最后一帧残留已完成文件的进度
        struct SlotGuard {
            feui::BatchProgress* ui;
            int slot;
            ~SlotGuard() { if(ui) ui->setSlot(slot,std::string(),0,0,false); }
        } guard{use_frame ? &progress_ui : nullptr,slot};

        while(true) {
            size_t idx=file_index.fetch_add(1);
            if(idx>=files_to_process.size()) break;
            const auto& in_path=files_to_process[idx];

            std::string out_path;
            if(!out_dir_clean.empty()) {
                out_path=build_batch_out_path(in_path,out_dir_clean,input_paths,encrypt);
                if(out_path.empty()) {
                    // 输出路径逃出目标目录（路径穿越）：跳过该文件，绝不回退到源路径，
                    std::lock_guard<std::mutex> lock(error_mutex);
                    error_files.push_back(in_path);
                    ++files_failed;
                    all_ok=false;
                    continue;
                }
            }
            else {
                out_path=in_path;
            }

            if(encrypt) {
                if(global_config().obfuscate_names) {
                    out_path=replace_basename(out_path,
                        make_obfuscated_basename(in_path,password));
                }
                out_path+=".ptd";
            }
            else {
                if(out_path.size()>=4&&
                    (out_path.substr(out_path.size()-4)==".ptd"||
                        out_path.substr(out_path.size()-4)==".PTD")) {
                    out_path=out_path.substr(0,out_path.size()-4);
                }
                // 还原文件名（与预扫描一致）：默认关闭以省去每文件 KDF
                if(restore_name) {
                    std::string orig_name;
                    auto _kit=kek_cache.find(in_path);
                    const unsigned char* kek_ptr=(_kit!=kek_cache.end())?_kit->second.data():nullptr;
                    if(read_original_name(in_path,orig_name,password,kek_ptr,kek_ptr?ARGON2_OUTPUT_LEN:0)
                       &&!orig_name.empty()) {
                        out_path=replace_basename(out_path,orig_name);
                    }
                }
            }

            size_t last_file_processed=0;

            bool ok=false;
            if(encrypt) {
                ok=encrypt_file(in_path,out_path,password,mode,
                    [&](size_t processed,size_t total) {
                        size_t inc=processed-last_file_processed;
                        last_file_processed=processed;
                        global_processed+=inc;
                        if(use_frame) {
                            // 帧模式：只更新槽位状态，实际绘制由显示线程按帧节流完成
                            progress_ui.setSlot(slot,in_path,processed,total,true);
                            progress_ui.setProcessed(global_processed.load());
                        }
                        else {
                            static std::mutex print_mutex;
                            std::lock_guard<std::mutex> lock(print_mutex);
                            print_progress(global_processed.load(),total_bytes,start_time,false);
                        }
                    },true,compress_level);
                if(ok && source_action!=0) {
                    if(!secure_handle_source(in_path, static_cast<SourceDisposition>(source_action))) {
                        std::lock_guard<std::mutex> lock(error_mutex);
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
            }
            else {
                // 伪 .ptd 预检：magic 不匹配直接按 SKIP 跳过，
                // 避免普通文件误冠 .ptd 后白跑一次 Argon2id 再误报 Failed。
                {
                    unsigned char m5[5];
                    std::ifstream mf;
                    if(open_stream(mf,in_path,std::ios::binary)
                       &&mf.read(reinterpret_cast<char*>(m5),5)&&mf.gcount()==5
                       &&memcmp(m5,MAGIC,4)!=0) {
                        ++skipped_not_ptd;
                        fprintf(stderr,"Skipped: %s (not a PTD encrypted file)\n",in_path.c_str());
                        continue;
                    }
                }
                const unsigned char* dec_kek=nullptr;
                { auto _kit=kek_cache.find(in_path); if(_kit!=kek_cache.end()) dec_kek=_kit->second.data(); }
                ok=decrypt_file(in_path,out_path,password,
                    [&](size_t processed,size_t total) {
                        size_t inc=processed-last_file_processed;
                        last_file_processed=processed;
                        global_processed+=inc;
                        if(use_frame) {
                            progress_ui.setSlot(slot,in_path,processed,total,true);
                            progress_ui.setProcessed(global_processed.load());
                        }
                        else {
                            static std::mutex print_mutex;
                            std::lock_guard<std::mutex> lock(print_mutex);
                            print_progress(global_processed.load(),total_bytes,start_time,false);
                        }
                    },true,true,nullptr,dec_kek);
                // 解密成功后处理源 .ptd（-de 删除 / 擦除 / 回收站）；此前解密分支缺失此步
                if(ok && source_action!=0) {
                    if(!secure_handle_source(in_path,static_cast<SourceDisposition>(source_action))) {
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
            }

            if(ok) {
                // 仅在成功处理的文件上补齐进度，避免失败文件把进度条拉满到 100%；
                // 尺寸优先查预扫描缓存，缺省才回退 stat（源文件已按 -de 删除时缓存仍可用）
                int64_t fsize=-1;
                { auto _it=size_cache.find(in_path); if(_it!=size_cache.end()) fsize=_it->second; }
                if(fsize<0) fsize=get_file_size_utf8(in_path);
                if(fsize>=0) {
                    size_t file_size=(size_t)fsize;
                    if(last_file_processed<file_size) {
                        global_processed+=(file_size-last_file_processed);
                        last_file_processed=file_size;
                    }
                }
                if(encrypt && write_sha256_enabled()) write_sha256_sidecar(out_path); // 功能10：校验单
                ++files_done;
                log_event(LOG_DEBUG,"file_done",{{"path",in_path}});
            }
            else {
                ++files_failed;
                // 单文件失败仅记录并继续（统一 Failed: 前缀供 GUI 统计），不中断整批
                all_ok=false;
                {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    error_files.push_back(in_path);
                }
                fprintf(stderr,"Failed: %s (skipped, continuing with remaining files)\n",in_path.c_str());
                log_event(LOG_ERROR,"file_failed",{{"path",in_path}});
            }
        }
        };

    std::vector<std::thread> threads;
    for(int i=0; i<num_threads; ++i) {
        threads.emplace_back(worker,i);   // 每个 worker 绑定一个显示槽位（帧的第 i+2 行）
    }
    for(auto& t:threads) {
        t.join();
    }
    // 停止显示线程后再收尾，避免最后一帧被后台线程覆盖
    display_stop.store(true);
    if(display_thread.joinable()) display_thread.join();

    if(error_files.empty()) {
        // 全部成功：安全地拉满到 100%（任务中途失败文件已不会拉满）
        global_processed=total_bytes;
    }
    // 有失败文件：按真实已处理字节收尾，不掩盖失败/跳过情况
    if(use_frame) {
        progress_ui.setProcessed(global_processed.load());
        progress_ui.setFileStats(files_done.load(),files_failed.load(),
                                 files_skipped+skipped_not_ptd.load(),files_to_process.size());
        progress_ui.finish();            // 渲染最终帧并换行收尾
    }
    else {
        print_progress(global_processed.load(),total_bytes,start_time,true);
    }
    if(!error_files.empty()) {
        fprintf(stderr,
            "\nWarning: %zu file(s) failed; the final progress reflects processed bytes only.\n",
            error_files.size());
    }

    if(!encrypt&&!error_files.empty()) {
        fprintf(stderr,"\n--- Decryption errors (%zu files) ---\n",error_files.size());
        for(const auto& f:error_files) {
            fprintf(stderr,"  %s\n",f.c_str());
        }
        fprintf(stderr,"Total %zu files failed.\n",error_files.size());
    }
    if(encrypt&&!error_files.empty()) {
        fprintf(stderr,"\n--- Encryption errors (%zu files) ---\n",error_files.size());
        for(const auto& f:error_files) {
            fprintf(stderr,"  %s\n",f.c_str());
        }
        fprintf(stderr,"Total %zu files failed.\n",error_files.size());
    }

    // 清空中缓存的派生密钥，避免明文残留于进程内存
    for(auto& kv:kek_cache) sodium_memzero(kv.second.data(), kv.second.size());
    kek_cache.clear();

    // 宿主（GUI）可通过环境变量指定统计文件，批量结束时写入 JSON 供宿主解析
    if(const char* stats_path=std::getenv("FILEENCRYPTOR_STATS_FILE")) {
        FILE* sf=fopen(stats_path,"wb");
        if(sf) {
            fprintf(sf,"{\"total_bytes\":%llu,\"files_done\":%llu,\"files_failed\":%llu,"
                      "\"files_skipped\":%llu,\"total_files\":%llu}\n",
                (unsigned long long)total_bytes,
                (unsigned long long)files_done.load(),
                (unsigned long long)files_failed.load(),
                (unsigned long long)(files_skipped+skipped_not_ptd.load()),
                (unsigned long long)all_files.size());
            fclose(sf);
        }
    }

    return all_ok.load();
}