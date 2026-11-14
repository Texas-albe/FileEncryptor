#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <windows.h>    // 必须早于 C++ 头
#include <winioctl.h>   // FSCTL_GET_REPARSE_POINT
#endif
#include "FileEncryptor.hpp"
#ifdef FE_WITH_ZSTD
#include "zstd.h"   // 仅当构建集成
#endif
#include <cstdio>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <memory>
#include <array>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>
#include <chrono>
#include <iostream>
#include <functional>
#include <cctype>
#include <sys/stat.h>
#include <sodium.h>
#include "config.hpp"
#include "cipher.hpp"
#include "progress_frame.hpp"
#include "ptd_format.hpp"
#include "asym_crypto.hpp"
#include "machine_id.hpp"
#include "watermark.hpp"
#include "split_volumes.hpp"
#include "kdf.hpp"
#include "util/byte_io.hpp"
#include "util/hex.hpp"
#include "secure_zero.hpp"
#include "buffer_pool.hpp"
#include <atomic>
#ifdef FE_WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#endif
#include <thread>
#include <mutex>
#include <condition_variable>
#include <filesystem>
#include <ctime>

#ifdef _WIN32
#include <io.h>      // _isatty / _fileno
#else
#include <unistd.h> // isatty
#endif

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>    // _aligned_malloc / _aligned_free
#include <debugapi.h>
#include <shlobj.h>
#include <aclapi.h>       // SetEntriesInAclW / SetNamedSecurityInfoW
#include <direct.h>
#include <io.h>
#include <process.h>
#pragma comment(lib, "shell32.lib")   // SHFileOperationW
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>     // chmod
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
// 常量
// 主加密块大小
// 实测上调到 4MiB 反
// 缓冲随块大小翻

// 头里 chunk_size

// 读取端上界必须 <=
// 放行

static constexpr size_t PASSWORD_MIN_LEN=6;

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;
static constexpr size_t AEGIS256_IV_LEN=crypto_aead_aegis256_NPUBBYTES;
static constexpr size_t SM4_IV_LEN=12;   // GCM 推荐 nonce 长度
static constexpr size_t AEGIS256_TAG_SIZE=crypto_aead_aegis256_ABYTES;
static constexpr size_t TAG_SIZE=16;
static constexpr size_t MAX_TAG_SIZE=AEGIS256_TAG_SIZE;

// v2

// 压缩帧
#ifdef FE_WITH_ZSTD
static const size_t COMP_BUF_MAX = ZSTD_compressBound(CHUNK_SIZE);
#else
static const size_t COMP_BUF_MAX = CHUNK_SIZE;
#endif

// 试压自适应
int fe_probe_compress_level(const unsigned char* data, size_t len) {
#ifdef FE_WITH_ZSTD
    if(!data || len < 4096) return 0;
    size_t cap = ZSTD_compressBound(len);
    std::vector<unsigned char> dst(cap);
    size_t n = ZSTD_compress(dst.data(), cap, data, len, 3);
    if(ZSTD_isError(n) || n >= len - len / 20) return 0;
    return 3;
#else
    (void)data; (void)len;
    return 0;
#endif
}

// 数据阶段缓冲池
// 池化后固定复用
namespace {
struct DataBufPool {
    static BufferPool& plain()  { static BufferPool p(CHUNK_SIZE, true);  return p; }
    static BufferPool& comp()   { static BufferPool p(COMP_BUF_MAX, true); return p; }
    static BufferPool& cipher() { static BufferPool p(COMP_BUF_MAX+MAX_TAG_SIZE, false); return p; }
};
// 从池取缓冲、析构
class PooledBuf {
    BufferPool* pool_;
    std::vector<unsigned char> v_;
public:
    explicit PooledBuf(BufferPool& p) : pool_(&p), v_(p.acquire()) {}
    ~PooledBuf() { if(pool_) pool_->release(v_); }
    unsigned char* data() { return v_.data(); }
    const unsigned char* data() const { return v_.data(); }
    size_t size() const { return v_.size(); }
    bool empty() const { return v_.empty(); }
    // 只擦内容不改容
    void clear() { if(!v_.empty()) sodium_memzero(v_.data(),v_.size()); }
    void shrink_to_fit() {}
    PooledBuf(const PooledBuf&)=delete;
    PooledBuf& operator=(const PooledBuf&)=delete;
};
}

// ProgressInfo / PROGRESS_MAGIC /

// 辅助
size_t tag_size_for_mode(CryptoMode m) {
    if(m==CryptoMode::AEGIS256) return AEGIS256_TAG_SIZE;
#ifdef FE_WITH_OPENSSL
    if(m==CryptoMode::SM4)      return 16;
#endif
    return TAG_SIZE;
}

// 认证失败信息泄
// 非详细模式下认
static bool g_verbose=false;
void set_verbose(bool v) { g_verbose=v; }

// 最近一次解密失
// 供 fe_mobile C ABI
// report_auth_error 置位。并发解密只
static std::atomic<bool> g_last_fail_auth{false};
bool fe_last_fail_auth() { return g_last_fail_auth.load(); }

// mlock 失败告警
// swap / 落进 core dump。首次失败
void fe_report_mlock_warning_once() {
    static std::atomic<bool> warned{false};
    if(!warned.exchange(true)) {
        fprintf(stderr,"Warning: sodium_mlock failed; sensitive key material may be swappable.\n");
        log_event(LOG_WARN,"mlock_failed",
            {{"detail","memory pages could not be locked; keys may be written to swap"}});
    }
}

static void report_auth_error(bool silent, const std::string& detail) {
    g_last_fail_auth.store(true);
    if(silent) return;
    const Config& cfg=global_config();
    bool detailed = g_verbose || cfg.log_level>=LOG_DEBUG;
    if(detailed) fprintf(stderr, "%s\n", detail.c_str());
    else fprintf(stderr, "Error: Decryption failed. (Invalid key or corrupted file)\n");
}

// 路径规范化
// lexically_normal 解析
// normalize_path_lexical 已迁到 core/fileio_util.cpp

// 续传进度绑定
// 源路径+大小+mtime 纳入 .prs
// 前向声明

// 内容令牌
// 小文件

// 明文 Blake2b 哈希
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

// 4 MiB 聚合写出缓冲
// 块密文/明文攒满 4 MiB
struct AggWriter {
    std::ostream* os=nullptr;
    std::vector<unsigned char> buf;
    static constexpr size_t CAP=4*1024*1024;
    void bind(std::ostream& s){ os=&s; buf.reserve(CAP); }
    bool put(const unsigned char* p, size_t n){
        if(!os) return true;                  // verify_only
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

// 输入侧 4 MiB 页对齐大
// 缓冲
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

// SHA-256 校验单
// 加密后生成 <file>.sha256，供外
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

// AEGIS-256 可用性探测
// magic static 局部初始化保证
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

bool sm4_supported() {
#ifdef FE_WITH_OPENSSL
    static const bool s_supported = []() -> bool {
        unsigned char key[16], nonce[12], pt[32], ct[64], pt2[32];
        unsigned long long ct_len = 0, pt_len = 0;
        randombytes_buf(key, sizeof(key));
        randombytes_buf(nonce, sizeof(nonce));
        memset(pt, 0x5A, sizeof(pt));
        std::unique_ptr<Cipher> c = create_cipher(CryptoMode::SM4);
        if(!c) return false;
        int e = c->encrypt(pt, sizeof(pt), nullptr, 0, nonce, key, ct, ct_len);
        int d = (e == 0) ? c->decrypt(ct, ct_len, nullptr, 0, nonce, key, pt2, pt_len) : -1;
        return (e == 0 && d == 0 && pt_len == sizeof(pt) && memcmp(pt, pt2, sizeof(pt)) == 0);
    }();
    return s_supported;
#else
    return false;
#endif
}

// 运行时探测 AES-256-GCM 是否
// 启用 OpenSSL
bool aes_gcm_supported() {
    static const bool s_supported = []() -> bool {
        unsigned char key[32], nonce[12], pt[32], ct[64], pt2[32];
        unsigned long long ct_len = 0, pt_len = 0;
        randombytes_buf(key, sizeof(key));
        randombytes_buf(nonce, sizeof(nonce));
        memset(pt, 0x5A, sizeof(pt));
        std::unique_ptr<Cipher> c = create_cipher(CryptoMode::AES_GCM);
        if(!c) return false;
        int e = c->encrypt(pt, sizeof(pt), nullptr, 0, nonce, key, ct, ct_len);
        int d = (e == 0) ? c->decrypt(ct, ct_len, nullptr, 0, nonce, key, pt2, pt_len) : -1;
        return (e == 0 && d == 0 && pt_len == sizeof(pt) && memcmp(pt, pt2, sizeof(pt)) == 0);
    }();
    return s_supported;
}

// 运行时探测 OpenSSL 是否
// 实测 OpenSSL 4.1
bool pqc_supported() {
#ifdef FE_WITH_OPENSSL
    static const bool s_supported = []() -> bool {
        return EVP_PKEY_CTX_new_id(NID_ML_KEM_768, nullptr) != nullptr;
    }();
    return s_supported;
#else
    return false;
#endif
}

bool stdin_is_interactive() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

// 解析加密模式
// 非交互禁止自动
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

    // 非交互
    refuse=true;
    message="AEGIS-256 requires AES-NI hardware support, which is not available on this CPU.\n"
            "Using AEGIS-256 here is extremely slow and not side-channel resistant.\n"
            "Switch to XChaCha20-Poly1305 (-m xchacha20) for secure, fast encryption.";
    return requested;
}

// AAD 构建
// 传入头部原始字
static std::vector<unsigned char> build_aad_with_metadata(
    const unsigned char* hdr_ptr, size_t hdr_len,
    uint32_t chunk_size,
    uint32_t total_chunks,
    uint64_t orig_size) {
    std::vector<unsigned char> aad;
    aad.insert(aad.end(),hdr_ptr,hdr_ptr+hdr_len);

    fe::util::write_u32_le(aad, chunk_size);
    fe::util::write_u32_le(aad, total_chunks);
    fe::util::write_u64_le(aad, orig_size);
    return aad;
}

// 文件系统辅助
// file_exists / get_file_size_utf8 /
// 对外名分别

// 判断路径是否
// v2.1.2
bool path_is_symlink(const std::string& path) {
    // SAF content
    if (path.rfind("content://", 0) == 0) return false;
#ifdef _WIN32
    std::wstring w=utf8_to_wstring(path);
    DWORD attr=GetFileAttributesW(w.c_str());
    if(attr==INVALID_FILE_ATTRIBUTES) return false;
    // 属性位检查
    // 用 FILE_FLAG_OPEN_REPARSE
    HANDLE h=CreateFileW(w.c_str(),0,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|(attr&FILE_ATTRIBUTE_DIRECTORY
            ? FILE_FLAG_BACKUP_SEMANTICS : 0u),
        nullptr);
    if(h!=INVALID_HANDLE_VALUE) {
        std::vector<char> buf(4096,0);
        DWORD ret=0;
        // 句柄级读出重解
        if(DeviceIoControl(h,FSCTL_GET_REPARSE_POINT,nullptr,0,
                buf.data(),(DWORD)buf.size(),&ret,nullptr)) {
            CloseHandle(h);
            return true;
        }
        const DWORD err=GetLastError();
        CloseHandle(h);
        if(err==ERROR_NOT_A_REPARSE_POINT) return false;
        // 打不开/非重解析
    }
    return (attr&FILE_ATTRIBUTE_REPARSE_POINT)!=0;
#else
    struct stat st;
    if(lstat(path.c_str(),&st)!=0) return false;
    return S_ISLNK(st.st_mode);
#endif
}

// 组件法
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

// 用 std
// 使白名单前缀比
// 局限
static std::string resolve_real_path(const std::string& p) {
    std::error_code ec;
#ifdef _WIN32
    fs::path r = fs::weakly_canonical(fs::path(utf8_to_wstring(p)), ec);
    if(ec) return fe_normalize_path_lexical(p);
    return wstring_to_utf8(r.make_preferred().wstring());
#else
    fs::path r = fs::weakly_canonical(fs::path(p), ec);
    if(ec) return fe_normalize_path_lexical(p);
    return r.make_preferred().string();
#endif
}

// 依据 YAML 配置校验输
// v2.1.2 去掉 static
bool validate_io_paths(const std::string& in_path,const std::string& out_path,bool silent) {
    const Config& cfg=global_config();
    // ".."
    // 下面
    // 规范化
    // 堵住基于路径别
    const std::string in_norm = fe_normalize_path_lexical(in_path);
    const std::string out_norm = fe_normalize_path_lexical(out_path);
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
        // 白名单相对路径
        auto resolve_root=[&](const std::string& r)->std::string {
            std::string rnorm = fe_normalize_path_lexical(r);
            bool is_abs = false;
#ifdef _WIN32
            is_abs = (rnorm.size()>=2 && rnorm[1]==':') ||
                     (!rnorm.empty() && (rnorm[0]=='/'||rnorm[0]=='\\'));
#else
            is_abs = !rnorm.empty() && rnorm[0]=='/';
#endif
            if(is_abs) return rnorm;
            char cwd[4096];
            if(getcwd(cwd,sizeof(cwd))) {
                std::string base = fe_normalize_path_lexical(cwd);
                if(!base.empty() && base.back()!='/' && base.back()!='\\') base.push_back('/');
                return fe_normalize_path_lexical(base + rnorm);
            }
            return rnorm;
        };
        // 符号链接解析
        const std::string in_real = resolve_real_path(in_path);
        const std::string out_real = resolve_real_path(out_path);
        bool in_ok=false,out_ok=false;
        for(const auto& r:cfg.path_whitelist) {
            const std::string rnorm = resolve_real_path(resolve_root(r));
            if(!in_ok&&under(in_real,rnorm))  in_ok=true;
            if(!out_ok&&under(out_real,rnorm)) out_ok=true;
        }
        if(!in_ok)  { if(!silent) fprintf(stderr,"Input path not in whitelist: %s\n",in_path.c_str());  return false; }
        if(!out_ok) { if(!silent) fprintf(stderr,"Output path not in whitelist: %s\n",out_path.c_str()); return false; }
    }
    return true;
}

// 收紧新建输出文
// Windows 复用密钥文件
static void restrict_permissions(const std::string& path) {
#ifdef _WIN32
    tighten_file_permissions(path);
#elif defined(__ANDROID__)
    // SAF fd
    // 静默忽略
    (void)path;
#else
    chmod(path.c_str(),0600);
#endif
}

// 删除前覆写文件
// SSD 磨损均衡使覆写
static void secure_wipe_and_remove(const std::string& path) {
#ifdef _WIN32
    const std::wstring w=utf8_to_wstring(path);
    HANDLE h=CreateFileW(w.c_str(),GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h!=INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if(GetFileSizeEx(h,&sz)&&sz.QuadPart>0) {
            unsigned char zbuf[64*1024];
            memset(zbuf,0,sizeof(zbuf));
            LARGE_INTEGER remain=sz;
            while(remain.QuadPart>0) {
                DWORD want=(DWORD)(remain.QuadPart<(LONGLONG)sizeof(zbuf)?remain.QuadPart:(LONGLONG)sizeof(zbuf));
                DWORD wr=0;
                if(!WriteFile(h,zbuf,want,&wr,NULL)||wr==0) break;
                remain.QuadPart-=wr;
            }
            FlushFileBuffers(h);
        }
        CloseHandle(h);
    }
#else
#ifdef __ANDROID__
    // SAF fd 无覆写句柄
    // 也不保留半成品
    remove_file_utf8(path);
    return;
#endif
    // 只读源直接 O_WRONLY
    // 复用源文件处置
    clear_readonly_attribute(path);
    int fd=::open(path.c_str(),O_WRONLY);
    if(fd<0) {
        // 补写位仍失败
        return;
    }
    {
        off_t sz=lseek(fd,0,SEEK_END);
        if(sz>0) {
            lseek(fd,0,SEEK_SET);
            char zbuf[64*1024];
            memset(zbuf,0,sizeof(zbuf));
            off_t remain=sz;
            while(remain>0) {
                size_t want=(size_t)(remain<(off_t)sizeof(zbuf)?remain:(off_t)sizeof(zbuf));
                ssize_t wr=::write(fd,zbuf,want);
                if(wr<=0) break;
                remain-=wr;
            }
            fsync(fd);
        }
        ::close(fd);
    }
#endif
    remove_file_utf8(path);
}

// POSIX
// 消除"先 0644
#ifndef _WIN32
struct ScopedUmask {
    mode_t old;
    explicit ScopedUmask(mode_t m){ old=umask(m); }
    ~ScopedUmask(){ umask(old); }
};

// POSIX
// 成功返回 true
// create_output_no_follow 已迁到 core/output_lock.cpp
#endif   // 原 #ifndef _WIN32 分支

// 跨进程输出锁
// process_alive_pid 已迁到 core/output_lock.cpp


// acquire_output_lock 已迁到 core/output_lock.cpp

// OutputLockGuard 已迁到 core/output_lock.hpp

// replace_file_utf8 / atomic_tmp_path /



// clear_readonly_attribute / tighten_file_permissio


// 反调试
// 检测到调试器
void anti_debug_check() {
#ifdef _WIN32
    if(IsDebuggerPresent()) {
        fprintf(stderr,"Debugger detected, exiting.\n");
        exit(1);
    }
#else
    // 在缺少 ptrace 权限
    if(ptrace(PTRACE_TRACEME,0,0,0)==-1) {
        if(errno==EBUSY) {
            fprintf(stderr,"Debugger detected, exiting.\n");
            exit(1);
        }
    }
#endif
}

bool g_force_decrypt = false;

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

// 辅助
template<typename T>
static void secure_clear(T& v) {
    if(v.empty()) return;
    sodium_memzero(v.data(),v.size());
    v.clear();
    v.shrink_to_fit();
}

// 目录创建
// create_directory_recursive 已迁到 core/fileio_util.cpp

// 文件有效性检查

// 进度
// 仅读取并校验结



// 进程级限速器
// 主循环
// 限速全局

// 限速已移出到 core

void print_progress(size_t processed,size_t total,
    std::chrono::steady_clock::time_point start,
    bool finish, std::ostream* progress_out) {
    if(!progress_out) return;   // 管道输出模式
    static std::mutex print_mutex;
    std::lock_guard<std::mutex> lock(print_mutex);

    if(total==0) return;

    const int bar_width=40;
    double fraction=static_cast<double>(processed)/total;
    int pos=static_cast<int>(bar_width*fraction);
    if(pos>bar_width) pos=bar_width;

    int pct=static_cast<int>(fraction*100.0 + 1e-9);
    static int last_pct=-1;
    // 非帧进度条
    if(!finish && pct==last_pct) return;
    last_pct=pct;

    auto now=std::chrono::steady_clock::now();
    double elapsed=std::chrono::duration<double>(now-start).count();
    double speed=(elapsed>0) ? (processed/1048576.0)/elapsed : 0.0; // MB/s
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
        last_pct=-1;   // 复位
        *progress_out<<buf<<'\n';
    }
    else {
        *progress_out<<buf<<std::flush;
    }
}

// 读取尾部水印记

// 明文窗口
class WindowOutBuf : public std::streambuf {
public:
    WindowOutBuf(uint64_t lo, uint64_t hi, std::vector<unsigned char>& out)
        : lo_(lo), out_(out) { out.assign((size_t)(hi - lo), 0); }
protected:
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        uint64_t from = pos_, to = pos_ + (uint64_t)n;
        pos_ = to;
        uint64_t a = (std::max)(from, lo_), b = (std::min)(to, lo_ + out_.size());
        if(a < b) std::memcpy(out_.data() + (size_t)(a - lo_), s + (a - from), (size_t)(b - a));
        return n;
    }
    int_type overflow(int_type c) override {
        if(traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
        char ch = traits_type::to_char_type(c);
        return xsputn(&ch, 1) == 1 ? c : traits_type::eof();
    }
private:
    uint64_t lo_, pos_ = 0;
    std::vector<unsigned char>& out_;
};

// 会话式随机读
struct PtdReadSession {
    std::string path;
    PtdMeta meta;
    unsigned char hdrbuf[320];
    unsigned char ver=0;
    uint32_t recip_len=0;
    unsigned char key[32]={0};
    std::vector<unsigned char> aad;
    unsigned char iv[32]={0};
    size_t iv_len=0;
    bool use_increment=false;
    uint64_t base=0;
    uint32_t chunk_size=0;
    uint64_t stride=0;
    uint64_t orig_size=0;
    size_t tag_size=0;
    std::ifstream fin;
    ~PtdReadSession() {
        if (fin.is_open()) fin.close();
        sodium_memzero(key, sizeof(key));
        sodium_memzero(hdrbuf, sizeof(hdrbuf));
        sodium_memzero(iv, sizeof(iv));
    }
};

bool ptd_session_open(const std::string& ptd_path, const SecureBuffer& password,
                      const unsigned char* pre_kek, bool silent, PtdReadSession** out) {
    *out = nullptr;
    std::unique_ptr<PtdReadSession> s(new PtdReadSession());
    s->path = ptd_path;
    if (!read_ptd_metadata(ptd_path, s->meta) || !s->meta.valid) {
        if (!silent) fprintf(stderr, "Cannot read .ptd metadata or invalid file.\n");
        return false;
    }
    if (s->meta.compression != 0) return false;   // 压缩件不建
    {
        std::ifstream hf;
        if (!open_stream(hf, ptd_path, std::ios::binary) ||
            !hf.read(reinterpret_cast<char*>(s->hdrbuf), 5)) {
            if (!silent) fprintf(stderr, "Cannot open input file.\n");
            return false;
        }
        s->ver = s->hdrbuf[4];
        size_t hs = header_size_for_version(s->ver);
        if (hs < 5 || hs > sizeof(s->hdrbuf) ||
            !hf.read(reinterpret_cast<char*>(s->hdrbuf + 5), (std::streamoff)(hs - 5))) {
            if (!silent) fprintf(stderr, "Read header failed.\n");
            return false;
        }
    }
    unsigned char dek_box[64]={0};
    unsigned char dek_nonce[24]={0};
    if (s->ver == 6) {
        auto h6 = load_header<FileHeaderV6>(s->hdrbuf);
        s->recip_len = get_recip_len(h6.reserved);
        memcpy(dek_box, h6.dek_box, sizeof(dek_box));
        memcpy(dek_nonce, h6.dek_nonce, sizeof(dek_nonce));
    } else if (s->ver != 3 && s->ver != VERSION && s->ver != 5) {
        if (!silent) fprintf(stderr, "Legacy version %u does not support random read.\n", s->ver);
        return false;
    }
    if (s->recip_len > 0) {
        if (!silent) fprintf(stderr, "Random read not supported for asymmetric containers (recip_len>0).\n");
        return false;
    }
    unsigned char salt_buf[ARGON2_SALT_LEN];
    s->iv_len = s->meta.iv_hex.size() / 2;
    if (s->iv_len < 8 || s->iv_len > sizeof(s->iv) ||
        sodium_hex2bin(salt_buf, ARGON2_SALT_LEN, s->meta.salt_hex.data(), s->meta.salt_hex.size(),
                       nullptr, nullptr, nullptr) != 0) {
        if (!silent) fprintf(stderr, "Invalid salt hex.\n");
        return false;
    }
    if (sodium_hex2bin(s->iv, s->iv_len, s->meta.iv_hex.data(), s->meta.iv_hex.size(),
                       nullptr, nullptr, nullptr) != 0) {
        if (!silent) fprintf(stderr, "Invalid iv hex.\n");
        return false;
    }
    if (s->ver == 6) {
        SecureBuffer kek(ARGON2_OUTPUT_LEN);
        if (pre_kek) {
            memcpy(kek.data(), pre_kek, ARGON2_OUTPUT_LEN);
        } else if (!derive_key(password.data(), password.size(), salt_buf, kek.data(),
                               s->meta.opslimit, (size_t)s->meta.memlimit_kb * 1024)) {
            if (!silent) fprintf(stderr, "Key derivation failed.\n");
            return false;
        }
        unsigned char dek[32];
        if (!unwrap_dek(dek_box, kek.data(), dek_nonce, dek)) {
            report_auth_error(silent, "Failed to unwrap DEK (wrong password or corrupted container).");
            return false;
        }
        memcpy(s->key, dek, 32);
        sodium_memzero(dek, sizeof(dek));
        sodium_memzero(kek.data(), kek.size());
    } else {
        if (pre_kek) {
            memcpy(s->key, pre_kek, 32);
        } else if (!derive_key(password.data(), password.size(), salt_buf, s->key,
                               s->meta.opslimit, (size_t)s->meta.memlimit_kb * 1024)) {
            if (!silent) fprintf(stderr, "Key derivation failed.\n");
            return false;
        }
    }
    size_t aad_hdr_len = (s->ver == 6) ? (size_t)HEADER_AAD_COVER_V6
                                       : (size_t)header_hmac_cover(s->ver);
    s->aad = build_aad_with_metadata(s->hdrbuf, aad_hdr_len, s->meta.chunk_size,
                                     s->meta.total_chunks, s->meta.orig_size);
    s->tag_size = tag_size_for_mode(s->meta.mode);
    s->base = (uint64_t)header_size_for_version(s->ver) + (uint64_t)s->recip_len + 16;
    s->chunk_size = s->meta.chunk_size;
    if (s->chunk_size == 0) return false;
    s->stride = (uint64_t)s->chunk_size + s->tag_size;
    s->orig_size = s->meta.orig_size;
    s->use_increment = (s->ver == VERSION || s->ver == 5 || s->ver == 6);
    if (!open_stream(s->fin, ptd_path, std::ios::binary)) {
        if (!silent) fprintf(stderr, "Cannot open input file.\n");
        return false;
    }
    *out = s.release();
    return true;
}

bool ptd_session_read(PtdReadSession* s, uint64_t offset, uint64_t len,
                      std::vector<unsigned char>& out, bool silent) {
    out.clear();
    if (!s || len == 0) return true;
    if (!s->fin.is_open()) return false;
    if (offset >= s->orig_size) return true;
    if (offset + len > s->orig_size) len = s->orig_size - offset;
    uint32_t start_chunk = (uint32_t)(offset / s->chunk_size);
    uint32_t end_chunk = (uint32_t)((offset + len - 1) / s->chunk_size);
    unsigned char nonce[32]={0};
    memcpy(nonce, s->iv, s->iv_len);
    if (s->use_increment)
        for (uint32_t k = 0; k < start_chunk; ++k) sodium_increment(nonce, s->iv_len);
    std::unique_ptr<Cipher> ciph(create_cipher(s->meta.mode));
    if (!ciph) return false;
    out.assign((size_t)len, 0);
    uint64_t out_pos = 0;
    for (uint32_t i = start_chunk; i <= end_chunk; ++i) {
        uint64_t chunk_start = (uint64_t)i * s->chunk_size;
        size_t chunk_plain = (size_t)std::min<uint64_t>(s->chunk_size, s->orig_size - chunk_start);
        size_t expected = chunk_plain + s->tag_size;
        std::vector<unsigned char> ct(expected);
        s->fin.seekg((std::streamoff)(s->base + (uint64_t)i * s->stride));
        s->fin.read(reinterpret_cast<char*>(ct.data()), (std::streamsize)expected);
        if ((size_t)s->fin.gcount() != (size_t)expected) { out.clear(); return false; }
        if (!s->use_increment) {
            memcpy(nonce, s->iv, s->iv_len);
            fe::util::xor_le64_tail(nonce, s->iv_len, (uint64_t)i);
        }
        unsigned long long frame_len = 0;
        std::vector<unsigned char> pt(chunk_plain);
        if (ciph->decrypt(ct.data(), expected, s->aad.data(), s->aad.size(), nonce,
                          s->key, pt.data(), frame_len) != 0) {
            report_auth_error(silent, "Decryption failed (invalid key or corrupted data).");
            out.clear();
            return false;
        }
        uint64_t take_from = std::max<uint64_t>(chunk_start, offset);
        uint64_t take_to = std::min<uint64_t>(chunk_start + chunk_plain, offset + len);
        memcpy(out.data() + out_pos, pt.data() + (take_from - chunk_start),
               (size_t)(take_to - take_from));
        out_pos += take_to - take_from;
        if (s->use_increment && i < end_chunk) sodium_increment(nonce, s->iv_len);
    }
    out.resize((size_t)out_pos);
    return true;
}

void ptd_session_destroy(PtdReadSession* s) { delete s; }

// 随机块读
bool random_read_ptd(const std::string& ptd_path, const SecureBuffer& password,
                     uint64_t offset, uint64_t len,
                     std::vector<unsigned char>& out,
                     bool* out_compressed, bool silent, const unsigned char* pre_kek,
                     std::vector<unsigned char>* out_full) {
    out.clear();
    if(out_full) out_full->clear();
    if(out_compressed) *out_compressed=false;
    if(len==0) return true;

    PtdMeta meta;
    if(!read_ptd_metadata(ptd_path, meta) || !meta.valid) {
        if(!silent) fprintf(stderr,"Cannot read .ptd metadata or invalid file.\n");
        return false;
    }
    if(meta.compression!=0) {
        if(out_compressed) *out_compressed=true;
#ifdef FE_WITH_ZSTD
        if(offset>=meta.orig_size) return true;
        uint64_t want = std::min<uint64_t>(len, meta.orig_size-offset);
        // 小文件一次性解
        bool cache_all = out_full && meta.orig_size <= (64ull<<20);
        std::vector<unsigned char> local_full;
        std::vector<unsigned char>& full = cache_all ? *out_full : local_full;
        uint64_t lo = cache_all ? 0 : offset;
        uint64_t hi = cache_all ? meta.orig_size : offset + want;
        WindowOutBuf wb(lo, hi, full);
        std::ostream os(&wb);
        bool ok = decrypt_file(ptd_path, std::string(), password, nullptr, /*silent=*/true,
                               /*resume=*/false, /*ext_key=*/nullptr, /*ext_kek=*/nullptr,
                               /*ext_kek_len=*/0, /*verify_only=*/false, /*preview_bytes=*/0,
                               std::string(), /*force_overwrite=*/false, &os, nullptr);
        if(!ok) { full.clear(); return false; }
        if(cache_all) {
            size_t from = (size_t)offset;
            size_t to = (size_t)std::min<uint64_t>(full.size(), offset + want);
            out.assign(want, 0);
            if(from < to) std::copy(full.begin()+from, full.begin()+to, out.begin());
            out.resize(to > from ? to - from : 0);
        } else {
            out = std::move(full);
            out.resize((size_t)std::min<uint64_t>(out.size(), want));
        }
        return true;
#else
        return false;
#endif
    }
    if(offset>=meta.orig_size) return true;

    // 非压缩
    PtdReadSession* sess=nullptr;
    if(!ptd_session_open(ptd_path, password, pre_kek, silent, &sess)) return false;
    bool ok = ptd_session_read(sess, offset, len, out, silent);
    ptd_session_destroy(sess);
    return ok;
}

// 派生某 .ptd
bool fe_ptd_argon2_key(const std::string& ptd_path, const SecureBuffer& password,
                       unsigned char out[32]) {
    PtdMeta meta;
    if(!read_ptd_metadata(ptd_path, meta) || !meta.valid) return false;
    unsigned char salt_buf[ARGON2_SALT_LEN];
    if(sodium_hex2bin(salt_buf,ARGON2_SALT_LEN,meta.salt_hex.data(),meta.salt_hex.size(),
                      nullptr,nullptr,nullptr)!=0) return false;
    return derive_key(password.data(),password.size(),salt_buf,out,
                      meta.opslimit,(size_t)meta.memlimit_kb*1024);
}

// 完整性校验

bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback,
    bool resume,
    int compress_level,
    bool asym_mode,
    const std::vector<std::string>* asym_recipients,
    const WatermarkSpec* wm,
    const unsigned char* ext_salt,
    const unsigned char* ext_kek,
    uint32_t chunk_override,
    std::istream* in_stream,
    std::ostream* out_stream,
    const std::string* footer_name) {

    disable_core_dump();

    // 流输出
    if(out_stream) {
#ifdef _WIN32
        (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
    }

    // 名字信封
    // 用调用方给
    const std::string& footer_src = footer_name ? *footer_name : in_path;

    // 非对称加密
    std::vector<unsigned char> recip_blob_out;
    if(asym_mode) resume=false;

    // 依据 YAML 配置校验输
    // 流输出不落盘
    if(!in_stream && !out_stream && !validate_io_paths(in_path,out_path,false)) {
        fprintf(stderr,"Path validation failed (config policy)\n");
        return false;
    }

    // 防路径穿越
    if(path_has_traversal(out_path)) {
        fprintf(stderr,"Output path contains directory traversal\n");
        return false;
    }
    // 非对称模式
    const bool asym_active = asym_mode && asym_recipients && !asym_recipients->empty();
    if(password.size()<PASSWORD_MIN_LEN && !asym_active) {
        fprintf(stderr,"Password too short (min %zu characters)\n",PASSWORD_MIN_LEN);
        return false;
    }

    // 输入侧 4 MiB 页对齐大
    InputBuffer fin_buf;
    std::ifstream fin;
    // 管道/stdin 输入 或 流输
    // 管道输入规避 stdin
    // 不可 seek 输出因明文
    // fd 等可 seek 流
    // 明文只驻内存
    std::string mem_in;
    std::unique_ptr<std::istringstream> mem_is;
    std::istream* inp=&fin;
    // 可 seek 探测
    bool in_seekable=true, out_seekable=true;
    if(in_stream) {
        in_stream->clear();
        in_stream->seekg(0,std::ios::cur);
        in_seekable=!in_stream->fail();
        in_stream->clear();
    }
    if(out_stream) {
        out_stream->clear();
        out_stream->seekp(0,std::ios::cur);
        out_seekable=!out_stream->fail();
        out_stream->clear();
    }
    bool buffer_input = (in_stream && !in_seekable) || (out_stream && !out_seekable);
    if(buffer_input) {
        resume=false;   // 缓冲输入不可重
        if(in_stream) {
            std::ostringstream ss; ss<<in_stream->rdbuf();
            mem_in=std::move(ss).str();
        } else {
            // 流输出 + 文件输入
            // 此分支下 fin 尚未打
            // 必须显式打开
            if(!open_stream(fin,in_path,std::ios::binary)) {
                fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
                return false;
            }
            std::ostringstream ss; ss<<fin.rdbuf();
            mem_in=std::move(ss).str();
        }
        mem_is=std::make_unique<std::istringstream>(mem_in);
        inp=mem_is.get();
    } else if(in_stream) {
        inp=in_stream;   // fd / 外部可 seek 流
    } else {
        if(!open_stream(fin,in_path,std::ios::binary)) {
            fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
            return false;
        }
    }
    fin_buf.attach(*inp);
    inp->seekg(0,std::ios::end);
    uint64_t total_size=static_cast<uint64_t>(inp->tellg());
    inp->seekg(0,std::ios::beg);
    auto start_time=std::chrono::steady_clock::now();
    // .prs 节流基点
    // （声明
    auto last_prs_save=std::chrono::steady_clock::now();

    uint32_t chunk_size=(chunk_override>=MIN_CHUNK_SIZE&&chunk_override<=MAX_CHUNK_SIZE)
                        ? chunk_override : CHUNK_SIZE;
    uint64_t total_chunks_64=(total_size+chunk_size-1)/chunk_size;
    if(total_chunks_64>UINT32_MAX) {
        fprintf(stderr,"File too large: %llu chunks exceeds uint32_t limit (%u).\n",
            (unsigned long long)total_chunks_64,UINT32_MAX);
        return false;
    }
    uint32_t total_chunks=static_cast<uint32_t>(total_chunks_64);
    uint64_t orig_size=total_size;

    size_t iv_len=(mode==CryptoMode::AES_GCM)?AES_GCM_IV_LEN
                 :(mode==CryptoMode::AEGIS256)?AEGIS256_IV_LEN
                 :(mode==CryptoMode::SM4)?SM4_IV_LEN:XCHACHA20_IV_LEN;
    size_t tag_size=tag_size_for_mode(mode);

    // 续传检测
    ProgressInfo prog_info{0,0,0,0,{0}};
    bool has_progress=false;
    bool out_exists=fe_file_exists(out_path);
    bool prog_present=fe_file_exists(out_path+".prs");
    FileHeaderV3 existing_v3{};   // 复用 v3 前缀结构读
    FileHeaderV6 existing_v6{};   // v6 容器头
    bool existing_is_v3=false;   // 现有输出
    bool existing_is_v4=false;
    bool existing_is_v5=false;
    bool existing_is_v6=false;   // 现有输出
    unsigned char existing_mode=0; // 现有输出
    unsigned char existing_compression=0;  // v5 压缩标记
    int existing_comp_level=0;             // v5 压缩级别
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
    std::string prog_binding = fe_compute_progress_binding(in_path);

    if(resume && prog_present && fe_load_progress(out_path,prog_info)) {
        if(existing_is_v3) {
            if(!derive_key(password.data(),password.size(),existing_v3.salt,key.data(),
                    existing_v3.opslimit,(size_t)existing_v3.memlimit_kb*1024)) {
                fprintf(stderr,"Key derivation failed for resume\n");
            } else {
                derive_progress_auth_key(key.data(),auth_key.data());
                // v4 / v5 输出
                bool hdr_ok=true;
                if(existing_is_v4 || existing_is_v5) {
                    unsigned char hdr_auth[HEADER_HMAC_SIZE];
                    derive_header_auth_key(key.data(),hdr_auth);
                    size_t cover = existing_is_v5 ? HEADER_HMAC_COVER_V5 : HEADER_HMAC_COVER;
                    hdr_ok=(crypto_auth_verify(existing_hdr_hmac,
                        reinterpret_cast<const unsigned char*>(&existing_v3),cover,hdr_auth)==0);
                    sodium_memzero(hdr_auth,sizeof(hdr_auth));
                }
                if(hdr_ok && fe_verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
                    && prog_info.processed_chunks<=total_chunks
                    && prog_info.processed_bytes<=total_size) {
                    has_progress=true;
                }
            }
        }
        else if(existing_is_v6) {
            // v6 续传
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
                    sodium_memzero(hdr_auth,sizeof(hdr_auth));
                    if(hdr_ok && fe_verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
                        && prog_info.processed_chunks<=total_chunks
                        && prog_info.processed_bytes<=total_size) {
                        has_progress=true;
                    }
                } else {
                    fprintf(stderr,"Failed to unwrap DEK on resume (wrong password)\n");
                }
                sodium_memzero(kek.data(),kek.size());
            }
        }
        // 注意
        // 保留 key
    }

    // .prs 无法认证
    // 造成数据永久丢
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

    // 自动试压
    if(compress_level == FE_COMPRESS_AUTO) {
        int probed = 0;
        if(!has_progress && total_size > 0) {
            std::streampos save = inp->tellg();
            if(save < 0) save = 0;
            size_t want = (size_t)std::min<uint64_t>(64 * 1024, total_size);
            std::vector<unsigned char> probe(want);
            inp->read(reinterpret_cast<char*>(probe.data()), (std::streamsize)want);
            size_t got = (size_t)inp->gcount();
            inp->clear();
            inp->seekg(save, std::ios::beg);
            probed = fe_probe_compress_level(probe.data(), got);
        }
        compress_level = probed;
    }

    // 压缩决策
    bool do_compress;
#ifdef FE_WITH_ZSTD
    do_compress = (compress_level != 0) || (has_progress && existing_is_v5 && existing_compression==1);
    if(do_compress && has_progress && existing_is_v5 && existing_compression==1 && compress_level==0)
        compress_level = existing_comp_level;
#else
    do_compress = false;
    (void)compress_level;
#endif
    // v6
    // 载荷 AAD 只覆盖稳定
    const bool use_v6 = true;
    const size_t hdr_cover = use_v6 ? HEADER_HMAC_COVER_V6
                          : (do_compress ? HEADER_HMAC_COVER_V5 : HEADER_HMAC_COVER);
    const size_t aad_cover = use_v6 ? HEADER_AAD_COVER_V6 : hdr_cover;
    const bool resume_compressed = (has_progress && existing_is_v5 && existing_compression==1);

    size_t existing_hdr_size = existing_is_v6 ? HEADER_SIZE_V6
                              : (existing_is_v5 ? HEADER_SIZE_V5
                                : (existing_is_v4 ? HEADER_SIZE_V4 : HEADER_SIZE_V3));
    // 续传时沿用既有
    // st_chunk 与新默认值
    uint32_t res_chunk=0; uint32_t res_total=0; uint64_t res_orig=0; bool res_meta=false;
    if(has_progress&&start_chunk>0) {
        std::ifstream fhex;
        if(open_stream(fhex,out_path,std::ios::binary)
            && fhex.seekg(existing_hdr_size,std::ios::beg)
            && fhex.read(reinterpret_cast<char*>(&res_chunk),4)
            && fhex.read(reinterpret_cast<char*>(&res_total),4)
            && fhex.read(reinterpret_cast<char*>(&res_orig),8)) {
            res_meta=true;
            if(res_chunk>=MIN_CHUNK_SIZE&&res_chunk<=MAX_CHUNK_SIZE&&res_chunk!=chunk_size) {
                chunk_size=res_chunk;
                total_chunks_64=(total_size+chunk_size-1)/chunk_size;
                total_chunks=static_cast<uint32_t>(total_chunks_64);
            }
        }
    }

    uint64_t trunc_pos;
    if(resume_compressed && start_chunk>0) {
        // v5 压缩文件
        uint64_t off=0; bool scan_ok=true;
        std::ifstream ef;
        if(open_stream(ef,out_path,std::ios::binary) && ef.seekg((std::streamoff)(existing_hdr_size+12))) {
            for(uint32_t i=0;i<start_chunk;++i) {
                uint32_t cl=0;
                if(!ef.read(reinterpret_cast<char*>(&cl),4) || ef.gcount()!=4) { scan_ok=false; break; }
                // 前缀 4 字节 = 本块 AEAD 密
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

    // 跨进程锁
    // 流输出
    std::string lock_path;
    if(out_stream) {
        // 流输出无锁对象
    } else {
        LockResult lr=fe_acquire_output_lock(out_path,lock_path);
        if(lr!=LockResult::OK) {
            if(lr==LockResult::LOCKED)
                fprintf(stderr,"Output file is locked by another process: %s\n",out_path.c_str());
            else
                fprintf(stderr,"Cannot create output lock file (permission or path issue): %s\n",lock_path.c_str());
            return false;
        }
    }
    OutputLockGuard lock_guard{lock_path,true};

    // 防符号链接劫持
    if(path_is_symlink(out_path)) {
        fprintf(stderr,"Refusing to write through existing symlink: %s\n",out_path.c_str());
        return false;
    }

    // 续传一致性校验
    // cleanup 会删 .ptd/.prs，用户可用正
    if(has_progress&&start_chunk>0) {
        if(existing_mode!=static_cast<unsigned char>(mode)) {
            fprintf(stderr,"Output file was created with a different encryption mode "
                "(existing=%d, requested=%d); cannot resume. Use the same -m mode, "
                "or delete the output file first.\n",
                (int)existing_mode,(int)mode);
            return false;
        }
        if(!res_meta) {
            fprintf(stderr,"Cannot read metadata from existing file\n");
            return false;
        }
        const uint32_t st_chunk=res_chunk, st_total=res_total;
        const uint64_t st_orig=res_orig;
        if(st_chunk!=chunk_size||st_total!=total_chunks||st_orig!=orig_size) {
            fprintf(stderr,"Metadata mismatch: file may be corrupted\n");
            return false;
        }
    }

    std::fstream fout;
    std::ostream* eff_out=nullptr;   // 流输出模式指
    std::ostream* wout=nullptr;     // 实际写入目标
    if(out_stream) {
        // 流输出
        eff_out=out_stream;
        wout=out_stream;
    }
    else if(has_progress&&start_chunk>0) {
        // 续传
        if(!fe_truncate_file(out_path,trunc_pos)) {
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
#ifdef _WIN32
        // Windows
#else
        ScopedUmask su(0077);
#endif
        if(!fe_create_output_no_follow(out_path)) {
            fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        if(!open_stream(fout,out_path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(out_path);
        fe_remove_progress(out_path);
    }

    bool header_written=has_progress&&start_chunk>0;

    FileHeaderV6 header{};
    bool ok=true;
    std::unique_ptr<Cipher> ciph=create_cipher(mode);
    if(!ciph) { fprintf(stderr,"Unsupported encryption mode\n"); return false; }
    std::vector<unsigned char> aad;
    PooledBuf plaintext_chunk(DataBufPool::plain());
    // 压缩帧缓冲
    PooledBuf comp_chunk(DataBufPool::comp());
    PooledBuf ciphertext_chunk(DataBufPool::cipher());
    unsigned char nonce[32]={0};
    uint64_t processed_bytes=start_bytes;

    // 小于 64 MiB
    // .prs 写穿
    bool persistent_progress=(total_size>=64ULL*1024*1024);

    // 4 MiB 聚合写出缓冲
    AggWriter outbuf;
    outbuf.bind(eff_out ? *eff_out : fout);
    if(!eff_out) wout=&fout;   // 文件模式

    if(!header_written) {
        memcpy(header.magic,MAGIC,4);
        header.version = use_v6 ? 6 : (do_compress ? 5 : VERSION);   // v6 容器默认
        header.mode=static_cast<unsigned char>(mode);
        header.iv_len=static_cast<unsigned char>(iv_len);
        header.opslimit=ARGON2_OPS_DEFAULT;
        header.memlimit_kb=ARGON2_MEM_DEFAULT_KB;
        {   // 功能14
            unsigned int pops=ARGON2_OPS_DEFAULT, pmem=ARGON2_MEM_DEFAULT_KB;
            kdf_preset_params(global_config().kdf_preset, pops, pmem);
            header.opslimit=pops;
            header.memlimit_kb=pmem;
        }
        // 批量预派生
        if(ext_salt) memcpy(header.salt,ext_salt,ARGON2_SALT_LEN);
        else         randombytes_buf(header.salt,ARGON2_SALT_LEN);
        randombytes_buf(header.iv,iv_len);
        header.compression = do_compress ? 1 : 0;
        header.comp_level   = do_compress ? (unsigned char)(int)compress_level : 0;
        sodium_memzero(header.plaintext_hash,HASH_SIZE);
        sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);

        // v6 容器
        // 载荷 AEAD 密钥 = DEK
        // 非对称模式
        SecureBuffer kek(ARGON2_OUTPUT_LEN);
        if(asym_active) {
            sodium_memzero(kek.data(), kek.size());
        } else if(ext_kek) {
            // 批量预派生命
            memcpy(kek.data(),ext_kek,ARGON2_OUTPUT_LEN);
        } else if(!derive_key(password.data(),password.size(),header.salt,kek.data(),
                header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false; goto cleanup;
        }
        if(use_v6) {
            unsigned char dek[32];
            randombytes_buf(dek,sizeof(dek));
            put_be32(reinterpret_cast<unsigned char*>(&header.container_len), V6_CONTAINER_LEN);
            if(asym_active) {
                // 非对称
                std::vector<RecipientStanza> stanzas;
                AsymOutcome aw=fe_wrap_dek_to_recipients(dek,*asym_recipients,stanzas);
                if(!aw.ok) {
                    fprintf(stderr,"Recipient wrap failed: %s\n",aw.error.c_str());
                    sodium_memzero(dek,sizeof(dek)); ok=false; goto cleanup;
                }
                if(!serialize_recipients(stanzas, recip_blob_out)) {
                    fprintf(stderr,"Recipient blob serialize failed\n");
                    sodium_memzero(dek,sizeof(dek)); ok=false; goto cleanup;
                }
                put_recip_len(header.reserved, (uint32_t)recip_blob_out.size());
                // dek_box 留零
                memset(header.dek_box, 0, sizeof(header.dek_box));
            } else {
                if(!wrap_dek(dek, kek.data(), header.dek_nonce, header.dek_box)) {
                    fprintf(stderr,"DEK wrap failed\n"); ok=false; goto cleanup;
                }
            }
            put_be32(reinterpret_cast<unsigned char*>(&header.key_version), 0);
            sodium_memzero(header.reserved + 4, sizeof(header.reserved) - 4);
            memcpy(key.data(), dek, 32);          // 载荷密钥 = DEK
            sodium_memzero(dek, sizeof(dek));
        } else {
            memcpy(key.data(), kek.data(), ARGON2_OUTPUT_LEN);   // 旧格式
        }
        sodium_memzero(kek.data(), kek.size());
        derive_progress_auth_key(key.data(),auth_key.data());

        // 载荷 AAD 只覆盖稳定
        aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
            aad_cover, chunk_size,total_chunks,orig_size);

        // 流输出
        // 故先对缓冲明文
        if(out_stream && !out_seekable) {
            crypto_generichash(header.plaintext_hash, HASH_SIZE,
                reinterpret_cast<const unsigned char*>(mem_in.data()), mem_in.size(), nullptr, 0);
        }

        // 文件头 HMAC 写头时即
        // 半成品 .ptd
        {
            unsigned char hdr_auth[HEADER_HMAC_SIZE];
            derive_header_auth_key(key.data(),hdr_auth);
            crypto_auth(header.header_hmac,
                reinterpret_cast<const unsigned char*>(&header),hdr_cover,hdr_auth);
            sodium_memzero(hdr_auth,sizeof(hdr_auth));
        }

        if(!wout->write(reinterpret_cast<const char*>(&header),
                use_v6 ? HEADER_SIZE_V6 : (do_compress?HEADER_SIZE_V5:HEADER_SIZE_V4))) {
            fprintf(stderr,"Write header failed\n"); ok=false; goto cleanup;
        }
        // 非对称
        if(asym_mode && !recip_blob_out.empty()) {
            if(!wout->write(reinterpret_cast<const char*>(recip_blob_out.data()),
                    (std::streamsize)recip_blob_out.size())) {
                fprintf(stderr,"Write recipient blob failed\n"); ok=false; goto cleanup;
            }
        }
        if(!wout->write(reinterpret_cast<const char*>(&chunk_size),4)||
            !wout->write(reinterpret_cast<const char*>(&total_chunks),4)||
            !wout->write(reinterpret_cast<const char*>(&orig_size),8)) {
            fprintf(stderr,"Write metadata failed\n"); ok=false; goto cleanup;
        }
    }
    else {
        if(existing_is_v6) {
            // v6 续传
            header = existing_v6;
            SecureBuffer kek(ARGON2_OUTPUT_LEN);
            if(!derive_key(password.data(),password.size(),header.salt,kek.data(),
                    header.opslimit,(size_t)header.memlimit_kb*1024)) {
                ok=false; goto cleanup;
            }
            unsigned char dek[32];
            if(!unwrap_dek(header.dek_box, kek.data(), header.dek_nonce, dek)) {
                fprintf(stderr,"Failed to unwrap DEK on resume (wrong password)\n");
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

    // 明文 Blake2b 流式哈希
    crypto_generichash_state hstate;
    crypto_generichash_init(&hstate,nullptr,0,HASH_SIZE);
    if(start_bytes>0) {
        inp->seekg(0,std::ios::beg);
        uint64_t remain=start_bytes;
        PooledBuf tmp(DataBufPool::plain());
        while(remain>0) {
            size_t n=(size_t)std::min<uint64_t>(CHUNK_SIZE,remain);
            inp->read(reinterpret_cast<char*>(tmp.data()),n);
            if(inp->gcount()!=(std::streamsize)n) {
                fprintf(stderr,"Read error during hash catch-up\n");
                ok=false; break;
            }
            crypto_generichash_update(&hstate,tmp.data(),n);
            remain-=n;
        }
        if(!ok) goto cleanup;
        inp->seekg((std::streamoff)start_bytes,std::ios::beg);
    }

    // nonce 基值 =
    memcpy(nonce,header.iv,iv_len);
    for(uint32_t k=0;k<start_chunk;++k) sodium_increment(nonce,iv_len);

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
        if(processed_bytes>=total_size) break;
        size_t chunk_len=std::min<size_t>(chunk_size,(size_t)(total_size-processed_bytes));
        inp->read(reinterpret_cast<char*>(plaintext_chunk.data()),chunk_len);
        if(inp->gcount()!=(std::streamsize)chunk_len) {
            fprintf(stderr,"Read error at chunk %u\n",i);
            ok=false; break;
        }

        crypto_generichash_update(&hstate,plaintext_chunk.data(),chunk_len);

        // v5+压缩
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
        int rc=ciph->encrypt(aead_in,aead_in_len,aad.data(),aad.size(),
            nonce,key.data(),ciphertext_chunk.data(),ciphertext_len);
        if(rc!=0) {
            fprintf(stderr,"Encryption failed at chunk %u\n",i);
            ok=false; break;
        }

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
        fe_throttle_consume(chunk_len);
        // 逐块 save_progress 曾拖垮吞吐
        // 保持「磁盘 out ≥ .prs 记账」
        // 流输出
        auto prs_now=std::chrono::steady_clock::now();
        if(persistent_progress && !out_stream && prs_now-last_prs_save>=std::chrono::milliseconds(500)) {
            outbuf.flush();   // 先落盘密文
            if(!fe_save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
                fprintf(stderr,"Failed to save progress at chunk %u\n",i);
            }
            last_prs_save=prs_now;
        }

        if(progress_callback) progress_callback(processed_bytes,total_size);
        else print_progress(processed_bytes,total_size,start_time,false,
                           out_stream ? &std::cerr : &std::cout);

        if(i+1<total_chunks) sodium_increment(nonce,iv_len);
    }

    if(ok) {
        if(out_stream && !out_seekable) {
            // 不可 seek 流输出
            // 仍需追加加密文
            outbuf.flush();
            if(!fe_append_encrypted_name_footer(*out_stream,footer_src,key.data(),header.salt)) {
                fprintf(stderr,"Failed to append encrypted original-name footer.\n");
                ok=false;
            }
            out_stream->flush();
        }
        else if(out_stream) {
            // 可 seek 流输出
            // 再定位末尾写文
            crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
            unsigned char hdr_auth[HEADER_HMAC_SIZE];
            derive_header_auth_key(key.data(),hdr_auth);
            crypto_auth(header.header_hmac,
                reinterpret_cast<const unsigned char*>(&header),hdr_cover,hdr_auth);
            sodium_memzero(hdr_auth,sizeof(hdr_auth));
            outbuf.flush();   // 先把缓冲
            size_t hdr_size = use_v6 ? HEADER_SIZE_V6
                            : (do_compress?HEADER_SIZE_V5:HEADER_SIZE_V4);
            wout->seekp((std::streamoff)(hdr_size-HASH_SIZE-HEADER_HMAC_SIZE),std::ios::beg);
            wout->write(reinterpret_cast<const char*>(header.plaintext_hash),HASH_SIZE);
            wout->write(reinterpret_cast<const char*>(header.header_hmac),HEADER_HMAC_SIZE);
            wout->seekp(0,std::ios::end);
            if(!fe_append_encrypted_name_footer(*out_stream,footer_src,key.data(),header.salt)) {
                fprintf(stderr,"Failed to append encrypted original-name footer.\n");
                ok=false;
            }
            out_stream->flush();
        } else {
            // 结束哈希并回填
            // v6=192 / v5=63 / v4=61 字
            crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
            unsigned char hdr_auth[HEADER_HMAC_SIZE];
            derive_header_auth_key(key.data(),hdr_auth);
            crypto_auth(header.header_hmac,
                reinterpret_cast<const unsigned char*>(&header),hdr_cover,hdr_auth);
            sodium_memzero(hdr_auth,sizeof(hdr_auth));
            outbuf.flush();   // 先把缓冲
            size_t hdr_size = use_v6 ? HEADER_SIZE_V6
                            : (do_compress?HEADER_SIZE_V5:HEADER_SIZE_V4);
            fout.seekp((std::streamoff)(hdr_size-HASH_SIZE-HEADER_HMAC_SIZE),std::ios::beg);
            fout.write(reinterpret_cast<const char*>(header.plaintext_hash),HASH_SIZE);
            fout.write(reinterpret_cast<const char*>(header.header_hmac),HEADER_HMAC_SIZE);
            fout.flush();
            if(wm && wm->enabled && !fe_append_watermark_tail(fout,*wm)) {
                fprintf(stderr,"Failed to append watermark tail.\n");
                ok=false;
            }
            if(ok && !fe_append_encrypted_name_footer(fout,footer_src,key.data(),header.salt)) {
                fprintf(stderr,"Failed to append encrypted original-name footer.\n");
                ok=false;
            }
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
        fe_remove_progress(out_path);
        if(!progress_callback) print_progress(total_size,total_size,start_time,true,
                                              out_stream ? &std::cerr : &std::cout);

        // 自解密验证
        // 落盘 .verify.tmp
        // 流输出
        if(!out_stream) {
        bool verify_ok=decrypt_file(out_path, out_path, password,
            [](size_t,size_t){}, true, false, key.data(), nullptr, 0, true);
        if(!verify_ok) {
            ok=false;
            remove_file_utf8(out_path);
            fe_remove_progress(out_path);
            fprintf(stderr,"Self-decrypt verification failed, output removed.\n");
        }
        }
    }
    else {
        remove_file_utf8(out_path);
        fe_remove_progress(out_path);
        fprintf(stderr,"Encryption failed, output removed.\n");
    }

    // 自校验已结束
    // 函数返回时析构
    return ok;
}

// 解密
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    std::function<void(size_t,size_t)> progress_callback,
    bool silent,
    bool resume,
    const unsigned char* ext_key,
    const unsigned char* ext_kek, size_t ext_kek_len,
    bool verify_only,
    size_t preview_bytes,
    const std::string& asym_identity, bool force_overwrite,
    std::ostream* out_stream,
    std::istream* in_stream) {
    size_t force_skipped_chunks=0;
    bool preview_only=(preview_bytes>0);
    g_last_fail_auth.store(false);   // 本次解密
    if(preview_only || out_stream) {
        // 预览/管道输出走
#ifdef _WIN32
        (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
    }
    disable_core_dump();

    // 依据 YAML 配置校验输
    if(!out_stream && !validate_io_paths(in_path,out_path,silent)) {
        if(!silent) fprintf(stderr,"Path validation failed (config policy)\n");
        return false;
    }

    // 防路径穿越
    if(!out_stream && path_has_traversal(out_path)) {
        if(!silent) fprintf(stderr,"Output path contains directory traversal\n");
        return false;
    }
    // 密码
    if(password.size()<PASSWORD_MIN_LEN && asym_identity.empty() && !ext_key) {
        if(!silent) fprintf(stderr,"Password too short (min %zu characters)\n",PASSWORD_MIN_LEN);
        return false;
    }

    // 输入侧 4 MiB 页对齐大
    InputBuffer fin_buf;
    std::ifstream fin;
    std::istream* finp=&fin;   // fd 输入时指向调用
    if(in_stream) {
        finp=in_stream;   // fd / 外部流
    }
    else if(!open_stream(fin,in_path,std::ios::binary)) {
        if(!silent) fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }
    fin_buf.attach(*finp);
    finp->seekg(0,std::ios::end);
    auto file_size=finp->tellg();
    finp->seekg(0,std::ios::beg);

    // 版本感知
    // 缓冲须容纳
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
    bool is_v5=false;          // v5 头部
    bool is_v6=false;          // v6 容器头部
    bool comp_on=false;        // 本文件已启用 zstd 压
    int comp_level_val=0;      // 已编码
    uint32_t v6_key_version=0; // v6 密钥版本
    uint32_t recip_len=0;      // v6 收件人 blob 字节数
    std::vector<RecipientStanza> recip_stanzas;  // v6 非对称收件人条

    // strict-aliasing 安全：头部
    // salt/iv 指针指向这些结
    FileHeaderV1 hv1{}; FileHeaderV2 hv2{}; FileHeaderV3 hv3{};
    FileHeaderV4 hv4{}; FileHeaderV5 hv5{}; FileHeaderV6 hv6{};

    // 密钥相关缓冲区
    SecureBuffer key(ARGON2_OUTPUT_LEN);
    SecureBuffer auth_key(crypto_auth_KEYBYTES);

    if(!finp->read(reinterpret_cast<char*>(hdrbuf),5)) {
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
            return false;
        }
        if(!finp->read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
            return false;
        }
        if(!finp->read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
            return false;
        }
        if(!finp->read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
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
        // v4
        hdr_size=HEADER_SIZE_V4;
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
            return false;
        }
        if(!finp->read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
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
        // v5
        hdr_size=HEADER_SIZE_V5;
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
            return false;
        }
        if(!finp->read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
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
        // v6 容器
        hdr_size=HEADER_SIZE_V6;
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
            return false;
        }
        if(!finp->read(reinterpret_cast<char*>(hdrbuf+5),hdr_size-5)) {
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
        recip_len=get_recip_len(hv6.reserved);
    }
    else {
        if(!silent) fprintf(stderr,"Unsupported file version: %u\n",ver);
        return false;
    }

    // 严格校验加密模
    if(mode!=CryptoMode::AES_GCM&&mode!=CryptoMode::XCHACHA20&&mode!=CryptoMode::AEGIS256&&mode!=CryptoMode::SM4) {
        if(!silent) fprintf(stderr,"Invalid encryption mode in header\n");
        return false;
    }
    // 兜底
    size_t tag_size=tag_size_for_mode(mode);
    if(iv_len>32) {
        if(!silent) fprintf(stderr,"Invalid IV length (too large)\n");
        return false;
    }
    // 旧格式
    // 会越界读到相邻
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

    // v6 非对称容器
    // recip_len 已在头部解析阶
    if(is_v6 && recip_len>0) {
        std::vector<unsigned char> blob(recip_len);
        if(!finp->read(reinterpret_cast<char*>(blob.data()), (std::streamsize)recip_len) ||
           (size_t)finp->gcount()!=recip_len) {
            if(!silent) fprintf(stderr,"Read recipient blob failed\n");
            return false;
        }
        if(!parse_recipients(blob.data(), recip_len, recip_stanzas)) {
            if(!silent) fprintf(stderr,"Parse recipient blob failed\n");
            return false;
        }
    }

    uint32_t chunk_size=0,total_chunks=0;
    uint64_t orig_size=0;
    if(!finp->read(reinterpret_cast<char*>(&chunk_size),4)||
        !finp->read(reinterpret_cast<char*>(&total_chunks),4)||
        !finp->read(reinterpret_cast<char*>(&orig_size),8)) {
        if(!silent) fprintf(stderr,"Read metadata failed\n");
        return false;
    }

    // 块大小
    if(chunk_size<MIN_CHUNK_SIZE||chunk_size>MAX_CHUNK_SIZE) {
        if(!silent) {
            fprintf(stderr,"Invalid chunk_size: %u (allowed %zu..%zu). File may be corrupted.\n",
                chunk_size,(size_t)MIN_CHUNK_SIZE,(size_t)MAX_CHUNK_SIZE);
        }
        return false;
    }

    // 派生密钥
    // 计算源文件绑定
    std::string prog_binding = fe_compute_progress_binding(in_path);
    // ext_kek
    // ext_key
    const bool have_kek = (ext_kek && ext_kek_len >= ARGON2_OUTPUT_LEN);
    if(is_v6) {
        // v6 非对称容器
        if(!asym_identity.empty()) {
            if(recip_stanzas.empty()) {
                report_auth_error(silent, "Asymmetric container has no recipient entries.");
                return false;
            }
            unsigned char dek[32];
            if(!fe_recover_dek_from_stanzas(recip_stanzas, asym_identity, dek).ok) {
                report_auth_error(silent, "Failed to recover DEK (no matching identity or corrupted container).");
                sodium_memzero(dek, sizeof(dek));
                return false;
            }
            memcpy(key.data(), dek, 32);
            sodium_memzero(dek, sizeof(dek));
        }
        // v6 容器
        else if(have_kek) {
            unsigned char dek[32];
            if(!unwrap_dek(hv6.dek_box, ext_kek, hv6.dek_nonce, dek)) {
                report_auth_error(silent, "Failed to unwrap DEK (wrong password or corrupted container).");
                return false;
            }
            memcpy(key.data(), dek, 32);
            sodium_memzero(dek, sizeof(dek));
        } else if(ext_key) {
            memcpy(key.data(), ext_key, ARGON2_OUTPUT_LEN);   // 自校验
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
        // 非 v6
        if(ext_key) memcpy(key.data(), ext_key, ARGON2_OUTPUT_LEN);
        else        memcpy(key.data(), ext_kek, ARGON2_OUTPUT_LEN);
        derive_progress_auth_key(key.data(), auth_key.data());
    } else if(!derive_key(password.data(),password.size(),salt_ptr,key.data(),kdf_ops,kdf_mem)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    } else {
        derive_progress_auth_key(key.data(), auth_key.data());
    }

    // v4/v5/v6 文件头 HMAC 校验：独立
    // v6 由 DEK 派生密钥、覆盖
    if(is_v4 || is_v5 || is_v6) {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(key.data(), hdr_auth);
        if(crypto_auth_verify(hdr_hmac, hdrbuf, header_hmac_cover(ver), hdr_auth)!=0) {
            report_auth_error(silent, "Header authentication failed (file tampered or wrong key).");
            return false;
        }
        sodium_memzero(hdr_auth,sizeof(hdr_auth));
    }

    // 跨进程锁 + 流式直
    // 防符号链接劫持
    // 流输出
    if(!verify_only && !preview_only && !out_stream && path_is_symlink(out_path)) {
        if(!silent) fprintf(stderr,"Refusing to write through existing symlink: %s\n",out_path.c_str());
        return false;
    }
    std::string lock_path;
    OutputLockGuard lock_guard;   // 函数作用域 RAII
    if(!verify_only && !preview_only && !out_stream) {
        LockResult lr=fe_acquire_output_lock(out_path,lock_path);
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

    // 密文末尾可能附
    uint64_t footer_len=0;
    if(in_stream) {
        // fd 输入
        (void)fe_peek_name_footer_len_stream(*in_stream,(uint64_t)file_size,footer_len);
        finp->clear();
        finp->seekg(0,std::ios::beg);
    } else {
        fe_peek_name_footer_len(in_path, footer_len);
    }

    uint64_t total_size=orig_size;
    if(total_chunks==0) {
        if((size_t)file_size!=hdr_size+recip_len+4+4+8+footer_len) {
            if(!silent) fprintf(stderr,"File size mismatch for empty file.\n");
            return false;
        }
        if(verify_only || preview_only) {
            // 自校验 / 预览空文
            if(have_hash && !preview_only) {
                unsigned char empty_hash[HASH_SIZE];
                crypto_generichash(empty_hash,HASH_SIZE,nullptr,0,nullptr,0);
                if(sodium_memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) return false;
            }
            return true;
        }
        if(out_stream) {
            // 空文件
            if(have_hash) {
                unsigned char empty_hash[HASH_SIZE];
                crypto_generichash(empty_hash,HASH_SIZE,nullptr,0,nullptr,0);
                if(sodium_memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) {
                    report_auth_error(silent, "Plaintext integrity check failed (empty file).");
                    return false;
                }
            }
            return true;
        }
        std::ofstream fout;
#ifdef _WIN32
        // Windows
#else
        ScopedUmask su_empty(0077);
#endif
        if(!fe_create_output_no_follow(out_path)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        if(!open_stream(fout,out_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(out_path);
        fout.close();
        fe_remove_progress(out_path);
        // 空文件完整性校
        if(have_hash) {
            unsigned char empty_hash[HASH_SIZE];
            crypto_generichash(empty_hash,HASH_SIZE,nullptr,0,nullptr,0);
            if(sodium_memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) {
                report_auth_error(silent, "Plaintext integrity check failed (empty file).");
                remove_file_utf8(out_path);
                return false;
            }
        }
        return true;
    }

    uint64_t last_chunk_len=orig_size-(uint64_t)(total_chunks-1)*chunk_size;
    // 压缩文件
    if(!comp_on) {
        uint64_t expected_size=(uint64_t)hdr_size+recip_len+4+4+8
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
    // 续传需要「进度文
    bool has_progress=false;
    std::string part_path = out_path + ".prt";   // 半成品
    if(resume && fe_load_progress(out_path,prog_info) && fe_file_exists(part_path)) {
        // 密钥
        // 并把源文件绑定
        if(fe_verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
            && prog_info.processed_chunks<=total_chunks
            && prog_info.processed_bytes<=total_size) {
            has_progress=true;
        } else {
            if(!silent) fprintf(stderr,"Corrupted progress file detected, restarting from beginning.\n");
        }
    }
    uint64_t start_chunk=has_progress ? prog_info.processed_chunks : 0;
    uint64_t start_bytes=has_progress ? prog_info.processed_bytes : 0;

    // 解密续传
    std::fstream fout;
    std::ostream* eff_out = nullptr;   // stream 模式指向调用方
    if(verify_only || preview_only) {
        // 自校验 / 预览模式
    }
    else if(out_stream) {
        // 管道输出
        eff_out = out_stream;
    }
    else if(has_progress&&start_chunk>0) {
        if(!fe_truncate_file(part_path,start_bytes)) {
            if(!silent) fprintf(stderr,"Failed to truncate partial output for resume: %s\n",out_path.c_str());
            return false;
        }
        if(!open_stream(fout,part_path,std::ios::in|std::ios::out|std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot open output file for resume: %s\n",out_path.c_str());
            return false;
        }
        fout.seekp((std::streamoff)start_bytes,std::ios::beg);
    }
    else {
#ifdef _WIN32
        // Windows
#else
        ScopedUmask su_out(0077);
#endif
        if(force_overwrite) { remove_file_utf8(out_path); remove_file_utf8(part_path); }
        if(!fe_create_output_no_follow(part_path)) {
            if(!silent) {
                if(fe_file_exists(part_path))
                    fprintf(stderr,"Output file already exists (delete it first, or use -y to overwrite, or resume if interrupted): %s\n",out_path.c_str());
                else
                    fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            }
            return false;
        }
        if(!open_stream(fout,part_path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(part_path);
        fe_remove_progress(out_path);
    }

    // 4 MiB 聚合写出缓冲
    AggWriter outbuf;
    if(!verify_only && !preview_only) outbuf.bind(eff_out ? *eff_out : fout);

    // 密钥已

    // AAD 须严格复刻加密
    // v6 只到稳定前缀
    size_t aad_hdr_len=(ver==6) ? HEADER_AAD_COVER_V6 : header_hmac_cover(ver);
    std::vector<unsigned char> aad=build_aad_with_metadata(hdrbuf,aad_hdr_len,chunk_size,total_chunks,orig_size);

    // AES-GCM / AEGIS-256
    // 走 EVP
    // 换算法
    if(mode==CryptoMode::AES_GCM && !aes_gcm_supported()) {
        if(!silent) fprintf(stderr,"该文件使用 AES-256-GCM，当前设备不支持该算法，无法解密。\n");
        return false;
    }
    if(mode==CryptoMode::AEGIS256 && !aegis256_supported()) {
        if(!silent) fprintf(stderr,"该文件使用 AEGIS-256，需要 CPU 支持 AES-NI，当前机器不支持，无法解密。\n");
        return false;
    }

    std::unique_ptr<Cipher> ciph=create_cipher(mode);
    if(!ciph) {
        if(!silent) fprintf(stderr,"Unsupported encryption mode in header\n");
        return false;
    }

    auto start_time=std::chrono::steady_clock::now();
    // .prs 节流基点
    auto last_prs_save=std::chrono::steady_clock::now();
    // 压缩块密文上界
    // 一律
    // 上界尺寸既能容
    PooledBuf ciphertext_chunk(DataBufPool::cipher());
    PooledBuf plaintext_chunk(DataBufPool::comp());   // AEAD 输出暂存
    PooledBuf dec_chunk(DataBufPool::plain());        // zstd 解压
    unsigned char nonce[32]={0};
    bool ok=true;
    bool rename_failed=false;   // rename 收尾失败
    uint64_t processed_bytes=start_bytes;
    uint64_t preview_written=0;   // 预览模式已写出 stdout
    // 小于 64 MiB
    bool persistent_progress=(total_size>=64ULL*1024*1024);

    // 提前声明
    bool use_increment=(ver==VERSION || ver==5 || ver==6);
    size_t input_offset=0;

    // 防整数溢出 / 越界
    // 须边界校验
    {
        // 非对称容器
        const uint64_t base = (uint64_t)hdr_size + (uint64_t)recip_len + 4 + 4 + 8;
        if(comp_on && start_chunk>0) {
            // 变长块
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
            if(!scan_ok) { if(!silent) fprintf(stderr,"Resume scan failed (corrupted file)\n"); ok=false; goto dec_cleanup; }
            uint64_t off_total = base + off;
            if(off_total > (uint64_t)file_size) { if(!silent) fprintf(stderr,"Seek offset out of range (corrupted header)\n"); ok=false; goto dec_cleanup; }
            input_offset=(size_t)off_total;
        } else {
            const uint64_t stride = (uint64_t)chunk_size + (uint64_t)tag_size;
            uint64_t off = base;
            if(stride != 0 && start_chunk > ((uint64_t)-1 - base) / stride) {
                if(!silent) fprintf(stderr,"Seek offset overflow (corrupted header)\n");
                ok=false; goto dec_cleanup;
            }
            off += (uint64_t)start_chunk * stride;
            if(off > (uint64_t)file_size) {
                if(!silent) fprintf(stderr,"Seek offset out of range (corrupted header)\n");
                ok=false; goto dec_cleanup;
            }
            input_offset = (size_t)off;
        }
    }

    // 明文 Blake2b 流式哈希
    crypto_generichash_state hstate;
    if(have_hash || verify_only) crypto_generichash_init(&hstate,nullptr,0,HASH_SIZE);
    if((have_hash || verify_only) && start_bytes>0) {
        std::ifstream pin;
        if(!open_stream(pin,part_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot open output for hash catch-up\n");
            ok=false;
        }
        else {
            uint64_t remain=start_bytes;
            PooledBuf tmp(DataBufPool::plain());
            while(remain>0 && ok) {
                size_t n=(size_t)std::min<uint64_t>(CHUNK_SIZE,remain);
                pin.read(reinterpret_cast<char*>(tmp.data()),n);
                if(pin.gcount()!=(std::streamsize)n) {
                    if(!silent) fprintf(stderr,"Read output for hash catch-up failed\n");
                    ok=false; break;
                }
                crypto_generichash_update(&hstate,tmp.data(),n);
                remain-=n;
            }
            pin.close();
        }
        if(!ok) goto dec_cleanup;
    }

    finp->seekg(input_offset,std::ios::beg);

    // 初始化 nonce
    memcpy(nonce,iv_ptr,iv_len);
    if(use_increment) {
        for(uint32_t k=0;k<start_chunk;++k) sodium_increment(nonce,iv_len);
    }
    else {
        uint64_t idx=start_chunk;
        fe::util::xor_le64_tail(nonce, iv_len, idx);
    }

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
        if(processed_bytes>=total_size) break;
        size_t chunk_len=std::min<size_t>(chunk_size,(size_t)(total_size-processed_bytes));
        // 读本块密文
        // 故记录
        size_t expected_cipher_len;
        if(comp_on) {
            uint32_t cl=0;
            if(!finp->read(reinterpret_cast<char*>(&cl),4) || finp->gcount()!=4) {
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
        finp->read(reinterpret_cast<char*>(ciphertext_chunk.data()),expected_cipher_len);
        if(finp->gcount()!=(std::streamsize)expected_cipher_len) {
            if(!silent) fprintf(stderr,"Read ciphertext chunk %u failed\n",i);
            ok=false;
            break;
        }

        if(!use_increment) {
            // 旧格式
            memcpy(nonce,iv_ptr,iv_len);
            uint64_t idx=i;
            fe::util::xor_le64_tail(nonce, iv_len, idx);
        }

        unsigned long long frame_len=0;   // AEAD 输出长度
        int rc=ciph->decrypt(ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),
            nonce,key.data(),plaintext_chunk.data(),frame_len);
        if(rc!=0) report_auth_error(silent, "Decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        if(rc!=0) {
            if(!g_force_decrypt) { ok=false; break; }
            if(!silent) fprintf(stderr,"[force] chunk %u failed, zero-filled\n",i);
            secure_zero(plaintext_chunk.data(), chunk_len);
            frame_len=(unsigned long long)chunk_len;
            ++force_skipped_chunks;
        }

        // 解压
        const unsigned char* out_ptr=plaintext_chunk.data();
        size_t out_len=(size_t)frame_len;
        if(comp_on) {
#ifdef FE_WITH_ZSTD
            unsigned long long dl=ZSTD_decompress(dec_chunk.data(),chunk_len,plaintext_chunk.data(),frame_len);
            if(ZSTD_isError(dl)) {
                if(!g_force_decrypt) { report_auth_error(silent, "zstd decompression failed at chunk " + std::to_string(i) + "."); ok=false; break; }
                if(!silent) fprintf(stderr,"[force] zstd failed at chunk %u, zero-filled\n",i);
                out_ptr=plaintext_chunk.data();
                out_len=chunk_len;
                ++force_skipped_chunks;
            } else {
                if((size_t)dl!=chunk_len) {
                    report_auth_error(silent, "Decompressed size mismatch at chunk " + std::to_string(i) + ".");
                    ok=false; break;
                }
                out_ptr=dec_chunk.data();
                out_len=chunk_len;
            }
#else
            report_auth_error(silent, "This file uses zstd compression but the binary was built without zstd.");
            ok=false; break;
#endif
        }

        if(preview_only) {
            // 预览
            // 已解密
            uint64_t remain=(uint64_t)preview_bytes - preview_written;
            size_t take=(size_t)std::min<uint64_t>(out_len,remain);
            if(take>0) {
                size_t wrote=(size_t)fwrite(out_ptr,1,take,stdout);
                if(wrote!=take) { if(!silent) fprintf(stderr,"Preview stdout write failed\n"); ok=false; break; }
                preview_written+=wrote;
            }
            if(preview_written>=(uint64_t)preview_bytes) break;
        }
        else if(!verify_only && !outbuf.put(out_ptr,out_len)) {
            if(!silent) fprintf(stderr,"Write plaintext chunk %u failed\n",i);
            ok=false;
            break;
        }
        if((have_hash && !preview_only) || verify_only) crypto_generichash_update(&hstate,out_ptr,out_len);

        processed_bytes+=out_len;
        fe_throttle_consume(out_len);
        // 逐块 save_progress 曾拖垮吞吐
        // 保持「磁盘 out ≥
        if(!verify_only && !out_stream && persistent_progress) {
            auto prs_now=std::chrono::steady_clock::now();
            if(prs_now-last_prs_save>=std::chrono::milliseconds(500)) {
                outbuf.flush();   // 先落盘明文
                if(!fe_save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
                    if(!silent) fprintf(stderr,"Failed to save progress at chunk %u\n",i);
                }
                last_prs_save=prs_now;
            }
        }

        if(progress_callback) {
            progress_callback(processed_bytes,total_size);
        }
        else {
            print_progress(processed_bytes,total_size,start_time,false,
                           out_stream ? &std::cerr : &std::cout);
        }

        if(use_increment) {
            if(i+1<total_chunks) sodium_increment(nonce,iv_len);
        }
    }

    // 明文完整性校验
    if((have_hash && !preview_only) || verify_only) {
        unsigned char final_hash[HASH_SIZE];
        crypto_generichash_final(&hstate,final_hash,HASH_SIZE);
        if(ok && have_hash && sodium_memcmp(final_hash,stored_hash,HASH_SIZE)!=0) {
            if(!g_force_decrypt) {
                report_auth_error(silent, "Plaintext integrity check failed: recovered data does not match original.");
                ok=false;
            } else if(!silent) {
                fprintf(stderr,"[force] integrity hash mismatch ignored (%zu chunk(s) recovered)\n",force_skipped_chunks);
            }
        }
        // 自校验模式
        if(ok && verify_only && (uint64_t)processed_bytes!=(uint64_t)total_size) {
            if(!silent) fprintf(stderr,"Self-verify size mismatch.\n");
            ok=false;
        }
    }

dec_cleanup:
    // key / auth_key
    // 任何 return / goto 路径
    secure_clear(ciphertext_chunk);
    secure_clear(plaintext_chunk);

    if(!in_stream) fin.close();   // fd 输入流属调用方
    outbuf.flush();   // 把缓冲
    if(out_stream) {
        // 管道输出
        out_stream->flush();
        if(preview_only) fflush(stdout);
    } else {
        fout.close();
    }

    if(verify_only || preview_only) {
        // 自校验 / 预览模式
        if(preview_only) fflush(stdout);
        return ok;
    }
    if(ok) {
        fe_remove_progress(out_path);
        // 原子收尾
        // 管道输出无 .prt / 无落
        if(!out_stream && !verify_only && !preview_only) {
            if(std::rename(part_path.c_str(), out_path.c_str()) != 0) {
                rename_failed=true;
                if(!silent) fprintf(stderr,"Failed to finalize output (rename .prt -> %s)\n",out_path.c_str());
                ok=false;
            }
        }
        if(!rename_failed && !progress_callback) {
            print_progress(total_size,total_size,start_time,true,
                           out_stream ? &std::cerr : &std::cout);
        }
    }
    if(!ok) {
        // 失败
        if(!out_stream && !rename_failed && !verify_only && !preview_only) remove_file_utf8(part_path);
        fe_remove_progress(out_path);
        if(!rename_failed && !silent) {
            fprintf(stderr,"Decryption failed, partial output removed.\n");
        }
    }
    return ok;
}


// 批量处理相关函
// 已迁至 core/batch.cpp。声明保留
