#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <windows.h>    // 必须早于 C++ 头：CreateFileW / DeviceIoControl
#include <winioctl.h>   // FSCTL_GET_REPARSE_POINT
#endif
#include "FileEncryptor.hpp"
#ifdef FE_WITH_ZSTD
#include "zstd.h"   // 仅当构建集成了 zstd 预编译库时引入（third_party/zstd/include）
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
// 常量
// 主加密块大小。块大小写入文件头（v2+），解密按头里的值走，故上调不会让旧文件解不开。
// 实测上调到 4MiB 反而略慢（12 核，48×1MB: 6.94s vs 6.70s；8×64MB: 2.63s vs 2.58s）：
// 缓冲随块大小翻倍、局部性变差，抵掉了每块固定开销的节省。暂维持 1MiB。

// 头里 chunk_size 的合法区间：该值同时决定解密侧缓冲尺寸，须防伪造头诱导超大分配

// 读取端上界必须 <= CHUNK_SIZE：解密缓冲按 CHUNK_SIZE 固定取（含压缩帧上界），
// 放行更大的 chunk_size 会让 secure_zero / ZSTD_decompress 写出缓冲边界。

static constexpr size_t PASSWORD_MIN_LEN=6;

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;
static constexpr size_t AEGIS256_IV_LEN=crypto_aead_aegis256_NPUBBYTES;
static constexpr size_t SM4_IV_LEN=12;   // GCM 推荐 nonce 长度（SM4 仅在 FE_WITH_OPENSSL 时可用，常量恒定义便于三元式）
static constexpr size_t AEGIS256_TAG_SIZE=crypto_aead_aegis256_ABYTES;
static constexpr size_t TAG_SIZE=16;
static constexpr size_t MAX_TAG_SIZE=AEGIS256_TAG_SIZE;

// v2：新增 HMAC 认证，防续传劫持

// 压缩帧最大缓冲：每块原始明文最多压缩到 ZSTD_compressBound(CHUNK_SIZE) 字节
#ifdef FE_WITH_ZSTD
static const size_t COMP_BUF_MAX = ZSTD_compressBound(CHUNK_SIZE);
#else
static const size_t COMP_BUF_MAX = CHUNK_SIZE;
#endif

// 数据阶段缓冲池：批量每文件反复 malloc/free 数 MiB 会带来分配抖动与缺页开销，
// 池化后固定复用。明文缓冲归还时清零，密文缓冲无敏感内容故省去清零。
namespace {
struct DataBufPool {
    static BufferPool& plain()  { static BufferPool p(CHUNK_SIZE, true);  return p; }
    static BufferPool& comp()   { static BufferPool p(COMP_BUF_MAX, true); return p; }
    static BufferPool& cipher() { static BufferPool p(COMP_BUF_MAX+MAX_TAG_SIZE, false); return p; }
};
// 从池取缓冲、析构自动归还。接口与 std::vector 对齐，供 secure_clear 等模板直接使用。
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
    // 只擦内容不改容量：保持与池的容量一致，下一轮仍可命中复用
    void clear() { if(!v_.empty()) sodium_memzero(v_.data(),v_.size()); }
    void shrink_to_fit() {}
    PooledBuf(const PooledBuf&)=delete;
    PooledBuf& operator=(const PooledBuf&)=delete;
};
} // namespace

// ProgressInfo / PROGRESS_MAGIC / PROGRESS_VERSION / PROGRESS_SIZE 已迁入 core/resume.hpp

// 辅助：模式查询
size_t tag_size_for_mode(CryptoMode m) {
    if(m==CryptoMode::AEGIS256) return AEGIS256_TAG_SIZE;
#ifdef FE_WITH_OPENSSL
    if(m==CryptoMode::SM4)      return 16;
#endif
    return TAG_SIZE;
}

// 认证失败信息泄露防护
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

// 路径规范化（防别名绕过）
// lexically_normal 解析 . 与 ..，make_preferred 统一分隔符，堵住路径别名绕过。
// normalize_path_lexical 已迁到 core/fileio_util.cpp（对外名 fe_normalize_path_lexical）

// 续传进度绑定（防重放）
// 源路径+大小+mtime 纳入 .prs 的 HMAC，旧 .prs 无法重放到不同文件。
// 前向声明：is_complete_output / decrypt_file 需要提前获知尾部（加密名）长度做文件大小校验。

// 内容令牌：对源文件头部64KB+尾部64KB+总大小求 Blake2b 作指纹，防 mtime 复刻重放；
// 小文件(<128KB)直接全文哈希，大文件不读全文，开销恒定。

// 明文 Blake2b 哈希（完整性校验）
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

// 输入侧 4 MiB 页对齐大缓冲
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

// SHA-256 校验单（功能10）
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

// AEGIS-256 可用性探测（缺 AES-NI 不可用）
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

// 运行时探测 AES-256-GCM 是否可用。与 SM4 同口径：真跑一轮加解密往返，不看编译期宏。
bool aes_gcm_supported() {
#ifdef FE_WITH_OPENSSL
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
#else
    return false;
#endif
}

// 运行时探测 OpenSSL 是否提供后量子密码（ML-KEM-768 密钥交换 + ML-DSA-65 签名）。
// 实测 OpenSSL 4.1 的头文件未导出 EVP_PKEY_ML_KEM_768 宏，只能按 NID 建上下文探测。
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

// AAD 构建（元数据）
// 传入头部原始字节（对于 v3 不含末尾 32 字节 plaintext_hash）与块元数据。
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

// 文件系统辅助（UTF-8 安全）
// file_exists / get_file_size_utf8 / truncate_file 已迁到 core/fileio_util.cpp，
// 对外名分别为 fe_file_exists / fe_file_size / fe_truncate_file。

// 判断路径是否为符号链接 / 重解析点（已存在才报告，不存在返回 false）。
// v2.1.2：去掉 static，供非对称分支（run_asym）复用同样的守卫。
bool path_is_symlink(const std::string& path) {
#ifdef _WIN32
    std::wstring w=utf8_to_wstring(path);
    DWORD attr=GetFileAttributesW(w.c_str());
    if(attr==INVALID_FILE_ATTRIBUTES) return false;
    // 属性位检查与实际创建之间不是原子的（TOCTOU）：句柄级再判一次，
    // 用 FILE_FLAG_OPEN_REPARSE_POINT 打开链接自身，避免“先查后建”期间被换成链接。
    HANDLE h=CreateFileW(w.c_str(),0,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|(attr&FILE_ATTRIBUTE_DIRECTORY
            ? FILE_FLAG_BACKUP_SEMANTICS : 0u),
        nullptr);
    if(h!=INVALID_HANDLE_VALUE) {
        std::vector<char> buf(4096,0);
        DWORD ret=0;
        // 句柄级读出重解析点内容＝确凿是链接，且不受后续换手影响
        if(DeviceIoControl(h,FSCTL_GET_REPARSE_POINT,nullptr,0,
                buf.data(),(DWORD)buf.size(),&ret,nullptr)) {
            CloseHandle(h);
            return true;
        }
        const DWORD err=GetLastError();
        CloseHandle(h);
        if(err==ERROR_NOT_A_REPARSE_POINT) return false;
        // 打不开/非重解析点的其它错误：回退到属性位
    }
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

// 用 std::filesystem::weakly_canonical 解析路径中已存在分量的符号链接/重解析点，
// 使白名单前缀比较基于真实路径而非词法路径。不存在的末分量（待创建的输出文件）保留词法形式。
// 局限：若白名单根目录内部存在指向外部的符号链接且运行期才被创建，仍可能绕过（本函数只解析调用时已存在的链路）。
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

// 依据 YAML 配置校验输入输出路径（长度上限/白名单根目录）；true 允许，false 拒绝。
// v2.1.2 去掉 static，供非对称分支复用。
bool validate_io_paths(const std::string& in_path,const std::string& out_path,bool silent) {
    const Config& cfg=global_config();
    // ".." 不再按字面拒绝：C:/allowed/../../outside/x 规范化后是 C:/outside/x，
    // 下面的白名单前缀比较同样能拦住，而 ../rel.txt 这类正常相对输入仍可用。
    // 规范化（解析 . 与 ..、统一分隔符）后的路径用于白名单前缀比较与长度上限，
    // 堵住基于路径别名的绕过（如 "C:/allowed/./x"、"C:/allowed//x" 等）。
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
        // 白名单相对路径基于 CWD 解析（缺陷16），而非硬编码绝对前缀
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
        // 符号链接解析后的真实路径用于白名单前缀比较，堵住根目录内部符号链接逃逸
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

// 收紧新建输出文件的权限（避免半截明文被其他用户读取）。
// Windows 复用密钥文件的 PROTECTED_DACL 实现（仅当前用户+SYSTEM），收紧半成品 .prt/输出文件 DACL。
static void restrict_permissions(const std::string& path) {
#ifdef _WIN32
    tighten_file_permissions(path);
#else
    chmod(path.c_str(),0600);
#endif
}

// 删除前覆写文件内容（至少一遍零覆写），避免含明文的半成品被取证恢复。
// SSD 磨损均衡使覆写不具密码学保证，此处为与源文件 Wipe 理念一致的尽力擦除。
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
    // 只读源直接 O_WRONLY 会失败，那样等于「跳过覆写只删文件」，明文仍可被恢复。
    // 复用源文件处置那条路径的 clear_readonly_attribute（补属主写位）
    clear_readonly_attribute(path);
    int fd=::open(path.c_str(),O_WRONLY);
    if(fd<0) {
        // 补写位仍失败（文件系统只读、权限受控等）：不能假装擦除成功，保留文件
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

// POSIX：创建输出文件前把进程 umask 收紧到 0077，使新建文件直接落 0600，
// 消除"先 0644 再 chmod"的短暂可读窗口；作用域结束恢复原 umask。
#ifndef _WIN32
struct ScopedUmask {
    mode_t old;
    explicit ScopedUmask(mode_t m){ old=umask(m); }
    ~ScopedUmask(){ umask(old); }
};

// POSIX：一次 open 同时完成"拒绝符号链接"与"0600 创建/截断"，消除 check 与 open 间的 TOCTOU。
// 成功返回 true（文件已创建并截断为空）；最终分量为符号链接时 ELOOP 返回 false。
// create_output_no_follow 已迁到 core/output_lock.cpp（对外名 fe_create_output_no_follow）
#endif   // 原 #ifndef _WIN32 分支的收尾（ScopedUmask 仅 POSIX 需要）

// 跨进程输出锁
// process_alive_pid 已迁到 core/output_lock.cpp（对外名 fe_process_alive）


// acquire_output_lock 已迁到 core/output_lock.cpp（对外名 fe_acquire_output_lock）

// OutputLockGuard 已迁到 core/output_lock.hpp

// replace_file_utf8 / atomic_tmp_path / AtomicOutput 实现已迁到 core/output_lock.cpp



// clear_readonly_attribute / tighten_file_permissions 已迁到 core/output_lock.cpp


// 反调试
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
// 仅读取并校验结构（magic / version），HMAC 认证需密钥，由调用方在派生密钥后验证。



// 进程级限速器（令牌桶，v1.7.2）
// 主循环按已处理字节数记账，超 max_bytes_per_sec 则休眠，覆盖全部并发线程。
// 限速全局（g_rl_*）已随限速实现迁到 core/rate_limit.cpp

// 限速已移出到 core/rate_limit.cpp（令牌桶状态随之私有化），此处只保留调用。

void print_progress(size_t processed,size_t total,
    std::chrono::steady_clock::time_point start,
    bool finish) {
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

// 读取尾部水印记录（无需密码）：尾部 [wm_len(4)][记录][FENX...]，wm_len 位于信封起点前 4 字节。

// M0：加密盘随机块读。非压缩块 O(1) 定位提取明文，不整文件解密。
// 压缩文件变长块无法 O(1) 定位，返回 false 且 *out_compressed=true；非对称容器暂不支持。
bool random_read_ptd(const std::string& ptd_path, const SecureBuffer& password,
                     uint64_t offset, uint64_t len,
                     std::vector<unsigned char>& out,
                     bool* out_compressed, bool silent, const unsigned char* pre_kek) {
    out.clear();
    if(out_compressed) *out_compressed=false;
    if(len==0) return true;

    PtdMeta meta;
    if(!read_ptd_metadata(ptd_path, meta) || !meta.valid) {
        if(!silent) fprintf(stderr,"Cannot read .ptd metadata or invalid file.\n");
        return false;
    }
    if(meta.compression!=0) {
        if(out_compressed) *out_compressed=true;
        return false;
    }
    if(offset>=meta.orig_size) return true;
    if(offset+len>meta.orig_size) len=meta.orig_size-offset;

    // 原始头部：供 build_aad_with_metadata 与 v6 dek_box/recip_len
    unsigned char hdrbuf[320];
    unsigned char ver=0;
    uint32_t recip_len=0;
    unsigned char dek_box[64]={0};
    unsigned char dek_nonce[24]={0};
    {
        std::ifstream hf;
        if(!open_stream(hf,ptd_path,std::ios::binary) || !hf.read(reinterpret_cast<char*>(hdrbuf),5)) {
            if(!silent) fprintf(stderr,"Cannot open input file.\n");
            return false;
        }
        ver=hdrbuf[4];
        size_t hs=header_size_for_version(ver);
        if(!hf.read(reinterpret_cast<char*>(hdrbuf+5),(std::streamoff)(hs-5))) {
            if(!silent) fprintf(stderr,"Read header failed.\n");
            return false;
        }
    }
    if(ver==6) {
        auto h=load_header<FileHeaderV6>(hdrbuf);
        recip_len=get_recip_len(h.reserved);
        memcpy(dek_box,h.dek_box,sizeof(dek_box));
        memcpy(dek_nonce,h.dek_nonce,sizeof(dek_nonce));
    } else if(ver!=3 && ver!=VERSION && ver!=5) {
        if(!silent) fprintf(stderr,"Legacy version %u does not support random read.\n",ver);
        return false;
    }
    if(recip_len>0) {
        if(!silent) fprintf(stderr,"Random read not supported for asymmetric containers (recip_len>0).\n");
        return false;
    }

    // salt/iv 由 meta hex 解码（避免再次解析头部取指针）
    unsigned char salt_buf[ARGON2_SALT_LEN];
    size_t iv_len=meta.iv_hex.size()/2;
    unsigned char iv_buf[32];
    if(sodium_hex2bin(salt_buf,ARGON2_SALT_LEN,meta.salt_hex.data(),meta.salt_hex.size(),nullptr,nullptr,nullptr)!=0) {
        if(!silent) fprintf(stderr,"Invalid salt hex.\n");
        return false;
    }
    if(sodium_hex2bin(iv_buf,iv_len,meta.iv_hex.data(),meta.iv_hex.size(),nullptr,nullptr,nullptr)!=0) {
        if(!silent) fprintf(stderr,"Invalid iv hex.\n");
        return false;
    }

    SecureBuffer key(ARGON2_OUTPUT_LEN);
    size_t aad_hdr_len;
    if(ver==6) {
        SecureBuffer kek(ARGON2_OUTPUT_LEN);
        if(pre_kek) {
            memcpy(kek.data(), pre_kek, ARGON2_OUTPUT_LEN);
        } else if(!derive_key(password.data(),password.size(),salt_buf,kek.data(),meta.opslimit,(size_t)meta.memlimit_kb*1024)) {
            if(!silent) fprintf(stderr,"Key derivation failed.\n");
            return false;
        }
        unsigned char dek[32];
        if(!unwrap_dek(dek_box, kek.data(), dek_nonce, dek)) {
            report_auth_error(silent,"Failed to unwrap DEK (wrong password or corrupted container).");
            return false;
        }
        memcpy(key.data(), dek, 32);
        sodium_memzero(dek, sizeof(dek));
        sodium_memzero(kek.data(), kek.size());
        aad_hdr_len=HEADER_AAD_COVER_V6;
    } else {
        if(pre_kek) {
            memcpy(key.data(), pre_kek, ARGON2_OUTPUT_LEN);
        } else if(!derive_key(password.data(),password.size(),salt_buf,key.data(),meta.opslimit,(size_t)meta.memlimit_kb*1024)) {
            if(!silent) fprintf(stderr,"Key derivation failed.\n");
            return false;
        }
        aad_hdr_len=header_hmac_cover(ver);
    }
    std::vector<unsigned char> aad=build_aad_with_metadata(hdrbuf,aad_hdr_len,meta.chunk_size,meta.total_chunks,meta.orig_size);

    size_t tag_size=tag_size_for_mode(meta.mode);
    uint64_t hdr_size=header_size_for_version(ver);
    uint64_t base=hdr_size + (uint64_t)recip_len + 16;
    uint32_t chunk_size=meta.chunk_size;
    uint64_t stride=chunk_size+tag_size;
    uint64_t orig_size=meta.orig_size;
    uint32_t start_chunk=(uint32_t)(offset/chunk_size);
    uint32_t end_chunk=(uint32_t)((offset+len-1)/chunk_size);

    unsigned char nonce[32]={0};
    memcpy(nonce, iv_buf, iv_len);
    bool use_increment=(ver==VERSION||ver==5||ver==6);
    if(use_increment) for(uint32_t k=0;k<start_chunk;++k) sodium_increment(nonce,iv_len);
    else { uint64_t idx=start_chunk; fe::util::xor_le64_tail(nonce, iv_len, idx); }

    std::ifstream fin;
    if(!open_stream(fin,ptd_path,std::ios::binary)) {
        if(!silent) fprintf(stderr,"Cannot open input file.\n");
        return false;
    }
    fin.seekg((std::streamoff)(base + (uint64_t)start_chunk*stride));
    std::unique_ptr<Cipher> ciph=create_cipher(meta.mode);
    if(!ciph) { if(!silent) fprintf(stderr,"Unsupported encryption mode.\n"); return false; }

    out.assign(len,0);
    uint64_t out_pos=0;
    bool ok=true;
    for(uint32_t i=start_chunk; i<=end_chunk; ++i) {
        uint64_t chunk_start=(uint64_t)i*chunk_size;
        size_t chunk_plain=(size_t)std::min<uint64_t>(chunk_size, orig_size-chunk_start);
        size_t expected=chunk_plain+tag_size;
        std::vector<unsigned char> ct(expected);
        fin.read(reinterpret_cast<char*>(ct.data()), (std::streamsize)expected);
        if((size_t)fin.gcount()!=(size_t)expected) { ok=false; break; }
        if(!use_increment){ memcpy(nonce, iv_buf, iv_len); fe::util::xor_le64_tail(nonce, iv_len, (uint64_t)i); }
        unsigned long long frame_len=0;
        std::vector<unsigned char> pt(chunk_plain);
        int rc=ciph->decrypt(ct.data(), expected, aad.data(), aad.size(), nonce, key.data(), pt.data(), frame_len);
        if(rc!=0) { report_auth_error(silent,"Decryption failed (invalid key or corrupted data)."); ok=false; break; }
        uint64_t take_from=std::max<uint64_t>(chunk_start, offset);
        uint64_t take_to=std::min<uint64_t>(chunk_start+chunk_plain, offset+len);
        uint64_t take_len=take_to-take_from;
        memcpy(out.data()+out_pos, pt.data()+(take_from-chunk_start), take_len);
        out_pos+=take_len;
        if(use_increment && i<end_chunk) sodium_increment(nonce, iv_len);
    }
    out.resize(out_pos);
    sodium_memzero(key.data(), key.size());
    return ok;
}

// 派生某 .ptd 的 Argon2 密钥材料（供挂载层 LRU 缓存，见 random_read_ptd 的 pre_kek）。
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

// 完整性校验（功能3：只验不解）

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
    uint32_t chunk_override) {

    disable_core_dump();

    // 非对称加密：DEK 仅由收件人包装，不经密码，且暂不支持断点续传（强制全新写入）。
    std::vector<unsigned char> recip_blob_out;
    if(asym_mode) resume=false;

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
    // 非对称模式：DEK 仅由收件人公钥包装，不依赖密码，故不做密码长度下限校验。
    const bool asym_active = asym_mode && asym_recipients && !asym_recipients->empty();
    if(password.size()<PASSWORD_MIN_LEN && !asym_active) {
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

    // 续传检测：先读已存在输出的头部获取 salt，派生密钥后才能验证 .prs 的 HMAC
    ProgressInfo prog_info{0,0,0,0,{0}};
    bool has_progress=false;
    bool out_exists=fe_file_exists(out_path);
    bool prog_present=fe_file_exists(out_path+".prs");
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
    std::string prog_binding = fe_compute_progress_binding(in_path);

    if(resume && prog_present && fe_load_progress(out_path,prog_info)) {
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
            // v6 续传：密码派生 KEK，解开 wrapped DEK（同时校验密码正确性），DEK 即载荷密钥
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
        // 注意：此处不能 key.clear() 提前 clear 会使后续 derive_key 写入已释放缓冲。
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
    // 续传时沿用既有文件头里的块大小：块大小随版本上调后，旧半成品仍能从断点续完，
    // 否则 st_chunk 与新默认值不等会被误判为损坏。须早于 trunc_pos 计算。
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
    LockResult lr=fe_acquire_output_lock(out_path,lock_path);
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
    if(has_progress&&start_chunk>0) {
        // 续传：先丢弃中断瞬间落盘但未记账的密文残片，再从断点继续写入
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
        // Windows: create_output_no_follow 内部用 GetFinalPathNameByHandleW 复核
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
    // 压缩帧缓冲（仅压缩模式使用，固定上界 ZSTD_compressBound(CHUNK_SIZE)；无 zstd 时退化为 CHUNK_SIZE）
    PooledBuf comp_chunk(DataBufPool::comp());
    PooledBuf ciphertext_chunk(DataBufPool::cipher());
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
        // 批量预派生：盐由调用方预生成（据此已在预扫描阶段派生好 KEK），此处直接沿用
        if(ext_salt) memcpy(header.salt,ext_salt,ARGON2_SALT_LEN);
        else         randombytes_buf(header.salt,ARGON2_SALT_LEN);
        randombytes_buf(header.iv,iv_len);
        header.compression = do_compress ? 1 : 0;
        header.comp_level   = do_compress ? (unsigned char)(int)compress_level : 0;
        sodium_memzero(header.plaintext_hash,HASH_SIZE);
        sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);

        // v6 容器：派生 KEK（Argon2id(password,salt)），生成随机 DEK，以德克包裹进容器；
        // 载荷 AEAD 密钥 = DEK，KEK 仅用于包裹/解裹（密钥轮换零重加密的基础）。
        // 非对称模式：DEK 仅经收件人公钥包装进容器 blob，KEK 不派生（允许空密码）。
        SecureBuffer kek(ARGON2_OUTPUT_LEN);
        if(asym_active) {
            sodium_memzero(kek.data(), kek.size());
        } else if(ext_kek) {
            // 批量预派生命中：直接复用预扫描阶段算好的 KEK，省掉本次 Argon2id
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
                // 非对称：DEK 以收件人公钥包装进容器收件人 blob，不再经密码 KEK。
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
                // dek_box 留零：对称密码路径不使用，DEK 仅存于收件人 blob
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
            sodium_memzero(hdr_auth,sizeof(hdr_auth));
        }

        if(!fout.write(reinterpret_cast<const char*>(&header),
                use_v6 ? HEADER_SIZE_V6 : (do_compress?HEADER_SIZE_V5:HEADER_SIZE_V4))) {
            fprintf(stderr,"Write header failed\n"); ok=false; goto cleanup;
        }
        // 非对称：固定头之后、16 字节块元数据之前写入收件人 blob（recip_len 已记入 reserved）
        if(asym_mode && !recip_blob_out.empty()) {
            if(!fout.write(reinterpret_cast<const char*>(recip_blob_out.data()),
                    (std::streamsize)recip_blob_out.size())) {
                fprintf(stderr,"Write recipient blob failed\n"); ok=false; goto cleanup;
            }
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

    // 明文 Blake2b 流式哈希；续传时先回放输入前缀 [0,start_bytes) 以补齐哈希状态
    crypto_generichash_state hstate;
    crypto_generichash_init(&hstate,nullptr,0,HASH_SIZE);
    if(start_bytes>0) {
        fin.seekg(0,std::ios::beg);
        uint64_t remain=start_bytes;
        PooledBuf tmp(DataBufPool::plain());
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
        // 逐块 save_progress 曾拖垮吞吐，改为按 500ms 节流：先 flush 密文再记账，
        // 保持「磁盘 .prt ≥ .prs 记账」不变式；强杀时截断到记账处重算。
        auto prs_now=std::chrono::steady_clock::now();
        if(persistent_progress && prs_now-last_prs_save>=std::chrono::milliseconds(500)) {
            outbuf.flush();   // 先落盘密文再记账进度（带 HMAC），保持「磁盘 .prt ≥ .prs」不变式
            if(!fe_save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
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
        sodium_memzero(hdr_auth,sizeof(hdr_auth));
        outbuf.flush();   // 先把缓冲的密文落盘，再回头写头部哈希 / HMAC
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
        if(ok && !fe_append_encrypted_name_footer(fout,in_path,key.data(),header.salt)) {
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
        fe_remove_progress(out_path);
        if(!progress_callback) print_progress(total_size,total_size,start_time,true);

        // 自解密验证：复用本次已派生的密钥（key），边解密边计算明文哈希，
        // 不再落盘 .verify.tmp，消除 4 倍 I/O（写明文 + 读回 + 哈希 + 删除）。
        bool verify_ok=decrypt_file(out_path, out_path, password,
            [](size_t,size_t){}, true, false, key.data(), nullptr, 0, true);
        if(!verify_ok) {
            ok=false;
            remove_file_utf8(out_path);
            fe_remove_progress(out_path);
            fprintf(stderr,"Self-decrypt verification failed, output removed.\n");
        }
    }
    else {
        remove_file_utf8(out_path);
        fe_remove_progress(out_path);
        fprintf(stderr,"Encryption failed, output removed.\n");
    }

    // 自校验已结束（期间复用了派生密钥 key）。密钥与认证密钥均由 SecureBuffer 持有，
    // 函数返回时析构自动 sodium_memzero + sodium_munlock，无需手动清零。
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
    const std::string& asym_identity) {
    size_t force_skipped_chunks=0;
    bool preview_only=(preview_bytes>0);
    if(preview_only) {
        // 预览输出走二进制 stdout，避免 Windows 文本模式把 0x0A 翻译成 CRLF 破坏内容。
#ifdef _WIN32
        (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
    }
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
    // 密码仅在「无外部密钥且非非对称恢复」时才必需：ext_key 供加密端自校验直接复用 DEK。
    if(password.size()<PASSWORD_MIN_LEN && asym_identity.empty() && !ext_key) {
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
    uint32_t recip_len=0;      // v6 收件人 blob 字节数（reserved[0..3]）；0=纯对称
    std::vector<RecipientStanza> recip_stanzas;  // v6 非对称收件人条目（asym 解密时恢复 DEK）

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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
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
        if(file_size<(std::streampos)(hdr_size+recip_len+4+4+8)) {
            if(!silent) fprintf(stderr,"File too small (corrupted)\n");
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
        recip_len=get_recip_len(hv6.reserved);
    }
    else {
        if(!silent) fprintf(stderr,"Unsupported file version: %u\n",ver);
        return false;
    }

    // 严格校验加密模式：仅允许已知枚举值，未知值直接拒绝（否则后续的 IV 长度校验会被整体短路跳过）
    if(mode!=CryptoMode::AES_GCM&&mode!=CryptoMode::XCHACHA20&&mode!=CryptoMode::AEGIS256&&mode!=CryptoMode::SM4) {
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

    // v6 非对称容器：在 256 字节固定头之后、16 字节块元数据之前读取收件人 blob。
    // recip_len 已在头部解析阶段从 reserved[0..3] 取出，偏移已计入文件大小校验。
    if(is_v6 && recip_len>0) {
        std::vector<unsigned char> blob(recip_len);
        if(!fin.read(reinterpret_cast<char*>(blob.data()), (std::streamsize)recip_len) ||
           (size_t)fin.gcount()!=recip_len) {
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
    if(!fin.read(reinterpret_cast<char*>(&chunk_size),4)||
        !fin.read(reinterpret_cast<char*>(&total_chunks),4)||
        !fin.read(reinterpret_cast<char*>(&orig_size),8)) {
        if(!silent) fprintf(stderr,"Read metadata failed\n");
        return false;
    }

    // 块大小以文件头为准（默认块大小可能随版本上调），仅约束区间防伪造头
    if(chunk_size<MIN_CHUNK_SIZE||chunk_size>MAX_CHUNK_SIZE) {
        if(!silent) {
            fprintf(stderr,"Invalid chunk_size: %u (allowed %zu..%zu). File may be corrupted.\n",
                chunk_size,(size_t)MIN_CHUNK_SIZE,(size_t)MAX_CHUNK_SIZE);
        }
        return false;
    }

    // 派生密钥（提前到空文件短路之前，以便 v4 文件头 HMAC 校验对空文件也生效）。
    // 同时计算源文件绑定标识，供 .prs 防重放校验使用。
    std::string prog_binding = fe_compute_progress_binding(in_path);
    // ext_kek：外部已派生 KEK（批量复用，跳过 Argon2id）；非 v6 即载荷密钥，v6 需解裹 DEK。
    // ext_key：外部最终密钥（自校验用），直接复用跳过 KDF 与解裹。
    const bool have_kek = (ext_kek && ext_kek_len >= ARGON2_OUTPUT_LEN);
    if(is_v6) {
        // v6 非对称容器：以身份私钥从收件人 stanza 恢复 DEK，跳过密码 KEK 派生。
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
        // v6 容器：KEK 解裹 DEK（同时校验密码正确性），DEK 即载荷密钥。
        else if(have_kek) {
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
        sodium_memzero(hdr_auth,sizeof(hdr_auth));
    }

    // 跨进程锁 + 临时文件：解密先将明文写入 <out>.prt，全部校验通过后再原子重命名
    std::string part_path=out_path+".prt";
    // 防符号链接劫持：若 .prt 半成品已存在且为符号链接/重解析点，拒绝写入，避免清空被指向的敏感文件
    if(!verify_only && !preview_only && path_is_symlink(part_path)) {
        if(!silent) fprintf(stderr,"Refusing to write through existing symlink: %s\n",part_path.c_str());
        return false;
    }
    std::string lock_path;
    OutputLockGuard lock_guard;   // 函数作用域 RAII；verify_only / preview_only 下不取锁、不写文件
    if(!verify_only && !preview_only) {
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

    // 密文末尾可能附加加密的原始文件名信封，大小校验必须把它计入
    uint64_t footer_len=0;
    fe_peek_name_footer_len(in_path, footer_len);

    uint64_t total_size=orig_size;
    if(total_chunks==0) {
        if((size_t)file_size!=hdr_size+recip_len+4+4+8+footer_len) {
            if(!silent) fprintf(stderr,"File size mismatch for empty file.\n");
            return false;
        }
        if(verify_only || preview_only) {
            // 自校验 / 预览空文件：不落盘，无明文内容可输出
            if(have_hash && !preview_only) {
                unsigned char empty_hash[HASH_SIZE];
                crypto_generichash(empty_hash,HASH_SIZE,nullptr,0,nullptr,0);
                if(sodium_memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) return false;
            }
            return true;
        }
        std::ofstream fout;
#ifdef _WIN32
        // Windows: create_output_no_follow 内部用 GetFinalPathNameByHandleW 复核
#else
        ScopedUmask su_empty(0077);
#endif
        if(!fe_create_output_no_follow(part_path)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        if(!open_stream(fout,part_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(part_path);
        fout.close();
        fe_remove_progress(out_path);
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
            if(sodium_memcmp(empty_hash,stored_hash,HASH_SIZE)!=0) {
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
    // 续传需要“进度文件”与“对应的 .prt 半成品”同时齐备，否则视为全新开始
    bool has_progress=false;
    if(resume && fe_load_progress(out_path,prog_info) && fe_file_exists(part_path)) {
        // 密钥与进度 HMAC 密钥已在前面（空文件短路之前）派生到 key / auth_key，此处直接复用，
        // 并把源文件绑定标识（规范化路径 + 大小 + mtime）纳入 HMAC 校验，防重放。
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

    // 解密续传：明文半成品（.prt）可能残留未完成块的残片，截断到已确认写入的明文长度
    std::fstream fout;
    if(verify_only || preview_only) {
        // 自校验 / 预览模式：不创建/写入任何明文文件；预览改向 stdout 输出前缀
    }
    else if(has_progress&&start_chunk>0) {
        if(!fe_truncate_file(part_path,start_bytes)) {
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
#ifdef _WIN32
        // Windows: create_output_no_follow 内部用 GetFinalPathNameByHandleW 复核
#else
        ScopedUmask su_prt(0077);
#endif
        if(!fe_create_output_no_follow(part_path)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        if(!open_stream(fout,part_path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        restrict_permissions(part_path);
        fe_remove_progress(out_path);
    }

    // 4 MiB 聚合写出缓冲：明文块写入 outbuf，攒满 4 MiB 再写盘（verify_only 下不绑定，空操作）
    AggWriter outbuf;
    if(!verify_only && !preview_only) outbuf.bind(fout);

    // 密钥已在前面（空文件短路之前）派生到 key / auth_key，此处无需重复派生。

    // AAD 须严格复刻加密端构造：v5 覆盖到压缩标记，v4/v3 到 iv；
    // v6 只到稳定前缀（不含容器区，rewrap 改写容器不使载荷 AAD 失效）。
    size_t aad_hdr_len=(ver==6) ? HEADER_AAD_COVER_V6 : header_hmac_cover(ver);
    std::vector<unsigned char> aad=build_aad_with_metadata(hdrbuf,aad_hdr_len,chunk_size,total_chunks,orig_size);

    // AES-GCM / AEGIS-256 都依赖 AES-NI：不支持的 CPU 上逐块解密只会报「AEAD 失败」，
    // 提前给出明确原因。解密端不做降级——换算法就解不出原文件。
    if(mode==CryptoMode::AES_GCM && crypto_aead_aes256gcm_is_available()==0) {
        if(!silent) fprintf(stderr,"该文件为旧版 AES-GCM 格式，需要 CPU 支持 AES-NI，当前机器不支持，无法解密。\n");
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
    // .prs 节流基点：进度文件只服务"进程被强杀后的断点续传"，无需逐块落盘。
    auto last_prs_save=std::chrono::steady_clock::now();
    // 压缩块密文上界为 ZSTD_compressBound(CHUNK_SIZE)+tag；未压缩块为 CHUNK_SIZE+tag
    // 一律按上界取缓冲：文件头 chunk_size 可能小于当前默认块大小（旧文件），
    // 上界尺寸既能容纳也便于命中缓冲池复用
    PooledBuf ciphertext_chunk(DataBufPool::cipher());
    PooledBuf plaintext_chunk(DataBufPool::comp());   // AEAD 输出暂存（压缩帧，上界 COMP_BUF_MAX）
    PooledBuf dec_chunk(DataBufPool::plain());        // zstd 解压后的最终明文（仅压缩模式使用）
    unsigned char nonce[32]={0};
    bool ok=true;
    uint64_t processed_bytes=start_bytes;
    uint64_t preview_written=0;   // 预览模式已写出 stdout 的明文字节数
    // 小于 64 MiB 的文件跳过进度文件写入（见 encrypt_file 同款说明）
    bool persistent_progress=(total_size>=64ULL*1024*1024);

    // 提前声明，避免 goto dec_cleanup 跨过带初始化的变量
    bool use_increment=(ver==VERSION || ver==5 || ver==6);
    size_t input_offset=0;

    // 防整数溢出 / 越界：input_offset 来自文件头（v3 未被 HMAC 认证）或续传进度，
    // 须边界校验后再 seekg。先以 uint64_t 做乘法溢出检查，再确认落在文件范围内。
    {
        // 非对称容器的收件人 blob 位于固定头之后、块元数据之前，密文起点必须计入 recip_len。
        const uint64_t base = (uint64_t)hdr_size + (uint64_t)recip_len + 4 + 4 + 8;
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
            PooledBuf tmp(DataBufPool::plain());
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
        fe::util::xor_le64_tail(nonce, iv_len, idx);
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
            fe::util::xor_le64_tail(nonce, iv_len, idx);
        }

        unsigned long long frame_len=0;   // AEAD 输出长度（压缩帧或未压缩明文）
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

        // 解压（仅压缩块）：zstd 解压后的长度应等于本块明文长度 chunk_len
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
            // 预览：仅向 stdout 写出明文前 preview_bytes 字节，达到上限即停止；
            // 已解密的块仍经过 AEAD 认证，故前缀保证与原文一致。
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
        // 逐块 save_progress 曾拖垮吞吐，改为 500ms 节流：先 flush 明文再记账，
        // 保持「磁盘 .prt ≥ .prs」不变式；verify_only 不落盘不写进度。
        if(!verify_only && persistent_progress) {
            auto prs_now=std::chrono::steady_clock::now();
            if(prs_now-last_prs_save>=std::chrono::milliseconds(500)) {
                outbuf.flush();   // 先落盘明文再记账进度（带 HMAC）
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
            print_progress(processed_bytes,total_size,start_time);
        }

        if(use_increment) {
            if(i+1<total_chunks) sodium_increment(nonce,iv_len);
        }
    }

    // 明文完整性校验：恢复的明文 Blake2b 必须与存储哈希一致
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

    if(verify_only || preview_only) {
        // 自校验 / 预览模式：不落盘、不替换、不删除任何文件
        if(preview_only) fflush(stdout);
        return ok;
    }
    if(ok) {
        fe_remove_progress(out_path);
        // 防符号链接劫持
        if(path_is_symlink(out_path)) {
            if(!silent) fprintf(stderr,"Refusing to overwrite existing symlink: %s\n",out_path.c_str());
            ok=false;
            secure_wipe_and_remove(part_path);
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
        // 失败时覆写并删除半成品（.prt），最终输出路径不写入任何明文
        secure_wipe_and_remove(part_path);
        fe_remove_progress(out_path);
        if(!silent) {
            fprintf(stderr,"Decryption failed, partial output removed.\n");
        }
    }
    return ok;
}


// 批量处理相关函数（is_directory / fe_path_is_directory / collect_files_from_dir /
// build_batch_out_path / read_header_kdf_params / kdf_params_for_batch_input / process_files）
// 已迁至 core/batch.cpp。声明保留在 FileEncryptor.hpp，供 CLI/cli/main.cpp 调用。
