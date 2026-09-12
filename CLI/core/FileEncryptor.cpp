#define _CRT_SECURE_NO_WARNINGS
#include "FileEncryptor.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
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
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <debugapi.h>
#include <shlobj.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
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
static constexpr size_t ARGON2_SALT_LEN=crypto_pwhash_SALTBYTES;
static constexpr size_t ARGON2_OUTPUT_LEN=32;

// Argon2id 参数：旧格式（v1）写死为交互档，新格式（v2）把参数存入文件头以便未来增强且兼容旧文件。
static constexpr unsigned int ARGON2_OPS_LEGACY=3;
static constexpr unsigned int ARGON2_MEM_LEGACY_KB=(unsigned int)(crypto_pwhash_MEMLIMIT_INTERACTIVE/1024);
static constexpr unsigned int ARGON2_OPS_DEFAULT=4;
static constexpr unsigned int ARGON2_MEM_DEFAULT_KB=128*1024;

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;
static constexpr size_t XCHACHA20_IV_LEN=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t AEGIS256_IV_LEN=crypto_aead_aegis256_NPUBBYTES;
static constexpr size_t AEGIS256_TAG_SIZE=crypto_aead_aegis256_ABYTES;
static constexpr size_t TAG_SIZE=16;
static constexpr size_t MAX_TAG_SIZE=AEGIS256_TAG_SIZE;
static constexpr size_t HASH_SIZE=crypto_generichash_BYTES;
static constexpr size_t CHUNK_SIZE=1*1024*1024;
static constexpr size_t PASSWORD_MIN_LEN=6;

const unsigned char MAGIC[4]={'F','E','N','C'};
// 磁盘格式版本：v4 在 v3 基础上于文件头末尾追加 32 字节 header_hmac（独立于数据加密
// 密钥的元数据认证密钥派生），使整个文件头成为可认证的“安全信封”，防文件头篡改。
// v1/v2/v3 读取保持兼容。
const unsigned char VERSION=4;

// 续传回退选择：AEGIS-256 在缺少 AES-NI 的 CPU 上不可用，运行时探测失败后回退 XChaCha20
static std::atomic<int> g_aegis_fallback_choice{0};

static const uint32_t PROGRESS_MAGIC=0x504F5247;
static const uint32_t PROGRESS_VERSION=2; 
// v2：新增 HMAC 认证，防续传劫持

// v2 头部 69 字节（以下 FileHeader）；v3 头部 109 字节（见 FileHeaderV3）
static constexpr size_t HEADER_SIZE_V2=69;

#pragma pack(push, 1)
struct FileHeader {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[24];
};
#pragma pack(pop)
static constexpr size_t HEADER_SIZE=HEADER_SIZE_V2; // 兼容别名：v2 头部大小

// v3 头部：在 v2 基础上将 iv 缓冲扩到 32 字节（容纳 AEGIS-256 的 32 字节 nonce），并新增 plaintext_hash
#pragma pack(push, 1)
struct FileHeaderV3 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char plaintext_hash[HASH_SIZE];
};
#pragma pack(pop)
static constexpr size_t HEADER_SIZE_V3=sizeof(FileHeaderV3);

// v4 头部：v3 前缀 + 末尾 32 字节 header_hmac（覆盖前 109 字节所有关键元数据，
// 由“元数据认证密钥”派生自主密钥 + 固定标签计算）。
static constexpr size_t HEADER_HMAC_SIZE=crypto_auth_BYTES; // 32
#pragma pack(push, 1)
struct FileHeaderV4 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    uint16_t opslimit;
    uint32_t memlimit_kb;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[32];
    unsigned char plaintext_hash[HASH_SIZE];
    unsigned char header_hmac[HEADER_HMAC_SIZE];
};
#pragma pack(pop)
static constexpr size_t HEADER_SIZE_V4=sizeof(FileHeaderV4); // 141
// 文件头 HMAC 覆盖区域：前 77 字节（magic..iv，含 salt/mode/Argon2 参数），
// 不含 plaintext_hash(32B) 与 header_hmac(32B) 自身。
// 设计上刻意排除 plaintext_hash——它要在加密结束、明文哈希算出后才可知；
// 若把 header_hmac 覆盖到 plaintext_hash（109 字节），就只能在所有块加密完才落盘，
// 导致被中断的半成品 .ptd 头 HMAC 恒为 0、续传时被“文件头篡改校验”拒之门外。
// 覆盖 77 字节既能独立认证“决定密钥派生与安全的前缀”（防替换 salt/iv/mode 重放），
// 又能在写头瞬间即算出合法 HMAC，使续传对中断文件可正常恢复。
static constexpr size_t HEADER_HMAC_COVER=HEADER_SIZE_V4-HASH_SIZE-HEADER_HMAC_SIZE; // 77

// 兼容旧版本（v1，47 字节）的文件头布局，仅用于解密时按版本解析
#pragma pack(push, 1)
struct FileHeaderV1 {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[24];
};
#pragma pack(pop)
static constexpr size_t HEADER_SIZE_V1=sizeof(FileHeaderV1);

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

// ---------- 辅助：版本 / 模式 查询 ----------
static size_t header_size_for_version(unsigned char ver) {
    if(ver==1) return HEADER_SIZE_V1;
    if(ver==2) return HEADER_SIZE_V2;
    if(ver==3) return HEADER_SIZE_V3;
    return HEADER_SIZE_V4;
}

static size_t tag_size_for_mode(CryptoMode m) {
    return (m==CryptoMode::AEGIS256) ? AEGIS256_TAG_SIZE : TAG_SIZE;
}

// ---------- 续传进度 HMAC 密钥派生 ----------
// 由主密钥域分离派生一个独立的 HMAC 密钥（Blake2b，带上下文标签），
// 使 .progress 的认证与 AEAD 加密使用不同子密钥。
static void derive_progress_auth_key(const unsigned char* master_key,
    unsigned char auth_key[crypto_auth_KEYBYTES]) {
    const char tag[]="FE_progress_auth_v3";
    std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
    in.insert(in.end(), master_key, master_key+ARGON2_OUTPUT_LEN);
    crypto_generichash(auth_key, crypto_auth_KEYBYTES, in.data(), in.size(), nullptr, 0);
}

// ---------- 文件头 HMAC 密钥派生 ----------
// 由主密钥域分离派生一个与进度认证密钥、AEAD 加密密钥都不同的“元数据认证密钥”，
// 用于对文件头（magic/version/mode/Argon2 参数/salt/iv/plaintext_hash）做独立认证。
static void derive_header_auth_key(const unsigned char* master_key,
    unsigned char auth_key[HEADER_HMAC_SIZE]) {
    const char tag[]="FE_header_auth_v4";
    std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
    in.insert(in.end(), master_key, master_key+ARGON2_OUTPUT_LEN);
    crypto_generichash(auth_key, HEADER_HMAC_SIZE, in.data(), in.size(), nullptr, 0);
}

// ---------- 认证失败信息泄露防护 ----------
// 默认（非 -v 且 log_level < DEBUG）下，所有认证失败只输出通用错误，不暴露
// “密码错误 / 文件头被改 / 哈希不符 / 进度损坏”等可用于枚举或侧信道探测的细节。
static bool g_verbose=false;
void set_verbose(bool v) { g_verbose=v; }

static void report_auth_error(bool silent, const std::string& detail) {
    if(silent) return;
    const Config& cfg=global_config();
    bool detailed = g_verbose || cfg.log_level>=LOG_DEBUG;
    if(detailed) fprintf(stderr, "%s\n", detail.c_str());
    else fprintf(stderr, "Error: Decryption failed. (Invalid key or corrupted file)\n");
}

// ---------- 路径规范化（防别名绕过） ----------
// 用 lexically_normal 解析掉 . 与 ..（不做文件系统访问，故对尚不存在的输出路径也安全），
// 再 make_preferred 统一分隔符。配合 path_has_traversal 与白名单，堵住基于路径别名的绕过。
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
    // 注意：fs::path 的窄字符串构造按 ANSI 代码页（GBK）解释字节，含中文/Emoji 的
    // UTF-8 路径在 .string() 往返时会抛 "No mapping for the Unicode character"
    // （未捕获即 fastfail 崩溃）。必须先经 utf8_to_wstring 转宽字符再构造 path，
    // 规范化后用 wstring_to_utf8 取回，全程无 ACP 往返、编码无损。
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

// ---------- 续传进度文件绑定标识（防重放） ----------
// 将"正在处理的源文件"的规范化路径 + 大小 + mtime 纳入 .progress 的 HMAC 输入，
// 使旧的有效 .progress 无法被重放到不同的文件（路径/mtime/size 任一变化即 HMAC 失配）。
// 前向声明：compute_progress_binding 依赖下方"文件系统辅助"中的 get_file_size_utf8。
static int64_t get_file_size_utf8(const std::string& path);
// 前向声明：is_complete_output / decrypt_file 需要提前获知尾部（加密名）长度做文件大小校验。
static bool peek_name_footer_len(const std::string& ptd_path, uint64_t& footer_len);
static std::string compute_progress_binding(const std::string& in_path) {
    std::error_code ec;
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
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "|%s|%lld|%lld",
        norm.c_str(), (long long)sz, (long long)mt);
    return std::string(buf, (size_t)(n>0?n:0));
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

// ---------- AEGIS-256 可用性探测（缺 AES-NI 的 CPU 上不可用） ----------
bool aegis256_supported() {
    static int cached=-1;
    if(cached>=0) return cached!=0;
    unsigned char k[32],npub[32],m[16],c[64],m2[16];
    unsigned long long clen=0,mlen=0;
    randombytes_buf(k,32);
    randombytes_buf(npub,32);
    memset(m,0xAB,sizeof(m));
    int e=crypto_aead_aegis256_encrypt(c,&clen,m,sizeof(m),nullptr,0,nullptr,npub,k);
    int d=(e==0)?crypto_aead_aegis256_decrypt(m2,&mlen,nullptr,c,clen,nullptr,0,npub,k):-1;
    cached=(e==0&&d==0&&mlen==sizeof(m)&&memcmp(m,m2,sizeof(m))==0)?1:0;
    return cached!=0;
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

// 判断路径是否为符号链接 / 重解析点（已存在才报告，不存在返回 false）
static bool path_is_symlink(const std::string& path) {
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

// 路径穿越检测
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

// 依据全局 YAML 配置校验输入输出路径（长度上限 / 白名单根目录）。
// 返回 true 表示允许；false 表示被策略拒绝（并打印原因）。
static bool validate_io_paths(const std::string& in_path,const std::string& out_path,bool silent) {
    const Config& cfg=global_config();
    // 1.5.2 安全加固：任何 ".." 组件一律拒绝，堵住白名单前缀比较被
    // "C:/allowed/../../outside/x" 绕过。必须在规范化之前检查原始路径——
    // lexically_normal 会把 ".." 折叠掉，若先规范化再做后续校验反而可能漏掉穿越。
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

// 返回获取锁的结果：
//   OK            成功获得锁
//   LOCKED        锁文件存在且持有进程仍存活（真被其它进程占用）
//   CANNOT_CREATE 无法创建锁文件（权限不足 / 路径过长或非法等）
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
static bool replace_file_utf8(const std::string& from,const std::string& to) {
#ifdef _WIN32
    std::wstring wf=utf8_to_wstring(from);
    std::wstring wt=utf8_to_wstring(to);
    return MoveFileExW(wf.c_str(),wt.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
#else
    std::remove(to.c_str());
    return std::rename(from.c_str(),to.c_str())==0;
#endif
}

// UTF-8 安全的文件复制（用于进度文件轮转备份 .progress → .progress.bak）
static bool copy_file_utf8(const std::string& from,const std::string& to) {
#ifdef _WIN32
    std::wstring wf=utf8_to_wstring(from);
    std::wstring wt=utf8_to_wstring(to);
    return CopyFileW(wf.c_str(),wt.c_str(),FALSE)!=0;
#else
    std::ifstream src;
    if(!open_stream(src,from,std::ios::binary)) return false;
    std::ofstream dst;
    if(!open_stream(dst,to,std::ios::binary|std::ios::trunc)) { src.close(); return false; }
    dst<<src.rdbuf();
    bool ok=dst.good();
    src.close(); dst.close();
    return ok;
#endif
}

// ---------- 反调试 ----------
// 反调试检查。
// 重要（缺陷修复约束）：本函数内部在检测到调试器时会直接 exit(1)。
// 因此它【只能】在 main() 启动期、任何工作线程创建之前调用（当前即如此，见 cli/main.cpp）。
// 切勿将其移入 process_files 的并发 worker 或任何子线程 —— 否则 worker 中 exit(1) 会终止整个
// 批量加解密任务，而非仅中止单文件。保持仅在主线程调用。
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
        // 盘符根（"H:"）：其 stat 依赖进程级"盘符当前目录"（CWD 在其他盘时失败），
        // 且 _wmkdir("H:") 恒失败——两者都不可靠。改用绝对根 "H:/" 探测：
        // 根目录存在（盘可访问）则继续创建剩余分量，否则失败。
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

// ---------- 密钥派生 ----------
static bool derive_key(const unsigned char* password, size_t pwd_len,
    const unsigned char* salt,
    unsigned char* key,
    unsigned int opslimit,
    size_t memlimit,
    size_t key_len=ARGON2_OUTPUT_LEN) {
    if(crypto_pwhash(key,key_len,
        reinterpret_cast<const char*>(password),pwd_len,
        salt,
        opslimit,
        memlimit,
        crypto_pwhash_ALG_ARGON2ID13)!=0) {
        fprintf(stderr,"crypto_pwhash failed\n");
        return false;
    }
    return true;
}

// ---------- 文件有效性检查 ----------
static bool is_file_valid(const std::string& path) {
    std::ifstream f;
    if(!open_stream(f,path,std::ios::binary)) return false;
    unsigned char hbuf[HEADER_SIZE_V4];
    f.read(reinterpret_cast<char*>(hbuf),HEADER_SIZE_V4);
    if(f.gcount()<5) return false;
    unsigned char ver=hbuf[4];
    uint64_t need=header_size_for_version(ver);
    if((uint64_t)f.gcount()<need) return false;
    return (memcmp(hbuf,MAGIC,4)==0&&(ver==1||ver==2||ver==3||ver==VERSION));
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
    std::string prog_path=out_path+".progress";
    std::ifstream f;
    if(!open_stream(f,prog_path,std::ios::binary)) return false;
    f.read(reinterpret_cast<char*>(&info),sizeof(info));
    if(f.gcount()!=sizeof(info)) return false;
    if(info.magic!=PROGRESS_MAGIC||info.version!=PROGRESS_VERSION) {
        return false;
    }
    return true;
}

// 校验 .progress 的 HMAC（防续传劫持 + 防重放）：覆盖前 24 字节
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

    std::string prog_path=out_path+".progress";
    std::string temp_prog=prog_path+".tmp";
    // 清除可能残留的临时进度文件（UTF-8 安全）
    remove_file_utf8(temp_prog);

    std::ofstream f;
    if(!open_stream(f,temp_prog,std::ios::binary|std::ios::trunc)) return false;
    f.write(reinterpret_cast<const char*>(&info),sizeof(info));
    if(!f.good()) {
        f.close();
        remove_file_utf8(temp_prog);
        return false;
    }
    f.close();
    // 关键修复：Windows 下 std::rename 在目标已存在时会失败（EEXIST，与 POSIX 语义不同），
    // 导致从第 2 个块起进度文件永远写不进去、断点续传退化为从头重做。
    // 进度文件轮转：覆盖前先将现有 .progress 备份为 .progress.bak（best-effort）。
    // 若本次写入后校验/续传异常，旧进度仍可用于恢复，避免“写坏即丢失断点”。
    if(global_config().progress_rotation && file_exists(prog_path)) {
        if(!copy_file_utf8(prog_path,prog_path+".bak")) {
            // 备份失败（权限/空间）仅降低恢复余量，不影响本次写入；记录以便排查
            log_event(LOG_WARN,"progress_rotation_backup_failed",{{"path",prog_path}});
        }
    }

    // 改用 replace_file_utf8()（Windows 用 MoveFileExW(MOVEFILE_REPLACE_EXISTING)、
    // Linux 用 std::remove+std::rename 等价实现），保证每次块处理后都能覆盖更新进度文件。
    if(!replace_file_utf8(temp_prog,prog_path)) {
        remove_file_utf8(temp_prog);
        return false;
    }
    return true;
}

static void remove_progress(const std::string& out_path) {
    std::string prog_path=out_path+".progress";
    remove_file_utf8(prog_path);
}

// ---------- 进程级限速器（令牌桶，v1.7.2） ----------
// 由 init_rate_limiter() 在加载配置后初始化一次；加/解密主循环按已处理字节数记账，
// 超出 max_bytes_per_sec 则休眠，实现进程级总吞吐上限（覆盖批处理的全部并发线程）。
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
        std::cout<<buf<<'\n';
    }
    else {
        std::cout<<buf<<std::flush;
    }
}

// ---------- 文件名 / 扩展名混淆（v1.7.0） ----------
// 输出形如 "<16 位十六进制>.<混淆扩展名>.ptd"：.ptd 恒在末尾，批量解密仍可据此筛选。
// 混淆名 = Blake2b(key=Blake2b(口令), msg=输入路径)，确定性（同口令 + 同输入 -> 同名字），
// 因此中断后续传仍能命中同一输出文件与 .progress，同时不泄露原始文件名。
static const char* const OBFUSCATED_EXTS[] = {
    "png","jpg","jpeg","apng","mp4","mp3","aac","avi","bmp","txt","yaml",
    "json","js","cpp","hpp","c","md","pdf","doc","docx","ppt","pptx","xls",
    "xlsx","gif","zip","rar","iso","htm","html","css"
};
static constexpr size_t OBFUSCATED_EXT_COUNT=sizeof(OBFUSCATED_EXTS)/sizeof(OBFUSCATED_EXTS[0]);

// ---------- 原始文件名（混淆前）加密存储（v1.7.1） ----------
// 原始文件名以"加密信封"形式追加在密文末尾：与主密文使用相同配置
// （XChaCha20-Poly1305，同一派生主密钥，nonce 由文件 salt 派生），故文件名
// 不再以明文暴露；UTF-8 多字节文件名天然兼容。尾部布局（文件最末）：
//   [加密名 n+16 字节][magic "FENX"][name_len 4 字节]
// magic 与长度固定在文件最末 8 字节，读取时无需回扫即可定位；保留对早期
// 明文尾部（magic "FENM"）的兼容读取，但新写入一律加密。
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

// 尾部元数据未做认证，还原前必须严格净化，防止构造出 "../x" 之类的越权输出路径。
static bool sanitize_restored_name(const std::string& n) {
    if(n.empty()||n.size()>255) return false;
    if(n[0]=='.') return false;
    if(n.find("..")!=std::string::npos) return false;
    for(unsigned char c : n) {
        if(c<0x20||c==0x7F) return false;
        if(c=='/'||c=='\\'||c==':') return false;
    }
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
    const SecureBuffer& password) {
    out_name.clear();
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdrbuf[160];
    if(!f.read(reinterpret_cast<char*>(hdrbuf),5)) return false;
    if(memcmp(hdrbuf,MAGIC,4)!=0) return false;
    unsigned char ver=hdrbuf[4];
    if(ver!=1&&ver!=2&&ver!=3&&ver!=VERSION) return false;
    size_t hdr_size=header_size_for_version(ver);
    if(!f.read(reinterpret_cast<char*>(hdrbuf+5),(std::streamoff)(hdr_size-5))) return false;
    const unsigned char* salt_ptr=nullptr;
    unsigned int kdf_ops=ARGON2_OPS_LEGACY;
    size_t kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    if(ver==1)      { FileHeaderV1* h=reinterpret_cast<FileHeaderV1*>(hdrbuf); salt_ptr=h->salt; }
    else if(ver==2) { FileHeader*  h=reinterpret_cast<FileHeader*>(hdrbuf);  salt_ptr=h->salt; kdf_ops=h->opslimit; kdf_mem=(size_t)h->memlimit_kb*1024; }
    else if(ver==3) { FileHeaderV3* h=reinterpret_cast<FileHeaderV3*>(hdrbuf); salt_ptr=h->salt; kdf_ops=h->opslimit; kdf_mem=(size_t)h->memlimit_kb*1024; }
    else            { FileHeaderV4* h=reinterpret_cast<FileHeaderV4*>(hdrbuf); salt_ptr=h->salt; kdf_ops=h->opslimit; kdf_mem=(size_t)h->memlimit_kb*1024; }
    SecureBuffer key(ARGON2_OUTPUT_LEN);
    if(!derive_key(password.data(),password.size(),salt_ptr,key.data(),kdf_ops,kdf_mem)) return false;
    return decrypt_name_footer(ptd_path, out_name, key.data(), salt_ptr);
}

// ---------- 加密 ----------
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const SecureBuffer& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback,
    bool resume) {

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

    std::ifstream fin;
    if(!open_stream(fin,in_path,std::ios::binary)) {
        fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }
    fin.seekg(0,std::ios::end);
    uint64_t total_size=static_cast<uint64_t>(fin.tellg());
    fin.seekg(0,std::ios::beg);
    auto start_time=std::chrono::steady_clock::now();

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

    // ---- 续传检测：先读已存在输出的头部获取 salt，派生密钥后才能验证 .progress 的 HMAC ----
    ProgressInfo prog_info{0,0,0,0,{0}};
    bool has_progress=false;
    bool out_exists=file_exists(out_path);
    bool prog_present=file_exists(out_path+".progress");
    FileHeaderV3 existing_v3{};   // 复用 v3 前缀结构读取前 109 字节（v3 / v4 通用）
    bool existing_is_v3=false;   // 现有输出为 v3 或 v4
    bool existing_is_v4=false;
    unsigned char existing_hdr_hmac[HEADER_HMAC_SIZE]={0};
    if(out_exists) {
        std::ifstream fhex;
        if(open_stream(fhex,out_path,std::ios::binary)) {
            unsigned char ehbuf[HEADER_SIZE_V4];
            if(fhex.read(reinterpret_cast<char*>(ehbuf),HEADER_SIZE_V4)
                && fhex.gcount()==HEADER_SIZE_V4
                && memcmp(ehbuf,MAGIC,4)==0 && (ehbuf[4]==3||ehbuf[4]==VERSION)) {
                memcpy(&existing_v3,ehbuf,HEADER_SIZE_V3);
                if(ehbuf[4]==VERSION) {
                    existing_is_v4=true;
                    memcpy(existing_hdr_hmac,ehbuf+HEADER_SIZE_V3,HEADER_HMAC_SIZE);
                }
                existing_is_v3=true;
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
                // v4 输出：先校验文件头 HMAC（防文件头被篡改后重放旧 .progress）
                bool hdr_ok=true;
                if(existing_is_v4) {
                    unsigned char hdr_auth[HEADER_HMAC_SIZE];
                    derive_header_auth_key(key.data(),hdr_auth);
                    hdr_ok=(crypto_auth_verify(existing_hdr_hmac,
                        reinterpret_cast<const unsigned char*>(&existing_v3),HEADER_HMAC_COVER,hdr_auth)==0);
                }
                if(hdr_ok && verify_progress_hmac(prog_info,auth_key.data(),prog_binding)
                    && prog_info.processed_chunks<=total_chunks
                    && prog_info.processed_bytes<=total_size) {
                    has_progress=true;
                }
            }
        }
        // 注意：此处不能 key.clear()。key 由 SecureBuffer 持有，函数返回时析构已安全清零+解锁；
        // 若提前 clear，后续续传分支（!header_written 或 else）再次 derive_key(..., key.data(), ...)
        // 会写入已释放（nullptr）的缓冲，触发段错误。保留 key 的有效 32 字节缓冲即可。
    }

    // 进度文件存在但无法认证（HMAC 失败 / 格式损坏 / 旧格式）：
    // 原输出已存在时禁止从头重写覆盖——否则正确密码加密的密文会被错误密码的产物
    // 静默抹掉，且 .progress 随后被删，造成数据永久丢失（批量 -be 无交互确认即触发）。
    // 仅当原输出不存在（孤立 .progress）时才安全从头重做。
    if(resume && prog_present && !has_progress) {
        if(out_exists) {
            fprintf(stderr,"Refusing to overwrite existing output '%s': progress authentication failed "
                "(likely wrong password or corrupt .progress). Use a different output path, or delete "
                "the file and its .progress first if you intend to restart.\n", out_path.c_str());
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
    size_t existing_hdr_size = existing_is_v4 ? HEADER_SIZE_V4 : HEADER_SIZE_V3;
    uint64_t trunc_pos=(uint64_t)existing_hdr_size+4+4+8+(uint64_t)start_chunk*(chunk_size+tag_size);

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

    // 续传前先做一致性校验，且必须在 truncate_file 之前完成。
    // 否则校验失败时输出已被截断，随后的 cleanup 会删除 .ptd 与 .progress，
    // 用户可用正确的 -m 重新运行，断点不丢失。
    if(has_progress&&start_chunk>0) {
        if(existing_v3.mode!=static_cast<unsigned char>(mode)) {
            fprintf(stderr,"Output file was created with a different encryption mode "
                "(existing=%d, requested=%d); cannot resume. Use the same -m mode, "
                "or delete the output file first.\n",
                (int)existing_v3.mode,(int)mode);
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

    FileHeaderV4 header{};
    bool ok=true;
    std::vector<unsigned char> aad;
    std::vector<unsigned char> plaintext_chunk(CHUNK_SIZE);
    std::vector<unsigned char> ciphertext_chunk(CHUNK_SIZE+MAX_TAG_SIZE);
    unsigned char nonce[32]={0};
    uint64_t processed_bytes=start_bytes;

    if(!header_written) {
        memcpy(header.magic,MAGIC,4);
        header.version=VERSION;
        header.mode=static_cast<unsigned char>(mode);
        header.iv_len=static_cast<unsigned char>(iv_len);
        header.opslimit=ARGON2_OPS_DEFAULT;
        header.memlimit_kb=ARGON2_MEM_DEFAULT_KB;
        randombytes_buf(header.salt,ARGON2_SALT_LEN);
        randombytes_buf(header.iv,iv_len);
        sodium_memzero(header.plaintext_hash,HASH_SIZE);
        sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);

        if(!derive_key(password.data(),password.size(),header.salt,key.data(),
                header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false; goto cleanup;
        }
        derive_progress_auth_key(key.data(),auth_key.data());

        // AAD 覆盖文件头前 77 字节（magic..iv），不含 plaintext_hash 与 header_hmac
        // （二者在加密后才确定，且 header_hmac 已对整段元数据独立认证，避免双重绑定导致自不一致）。
        aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
            HEADER_HMAC_COVER, chunk_size,total_chunks,orig_size);

        // 文件头 HMAC 在写头瞬间即计算并随头落盘：覆盖前 77 字节（含 salt/mode/Argon2 参数/iv），
        // 不含 plaintext_hash/header_hmac 自身。这样被中断的半成品 .ptd 也已携带合法 header_hmac，
        // 续传时“文件头篡改校验”可正常通过；同时防攻击者替换 salt/iv/mode 后重放旧 .progress。
        {
            unsigned char hdr_auth[HEADER_HMAC_SIZE];
            derive_header_auth_key(key.data(),hdr_auth);
            crypto_auth(header.header_hmac,
                reinterpret_cast<const unsigned char*>(&header),HEADER_HMAC_COVER,hdr_auth);
        }

        if(!fout.write(reinterpret_cast<const char*>(&header),HEADER_SIZE_V4)) {
            fprintf(stderr,"Write header failed\n"); ok=false; goto cleanup;
        }
        if(!fout.write(reinterpret_cast<const char*>(&chunk_size),4)||
            !fout.write(reinterpret_cast<const char*>(&total_chunks),4)||
            !fout.write(reinterpret_cast<const char*>(&orig_size),8)) {
            fprintf(stderr,"Write metadata failed\n"); ok=false; goto cleanup;
        }
    }
    else {
        memcpy(&header,&existing_v3,HEADER_SIZE_V3);
        sodium_memzero(header.header_hmac,HEADER_HMAC_SIZE);
        if(!derive_key(password.data(),password.size(),header.salt,key.data(),
                header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false; goto cleanup;
        }
        derive_progress_auth_key(key.data(),auth_key.data());
        aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
            HEADER_HMAC_COVER, chunk_size,total_chunks,orig_size);
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

        unsigned long long ciphertext_len=0;
        int rc;
        if(mode==CryptoMode::AES_GCM) {
            rc=crypto_aead_aes256gcm_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,aad.data(),aad.size(),NULL,nonce,key.data());
            if(rc!=0) fprintf(stderr,"AES-GCM encryption failed at chunk %u\n",i);
        }
        else if(mode==CryptoMode::AEGIS256) {
            rc=crypto_aead_aegis256_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,aad.data(),aad.size(),NULL,nonce,key.data());
            if(rc!=0) fprintf(stderr,"AEGIS-256 encryption failed at chunk %u\n",i);
        }
        else {
            rc=crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,aad.data(),aad.size(),NULL,nonce,key.data());
            if(rc!=0) fprintf(stderr,"XChaCha20 encryption failed at chunk %u\n",i);
        }
        if(rc!=0) { ok=false; break; }

        if(!fout.write(reinterpret_cast<const char*>(ciphertext_chunk.data()),ciphertext_len)) {
            fprintf(stderr,"Write ciphertext failed at chunk %u\n",i);
            ok=false; break;
        }

        processed_bytes+=chunk_len;
        throttle_consume(chunk_len);
        // 先落盘再记账进度（带 HMAC），确保磁盘内容永远不落后于 .progress
        fout.flush();
        if(!save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
            fprintf(stderr,"Failed to save progress at chunk %u\n",i);
        }

        if(progress_callback) progress_callback(processed_bytes,total_size);
        else print_progress(processed_bytes,total_size,start_time);

        if(i+1<total_chunks) sodium_increment(nonce,iv_len);
    }

    if(ok) {
        // 结束哈希并回填 plaintext_hash；文件头 HMAC 已在写头瞬间算好（覆盖前 77 字节），
        // 此处仅重算一遍（前 77 字节未变，结果一致）后随 plaintext_hash 一并写回。
        crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(key.data(),hdr_auth);
        crypto_auth(header.header_hmac,
            reinterpret_cast<const unsigned char*>(&header),HEADER_HMAC_COVER,hdr_auth);
        fout.flush();
        fout.seekp((std::streamoff)(HEADER_SIZE_V4-HASH_SIZE-HEADER_HMAC_SIZE),std::ios::beg);
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
    if(fout.is_open()) { fout.flush(); fout.close(); }

    if(ok) {
        remove_progress(out_path);
        if(!progress_callback) print_progress(total_size,total_size,start_time,true);

        // 自解密验证：复用本次已派生的密钥（ext_key），避免每文件重复执行一次昂贵的 Argon2 KDF
        std::string verify_path=out_path+".verify.tmp";
        remove_file_utf8(verify_path);
        bool verify_ok=decrypt_file(out_path,verify_path,password,
            [](size_t,size_t){}, true, false, key.data());
        if(verify_ok) {
            int64_t vsz=get_file_size_utf8(verify_path);
            if(vsz!=(int64_t)total_size) verify_ok=false;
            if(verify_ok) {
                unsigned char vhash[HASH_SIZE];
                if(file_blake2b(verify_path,vhash))
                    verify_ok=(sodium_memcmp(vhash,header.plaintext_hash,HASH_SIZE)==0);
                else verify_ok=false;
            }
        }
        remove_file_utf8(verify_path);
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
    const unsigned char* ext_key) {
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

    std::ifstream fin;
    if(!open_stream(fin,in_path,std::ios::binary)) {
        if(!silent) fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }
    fin.seekg(0,std::ios::end);
    auto file_size=fin.tellg();
    fin.seekg(0,std::ios::beg);

    // 版本感知的头部解析：先读 magic+version，再按版本读取剩余头部。
    unsigned char hdrbuf[160];
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
        FileHeaderV1* h1=reinterpret_cast<FileHeaderV1*>(hdrbuf);
        mode=static_cast<CryptoMode>(h1->mode);
        iv_len=h1->iv_len;
        salt_ptr=h1->salt;
        iv_ptr=h1->iv;
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
        FileHeader* h2=reinterpret_cast<FileHeader*>(hdrbuf);
        mode=static_cast<CryptoMode>(h2->mode);
        iv_len=h2->iv_len;
        salt_ptr=h2->salt;
        iv_ptr=h2->iv;
        kdf_ops=h2->opslimit;
        kdf_mem=(size_t)h2->memlimit_kb*1024;
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
        FileHeaderV3* h3=reinterpret_cast<FileHeaderV3*>(hdrbuf);
        mode=static_cast<CryptoMode>(h3->mode);
        iv_len=h3->iv_len;
        salt_ptr=h3->salt;
        iv_ptr=h3->iv;
        kdf_ops=h3->opslimit;
        kdf_mem=(size_t)h3->memlimit_kb*1024;
        memcpy(stored_hash,h3->plaintext_hash,HASH_SIZE);
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
        FileHeaderV4* h4=reinterpret_cast<FileHeaderV4*>(hdrbuf);
        mode=static_cast<CryptoMode>(h4->mode);
        iv_len=h4->iv_len;
        salt_ptr=h4->salt;
        iv_ptr=h4->iv;
        kdf_ops=h4->opslimit;
        kdf_mem=(size_t)h4->memlimit_kb*1024;
        memcpy(stored_hash,h4->plaintext_hash,HASH_SIZE);
        memcpy(hdr_hmac,h4->header_hmac,HEADER_HMAC_SIZE);
        have_hash=true;
        is_v4=true;
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
    // 同时计算源文件绑定标识，供 .progress 防重放校验使用。
    std::string prog_binding = compute_progress_binding(in_path);
    if(ext_key) {
        // 复用外部已派生密钥：跳过昂贵的 Argon2 KDF（用于加密后自校验）
        memcpy(key.data(), ext_key, ARGON2_OUTPUT_LEN);
    } else if(!derive_key(password.data(),password.size(),salt_ptr,key.data(),kdf_ops,kdf_mem)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    }
    derive_progress_auth_key(key.data(), auth_key.data());

    // v4 文件头 HMAC 校验：独立于 AEAD，防止文件头被篡改（如替换 salt/iv/mode 后重放）。
    // 必须在任何明文输出之前完成，且校验失败只给通用错误（防侧信道）。
    if(is_v4) {
        unsigned char hdr_auth[HEADER_HMAC_SIZE];
        derive_header_auth_key(key.data(), hdr_auth);
        if(crypto_auth_verify(hdr_hmac, hdrbuf, HEADER_HMAC_COVER, hdr_auth)!=0) {
            report_auth_error(silent, "Header authentication failed (file tampered or wrong key).");
            return false;
        }
    }

    // 跨进程锁 + 临时文件：解密先将明文写入 <out>.part，全部校验通过后再原子重命名
    std::string part_path=out_path+".part";
    // 防符号链接劫持：若 .part 半成品已存在且为符号链接/重解析点，拒绝写入，避免清空被指向的敏感文件
    if(path_is_symlink(part_path)) {
        if(!silent) fprintf(stderr,"Refusing to write through existing symlink: %s\n",part_path.c_str());
        return false;
    }
    std::string lock_path;
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
    OutputLockGuard lock_guard{lock_path,true};

    // 密文末尾可能附加加密的原始文件名信封，大小校验必须把它计入
    uint64_t footer_len=0;
    peek_name_footer_len(in_path, footer_len);

    uint64_t total_size=orig_size;
    if(total_chunks==0) {
        if((size_t)file_size!=hdr_size+4+4+8+footer_len) {
            if(!silent) fprintf(stderr,"File size mismatch for empty file.\n");
            return false;
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

    ProgressInfo prog_info={0,0,0,0,{0}};
    // 续传需要“进度文件”与“对应的 .part 半成品”同时齐备，否则视为全新开始
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

    // 解密续传：明文半成品（.part）可能残留未完成块的残片，截断到已确认写入的明文长度
    std::fstream fout;
    if(has_progress&&start_chunk>0) {
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

    // 密钥已在前面（空文件短路之前）派生到 key / auth_key，此处无需重复派生。

    // AAD 必须严格复刻加密时的构造：v4 排除末尾 32 字节明文哈希 + 32 字节 header_hmac，
    // v3 仅排除末尾 32 字节明文哈希；二者最终都覆盖头部前 77 字节（magic..iv）。
    size_t aad_hdr_len=hdr_size - (ver==VERSION?(HASH_SIZE+HEADER_HMAC_SIZE):HASH_SIZE);
    std::vector<unsigned char> aad=build_aad_with_metadata(hdrbuf,aad_hdr_len,chunk_size,total_chunks,orig_size);

    auto start_time=std::chrono::steady_clock::now();
    std::vector<unsigned char> ciphertext_chunk(chunk_size+MAX_TAG_SIZE);
    std::vector<unsigned char> plaintext_chunk(chunk_size);
    unsigned char nonce[32]={0};
    bool ok=true;
    uint64_t processed_bytes=start_bytes;

    // 提前声明，避免 goto dec_cleanup 跨过带初始化的变量
    bool use_increment=(ver==VERSION);
    size_t input_offset=hdr_size+4+4+8+(size_t)start_chunk*(chunk_size+tag_size);

    // 防整数溢出 / 越界：input_offset 来自文件头（v3 未被 HMAC 认证）或续传进度，
    // 须边界校验后再 seekg。先以 uint64_t 做乘法溢出检查，再确认落在文件范围内。
    {
        const uint64_t base = (uint64_t)hdr_size + 4 + 4 + 8;
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

    // 明文 Blake2b 流式哈希（续传时先回放 .part 前缀）
    crypto_generichash_state hstate;
    if(have_hash) crypto_generichash_init(&hstate,nullptr,0,HASH_SIZE);
    if(have_hash && start_bytes>0) {
        std::ifstream pin;
        if(!open_stream(pin,part_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot open .part for hash catch-up\n");
            ok=false;
        }
        else {
            uint64_t remain=start_bytes;
            std::vector<unsigned char> tmp(CHUNK_SIZE);
            while(remain>0 && ok) {
                size_t n=(size_t)std::min<uint64_t>(CHUNK_SIZE,remain);
                pin.read(reinterpret_cast<char*>(tmp.data()),n);
                if(pin.gcount()!=(std::streamsize)n) {
                    if(!silent) fprintf(stderr,"Read .part for hash catch-up failed\n");
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
        size_t expected_cipher_len=chunk_len+tag_size;
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

        unsigned long long plaintext_len=0;
        int rc;
        if(mode==CryptoMode::AES_GCM) {
            rc=crypto_aead_aes256gcm_decrypt(plaintext_chunk.data(),&plaintext_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key.data());
            if(rc!=0) report_auth_error(silent, "AES-GCM decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        }
        else if(mode==CryptoMode::AEGIS256) {
            rc=crypto_aead_aegis256_decrypt(plaintext_chunk.data(),&plaintext_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key.data());
            if(rc!=0) report_auth_error(silent, "AEGIS-256 decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        }
        else {
            rc=crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext_chunk.data(),&plaintext_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key.data());
            if(rc!=0) report_auth_error(silent, "XChaCha20 decryption failed at chunk " + std::to_string(i) + " (invalid key or corrupted data).");
        }
        if(rc!=0) { ok=false; break; }

        if(!fout.write(reinterpret_cast<const char*>(plaintext_chunk.data()),plaintext_len)) {
            if(!silent) fprintf(stderr,"Write plaintext chunk %u failed\n",i);
            ok=false;
            break;
        }
        if(have_hash) crypto_generichash_update(&hstate,plaintext_chunk.data(),plaintext_len);

        processed_bytes+=plaintext_len;
        throttle_consume(plaintext_len);
        fout.flush();   // 先落盘再记账进度（带 HMAC），确保磁盘内容永远不落后于 .progress
        if(!save_progress(out_path,i+1,processed_bytes,auth_key.data(),prog_binding)) {
            if(!silent) fprintf(stderr,"Failed to save progress at chunk %u\n",i);
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

    // 明文完整性校验（v3）：恢复的明文 Blake2b 必须与存储哈希一致
    if(have_hash) {
        unsigned char final_hash[HASH_SIZE];
        crypto_generichash_final(&hstate,final_hash,HASH_SIZE);
        if(ok && sodium_memcmp(final_hash,stored_hash,HASH_SIZE)!=0) {
            report_auth_error(silent, "Plaintext integrity check failed: recovered data does not match original.");
            ok=false;
        }
    }

dec_cleanup:
    // key / auth_key 由 SecureBuffer 持有，函数返回时析构自动 sodium_memzero + sodium_munlock，
    // 任何 return / goto 路径都已安全清理，无需在此手动清零。
    secure_clear(ciphertext_chunk);
    secure_clear(plaintext_chunk);

    fin.close();
    fout.close();

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
        // 失败时只删除半成品（.part），最终输出路径不写入任何明文
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
        // 前缀匹配需带边界检查：root 必须是 in_path 的目录前缀，
        // 即 root 之后紧跟路径分隔符，或与 in_path 完全相同，
        // 否则 "D:\data" 会误匹配 "D:\database\x"（Issue N-C）。
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
        // 加密：保留输入根目录名作为顶层目录（避免多 -i 同名冲突，且还原后保持源目录名）；
        // 解密：默认不附加输入根目录名，使还原结构为 <输出目录>/<源目录>/...（与 v1.1.1 一致）。
        // 但当存在多个输入根目录时（input_paths.size()>1），即使是解密也附加根目录名前缀
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
    CryptoMode mode,
    bool encrypt,
    bool delete_source,
    bool force_overwrite,
    int num_threads,
    bool restore_name) {
    // 批量模式 AEGIS-256 可用性回退：缺 AES-NI 时自动切换到 XChaCha20
    if(encrypt&&mode==CryptoMode::AEGIS256&&!aegis256_supported()) {
        if(g_aegis_fallback_choice.load()==0) {
            std::cout<<"Warning: AEGIS-256 is not available on this CPU (AES-NI required).\n"
                <<"Do you want to switch to XChaCha20 (secure) for all files? (y/N): ";
            char ch='n';
            std::cin>>ch;
            if(ch=='y'||ch=='Y') {
                g_aegis_fallback_choice.store(1);
            }
            else {
                g_aegis_fallback_choice.store(-1);
            }
        }
        if(g_aegis_fallback_choice.load()==1) {
            mode=CryptoMode::XCHACHA20;
            fprintf(stderr,"Switched to XChaCha20 mode for this batch.\n");
        }
        else {
            fprintf(stderr,"Continuing with AEGIS-256 (may fail on this CPU).\n");
        }
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
    for(const auto& f:all_files) {
        int64_t s=get_file_size_utf8(f);
        if(s>=0) total_bytes+=(size_t)s;
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
    for(const auto& in_path:all_files) {
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
            // 批量解密文件名还原：默认关闭（省去每文件昂贵的 Argon2id KDF），仅保留扩展名；
            // restore_name=true 时还原完整原始文件名（性能较差）。
            if(restore_name) {
                std::string orig_name;
                if(read_original_name(in_path,orig_name,password)&&!orig_name.empty()) {
                    out_path=replace_basename(out_path,orig_name);
                }
            }
        }

        size_t dirpos=out_path.find_last_of("/\\");
        if(dirpos!=std::string::npos) {
            std::string out_subdir=out_path.substr(0,dirpos);
            create_directory_recursive(out_subdir);
        }

        bool skip=false;
        if(!force_overwrite) {
            bool exists=false;
            bool valid=false;
            {
                std::ifstream test;
                if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                    exists=true;
                    test.close();
                    valid=is_file_valid(out_path);
                }
            }
            if(exists) {
                if(!valid) {
                    fprintf(stderr,"Existing file %s is corrupted, will overwrite.\n",out_path.c_str());
                }
                else if(file_exists(out_path+".progress")) {
                    fprintf(stderr,"Existing file %s has unfinished progress, will resume.\n",out_path.c_str());
                }
                else if(is_complete_output(out_path,encrypt,in_path)) {
                    // 头部有效、无 .progress、且尺寸完整，确属已完成成品，安全跳过
                    skip=true;
                }
                else {
                    // 头部有效但尺寸不完整且无 .progress：多半是上一轮在首个 save_progress 前被强杀，
                    // 残留下“仅头部”的半截 .ptd。当作未完成重新加密，避免解密字节不一致。
                    fprintf(stderr,"Existing file %s is incomplete (no progress), will re-encrypt.\n",out_path.c_str());
                }
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

    std::atomic<size_t> file_index{0};
    std::atomic<size_t> global_processed{0};
    std::mutex error_mutex;
    std::vector<std::string> error_files;
    std::chrono::steady_clock::time_point start_time=std::chrono::steady_clock::now();
    std::atomic<bool> all_ok{true};

    auto worker=[&]() {
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
                // 批量解密文件名还原（与预扫描一致）：默认关闭省去每文件 KDF
                if(restore_name) {
                    std::string orig_name;
                    if(read_original_name(in_path,orig_name,password)&&!orig_name.empty()) {
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
                        static std::mutex print_mutex;
                        std::lock_guard<std::mutex> lock(print_mutex);
                        print_progress(global_processed.load(),total_bytes,start_time,false);
                    },true);
                if(ok&&delete_source) {
                    if(!remove_file_utf8(in_path)) {
                        std::lock_guard<std::mutex> lock(error_mutex);
                        std::cerr<<"Error: could not delete source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
            }
            else {
                ok=decrypt_file(in_path,out_path,password,
                    [&](size_t processed,size_t total) {
                        size_t inc=processed-last_file_processed;
                        last_file_processed=processed;
                        global_processed+=inc;
                        static std::mutex print_mutex;
                        std::lock_guard<std::mutex> lock(print_mutex);
                        print_progress(global_processed.load(),total_bytes,start_time,false);
                    },true,true);
            }

            if(ok) {
                // 仅在成功处理的文件上补齐进度，避免失败文件把进度条拉满到 100%
                int64_t fsize=get_file_size_utf8(in_path);
                if(fsize>=0) {
                    size_t file_size=(size_t)fsize;
                    if(last_file_processed<file_size) {
                        global_processed+=(file_size-last_file_processed);
                        last_file_processed=file_size;
                    }
                }
                log_event(LOG_DEBUG,"file_done",{{"path",in_path}});
            }
            else {
                all_ok=false;
                std::lock_guard<std::mutex> lock(error_mutex);
                error_files.push_back(in_path);
                log_event(LOG_ERROR,"file_failed",{{"path",in_path}});
            }
        }
        };

    std::vector<std::thread> threads;
    for(int i=0; i<num_threads; ++i) {
        threads.emplace_back(worker);
    }
    for(auto& t:threads) {
        t.join();
    }

    if(error_files.empty()) {
        // 全部成功：安全地拉满到 100%（任务中途失败文件已不会拉满）
        global_processed=total_bytes;
    }
    // 有失败文件：按真实已处理字节收尾，不掩盖失败/跳过情况
    print_progress(global_processed.load(),total_bytes,start_time,true);
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

    return all_ok.load();
}