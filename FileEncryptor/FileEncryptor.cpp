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
#include <atomic>
#include <thread>
#include <mutex>

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
const unsigned char VERSION=3;

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
    return HEADER_SIZE_V3;
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
static bool path_has_traversal(const std::string& p) {
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

// ---------- 反调试 ----------
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
    if(path.empty()) return true;
#ifdef _WIN32
    struct _stat64 st;
    if(_wstat64(utf8_to_wstring(path).c_str(),&st)==0) {
        return (st.st_mode&S_IFDIR)!=0;
    }
    size_t pos=path.find_last_of("/\\");
    if(pos!=std::string::npos) {
        if(!create_directory_recursive(path.substr(0,pos))) return false;
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
static bool derive_key(const std::vector<char>& password,
    const unsigned char* salt,
    unsigned char* key,
    unsigned int opslimit,
    size_t memlimit,
    size_t key_len=ARGON2_OUTPUT_LEN) {
    if(crypto_pwhash(key,key_len,
        password.data(),password.size(),
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
    unsigned char hbuf[HEADER_SIZE_V3];
    f.read(reinterpret_cast<char*>(hbuf),HEADER_SIZE_V3);
    if(f.gcount()<5) return false;
    unsigned char ver=hbuf[4];
    uint64_t need=(ver==1)?HEADER_SIZE_V1:(ver==2)?HEADER_SIZE_V2:HEADER_SIZE_V3;
    if((uint64_t)f.gcount()<need) return false;
    return (memcmp(hbuf,MAGIC,4)==0&&(ver==1||ver==2||ver==VERSION));
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

// 校验 .progress 的 HMAC（防续传劫持）：覆盖前 24 字节（magic+version+chunks+bytes）。
static bool verify_progress_hmac(const ProgressInfo& info,const unsigned char* auth_key) {
    return crypto_auth_verify(info.hmac,
        reinterpret_cast<const unsigned char*>(&info),24,auth_key)==0;
}

// 计算并写入带 HMAC 的进度（先落盘再返回；success 时调用方再记账 HMAC 之前已 flush 密文）。
static bool save_progress(const std::string& out_path,
    uint64_t processed_chunks,uint64_t processed_bytes,
    const unsigned char* auth_key) {
    ProgressInfo info;
    info.magic=PROGRESS_MAGIC;
    info.version=PROGRESS_VERSION;
    info.processed_chunks=processed_chunks;
    info.processed_bytes=processed_bytes;
    crypto_auth(info.hmac,
        reinterpret_cast<const unsigned char*>(&info),24,auth_key);

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
    double speed=(elapsed>0) ? (processed/1048576.0)/elapsed : 0.0;
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
    snprintf(buf,sizeof(buf),"\r%s %zu/%zu bytes | %.1f MiB/s | %d:%02d",
        bar.c_str(),processed,total,speed,eta/60,eta%60);

    if(finish) {
        std::cout<<buf<<'\n';
    }
    else {
        std::cout<<buf<<std::flush;
    }
}

// ---------- 加密 ----------
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::vector<char>& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback,
    bool resume) {

    disable_core_dump();

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

    // ---- 续传检测：先读已存在输出的 v3 头部获取 salt，派生密钥后才能验证 .progress 的 HMAC ----
    ProgressInfo prog_info{0,0,0,0,{0}};
    bool has_progress=false;
    bool out_exists=file_exists(out_path);
    FileHeaderV3 existing_v3{};
    bool existing_is_v3=false;
    if(out_exists) {
        std::ifstream fhex;
        if(open_stream(fhex,out_path,std::ios::binary)) {
            unsigned char hbuf[HEADER_SIZE_V3];
            if(fhex.read(reinterpret_cast<char*>(hbuf),HEADER_SIZE_V3)
                && fhex.gcount()==HEADER_SIZE_V3
                && memcmp(hbuf,MAGIC,4)==0 && hbuf[4]==VERSION) {
                memcpy(&existing_v3,hbuf,HEADER_SIZE_V3);
                existing_is_v3=true;
            }
            fhex.close();
        }
    }

    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    unsigned char auth_key[crypto_auth_KEYBYTES]={0};

    if(resume && load_progress_raw(out_path,prog_info)) {
        if(existing_is_v3) {
            if(!derive_key(password,existing_v3.salt,key,existing_v3.opslimit,
                    (size_t)existing_v3.memlimit_kb*1024)) {
                fprintf(stderr,"Key derivation failed for resume\n");
            } else {
                derive_progress_auth_key(key,auth_key);
                if(verify_progress_hmac(prog_info,auth_key)
                    && prog_info.processed_chunks<=total_chunks
                    && prog_info.processed_bytes<=total_size) {
                    has_progress=true;
                } else {
                    fprintf(stderr,"Progress authentication failed / corrupt, restarting from beginning.\n");
                }
            }
        } else {
            fprintf(stderr,"Cannot authenticate legacy progress file, restarting from beginning.\n");
        }
        sodium_memzero(key,sizeof(key));
        if(!has_progress) prog_info={0,0,0,0,{0}};
    }

    uint64_t start_chunk=has_progress?prog_info.processed_chunks:0;
    uint64_t start_bytes=has_progress?prog_info.processed_bytes:0;
    uint64_t trunc_pos=(uint64_t)HEADER_SIZE_V3+4+4+8+(uint64_t)start_chunk*(chunk_size+tag_size);

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
    // 导致断点全损（Issue N-B）。这里直接返回并保留已存在的输出，
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
                || !fhex.seekg(HEADER_SIZE_V3,std::ios::beg)
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

    FileHeaderV3 header{};
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

        if(!derive_key(password,header.salt,key,header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false; goto cleanup;
        }
        if(sodium_mlock(key,sizeof(key))==0) key_locked=true;
        else fprintf(stderr,"Warning: could not lock key memory (possible performance/security impact).\n");
        derive_progress_auth_key(key,auth_key);

        // AAD 不含末尾 32 字节 plaintext_hash（其为加密后写入，不在 AAD 内以保证一致性）
        aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
            HEADER_SIZE_V3-HASH_SIZE, chunk_size,total_chunks,orig_size);

        if(!fout.write(reinterpret_cast<const char*>(&header),HEADER_SIZE_V3)) {
            fprintf(stderr,"Write header failed\n"); ok=false; goto cleanup;
        }
        if(!fout.write(reinterpret_cast<const char*>(&chunk_size),4)||
            !fout.write(reinterpret_cast<const char*>(&total_chunks),4)||
            !fout.write(reinterpret_cast<const char*>(&orig_size),8)) {
            fprintf(stderr,"Write metadata failed\n"); ok=false; goto cleanup;
        }
    }
    else {
        header=existing_v3;
        if(!derive_key(password,header.salt,key,header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false; goto cleanup;
        }
        if(sodium_mlock(key,sizeof(key))==0) key_locked=true;
        derive_progress_auth_key(key,auth_key);
        aad=build_aad_with_metadata(reinterpret_cast<unsigned char*>(&header),
            HEADER_SIZE_V3-HASH_SIZE, chunk_size,total_chunks,orig_size);
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
                plaintext_chunk.data(),chunk_len,aad.data(),aad.size(),NULL,nonce,key);
            if(rc!=0) fprintf(stderr,"AES-GCM encryption failed at chunk %u\n",i);
        }
        else if(mode==CryptoMode::AEGIS256) {
            rc=crypto_aead_aegis256_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,aad.data(),aad.size(),NULL,nonce,key);
            if(rc!=0) fprintf(stderr,"AEGIS-256 encryption failed at chunk %u\n",i);
        }
        else {
            rc=crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,aad.data(),aad.size(),NULL,nonce,key);
            if(rc!=0) fprintf(stderr,"XChaCha20 encryption failed at chunk %u\n",i);
        }
        if(rc!=0) { ok=false; break; }

        if(!fout.write(reinterpret_cast<const char*>(ciphertext_chunk.data()),ciphertext_len)) {
            fprintf(stderr,"Write ciphertext failed at chunk %u\n",i);
            ok=false; break;
        }

        processed_bytes+=chunk_len;
        // 先落盘再记账进度（带 HMAC），确保磁盘内容永远不落后于 .progress
        fout.flush();
        if(!save_progress(out_path,i+1,processed_bytes,auth_key)) {
            fprintf(stderr,"Failed to save progress at chunk %u\n",i);
        }

        if(progress_callback) progress_callback(processed_bytes,total_size);
        else print_progress(processed_bytes,total_size,start_time);

        if(i+1<total_chunks) sodium_increment(nonce,iv_len);
    }

    if(ok) {
        // 结束哈希并回填到文件头（plaintext_hash 不纳入 AAD）
        crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
        fout.flush();
        fout.seekp((std::streamoff)(HEADER_SIZE_V3-HASH_SIZE),std::ios::beg);
        fout.write(reinterpret_cast<const char*>(header.plaintext_hash),HASH_SIZE);
        fout.flush();
    }
    else {
        crypto_generichash_final(&hstate,header.plaintext_hash,HASH_SIZE);
    }

cleanup:
    if(key_locked) sodium_munlock(key,sizeof(key));
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
            [](size_t,size_t){}, true, false, key);
        if(verify_ok) {
            int64_t vsz=get_file_size_utf8(verify_path);
            if(vsz!=(int64_t)total_size) verify_ok=false;
            if(verify_ok) {
                unsigned char vhash[HASH_SIZE];
                if(file_blake2b(verify_path,vhash))
                    verify_ok=(memcmp(vhash,header.plaintext_hash,HASH_SIZE)==0);
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

    // 自校验结束后再清零密钥：避免对同一个密码重复执行 Argon2 KDF（大批量加密时显著提速）
    sodium_memzero(key,sizeof(key));
    sodium_memzero(auth_key,sizeof(auth_key));
    return ok;
}

// ---------- 解密 ----------
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::vector<char>& password,
    std::function<void(size_t,size_t)> progress_callback,
    bool silent,
    bool resume,
    const unsigned char* ext_key) {
    disable_core_dump();

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
    unsigned char hdrbuf[128];
    size_t hdr_size=0;
    unsigned int kdf_ops=ARGON2_OPS_LEGACY;
    size_t kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    CryptoMode mode=CryptoMode::AES_GCM;
    size_t iv_len=0;
    const unsigned char* salt_ptr=nullptr;
    const unsigned char* iv_ptr=nullptr;
    unsigned char stored_hash[HASH_SIZE]={0};
    bool have_hash=false;

    // 密钥相关缓冲区提前声明，供异常跳转（dec_cleanup）安全清理
    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    unsigned char auth_key[crypto_auth_KEYBYTES]={0};

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
    else if(ver==VERSION) {
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

    uint64_t total_size=orig_size;
    if(total_chunks==0) {
        if((size_t)file_size!=hdr_size+4+4+8) {
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
                if(!silent) fprintf(stderr,"Plaintext integrity check failed (empty file).\n");
                remove_file_utf8(out_path);
                return false;
            }
        }
        return true;
    }

    uint64_t last_chunk_len=orig_size-(uint64_t)(total_chunks-1)*chunk_size;
    uint64_t expected_size=(uint64_t)hdr_size+4+4+8
        +(uint64_t)(total_chunks-1)*(uint64_t)(chunk_size+tag_size)
        +(uint64_t)last_chunk_len+tag_size;
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
        // 派生密钥 → 派生 HMAC 密钥 → 验证 .progress 的 HMAC
        unsigned char tkey[ARGON2_OUTPUT_LEN]={0};
        unsigned char tauth[crypto_auth_KEYBYTES]={0};
        if(derive_key(password,salt_ptr,tkey,kdf_ops,kdf_mem)) {
            derive_progress_auth_key(tkey,tauth);
            if(verify_progress_hmac(prog_info,tauth)
                && prog_info.processed_chunks<=total_chunks
                && prog_info.processed_bytes<=total_size) {
                has_progress=true;
            } else {
                if(!silent) fprintf(stderr,"Corrupted progress file detected, restarting from beginning.\n");
            }
            sodium_memzero(tkey,sizeof(tkey));
            sodium_memzero(tauth,sizeof(tauth));
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

    if(ext_key) {
        // 复用外部已派生密钥：跳过昂贵的 Argon2 KDF（用于加密后自校验）
        memcpy(key,ext_key,ARGON2_OUTPUT_LEN);
    }
    else if(!derive_key(password,salt_ptr,key,kdf_ops,kdf_mem)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    }
    if(sodium_mlock(key,sizeof(key))==0) {
        key_locked=true;
    }
    else {
        if(!silent) fprintf(stderr,"Warning: could not lock key memory (possible performance/security impact).\n");
    }
    derive_progress_auth_key(key,auth_key);

    // AAD 必须严格复刻加密时的构造：v3 不含末尾 32 字节明文哈希
    size_t aad_hdr_len=hdr_size - (ver==VERSION?HASH_SIZE:0);
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
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key);
            if(rc!=0&&!silent) fprintf(stderr,"AES-GCM decryption failed at chunk %u (wrong password or corrupted)\n",i);
        }
        else if(mode==CryptoMode::AEGIS256) {
            rc=crypto_aead_aegis256_decrypt(plaintext_chunk.data(),&plaintext_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key);
            if(rc!=0&&!silent) fprintf(stderr,"AEGIS-256 decryption failed at chunk %u (wrong password or corrupted)\n",i);
        }
        else {
            rc=crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext_chunk.data(),&plaintext_len,NULL,
                ciphertext_chunk.data(),expected_cipher_len,aad.data(),aad.size(),nonce,key);
            if(rc!=0&&!silent) fprintf(stderr,"XChaCha20 decryption failed at chunk %u (wrong password or corrupted)\n",i);
        }
        if(rc!=0) { ok=false; break; }

        if(!fout.write(reinterpret_cast<const char*>(plaintext_chunk.data()),plaintext_len)) {
            if(!silent) fprintf(stderr,"Write plaintext chunk %u failed\n",i);
            ok=false;
            break;
        }
        if(have_hash) crypto_generichash_update(&hstate,plaintext_chunk.data(),plaintext_len);

        processed_bytes+=plaintext_len;
        fout.flush();   // 先落盘再记账进度（带 HMAC），确保磁盘内容永远不落后于 .progress
        if(!save_progress(out_path,i+1,processed_bytes,auth_key)) {
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
        if(ok && memcmp(final_hash,stored_hash,HASH_SIZE)!=0) {
            if(!silent) fprintf(stderr,"Plaintext integrity check failed: recovered data does not match original.\n");
            ok=false;
        }
    }

dec_cleanup:
    if(key_locked) sodium_munlock(key,sizeof(key));
    sodium_memzero(key,sizeof(key));
    sodium_memzero(auth_key,sizeof(auth_key));
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

static void collect_files_from_dir(const std::string& dir,std::vector<std::string>& out_files) {
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
            collect_files_from_dir(full,out_files);
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
                collect_files_from_dir(full,out_files);
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
        // 但当存在多个输入根目录时（input_paths.size()>1），即使是解密也附加根目录名前缀，
        // 否则 dirA/x 与 dirB/x 会映射到同一输出路径，多线程并行时第二个线程被跨进程锁判为
        // “locked”，既混乱又误导（Issue: 批量解密多 -i 输出碰撞）。
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
    const std::vector<char>& password,
    CryptoMode mode,
    bool encrypt,
    bool delete_source,
    bool force_overwrite,
    int num_threads) {
    // 批量模式 AEGIS-256 可用性回退：缺 AES-NI 时自动切换到 XChaCha20
    if(encrypt&&mode==CryptoMode::AEGIS256&&!aegis256_supported()) {
        if(g_aegis_fallback_choice.load()==0) {
            std::cout<<"Warning: AEGIS-256 is not available on this CPU (AES-NI required).\n"
                <<"Do you want to switch to XChaCha20 (secure) for all files? (y/N): ";
            char ch;
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
    if(out_dir_clean.size()==2&&isalpha(out_dir_clean[0])&&out_dir_clean[1]==':') {
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
        // 批量解密只处理 .ptd 文件，与单文件 -d 强制 .ptd 保持一致：
        // 否则目录里的 readme.txt / data.txt 等非密文文件会被逐个尝试解密，
        // magic 校验失败后再安全返回，但它们全部计入 “Decryption errors” 误导用户；
        // 极端情况下，任何恰好以 FENC 开头且结构巧合的文件会被误当密文处理。
        std::vector<std::string> filtered;
        size_t skipped=0;
        for(const auto& f:all_files) {
            std::string lower=f;
            std::transform(lower.begin(),lower.end(),lower.begin(),::tolower);
            if(lower.size()>=4&&lower.compare(lower.size()-4,4,".ptd")==0) {
                filtered.push_back(f);
            } else {
                ++skipped;
            }
        }
        all_files=std::move(filtered);
        if(skipped>0) {
            fprintf(stderr,"Skipped %zu non-.ptd file(s) in batch decrypt.\n",skipped);
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

    printf("Total files: %zu, Total size: %.2f MiB\n",all_files.size(),total_bytes/1048576.0);

    if(num_threads<=0) {
        num_threads=std::thread::hardware_concurrency();
        if(num_threads<=0) num_threads=4;
    }
    printf("Using %d thread(s)\n",num_threads);

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
            out_path+=".ptd";
        }
        else {
            if(out_path.size()>=4&&
                (out_path.substr(out_path.size()-4)==".ptd"||
                    out_path.substr(out_path.size()-4)==".PTD")) {
                out_path=out_path.substr(0,out_path.size()-4);
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
                out_path+=".ptd";
            }
            else {
                if(out_path.size()>=4&&
                    (out_path.substr(out_path.size()-4)==".ptd"||
                        out_path.substr(out_path.size()-4)==".PTD")) {
                    out_path=out_path.substr(0,out_path.size()-4);
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
            }
            else {
                all_ok=false;
                std::lock_guard<std::mutex> lock(error_mutex);
                error_files.push_back(in_path);
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

    if(global_processed<total_bytes) {
        global_processed=total_bytes;
    }
    print_progress(global_processed.load(),total_bytes,start_time,true);

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