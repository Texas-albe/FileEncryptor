#define _CRT_SECURE_NO_WARNINGS
#include "FileEncryptor.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
#endif

// ---------- 常量 ----------
static constexpr size_t ARGON2_SALT_LEN=crypto_pwhash_SALTBYTES;
static constexpr size_t ARGON2_OUTPUT_LEN=32;

// Argon2id 参数：旧格式（v1）写死为交互档，新格式（v2）把参数存入文件头以便未来增强且兼容旧文件。
// 新文件默认提升到 moderate 档（4 次迭代 / 128MiB），比交互档更适合静态/长期加密。
static constexpr unsigned int ARGON2_OPS_LEGACY=3;
static constexpr unsigned int ARGON2_MEM_LEGACY_KB=(unsigned int)(crypto_pwhash_MEMLIMIT_INTERACTIVE/1024);
static constexpr unsigned int ARGON2_OPS_DEFAULT=4;
static constexpr unsigned int ARGON2_MEM_DEFAULT_KB=128*1024;

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;
static constexpr size_t XCHACHA20_IV_LEN=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t TAG_SIZE=16;
static constexpr size_t CHUNK_SIZE=1*1024*1024;
static constexpr size_t PASSWORD_MIN_LEN=6;

const unsigned char MAGIC[4]={'F','E','N','C'};
const unsigned char VERSION=2;

static std::atomic<int> g_aes_fallback_choice{0};

static const uint32_t PROGRESS_MAGIC=0x504F5247;
static const uint32_t PROGRESS_VERSION=1;

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
static constexpr size_t HEADER_SIZE=sizeof(FileHeader);

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

// 断点进度结构（带魔数和版本）
#pragma pack(push, 1)
struct ProgressInfo {
    uint32_t magic;
    uint32_t version;
    uint64_t processed_chunks;
    uint64_t processed_bytes;
};
#pragma pack(pop)

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

static bool acquire_output_lock(const std::string& out_path,std::string& lock_path) {
    lock_path=out_path+".lock";
#ifdef _WIN32
    std::wstring w=utf8_to_wstring(lock_path);
    HANDLE h=CreateFileW(w.c_str(),GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h!=INVALID_HANDLE_VALUE) {
        DWORD pid=GetCurrentProcessId(),wr;
        WriteFile(h,&pid,sizeof(pid),&wr,NULL);
        CloseHandle(h);
        return true;
    }
    // 已存在：若持有者进程已退出则回收失效锁
    h=CreateFileW(w.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(h!=INVALID_HANDLE_VALUE) {
        DWORD pid=0,rd=0;
        ReadFile(h,&pid,sizeof(pid),&rd,NULL);
        CloseHandle(h);
        if(rd==sizeof(pid)&&!process_alive_pid((int)pid)) {
            DeleteFileW(w.c_str());
            h=CreateFileW(w.c_str(),GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
            if(h!=INVALID_HANDLE_VALUE) {
                DWORD p2=GetCurrentProcessId(),wr;
                WriteFile(h,&p2,sizeof(p2),&wr,NULL);
                CloseHandle(h);
                return true;
            }
        }
    }
    return false;
#else
    int fd=open(lock_path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd>=0) {
        int pid=getpid();
        write(fd,&pid,sizeof(pid));
        close(fd);
        return true;
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
                write(fd,&p2,sizeof(p2));
                close(fd);
                stolen=true;
            }
        }
        else {
            close(fd);
        }
        if(stolen) return true;
    }
    return false;
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
    // 注意：在缺少 ptrace 权限的环境（容器/沙箱）下 ptrace 会失败，
    // 但这并不等于“被调试”。仅当“已被其它 tracer 占用”(EBUSY) 时才视为被调试，
    // 避免在普通受限环境中误退出（此前会因权限不足直接 exit(1)）。
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

// ---------- AAD 构建（包含元数据） ----------
static std::vector<unsigned char> build_aad_with_metadata(
    const FileHeader& h,
    uint32_t chunk_size,
    uint32_t total_chunks,
    uint64_t orig_size) {
    std::vector<unsigned char> aad;
    const unsigned char* ptr=reinterpret_cast<const unsigned char*>(&h);
    aad.insert(aad.end(),ptr,ptr+HEADER_SIZE);

    for(int i=0; i<4; ++i) aad.push_back((chunk_size>>(i*8))&0xFF);
    for(int i=0; i<4; ++i) aad.push_back((total_chunks>>(i*8))&0xFF);
    for(int i=0; i<8; ++i) aad.push_back((orig_size>>(i*8))&0xFF);
    return aad;
}

// ---------- 文件有效性检查 ----------
static bool is_file_valid(const std::string& path) {
    std::ifstream f;
    if(!open_stream(f,path,std::ios::binary)) return false;
    FileHeader h;
    f.read(reinterpret_cast<char*>(&h),HEADER_SIZE);
    if(f.gcount()!=HEADER_SIZE) return false;
    return (memcmp(h.magic,MAGIC,4)==0&&(h.version==VERSION||h.version==1));
}

// ---------- 进度 ----------
static bool load_progress(const std::string& out_path,ProgressInfo& info) {
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

static bool save_progress(const std::string& out_path,const ProgressInfo& info) {
    std::string prog_path=out_path+".progress";
    std::string temp_prog=prog_path+".tmp";
    std::remove(temp_prog.c_str()); // 清除可能残留的临时进度文件
    std::ofstream f;
    if(!open_stream(f,temp_prog,std::ios::binary|std::ios::trunc)) return false;
    f.write(reinterpret_cast<const char*>(&info),sizeof(info));
    if(!f.good()) {
        f.close();
        std::remove(temp_prog.c_str());
        return false;
    }
    f.close();
    if(std::rename(temp_prog.c_str(),prog_path.c_str())!=0) {
        std::remove(temp_prog.c_str());
        return false;
    }
    return true;
}

static void remove_progress(const std::string& out_path) {
    std::string prog_path=out_path+".progress";
    std::remove(prog_path.c_str());
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

    ProgressInfo prog_info={0, 0, 0, 0};
    bool has_progress=resume&&load_progress(out_path,prog_info);
    if(has_progress&&(prog_info.processed_chunks>total_chunks||prog_info.processed_bytes>total_size)) {
        // 进度文件损坏（断点超出文件范围），放弃续传，从头重写
        fprintf(stderr,"Corrupted progress file detected, restarting from beginning.\n");
        has_progress=false;
        prog_info={0,0,0,0};
    }
    uint64_t start_chunk=has_progress ? prog_info.processed_chunks : 0;
    uint64_t start_bytes=has_progress ? prog_info.processed_bytes : 0;

    uint64_t trunc_pos=(uint64_t)HEADER_SIZE+4+4+8+(uint64_t)start_chunk*(chunk_size+TAG_SIZE);

    // 跨进程锁：在打开/截断输出之前获取，防止两个进程同时写同一输出导致损坏（N-2）
    std::string lock_path;
    if(!acquire_output_lock(out_path,lock_path)) {
        fprintf(stderr,"Output file is locked by another process: %s\n",out_path.c_str());
        return false;
    }
    OutputLockGuard lock_guard{lock_path,true};

    // 防符号链接劫持：若输出文件已存在且为符号链接/重解析点，拒绝写入，避免清空被指向的任意文件
    if(path_is_symlink(out_path)) {
        fprintf(stderr,"Refusing to write through existing symlink: %s\n",out_path.c_str());
        return false;
    }

    std::fstream fout;
    if(has_progress&&start_chunk>0) {
        // 续传：先丢弃中断瞬间落盘但未记账的密文残片，再从断点继续写入
        truncate_file(out_path,trunc_pos);
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

    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    FileHeader header={};
    bool ok=true;
    size_t iv_len=(mode==CryptoMode::AES_GCM) ? AES_GCM_IV_LEN : XCHACHA20_IV_LEN;
    std::vector<unsigned char> aad;
    std::vector<unsigned char> plaintext_chunk(CHUNK_SIZE);
    std::vector<unsigned char> ciphertext_chunk(CHUNK_SIZE+TAG_SIZE);
    unsigned char nonce[24]={0};
    uint64_t processed_bytes=start_bytes;

    if(mode==CryptoMode::AES_GCM&&!crypto_aead_aes256gcm_is_available()) {
        fprintf(stderr,"Warning: AES-GCM not hardware accelerated on this CPU.\n");
    }

    if(!header_written) {
        memcpy(header.magic,MAGIC,4);
        header.version=VERSION;
        header.mode=static_cast<unsigned char>(mode);
        header.iv_len=static_cast<unsigned char>(iv_len);
        header.opslimit=ARGON2_OPS_DEFAULT;
        header.memlimit_kb=ARGON2_MEM_DEFAULT_KB;

        randombytes_buf(header.salt,ARGON2_SALT_LEN);
        randombytes_buf(header.iv,iv_len);

        if(!derive_key(password,header.salt,key,header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false;
            goto cleanup;
        }
        if(sodium_mlock(key,sizeof(key))==0) {
            key_locked=true;
        }
        else {
            fprintf(stderr,"Warning: could not lock key memory (possible performance/security impact).\n");
        }

        aad=build_aad_with_metadata(header,chunk_size,total_chunks,orig_size);

        if(!fout.write(reinterpret_cast<const char*>(&header),HEADER_SIZE)) {
            fprintf(stderr,"Write header failed\n");
            ok=false;
            goto cleanup;
        }
        if(!fout.write(reinterpret_cast<const char*>(&chunk_size),4)||
            !fout.write(reinterpret_cast<const char*>(&total_chunks),4)||
            !fout.write(reinterpret_cast<const char*>(&orig_size),8)) {
            fprintf(stderr,"Write metadata failed\n");
            ok=false;
            goto cleanup;
        }
    }
    else {
        std::ifstream fin_out;
        if(!open_stream(fin_out,out_path,std::ios::binary)) {
            fprintf(stderr,"Cannot open existing output file for header read\n");
            ok=false;
            goto cleanup;
        }
        fin_out.read(reinterpret_cast<char*>(&header),HEADER_SIZE);
        if(fin_out.gcount()!=HEADER_SIZE) {
            fprintf(stderr,"Failed to read header from existing file\n");
            ok=false;
            goto cleanup;
        }
        uint32_t tmp_chunk_size,tmp_total_chunks;
        uint64_t tmp_orig_size;
        fin_out.seekg(HEADER_SIZE,std::ios::beg);
        fin_out.read(reinterpret_cast<char*>(&tmp_chunk_size),4);
        fin_out.read(reinterpret_cast<char*>(&tmp_total_chunks),4);
        fin_out.read(reinterpret_cast<char*>(&tmp_orig_size),8);
        fin_out.close();
        if(tmp_chunk_size!=CHUNK_SIZE||tmp_total_chunks!=total_chunks||tmp_orig_size!=orig_size) {
            fprintf(stderr,"Metadata mismatch: file may be corrupted\n");
            ok=false;
            goto cleanup;
        }
        iv_len=header.iv_len;
        if(!derive_key(password,header.salt,key,header.opslimit,(size_t)header.memlimit_kb*1024)) {
            ok=false;
            goto cleanup;
        }
        if(sodium_mlock(key,sizeof(key))==0) {
            key_locked=true;
        }
        aad=build_aad_with_metadata(header,chunk_size,total_chunks,orig_size);
    }

    if(start_bytes>0) {
        fin.seekg(start_bytes,std::ios::beg);
    }

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
        if(processed_bytes>=total_size) break;
        size_t chunk_len=std::min<size_t>(chunk_size,(size_t)(total_size-processed_bytes));
        fin.read(reinterpret_cast<char*>(plaintext_chunk.data()),chunk_len);
        if(fin.gcount()!=(std::streamsize)chunk_len) {
            fprintf(stderr,"Read error at chunk %u\n",i);
            ok=false;
            break;
        }

        memcpy(nonce,header.iv,iv_len);
        uint64_t idx=i;
        for(int j=0; j<8&&j<(int)iv_len; ++j) {
            nonce[iv_len-1-j]^=(unsigned char)((idx>>(j*8))&0xFF);
        }

        unsigned long long ciphertext_len=0;
        if(mode==CryptoMode::AES_GCM) {
            if(crypto_aead_aes256gcm_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,
                aad.data(),aad.size(),
                NULL,nonce,key)!=0) {
                fprintf(stderr,"AES-GCM encryption failed at chunk %u\n",i);
                ok=false;
                break;
            }
        }
        else {
            if(crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_chunk.data(),&ciphertext_len,
                plaintext_chunk.data(),chunk_len,
                aad.data(),aad.size(),
                NULL,nonce,key)!=0) {
                fprintf(stderr,"XChaCha20 encryption failed at chunk %u\n",i);
                ok=false;
                break;
            }
        }

        if(!fout.write(reinterpret_cast<const char*>(ciphertext_chunk.data()),ciphertext_len)) {
            fprintf(stderr,"Write ciphertext failed at chunk %u\n",i);
            ok=false;
            break;
        }

        processed_bytes+=chunk_len;
        fout.flush();   // 先落盘再记账进度，确保磁盘内容永远不落后于 .progress
        ProgressInfo new_info={PROGRESS_MAGIC, PROGRESS_VERSION, i+1, processed_bytes};
        save_progress(out_path,new_info);

        if(progress_callback) {
            progress_callback(processed_bytes,total_size);
        }
        else {
            print_progress(processed_bytes,total_size,start_time);
        }
    }

cleanup:
    if(key_locked) sodium_munlock(key,sizeof(key));
    sodium_memzero(key,sizeof(key));
    secure_clear(plaintext_chunk);
    secure_clear(ciphertext_chunk);

    fin.close();
    if(fout.is_open()) {
        fout.flush();
        fout.close();
    }

    if(ok) {
        remove_progress(out_path);
        if(!progress_callback) {
            print_progress(total_size,total_size,start_time,true);
        }
    }
    else {
        remove_file_utf8(out_path);
        remove_progress(out_path);
        fprintf(stderr,"Encryption failed, output removed.\n");
    }
    return ok;
}

// ---------- 解密 ----------
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::vector<char>& password,
    std::function<void(size_t,size_t)> progress_callback,
    bool silent,
    bool resume) {
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
    unsigned char hdrbuf[64];
    size_t hdr_size=0;
    unsigned int kdf_ops=ARGON2_OPS_LEGACY;
    size_t kdf_mem=(size_t)ARGON2_MEM_LEGACY_KB*1024;
    CryptoMode mode=CryptoMode::AES_GCM;
    size_t iv_len=0;
    const unsigned char* salt_ptr=nullptr;
    const unsigned char* iv_ptr=nullptr;

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
    else if(ver==VERSION) {
        hdr_size=HEADER_SIZE;
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
    else {
        if(!silent) fprintf(stderr,"Unsupported file version: %u\n",ver);
        return false;
    }

    // 严格校验加密模式：仅允许已知枚举值，未知值直接拒绝（否则后续的 IV 长度校验会被整体短路跳过）
    if(mode!=CryptoMode::AES_GCM&&mode!=CryptoMode::XCHACHA20) {
        if(!silent) fprintf(stderr,"Invalid encryption mode in header\n");
        return false;
    }
    // 兜底：IV 长度不得超过缓冲区，防止后续 memcpy(nonce, iv_ptr, iv_len) 越界读取
    if(iv_len>24) {
        if(!silent) fprintf(stderr,"Invalid IV length (too large)\n");
        return false;
    }
    if((mode==CryptoMode::AES_GCM&&iv_len!=AES_GCM_IV_LEN)||
        (mode==CryptoMode::XCHACHA20&&iv_len!=XCHACHA20_IV_LEN)) {
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
    if(!acquire_output_lock(out_path,lock_path)) {
        if(!silent) fprintf(stderr,"Output file is locked by another process: %s\n",out_path.c_str());
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
        return true;
    }

    uint64_t last_chunk_len=orig_size-(uint64_t)(total_chunks-1)*chunk_size;
    uint64_t expected_size=(uint64_t)hdr_size+4+4+8
        +(uint64_t)(total_chunks-1)*(uint64_t)(chunk_size+TAG_SIZE)
        +(uint64_t)last_chunk_len+TAG_SIZE;
    if((uint64_t)file_size!=expected_size) {
        if(!silent) {
            fprintf(stderr,"File size mismatch: expected %llu, got %llu. File corrupted.\n",
                (unsigned long long)expected_size,(unsigned long long)file_size);
        }
        return false;
    }

    ProgressInfo prog_info={0, 0, 0, 0};
    // 续传需要“进度文件”与“对应的 .part 半成品”同时齐备，否则视为全新开始
    bool has_progress=resume&&load_progress(out_path,prog_info)&&file_exists(part_path);
    if(has_progress&&(prog_info.processed_chunks>total_chunks||prog_info.processed_bytes>total_size)) {
        // 进度文件损坏（断点超出文件范围），放弃续传，从头重写
        fprintf(stderr,"Corrupted progress file detected, restarting from beginning.\n");
        has_progress=false;
        prog_info={0,0,0,0};
    }
    uint64_t start_chunk=has_progress ? prog_info.processed_chunks : 0;
    uint64_t start_bytes=has_progress ? prog_info.processed_bytes : 0;

    // 解密续传：明文半成品（.part）可能残留未完成块的残片，截断到已确认写入的明文长度
    std::fstream fout;
    if(has_progress&&start_chunk>0) {
        truncate_file(part_path,start_bytes);
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

    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    if(!derive_key(password,salt_ptr,key,kdf_ops,kdf_mem)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    }
    if(sodium_mlock(key,sizeof(key))==0) {
        key_locked=true;
    }
    else {
        if(!silent) fprintf(stderr,"Warning: could not lock key memory (possible performance/security impact).\n");
    }

    // AAD 必须严格复刻加密时的构造：原始文件头字节（v1=47 / v2=53）+ 元数据（chunk_size/total_chunks/orig_size）
    std::vector<unsigned char> aad;
    aad.insert(aad.end(),hdrbuf,hdrbuf+hdr_size);
    for(int i=0; i<4; ++i) aad.push_back((chunk_size>>(i*8))&0xFF);
    for(int i=0; i<4; ++i) aad.push_back((total_chunks>>(i*8))&0xFF);
    for(int i=0; i<8; ++i) aad.push_back((orig_size>>(i*8))&0xFF);

    auto start_time=std::chrono::steady_clock::now();
    std::vector<unsigned char> ciphertext_chunk(chunk_size+TAG_SIZE);
    std::vector<unsigned char> plaintext_chunk(chunk_size);
    unsigned char nonce[24]={0};
    bool ok=true;
    uint64_t processed_bytes=start_bytes;

    size_t input_offset=hdr_size+4+4+8+(size_t)start_chunk*(chunk_size+TAG_SIZE);
    fin.seekg(input_offset,std::ios::beg);

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
        if(processed_bytes>=total_size) break;
        size_t chunk_len=std::min<size_t>(chunk_size,(size_t)(total_size-processed_bytes));
        size_t expected_cipher_len=chunk_len+TAG_SIZE;
        fin.read(reinterpret_cast<char*>(ciphertext_chunk.data()),expected_cipher_len);
        if(fin.gcount()!=(std::streamsize)expected_cipher_len) {
            if(!silent) fprintf(stderr,"Read ciphertext chunk %u failed\n",i);
            ok=false;
            break;
        }

        memcpy(nonce,iv_ptr,iv_len);
        uint64_t idx=i;
        for(int j=0; j<8&&j<(int)iv_len; ++j) {
            nonce[iv_len-1-j]^=(unsigned char)((idx>>(j*8))&0xFF);
        }

        unsigned long long plaintext_len=0;
        if(mode==CryptoMode::AES_GCM) {
            if(crypto_aead_aes256gcm_decrypt(plaintext_chunk.data(),&plaintext_len,
                NULL,
                ciphertext_chunk.data(),expected_cipher_len,
                aad.data(),aad.size(),
                nonce,key)!=0) {
                if(!silent) fprintf(stderr,"AES-GCM decryption failed at chunk %u (wrong password or corrupted)\n",i);
                ok=false;
                break;
            }
        }
        else {
            if(crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext_chunk.data(),&plaintext_len,
                NULL,
                ciphertext_chunk.data(),expected_cipher_len,
                aad.data(),aad.size(),
                nonce,key)!=0) {
                if(!silent) fprintf(stderr,"XChaCha20 decryption failed at chunk %u (wrong password or corrupted)\n",i);
                ok=false;
                break;
            }
        }

        if(!fout.write(reinterpret_cast<const char*>(plaintext_chunk.data()),plaintext_len)) {
            if(!silent) fprintf(stderr,"Write plaintext chunk %u failed\n",i);
            ok=false;
            break;
        }

        processed_bytes+=plaintext_len;
        fout.flush();   // 先落盘再记账进度，确保磁盘内容永远不落后于 .progress
        ProgressInfo new_info={PROGRESS_MAGIC, PROGRESS_VERSION, i+1, processed_bytes};
        save_progress(out_path,new_info);

        if(progress_callback) {
            progress_callback(processed_bytes,total_size);
        }
        else {
            print_progress(processed_bytes,total_size,start_time);
        }
    }

    if(key_locked) sodium_munlock(key,sizeof(key));
    sodium_memzero(key,sizeof(key));
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
    const std::vector<std::string>& input_paths) {
    std::string out_path=out_dir_clean+"/";
    std::string best_root;
    for(const auto& root:input_paths) {
        if(is_directory(root)&&in_path.find(root)==0) {
            if(root.length()>best_root.length()) best_root=root;
        }
    }
    if(!best_root.empty()) {
        size_t root_pos=best_root.find_last_of("/\\");
        std::string root_name=(root_pos!=std::string::npos) ? best_root.substr(root_pos+1) : best_root;
        if(!root_name.empty()) out_path+=root_name+"/";
        std::string suffix=in_path.substr(best_root.length());
        if(!suffix.empty()&&(suffix[0]=='/'||suffix[0]=='\\')) suffix.erase(0,1);
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
    // 批量模式 AES 回退询问
    if(encrypt&&mode==CryptoMode::AES_GCM&&!crypto_aead_aes256gcm_is_available()) {
        if(g_aes_fallback_choice.load()==0) {
            std::cout<<"Warning: AES-GCM is not hardware accelerated on this CPU.\n"
                <<"Do you want to switch to XChaCha20 (faster, secure) for all files? (y/N): ";
            char ch;
            std::cin>>ch;
            if(ch=='y'||ch=='Y') {
                g_aes_fallback_choice.store(1);
            }
            else {
                g_aes_fallback_choice.store(-1);
            }
        }
        if(g_aes_fallback_choice.load()==1) {
            mode=CryptoMode::XCHACHA20;
            fprintf(stderr,"Switched to XChaCha20 mode for this batch.\n");
        }
        else {
            fprintf(stderr,"Continuing with AES-GCM (software fallback, may be slow).\n");
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
            out_path=build_batch_out_path(in_path,out_dir_clean,input_paths);
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
                else {
                    skip=true;
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
                out_path=build_batch_out_path(in_path,out_dir_clean,input_paths);
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
                    if(std::remove(in_path.c_str())!=0) {
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

            int64_t fsize=get_file_size_utf8(in_path);
            if(fsize>=0) {
                size_t file_size=(size_t)fsize;
                if(last_file_processed<file_size) {
                    size_t remaining=file_size-last_file_processed;
                    global_processed+=remaining;
                    last_file_processed=file_size;
                }
            }

            if(!ok) {
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

    return all_ok.load();
}