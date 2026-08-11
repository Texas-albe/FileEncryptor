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

#ifdef _WIN32
#include <windows.h>
#include <debugapi.h>
#include <shlobj.h>
#include <direct.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <pwd.h>
#include <dirent.h>
#endif

// ---------- 常量 ----------
static constexpr size_t ARGON2_SALT_LEN=crypto_pwhash_SALTBYTES;   // 16
static constexpr size_t ARGON2_OUTPUT_LEN=32;
static constexpr unsigned int ARGON2_ITER=3;
static constexpr size_t ARGON2_MEM=crypto_pwhash_MEMLIMIT_INTERACTIVE;   // 约 64 MiB

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;   // 12
static constexpr size_t XCHACHA20_IV_LEN=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
static constexpr size_t TAG_SIZE=16;
static constexpr size_t CHUNK_SIZE=1*1024*1024;   // 1 MiB
static constexpr size_t PASSWORD_MIN_LEN=6;

const unsigned char MAGIC[4]={'F','E','N','C'};
const unsigned char VERSION=1;

#pragma pack(push, 1)
struct FileHeader {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;          // 0: AES-GCM, 1: XChaCha20
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[24];        // 最大 24 字节（XChaCha20 用满）
};
#pragma pack(pop)
static constexpr size_t HEADER_SIZE=sizeof(FileHeader);

// ---------- 反调试 ----------
void anti_debug_check() {
#ifdef _WIN32
    if(IsDebuggerPresent()) {
        fprintf(stderr,"Debugger detected, exiting.\n");
        exit(1);
    }
#else
    if(ptrace(PTRACE_TRACEME,0,1,0)==-1) {
        fprintf(stderr,"Debugger detected, exiting.\n");
        exit(1);
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

#ifdef _WIN32
static bool lock_memory(void* ptr,size_t len) { return VirtualLock(ptr,len)!=0; }
static void unlock_memory(void* ptr,size_t len) { VirtualUnlock(ptr,len); }
#else
static bool lock_memory(void* ptr,size_t len) { return mlock(ptr,len)==0; }
static void unlock_memory(void* ptr,size_t len) { munlock(ptr,len); }
#endif

// ---------- 密钥派生 ----------
static bool derive_key(const std::string& password,
    const unsigned char* salt,
    unsigned char* key,
    size_t key_len=ARGON2_OUTPUT_LEN) {
    if(crypto_pwhash(key,key_len,
        password.c_str(),password.size(),
        salt,
        ARGON2_ITER,
        ARGON2_MEM,
        crypto_pwhash_ALG_ARGON2ID13)!=0) {
        fprintf(stderr,"crypto_pwhash failed\n");
        return false;
    }
    return true;
}

static std::vector<unsigned char> build_aad(const FileHeader& h) {
    const unsigned char* ptr=reinterpret_cast<const unsigned char*>(&h);
    return std::vector<unsigned char>(ptr,ptr+HEADER_SIZE);
}

// ---------- 进度 ----------
static bool check_and_clean_progress(const std::string& out_path) {
    std::string progress_path=out_path+".progress";
    std::ifstream f(progress_path);
    if(f.good()) {
        f.close();
        std::remove(out_path.c_str());
        std::remove(progress_path.c_str());
        fprintf(stderr,"Detected incomplete previous run, restarting.\n");
        return true;
    }
    return false;
}

static bool create_progress(const std::string& out_path) {
    std::string progress_path=out_path+".progress";
    std::ofstream f(progress_path,std::ios::out|std::ios::trunc);
    if(!f) return false;
    f.close();
    return true;
}

static void remove_progress(const std::string& out_path) {
    std::string progress_path=out_path+".progress";
    std::remove(progress_path.c_str());
}

static void print_progress(size_t processed,size_t total,
    std::chrono::steady_clock::time_point start,
    bool finish=false) {
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
    const std::string& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback) {
    disable_core_dump();

    if(password.size()<PASSWORD_MIN_LEN) {
        fprintf(stderr,"Password too short (min %zu characters)\n",PASSWORD_MIN_LEN);
        return false;
    }

    check_and_clean_progress(out_path);

    std::ifstream fin(in_path,std::ios::binary);
    if(!fin) {
        fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }

    fin.seekg(0,std::ios::end);
    size_t total_size=static_cast<size_t>(fin.tellg());
    fin.seekg(0,std::ios::beg);
    auto start_time=std::chrono::steady_clock::now();

    std::ofstream fout(out_path,std::ios::binary);
    if(!fout) {
        fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
        return false;
    }

    if(!create_progress(out_path)) {
        fprintf(stderr,"Cannot create progress file\n");
        return false;
    }

    // 所有变量提前声明（避免 goto 跳过初始化）
    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    FileHeader header={};
    bool ok=true;
    size_t iv_len=(mode==CryptoMode::AES_GCM) ? AES_GCM_IV_LEN : XCHACHA20_IV_LEN;
    std::vector<unsigned char> aad;
    std::vector<unsigned char> plaintext_chunk(CHUNK_SIZE);
    std::vector<unsigned char> ciphertext_chunk(CHUNK_SIZE+TAG_SIZE);
    unsigned char nonce[24]={0};
    uint32_t chunk_size=CHUNK_SIZE;
    uint32_t total_chunks=0;
    size_t processed_bytes=0;
    uint64_t orig_size=0;

    if(mode==CryptoMode::AES_GCM&&!crypto_aead_aes256gcm_is_available()) {
        fprintf(stderr,"Warning: AES-GCM not hardware accelerated on this CPU.\n");
    }

    memcpy(header.magic,MAGIC,4);
    header.version=VERSION;
    header.mode=static_cast<unsigned char>(mode);
    header.iv_len=static_cast<unsigned char>(iv_len);

    randombytes_buf(header.salt,ARGON2_SALT_LEN);
    randombytes_buf(header.iv,iv_len);

    if(!derive_key(password,header.salt,key)) {
        ok=false;
        goto cleanup;
    }
    if(lock_memory(key,sizeof(key))) {
        key_locked=true;
    }

    aad=build_aad(header);

    // 写入头部
    if(!fout.write(reinterpret_cast<const char*>(&header),HEADER_SIZE)) {
        fprintf(stderr,"Write header failed\n");
        ok=false;
        goto cleanup;
    }

    // 写入块大小、总块数、原始大小
    total_chunks=static_cast<uint32_t>((total_size+chunk_size-1)/chunk_size);
    orig_size=total_size;
    if(!fout.write(reinterpret_cast<const char*>(&chunk_size),4)||
        !fout.write(reinterpret_cast<const char*>(&total_chunks),4)||
        !fout.write(reinterpret_cast<const char*>(&orig_size),8)) {
        fprintf(stderr,"Write metadata failed\n");
        ok=false;
        goto cleanup;
    }

    // 逐块加密并写入
    for(uint32_t i=0; i<total_chunks; ++i) {
        size_t chunk_len=std::min<size_t>(chunk_size,total_size-processed_bytes);
        fin.read(reinterpret_cast<char*>(plaintext_chunk.data()),chunk_len);
        if(fin.gcount()!=(std::streamsize)chunk_len) {
            fprintf(stderr,"Read error at chunk %u\n",i);
            ok=false;
            break;
        }

        memcpy(nonce,header.iv,iv_len);
        uint64_t idx_le=i;
        for(int j=0; j<8&&j<(int)iv_len; ++j) {
            nonce[iv_len-1-j]^=((unsigned char*)&idx_le)[j];
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
        if(progress_callback) {
            progress_callback(processed_bytes,total_size);
        }
        else {
            print_progress(processed_bytes,total_size,start_time);
        }
    }

cleanup:
    if(key_locked) unlock_memory(key,sizeof(key));
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
        std::remove(out_path.c_str());
        remove_progress(out_path);
        fprintf(stderr,"Encryption failed, output removed.\n");
    }
    return ok;
}

// ---------- 解密 ----------
bool decrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::string& password,
    std::function<void(size_t,size_t)> progress_callback,
    bool silent) {
    disable_core_dump();

    if(password.size()<PASSWORD_MIN_LEN) {
        if(!silent) fprintf(stderr,"Password too short (min %zu characters)\n",PASSWORD_MIN_LEN);
        return false;
    }

    check_and_clean_progress(out_path);

    std::ifstream fin(in_path,std::ios::binary);
    if(!fin) {
        if(!silent) fprintf(stderr,"Cannot open input file: %s\n",in_path.c_str());
        return false;
    }

    fin.seekg(0,std::ios::end);
    auto file_size=fin.tellg();
    fin.seekg(0,std::ios::beg);
    if(file_size<(std::streampos)(HEADER_SIZE+4+4+8+TAG_SIZE)) {
        if(!silent) fprintf(stderr,"File too small (corrupted?)\n");
        return false;
    }

    FileHeader header;
    if(!fin.read(reinterpret_cast<char*>(&header),HEADER_SIZE)) {
        if(!silent) fprintf(stderr,"Read header failed\n");
        return false;
    }
    if(memcmp(header.magic,MAGIC,4)!=0||header.version!=VERSION) {
        if(!silent) fprintf(stderr,"Invalid magic/version\n");
        return false;
    }
    CryptoMode mode=static_cast<CryptoMode>(header.mode);
    size_t iv_len=header.iv_len;
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

    size_t total_size=static_cast<size_t>(orig_size);

    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    if(!derive_key(password,header.salt,key)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    }
    if(lock_memory(key,sizeof(key))) {
        key_locked=true;
    }

    auto aad=build_aad(header);

    auto start_time=std::chrono::steady_clock::now();
    std::vector<unsigned char> ciphertext_chunk(chunk_size+TAG_SIZE);
    std::vector<unsigned char> plaintext_chunk(chunk_size);
    unsigned char nonce[24]={0};
    bool ok=true;
    size_t processed_bytes=0;

    std::ofstream fout(out_path,std::ios::binary);
    if(!fout) {
        if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
        if(key_locked) unlock_memory(key,sizeof(key));
        sodium_memzero(key,sizeof(key));
        return false;
    }

    if(!create_progress(out_path)) {
        if(!silent) fprintf(stderr,"Cannot create progress file\n");
        if(key_locked) unlock_memory(key,sizeof(key));
        sodium_memzero(key,sizeof(key));
        return false;
    }

    for(uint32_t i=0; i<total_chunks; ++i) {
        size_t chunk_len=std::min<size_t>(chunk_size,total_size-processed_bytes);
        size_t expected_cipher_len=chunk_len+TAG_SIZE;
        fin.read(reinterpret_cast<char*>(ciphertext_chunk.data()),expected_cipher_len);
        if(fin.gcount()!=(std::streamsize)expected_cipher_len) {
            if(!silent) fprintf(stderr,"Read ciphertext chunk %u failed\n",i);
            ok=false;
            break;
        }

        memcpy(nonce,header.iv,iv_len);
        uint64_t idx_le=i;
        for(int j=0; j<8&&j<(int)iv_len; ++j) {
            nonce[iv_len-1-j]^=((unsigned char*)&idx_le)[j];
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
        if(progress_callback) {
            progress_callback(processed_bytes,total_size);
        }
        else {
            print_progress(processed_bytes,total_size,start_time);
        }
    }

    if(key_locked) unlock_memory(key,sizeof(key));
    sodium_memzero(key,sizeof(key));
    secure_clear(ciphertext_chunk);
    secure_clear(plaintext_chunk);

    fin.close();
    fout.close();

    if(ok) {
        remove_progress(out_path);
        if(!progress_callback) {
            print_progress(total_size,total_size,start_time,true);
        }
    }
    else {
        std::remove(out_path.c_str());
        remove_progress(out_path);
        if(!silent) {
            fprintf(stderr,"Decryption failed, output removed.\n");
        }
    }
    return ok;
}

// ---------- 目录遍历与批量处理 ----------
#ifdef _WIN32
#include <io.h>
#else
#include <dirent.h>
#endif

static bool is_directory(const std::string& path) {
    struct stat st;
    if(stat(path.c_str(),&st)!=0) return false;
    return (st.st_mode&S_IFDIR)!=0;
}

static bool create_directory_recursive(const std::string& path) {
    if(path.empty()) return true;
    struct stat st;
    if(stat(path.c_str(),&st)==0) {
        return (st.st_mode&S_IFDIR)!=0;
    }
    size_t pos=path.find_last_of("/\\");
    if(pos!=std::string::npos) {
        if(!create_directory_recursive(path.substr(0,pos))) return false;
    }
#ifdef _WIN32
    return _mkdir(path.c_str())==0;
#else
    return mkdir(path.c_str(),0755)==0;
#endif
}

static void collect_files_from_dir(const std::string& dir,std::vector<std::string>& out_files) {
#ifdef _WIN32
    std::string pattern=dir+"\\*";
    struct _finddata_t fd;
    intptr_t handle=_findfirst(pattern.c_str(),&fd);
    if(handle==-1) return;
    do {
        if(strcmp(fd.name,".")==0||strcmp(fd.name,"..")==0) continue;
        std::string full=dir+"\\"+fd.name;
        if(fd.attrib&_A_SUBDIR) {
            collect_files_from_dir(full,out_files);
        }
        else {
            out_files.push_back(full);
        }
    } while(_findnext(handle,&fd)==0);
    _findclose(handle);
#else
    DIR* dp=opendir(dir.c_str());
    if(!dp) return;
    struct dirent* entry;
    while((entry=readdir(dp))!=nullptr) {
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0) continue;
        std::string full=dir+"/"+entry->d_name;
        struct stat st;
        if(stat(full.c_str(),&st)==0) {
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
bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const std::string& password,
    CryptoMode mode,
    bool encrypt,
    bool delete_source) {
    // 清理输出目录路径
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

    // 计算总大小
    size_t total_bytes=0;
    for(const auto& f:all_files) {
        struct stat st;
        if(stat(f.c_str(),&st)==0) {
            total_bytes+=st.st_size;
        }
    }

    printf("Total files: %zu, Total size: %.2f MiB\n",all_files.size(),total_bytes/1048576.0);

    size_t global_processed=0;
    auto start_time=std::chrono::steady_clock::now();

    bool all_ok=true;
    std::vector<std::string> error_files;

    for(size_t idx=0; idx<all_files.size(); ++idx) {
        const auto& in_path=all_files[idx];

        std::string out_path;
        if(!out_dir_clean.empty()) {
            out_path=out_dir_clean+"/";
            std::string best_root;
            for(const auto& root:input_paths) {
                if(is_directory(root)&&in_path.find(root)==0) {
                    if(root.length()>best_root.length()) {
                        best_root=root;
                    }
                }
            }
            if(!best_root.empty()) {
                std::string suffix=in_path.substr(best_root.length());
                if(!suffix.empty()&&(suffix[0]=='/'||suffix[0]=='\\'))
                    suffix.erase(0,1);
                out_path+=suffix;
            }
            else {
                size_t pos=in_path.find_last_of("/\\");
                std::string fname=(pos!=std::string::npos) ? in_path.substr(pos+1) : in_path;
                out_path+=fname;
            }
        }
        else {
            out_path=in_path;
        }

        if(encrypt) {
            out_path+=".ptd";
        }
        else {
            if(out_path.size()>=4&&out_path.substr(out_path.size()-4)==".ptd") {
                out_path=out_path.substr(0,out_path.size()-4);
            }
        }

        size_t dirpos=out_path.find_last_of("/\\");
        if(dirpos!=std::string::npos) {
            std::string out_subdir=out_path.substr(0,dirpos);
            create_directory_recursive(out_subdir);
        }

        size_t last_file_processed=0;
        auto file_progress_callback=[&](size_t file_processed,size_t file_total) {
            size_t increment=file_processed-last_file_processed;
            last_file_processed=file_processed;
            global_processed+=increment;
            print_progress(global_processed,total_bytes,start_time);
            };

        bool ok=false;
        if(encrypt) {
            ok=encrypt_file(in_path,out_path,password,mode,file_progress_callback);
            if(ok&&delete_source) {
                std::remove(in_path.c_str());
            }
        }
        else {
            ok=decrypt_file(in_path,out_path,password,file_progress_callback,true);
            if(!ok) {
                error_files.push_back(in_path);
            }
        }

        if(!ok) {
            all_ok=false;
        }
    }

    if(global_processed<total_bytes) {
        global_processed=total_bytes;
    }
    print_progress(global_processed,total_bytes,start_time,true);

    if(!encrypt&&!error_files.empty()) {
        fprintf(stderr,"\n--- Decryption errors (%zu files) ---\n",error_files.size());
        for(const auto& f:error_files) {
            fprintf(stderr,"  %s\n",f.c_str());
        }
        fprintf(stderr,"Total %zu files failed.\n",error_files.size());
    }

    return all_ok;
}