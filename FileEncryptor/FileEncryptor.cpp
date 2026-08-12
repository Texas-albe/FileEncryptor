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
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <pwd.h>
#include <dirent.h>
#endif

// ---------- 常量 ----------
static constexpr size_t ARGON2_SALT_LEN=crypto_pwhash_SALTBYTES;
static constexpr size_t ARGON2_OUTPUT_LEN=32;
static constexpr unsigned int ARGON2_ITER=3;
static constexpr size_t ARGON2_MEM=crypto_pwhash_MEMLIMIT_INTERACTIVE;

static constexpr size_t AES_GCM_IV_LEN=crypto_aead_aes256gcm_NPUBBYTES;
static constexpr size_t XCHACHA20_IV_LEN=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t TAG_SIZE=16;
static constexpr size_t CHUNK_SIZE=1*1024*1024;
static constexpr size_t PASSWORD_MIN_LEN=6;

const unsigned char MAGIC[4]={'F','E','N','C'};
const unsigned char VERSION=1;

static std::atomic<int> g_aes_fallback_choice{0};

// 进度文件魔数 "PROG"
static const uint32_t PROGRESS_MAGIC=0x504F5247;
static const uint32_t PROGRESS_VERSION=1;

#pragma pack(push, 1)
struct FileHeader {
    unsigned char magic[4];
    unsigned char version;
    unsigned char mode;
    unsigned char salt[ARGON2_SALT_LEN];
    unsigned char iv_len;
    unsigned char iv[24];
};
#pragma pack(pop)
static constexpr size_t HEADER_SIZE=sizeof(FileHeader);

// 断点进度结构（带魔数和版本）
#pragma pack(push, 1)
struct ProgressInfo {
    uint32_t magic;
    uint32_t version;
    uint64_t processed_chunks;
    uint64_t processed_bytes;
};
#pragma pack(pop)

// ---------- 反调试 ----------
void anti_debug_check() {
#ifdef _WIN32
    if(IsDebuggerPresent()) {
        fprintf(stderr,"Debugger detected, exiting.\n");
        exit(1);
    }
#else
    if(ptrace(PTRACE_TRACEME,0,0,0)==-1) {
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

// ---------- 目录创建 ----------
bool create_directory_recursive(const std::string& path) {
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

// ---------- 密钥派生 ----------
static bool derive_key(const std::vector<char>& password,
    const unsigned char* salt,
    unsigned char* key,
    size_t key_len=ARGON2_OUTPUT_LEN) {
    if(crypto_pwhash(key,key_len,
        password.data(),password.size(),
        salt,
        ARGON2_ITER,
        ARGON2_MEM,
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
    return (memcmp(h.magic,MAGIC,4)==0&&h.version==VERSION);
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

// ---------- 加密（支持断点续传） ----------
bool encrypt_file(const std::string& in_path,
    const std::string& out_path,
    const std::vector<char>& password,
    CryptoMode mode,
    std::function<void(size_t,size_t)> progress_callback,
    bool resume) {

    disable_core_dump();

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

    // 计算块数，检测溢出
    uint32_t chunk_size=CHUNK_SIZE;
    uint64_t total_chunks_64=(total_size+chunk_size-1)/chunk_size;
    if(total_chunks_64>UINT32_MAX) {
        fprintf(stderr,"File too large: %llu chunks exceeds uint32_t limit (%u).\n",
            (unsigned long long)total_chunks_64,UINT32_MAX);
        return false;
    }
    uint32_t total_chunks=static_cast<uint32_t>(total_chunks_64);
    uint64_t orig_size=total_size;

    // 检查续传进度
    ProgressInfo prog_info={0, 0, 0, 0};
    bool has_progress=resume&&load_progress(out_path,prog_info);
    uint64_t start_chunk=has_progress ? prog_info.processed_chunks : 0;
    size_t start_bytes=has_progress ? (size_t)prog_info.processed_bytes : 0;

    // 打开输出文件（追加或截断）
    std::ios::openmode mode_out=std::ios::binary;
    if(has_progress&&start_chunk>0) {
        mode_out|=std::ios::app;
    }
    else {
        mode_out|=std::ios::trunc;
        remove_progress(out_path);
    }

    std::ofstream fout;
    if(!open_stream(fout,out_path,mode_out)) {
        fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
        return false;
    }

    // 如果续传且已经写过头部，直接跳到写数据；否则写入头
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
    size_t processed_bytes=start_bytes;

    if(mode==CryptoMode::AES_GCM&&!crypto_aead_aes256gcm_is_available()) {
        fprintf(stderr,"[!]AES-GCM not hardware accelerated on this CPU.\n");
    }

    if(!header_written) {
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
        if(sodium_mlock(key,sizeof(key))==0) {
            key_locked=true;
        }
        else {
            fprintf(stderr,"[!]Could not lock key memory (possible performance/security impact).\n");
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
        // 续传：读取已有的头和元数据，并与计算值比较
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
        if(!derive_key(password,header.salt,key)) {
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
        std::remove(out_path.c_str());
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

    if(file_size<(std::streampos)(HEADER_SIZE+4+4+8)) {
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

    if(chunk_size!=CHUNK_SIZE) {
        if(!silent) {
            fprintf(stderr,"Invalid chunk_size: %u (expected %zu). File may be corrupted.\n",
                chunk_size,CHUNK_SIZE);
        }
        return false;
    }
    if(chunk_size>64*1024*1024||chunk_size<1024) {
        if(!silent) fprintf(stderr,"Invalid chunk_size: %u (out of range)\n",chunk_size);
        return false;
    }

    size_t total_size=static_cast<size_t>(orig_size);
    if(total_chunks==0) {
        if((size_t)file_size!=HEADER_SIZE+4+4+8) {
            if(!silent) fprintf(stderr,"File size mismatch for empty file.\n");
            return false;
        }
        std::ofstream fout;
        if(!open_stream(fout,out_path,std::ios::binary)) {
            if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
            return false;
        }
        fout.close();
        remove_progress(out_path);
        return true;
    }

    size_t expected_size=HEADER_SIZE+4+4+8+
        (size_t)total_chunks*((size_t)chunk_size+TAG_SIZE);
    if((size_t)file_size!=expected_size) {
        if(!silent) {
            fprintf(stderr,"File size mismatch: expected %zu, got %zu. File corrupted.\n",
                expected_size,(size_t)file_size);
        }
        return false;
    }

    ProgressInfo prog_info={0, 0, 0, 0};
    bool has_progress=resume&&load_progress(out_path,prog_info);
    uint64_t start_chunk=has_progress ? prog_info.processed_chunks : 0;
    size_t start_bytes=has_progress ? (size_t)prog_info.processed_bytes : 0;

    std::ios::openmode mode_out=std::ios::binary;
    if(has_progress&&start_chunk>0) {
        mode_out|=std::ios::app;
    }
    else {
        mode_out|=std::ios::trunc;
        remove_progress(out_path);
    }

    std::ofstream fout;
    if(!open_stream(fout,out_path,mode_out)) {
        if(!silent) fprintf(stderr,"Cannot create output file: %s\n",out_path.c_str());
        return false;
    }

    unsigned char key[ARGON2_OUTPUT_LEN]={0};
    bool key_locked=false;
    if(!derive_key(password,header.salt,key)) {
        if(!silent) fprintf(stderr,"Key derivation failed\n");
        return false;
    }
    if(sodium_mlock(key,sizeof(key))==0) {
        key_locked=true;
    }
    else {
        if(!silent) fprintf(stderr,"[!]Could not lock key memory (possible performance/security impact).\n");
    }

    auto aad=build_aad_with_metadata(header,chunk_size,total_chunks,orig_size);

    auto start_time=std::chrono::steady_clock::now();
    std::vector<unsigned char> ciphertext_chunk(chunk_size+TAG_SIZE);
    std::vector<unsigned char> plaintext_chunk(chunk_size);
    unsigned char nonce[24]={0};
    bool ok=true;
    size_t processed_bytes=start_bytes;

    size_t input_offset=HEADER_SIZE+4+4+8+(size_t)start_chunk*(chunk_size+TAG_SIZE);
    fin.seekg(input_offset,std::ios::beg);

    for(uint32_t i=static_cast<uint32_t>(start_chunk); i<total_chunks; ++i) {
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

// ---------- 目录遍历 ----------
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

// ---------- 批量处理（支持并行） ----------
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
            std::cout<<"[!]AES-GCM is not hardware accelerated on this CPU.\n"
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

    // 清理输出目录
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
        struct stat st;
        if(stat(f.c_str(),&st)==0) {
            total_bytes+=st.st_size;
        }
    }

    printf("Total files: %zu, Total size: %.2f MiB\n",all_files.size(),total_bytes/1048576.0);

    if(num_threads<=0) {
        num_threads=std::thread::hardware_concurrency();
        if(num_threads<=0) num_threads=4;
    }
    printf("Using %d thread(s)\n",num_threads);

    // 构建待处理文件列表，增强覆盖检查
    std::vector<std::string> files_to_process;
    for(const auto& in_path:all_files) {
        std::string out_path;
        // 计算输出路径（与 worker 中逻辑保持一致）
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
                size_t root_pos=best_root.find_last_of("/\\");
                std::string root_name=(root_pos!=std::string::npos) ?
                    best_root.substr(root_pos+1) : best_root;
                if(!root_name.empty()) {
                    out_path+=root_name+"/";
                }
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
            if(out_path.size()>=4&&
                (out_path.substr(out_path.size()-4)==".ptd"||
                    out_path.substr(out_path.size()-4)==".PTD")) {
                out_path=out_path.substr(0,out_path.size()-4);
            }
        }

        // 创建输出子目录
        size_t dirpos=out_path.find_last_of("/\\");
        if(dirpos!=std::string::npos) {
            std::string out_subdir=out_path.substr(0,dirpos);
            create_directory_recursive(out_subdir);
        }

        // 覆盖检查增强：若文件存在，但头部无效，则视为损坏，强制覆盖
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
                    // 文件损坏，自动覆盖（不询问）
                    fprintf(stderr,"Existing file %s is corrupted, will overwrite.\n",out_path.c_str());
                }
                else {
                    // 有效文件，跳过（除非用户用 -y）
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

    // 并行处理
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

            // 计算输出路径（与上面相同）
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
                    size_t root_pos=best_root.find_last_of("/\\");
                    std::string root_name=(root_pos!=std::string::npos) ?
                        best_root.substr(root_pos+1) : best_root;
                    if(!root_name.empty()) {
                        out_path+=root_name+"/";
                    }
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
                if(out_path.size()>=4&&
                    (out_path.substr(out_path.size()-4)==".ptd"||
                        out_path.substr(out_path.size()-4)==".PTD")) {
                    out_path=out_path.substr(0,out_path.size()-4);
                }
            }

            size_t last_file_processed=0;
            auto file_progress_callback=[&](size_t file_processed,size_t file_total) {
                size_t increment=file_processed-last_file_processed;
                last_file_processed=file_processed;
                global_processed+=increment;
                };

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
                // 若加密成功但删除失败，则整体返回 false
                if(ok&&delete_source) {
                    if(std::remove(in_path.c_str())!=0) {
                        std::lock_guard<std::mutex> lock(error_mutex);
                        std::cerr<<"Error: could not delete source file: "<<in_path<<"\n";
                        ok=false;  // 删除失败视为整体失败
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

            // 补加最后一部分进度（若文件处理完成但回调未覆盖全量）
            struct stat st;
            if(stat(in_path.c_str(),&st)==0) {
                size_t file_size=st.st_size;
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