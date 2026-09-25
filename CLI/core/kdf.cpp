#include "kdf.hpp"
#include "config.hpp"
#include <cstdio>
#include <vector>
#include <mutex>
#include <condition_variable>

namespace {

// 进程级 KDF 内存预算：并发进入 Argon2 前先取信号量许可，避免批量解密时
// N 线程同时跑大内存 Argon2 导致 OOM。预算 = max_memory_bytes / 128MB；
// max_memory_bytes==0 表示不限制（由线程数本身约束）。惰性初始化。
struct KdfSemaphore {
    std::mutex mtx;
    std::condition_variable cv;
    long permits = 0;   // 0 = 不限制
    bool init = false;
    void ensure() {
        std::lock_guard<std::mutex> lk(mtx);
        if(init) return;
        const uint64_t budget = global_config().max_memory_bytes;
        if(budget > 0) {
            long cap = (long)(budget / (128ULL*1024*1024));   // 以标准预设 128MB 为单份
            if(cap < 1) cap = 1;
            permits = cap;
        }
        init = true;
    }
    void acquire() {
        if(permits == 0) return;
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&]{ return permits > 0; });
        --permits;
    }
    void release() {
        if(permits == 0) return;
        { std::lock_guard<std::mutex> lk(mtx); ++permits; }
        cv.notify_one();
    }
};

KdfSemaphore g_kdf_sem;

} // namespace

void kdf_preset_params(int preset, unsigned int& ops, unsigned int& mem_kb) {
    switch(preset) {
        case 0:  ops=3; mem_kb=64*1024;   break;
        case 2:  ops=6; mem_kb=512*1024;  break;
        case 1:
        default: ops=ARGON2_OPS_DEFAULT; mem_kb=ARGON2_MEM_DEFAULT_KB; break;
    }
}

bool derive_key(const unsigned char* password, size_t pwd_len,
    const unsigned char* salt,
    unsigned char* key,
    unsigned int opslimit,
    size_t memlimit,
    size_t key_len) {
    // 参数超界说明文件头被篡改或伪造：直接拒绝（零资源消耗），不降级
    if(opslimit>KDF_OPS_LIMIT_MAX||memlimit>KDF_MEM_LIMIT_MAX_BYTES) {
        fprintf(stderr,
            "Refusing to process file: KDF parameters in the header are out of range "
            "(opslimit=%u > %u or memlimit=%llu > %llu bytes). "
            "The file is corrupt or deliberately crafted.\n",
            opslimit,KDF_OPS_LIMIT_MAX,
            (unsigned long long)memlimit,(unsigned long long)KDF_MEM_LIMIT_MAX_BYTES);
        return false;
    }
    // 头里可能填 0（伪造），补齐 crypto_pwhash 要求的下界
    if(memlimit<crypto_pwhash_MEMLIMIT_MIN) memlimit=crypto_pwhash_MEMLIMIT_MIN;
    if(opslimit<1) opslimit=1;
    g_kdf_sem.ensure();
    g_kdf_sem.acquire();
    int rc=crypto_pwhash(key,key_len,
        reinterpret_cast<const char*>(password),pwd_len,
        salt,
        opslimit,
        memlimit,
        crypto_pwhash_ALG_ARGON2ID13);
    g_kdf_sem.release();
    if(rc!=0) {
        fprintf(stderr,"crypto_pwhash failed\n");
        return false;
    }
    return true;
}

void derive_progress_auth_key(const unsigned char* master_key,
    unsigned char auth_key[crypto_auth_KEYBYTES]) {
    const char tag[]="FE_progress_auth_v3";
    std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
    in.insert(in.end(), master_key, master_key+ARGON2_OUTPUT_LEN);
    crypto_generichash(auth_key, crypto_auth_KEYBYTES, in.data(), in.size(), nullptr, 0);
}

void derive_header_auth_key(const unsigned char* master_key,
    unsigned char auth_key[HEADER_HMAC_SIZE]) {
    const char tag[]="FE_header_auth_v4";
    std::vector<unsigned char> in(tag, tag+sizeof(tag)-1);
    in.insert(in.end(), master_key, master_key+ARGON2_OUTPUT_LEN);
    crypto_generichash(auth_key, HEADER_HMAC_SIZE, in.data(), in.size(), nullptr, 0);
}
