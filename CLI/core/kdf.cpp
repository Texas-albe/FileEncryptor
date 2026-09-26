#include "kdf.hpp"
#include "config.hpp"
#include <cstdio>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace {

// 进程级 KDF 内存预算：并发进入 Argon2 前取信号量许可，避免批量解密 N 线程同时跑大内存
// Argon2 导致 OOM。预算 = max_memory_bytes/128MB；为 0 表示不限制。惰性初始化。
struct KdfSemaphore {
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<long> permits{0};   // 0 = 不限制（无锁快路径读，消除 data race）
    std::atomic<bool> init{false};
    void ensure() {
        if(init.load(std::memory_order_acquire)) return;   // 无锁快路径
        std::lock_guard<std::mutex> lk(mtx);
        if(init.load(std::memory_order_relaxed)) return;   // 双重检查
        const uint64_t budget = global_config().max_memory_bytes;
        long cap = 0;
        if(budget > 0) {
            cap = (long)(budget / (128ULL*1024*1024));   // 以标准预设 128MB 为单份
            if(cap < 1) cap = 1;
        }
        permits.store(cap, std::memory_order_relaxed);
        init.store(true, std::memory_order_release);
    }
    void acquire() {
        if(permits.load(std::memory_order_acquire) == 0) return;   // 无锁读，无 data race
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&]{ return permits.load(std::memory_order_relaxed) > 0; });
        permits.fetch_sub(1, std::memory_order_acq_rel);
    }
    void release() {
        if(permits.load(std::memory_order_acquire) == 0) return;
        permits.fetch_add(1, std::memory_order_acq_rel);
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
