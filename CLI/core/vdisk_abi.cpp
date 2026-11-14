// libvdisk C ABI 实现
// VDISK_BUILD 由构建系统定义
#include "vdisk.h"
#include "FileEncryptor.hpp"   // random_read_ptd, SecureBuffer
#include "vault_index.hpp"     // VaultMeta/VaultEntry/vault_*
#include "ptd_meta.hpp"        // verify_ptd
#include "ptd_format.hpp"      // 头部布局
#include "fe_mobile.h"         // fe_m_decrypt_fd
#include "kdf.hpp"             // derive_key / kdf_preset_params
#include "config.hpp"          // global_config
#include "cipher.hpp"          // create_cipher
#include <sodium.h>
#include <algorithm>
#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <new>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <fstream>
#include <istream>
#include <ostream>
#include <streambuf>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <sys/statvfs.h>   // statvfs
#endif

namespace fs = std::filesystem;

// §4.1 KEK LRU
// 缓存
namespace {
constexpr size_t   LRU_MAX = 2048;   // 活跃 KEK 上限
constexpr uint64_t LRU_TTL_MS = 5ull * 60 * 1000;   // 5 分钟
}

struct KekEntry {
    SecureBuffer kek;          // 32B Argon2id
    uint64_t last_used_ms = 0;
};

// 目录枚举
struct DirChild {
    std::string name;
    uint64_t size = 0;
    uint64_t mtime = 0;
};

// 库内部状态
struct VDiskHandle {
    std::string library_dir;
    VaultMeta meta;
    bool unlocked = false;
    SecureBuffer passphrase;                 // 逐文件随机读用
    std::vector<VaultEntry> index;           // 解密
    std::vector<std::string> name_scratch;   // readdir name 存储
    // 索引派生缓存
    // readdir/getattr/stat_space 每次
    // 文件数大 + Explorer 滚动反
    std::unordered_map<std::string, size_t> index_map;          // rel_path → h->index 下标
    std::unordered_map<std::string, std::vector<DirChild>> dir_children; // 父目录
    std::unordered_map<std::string, uint64_t> dir_mtime;        // 目录 rel
    std::unordered_set<std::string> dir_set;                   // 目录 rel
    uint64_t index_used_bytes = 0;                             // 索引内文件明文
    uint64_t index_trash_bytes = 0;                            // 其中回收站保留
    uint64_t feindex_stamp_ms = 0;                             // 索引 mtime 轮询节流
    std::unordered_map<std::string, KekEntry> kek_cache;
    std::list<std::string> kek_lru;          // front =
    // salt 级 KEK 缓存
    // 按 salt
    // 决定性优化
    std::unordered_map<std::string, KekEntry> salt_kek_cache;
    std::list<std::string> salt_kek_lru;     // front =
    std::string mount_point;
    bool mounted = false;
    bool rw = false;          // M6 可写挂载标志
#ifdef _WIN32
    // M7
    // 经 Z
    std::unordered_map<std::string, void*> held_ptd;
#endif
    // M5 空闲超时自动锁
    // 批间 touch_activity 间隔超过超
    std::atomic<uint64_t> last_activity_ms{0};
    uint32_t idle_timeout_s = 0;
    // 索引变
    // 旧单 .feindex 回退
    uint64_t feindex_mtime = 0;
    uint64_t feindex_size = 0;
    bool     feindex_sharded = false;
    // M5 预读缓存
    bool     cache_on = false;
    uint64_t cache_cap_bytes = 0;
    uint32_t cache_ahead = 0;
    std::unordered_map<std::string, std::vector<unsigned char>> seg_cache;
    std::unordered_map<std::string, PtdReadSession*> ptd_sess;   // 非压缩读
    std::list<std::string> seg_lru;
    std::unordered_map<std::string, std::list<std::string>::iterator> seg_lru_pos;
    uint64_t seg_bytes = 0;
    // 跨批导入共享 KEK
    bool import_active = false;
    std::vector<unsigned char> import_salt;   // ARGON2_SALT_LEN
    SecureBuffer import_kek;                   // ARGON2_OUTPUT_LEN
    // WinFsp dispatcher 是多线程
    // lock/unlock/purge；index
    // 递归锁
    std::recursive_mutex mtx;
    // 索引损坏放行标
    // 用户可进库后点「
    bool index_damaged = false;
};

namespace {

// 虚拟路径 → 索引 rel_path；"" 表
std::string vpath_to_rel(const char* vpath) {
    std::string s = (vpath && *vpath) ? vpath : "/";
    for (char& c : s) if (c == '\\') c = '/';
    size_t i = 0; while (i < s.size() && s[i] == '/') i++;
    s = s.substr(i);
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

// 外部算法值 ↔ 内部
CryptoMode vd_mode_from_int(int m) {
    switch (m) {
        case VDISK_MODE_AEGIS256: return CryptoMode::AEGIS256;
        case VDISK_MODE_AES_GCM:  return CryptoMode::AES_GCM;
        case VDISK_MODE_SM4:      return CryptoMode::SM4;
        default:                  return CryptoMode::XCHACHA20;
    }
}
int vd_int_from_mode(CryptoMode m) {
    switch (m) {
        case CryptoMode::AEGIS256: return VDISK_MODE_AEGIS256;
        case CryptoMode::AES_GCM:  return VDISK_MODE_AES_GCM;
        case CryptoMode::SM4:      return VDISK_MODE_SM4;
        default:                   return VDISK_MODE_XCHACHA20;
    }
}
bool vd_mode_available(int m) {
    return create_cipher(vd_mode_from_int(m)) != nullptr;
}
CryptoMode vd_write_mode(VDiskHandle* h) {
    return vd_mode_from_int(h->meta.default_mode);
}
int vd_compress_level(VDiskHandle* h) {
    int p = h->meta.compress_policy;
    return (p == VDISK_COMPRESS_DEFAULT) ? VDISK_COMPRESS_AUTO : p;
}

// 取库内相对路径
// 库内路径用 '/' 分隔
static std::string rel_basename(const std::string& rel) {
    size_t p = rel.find_last_of('/');
    return (p == std::string::npos) ? rel : rel.substr(p + 1);
}

// Windows 语义大小写不敏
// WinFSP 驱动
// 精确匹配必然失
std::string ci_key(const std::string& s) {
    std::string k = s;
    for (char& c : k) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return k;
}
// a 前 b.size
bool ci_starts_with(const std::string& a, const std::string& b) {
    if (a.size() < b.size()) return false;
    for (size_t i = 0; i < b.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return false;
    }
    return true;
}
bool ci_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return false;
    }
    return true;
}

// 保留路径判定
// 回收站内部条目
// 时需要显式放行
bool rel_is_reserved(const std::string& rel) {
    size_t p = rel.find('/');
    std::string first = (p == std::string::npos) ? rel : rel.substr(0, p);
    return ci_equal(first, VDISK_RESERVED_TRASH);
}

// 大小写不敏感查
const VaultEntry* find_entry(const std::vector<VaultEntry>& idx, const std::string& rel) {
    for (const auto& e : idx) if (e.rel_path == rel) return &e;
    for (const auto& e : idx) if (ci_equal(e.rel_path, rel)) return &e;
    return nullptr;
}

bool is_dir(const std::vector<VaultEntry>& idx, const std::string& rel) {
    if (rel.empty()) return true;
    const VaultEntry* e = find_entry(idx, rel);
    if (e) return e->is_dir;   // 显式条目
    std::string pfx = rel + "/";
    for (const auto& x : idx) if (x.rel_path.size() > pfx.size() && ci_starts_with(x.rel_path, pfx)) return true;
    return false;
}

// 实际 .ptd 路径 / 随机存
std::string ptd_path_for(const std::string& library_dir, const std::string& rel, const std::string& store) {
    return vault_ptd_path(library_dir, rel, store);
}
std::string random_store_name() { return vault_random_store_name(); }

uint64_t now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// KEK LRU
// 文件级键 = ptd 路径
// salt 级键 = salt|KDF 参数：同批导
static void kek_lru_sweep(std::unordered_map<std::string, KekEntry>& map,
                          std::list<std::string>& lru, uint64_t now) {
    for (auto it = lru.begin(); it != lru.end(); ) {
        auto ce = map.find(*it);
        if (ce == map.end() || now - ce->second.last_used_ms > LRU_TTL_MS) {
            if (ce != map.end()) map.erase(ce);   // SecureBuffer 析构 memzero
            it = lru.erase(it);
        } else ++it;
    }
}

static bool kek_lru_get(std::unordered_map<std::string, KekEntry>& map,
                        std::list<std::string>& lru, const std::string& key,
                        unsigned char out[32], uint64_t now) {
    auto f = map.find(key);
    if (f == map.end()) return false;
    f->second.last_used_ms = now;
    lru.remove(key);
    lru.push_front(key);
    memcpy(out, f->second.kek.data(), 32);
    return true;
}

static void kek_lru_put(std::unordered_map<std::string, KekEntry>& map,
                        std::list<std::string>& lru, const std::string& key,
                        const unsigned char* kek32, uint64_t now) {
    auto it = map.find(key);
    if (it == map.end()) map.emplace(key, KekEntry{ SecureBuffer(kek32, 32), now });
    else it->second.last_used_ms = now;   // 键决定值
    lru.remove(key);
    lru.push_front(key);
    if (map.size() > LRU_MAX) {
        std::string victim = lru.back();
        lru.pop_back();
        map.erase(victim);
    }
}

// 取某 ptd
bool get_kek(VDiskHandle* h, const std::string& ptd, unsigned char out[32]) {
    const uint64_t now = now_ms();
    kek_lru_sweep(h->kek_cache, h->kek_lru, now);
    if (kek_lru_get(h->kek_cache, h->kek_lru, ptd, out, now)) return true;   // L1 文件级
    // L2 salt 级
    PtdMeta meta;
    if (!read_ptd_metadata(ptd, meta) || !meta.valid) return false;
    std::string skey = meta.salt_hex + "|" + std::to_string(meta.opslimit) + "|"
                     + std::to_string(meta.memlimit_kb);
    kek_lru_sweep(h->salt_kek_cache, h->salt_kek_lru, now);
    if (kek_lru_get(h->salt_kek_cache, h->salt_kek_lru, skey, out, now)) {
        kek_lru_put(h->kek_cache, h->kek_lru, ptd, out, now);   // 回填文件级
        return true;
    }
    // miss
    unsigned char buf[32];
    if (!fe_ptd_argon2_key(ptd, h->passphrase, buf)) return false;
    kek_lru_put(h->salt_kek_cache, h->salt_kek_lru, skey, buf, now);
    kek_lru_put(h->kek_cache, h->kek_lru, ptd, buf, now);
    memcpy(out, buf, 32);
    sodium_memzero(buf, sizeof(buf));
    return true;
}

// 索引密钥进程内
// 索引读写每次
// do_lock 时清
namespace {
std::mutex          g_ikm;
std::vector<unsigned char> g_ikm_key;
std::vector<unsigned char> g_ikm_salt;

bool index_key_cached(const SecureBuffer& pw, const VaultMeta& meta,
                      std::vector<unsigned char>& key, std::string& err) {
    if (meta.salt.size() != crypto_pwhash_SALTBYTES) { err = "bad salt size"; return false; }
    std::lock_guard<std::mutex> lk(g_ikm);
    if (!g_ikm_key.empty() && g_ikm_salt == meta.salt) { key = g_ikm_key; return true; }
    if (!derive_index_key(pw, meta, g_ikm_key, err)) return false;
    g_ikm_salt = meta.salt;
    key = g_ikm_key;
    return true;
}
// 清空索引密钥缓
void drop_index_key_cache() {
    std::lock_guard<std::mutex> lk(g_ikm);
    if (!g_ikm_key.empty()) sodium_memzero(g_ikm_key.data(), g_ikm_key.size());
    g_ikm_key.clear();
    g_ikm_salt.clear();
}
}  // namespace

// M34
// 但最后一批索引
// 非压缩 ptd 读
static void ptd_sess_clear(VDiskHandle* h) {
    for (auto& kv : h->ptd_sess) ptd_session_destroy(kv.second);
    h->ptd_sess.clear();
}
static void ptd_sess_erase(VDiskHandle* h, const std::string& ptd) {
    auto it = h->ptd_sess.find(ptd);
    if (it != h->ptd_sess.end()) { ptd_session_destroy(it->second); h->ptd_sess.erase(it); }
}
static PtdReadSession* get_ptd_sess(VDiskHandle* h, const std::string& ptd,
                                    const unsigned char* pre_kek) {
    auto it = h->ptd_sess.find(ptd);
    if (it != h->ptd_sess.end()) return it->second;
    if (h->ptd_sess.size() >= 8) ptd_sess_clear(h);
    PtdReadSession* s = nullptr;
    if (!ptd_session_open(ptd, h->passphrase, pre_kek, /*silent=*/true, &s)) return nullptr;
    h->ptd_sess.emplace(ptd, s);
    return s;
}

VDiskStatus do_lock(VDiskHandle* h) {
    // 锁定前先
    // 索引密钥算不出
    VDiskStatus st = VDISK_OK;
    {
        std::string e2;
        if (!vault_flush_index(h->library_dir, h->meta, h->passphrase, e2)) st = VDISK_E_IO;   // M34
    }
    forget_cached_index_keys();   // 经 hook 转发到本 TU
    vault_drop_index_mirror();   // 镜像含明文 JSON
    h->passphrase.clear();      // SecureBuffer
    h->index.clear();
    // M35
    h->index_map.clear();
    h->dir_children.clear();
    h->dir_set.clear();
    h->index_used_bytes = 0;
    h->index_trash_bytes = 0;
    h->name_scratch.clear();
    h->kek_cache.clear();       // 每个 SecureBuffer 析构
    h->kek_lru.clear();
    h->salt_kek_cache.clear();  // salt 级缓存同样持有
    h->salt_kek_lru.clear();
    h->import_active = false;   // 导入缓存同样持
    h->import_salt.clear();
    h->import_kek.clear();      // SecureBuffer::clear → memzero
    // M5 预读缓存同样持
    for (auto& kv : h->seg_cache) sodium_memzero(kv.second.data(), kv.second.size());
    h->seg_cache.clear();
    h->seg_lru.clear();
    h->seg_lru_pos.clear();
    h->seg_bytes = 0;
    ptd_sess_clear(h);   // 会话持有 DEK
    h->unlocked = false;
    h->index_damaged = false;   // 损坏放行态随锁
    return st;
}

// M5 空闲超
bool touch_activity(VDiskHandle* h) {
    const uint64_t now = now_ms();
    if (h->idle_timeout_s > 0 && h->unlocked &&
        (now - h->last_activity_ms) > (uint64_t)h->idle_timeout_s * 1000ull) {
        do_lock(h);
        return false;
    }
    h->last_activity_ms = now;
    return true;
}

// M5 只判超时、不刷新
// Explorer 打开盘
// 若这些
// 真正
bool check_idle_only(VDiskHandle* h) {
    const uint64_t now = now_ms();
    if (h->idle_timeout_s > 0 && h->unlocked &&
        (now - h->last_activity_ms) > (uint64_t)h->idle_timeout_s * 1000ull) {
        do_lock(h);
        return false;
    }
    return true;
}

// M5 预读缓存
constexpr uint64_t SEG_SIZE = 64ull * 1024;
constexpr uint64_t WIN_BYTES = 1ull * 1024 * 1024;   // 加密块对齐窗口

// 大文件放大窗口
static uint64_t win_bytes_for(uint64_t size, uint64_t cap) {
    uint64_t w = WIN_BYTES;
    if (size >= 512ull * 1024 * 1024) w = 8ull * 1024 * 1024;
    else if (size >= 64ull * 1024 * 1024) w = 4ull * 1024 * 1024;
    else if (size >= 8ull * 1024 * 1024) w = 2ull * 1024 * 1024;
    uint64_t budget = cap / 2;
    if (budget < WIN_BYTES) return WIN_BYTES;
    while (w > budget) w >>= 1;
    return w;
}

// 分隔符用 '\0'
std::string seg_key(const std::string& rel, uint64_t seg_idx) {
    std::string k = rel;
    k.push_back('\0');
    k.append(std::to_string(seg_idx));
    return k;
}
// 前缀匹配必须
std::string seg_prefix(const std::string& rel) {
    std::string p = rel;
    p.push_back('\0');
    return p;
}

void seg_put(VDiskHandle* h, const std::string& key, std::vector<unsigned char>&& data) {
    if (!h->cache_on || h->cache_cap_bytes == 0) return;
    auto it = h->seg_cache.find(key);
    if (it != h->seg_cache.end()) { h->seg_bytes -= it->second.size(); h->seg_cache.erase(it); }
    h->seg_bytes += data.size();
    h->seg_cache.emplace(key, std::move(data));
    auto pit = h->seg_lru_pos.find(key);
    if (pit != h->seg_lru_pos.end()) h->seg_lru.erase(pit->second);
    h->seg_lru.push_front(key);
    h->seg_lru_pos[key] = h->seg_lru.begin();
    while (h->seg_bytes > h->cache_cap_bytes && !h->seg_lru.empty()) {
        std::string victim = h->seg_lru.back(); h->seg_lru.pop_back();
        h->seg_lru_pos.erase(victim);
        auto v = h->seg_cache.find(victim);
        if (v != h->seg_cache.end()) {
            sodium_memzero(v->second.data(), v->second.size());
            h->seg_bytes -= v->second.size();
            h->seg_cache.erase(v);
        }
    }
}

const std::vector<unsigned char>* seg_get(VDiskHandle* h, const std::string& key) {
    if (!h->cache_on) return nullptr;
    auto it = h->seg_cache.find(key);
    if (it == h->seg_cache.end()) return nullptr;
    auto pit = h->seg_lru_pos.find(key);
    if (pit != h->seg_lru_pos.end()) {
        h->seg_lru.erase(pit->second);
        h->seg_lru.push_front(key);
        pit->second = h->seg_lru.begin();
    }
    return &it->second;
}

} // namespace
// M5+
// 正在写库
// 看片看到一半
VDISK_API void vdisk_note_activity(VDiskHandle* h) {
    try {
    if (!h) return;
    std::lock_guard<std::recursive_mutex> lk(h->mtx);
    if (h->unlocked) h->last_activity_ms = now_ms();

    } catch(...) {}
}

// M5+
// 供挂载层 watchdog 每秒轮
VDISK_API uint64_t vdisk_index_stamp(VDiskHandle* h) {
    try {
    if (!h) return 0;
    return vault_index_stamp(h->library_dir);

    } catch(...) { return 0; }
}

// M5+
// UINT32_MAX
VDISK_API int vdisk_is_unlocked(VDiskHandle* h) {
    try {
    if (!h) return 0;
    std::lock_guard<std::recursive_mutex> lk(h->mtx);
    return h->unlocked ? 1 : 0;

    } catch(...) { return 0; }
}


// 清理存储目录里
// 它们
static void cleanup_vault_temp_files(const std::string& dir);

// 安全擦除并删除
// 跨平台一致
static void secure_wipe_remove(const std::string& p) {
#ifdef _WIN32
    HANDLE h = CreateFileW(utf8_to_wstring(p).c_str(), GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(h, &sz)) {
            const DWORD chunk = 64 * 1024;
            std::vector<BYTE> buf(chunk, 0);
            LONGLONG left = sz.QuadPart;
            DWORD written = 0;
            while (left > 0) {
                DWORD n = (left > (LONGLONG)chunk) ? chunk : (DWORD)left;
                if (!WriteFile(h, buf.data(), n, &written, nullptr)) break;
                left -= written;
            }
        }
        FlushFileBuffers(h);   // 强制落盘
        CloseHandle(h);
    }
    DeleteFileW(utf8_to_wstring(p).c_str());
#else
    // POSIX
    int fd = open(p.c_str(), O_WRONLY | O_NONBLOCK);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            const size_t chunk = 64 * 1024;
            std::vector<unsigned char> buf(chunk, 0);
            off_t left = st.st_size;
            while (left > 0) {
                size_t n = (left > (off_t)chunk) ? chunk : (size_t)left;
                ssize_t w = write(fd, buf.data(), n);
                if (w <= 0) break;
                left -= w;
            }
        }
        fsync(fd);
        close(fd);
    }
    unlink(p.c_str());
#endif
}

static void cleanup_vault_temp_files(const std::string& dir) {
    std::error_code ec;
    fs::path vdir = fs::u8path(dir);
    // 先收集
    std::vector<std::string> dead;
    fs::recursive_directory_iterator it(vdir, ec);
    if (ec) return;
    for (auto& e : it) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension().u8string() != ".tmp") continue;
        // 进行
        if (e.path().filename().u8string() == ".feindex.tmp") {
            if (!fs::exists(e.path().parent_path() / ".feindex")) continue;
        }
        dead.push_back(e.path().u8string());
    }
    for (const auto& p : dead) {
        std::string stem = fs::path(p).stem().u8string();   // 去 .tmp
        if (stem.size() >= 6 && stem.compare(stem.size() - 6, 6, ".plain") == 0)
            secure_wipe_remove(p);   // 明文残片
        else
            fs::remove(fs::u8path(p), ec);
    }
}

// M7
// 打开+DELETE / MoveFile 全部失
// 访问权必须给
// 后续请求 DELETE
// 非 Windows
#ifdef _WIN32
static void m7_hold(VDiskHandle* h, const std::string& ptd) {
    if (!h->mounted) return;
    if (h->held_ptd.count(ptd)) return;
    HANDLE fh = CreateFileW(utf8_to_wstring(ptd).c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh != INVALID_HANDLE_VALUE) h->held_ptd[ptd] = fh;
}
static void m7_release(VDiskHandle* h, const std::string& ptd) {
    auto it = h->held_ptd.find(ptd);
    if (it != h->held_ptd.end()) { CloseHandle((HANDLE)it->second); h->held_ptd.erase(it); }
}
static void m7_release_all(VDiskHandle* h) {
    for (auto& kv : h->held_ptd) CloseHandle((HANDLE)kv.second);
    h->held_ptd.clear();
}
static void m7_refresh(VDiskHandle* h) {
    m7_release_all(h);
    if (h->mounted) for (const auto& e : h->index)
        m7_hold(h, ptd_path_for(h->library_dir, e.rel_path, e.store));
}
#else
static inline void m7_hold(VDiskHandle*, const std::string&) {}
static inline void m7_release(VDiskHandle*, const std::string&) {}
static inline void m7_release_all(VDiskHandle*) {}
static inline void m7_refresh(VDiskHandle*) {}
#endif

// 索引新鲜度
// 索引只
// -into-vault）往库里加文件，本
// 判据用库侧统一
// 旧库回退 .feindex.d 目录
static void index_stamp(const std::string& dir, uint64_t& mtime, uint64_t& size, bool& sharded) {
    // sharded 仅用于日志/兼容
    std::error_code ec;
    sharded = fs::exists(fs::u8path(dir + "/.feindex.d"), ec);
    mtime = vault_index_stamp(dir);
    size = 0;
}

// caller 持有 h->mtx
// 替代原先每次 readdir/getattr
// 文件数大 + Explorer 滚动反
static void rebuild_index_caches(VDiskHandle* h) {
    h->index_map.clear();
    h->dir_children.clear();
    h->dir_mtime.clear();
    h->dir_set.clear();
    h->dir_set.insert("");   // 根永远是一个目
    std::unordered_set<std::string> seen_child;   // 子项去重
    uint64_t used = 0;
    uint64_t trash = 0;
    // 第一遍
    // 隐式目录
    {
        std::unordered_map<std::string, uint64_t> dmax;   // 隐式目录
        std::vector<std::string> comp;
        for (size_t i = 0; i < h->index.size(); ++i) {
            const VaultEntry& e = h->index[i];
            const std::string& rel = e.rel_path;
            if (rel.empty()) continue;
            if (e.is_dir) {
                h->dir_mtime[ci_key(rel)] = (uint64_t)e.mtime;
                continue;
            }
            comp.clear();
            std::string cur;
            for (char c : rel) {
                if (c == '/') { if (!cur.empty()) comp.push_back(cur); cur.clear(); }
                else cur += c;
            }
            if (!cur.empty()) comp.push_back(cur);
            std::string anc;   // 逐级父目录
            for (size_t k = 0; k + 1 < comp.size(); ++k) {
                anc = anc.empty() ? comp[k] : (anc + "/" + comp[k]);
                auto& m = dmax[ci_key(anc)];
                if ((uint64_t)e.mtime > m) m = (uint64_t)e.mtime;
            }
        }
        for (auto& kv : dmax)
            if (!h->dir_mtime.count(kv.first)) h->dir_mtime[kv.first] = kv.second;
    }
    for (size_t i = 0; i < h->index.size(); ++i) {
        const VaultEntry& e = h->index[i];
        const std::string& rel = e.rel_path;
        if (rel.empty()) continue;                 // 防御
        h->index_map[ci_key(rel)] = i;             // 键统一小写
        if (!e.is_dir) {
            uint64_t sz = (e.size > 0) ? (uint64_t)e.size : 0;
            used += sz;
            if (rel_is_reserved(rel)) trash += sz;
        }
        // 拆分层级组件
        std::vector<std::string> comp;
        std::string cur;
        for (char c : rel) {
            if (c == '/') { if (!cur.empty()) comp.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) comp.push_back(cur);
        if (comp.empty()) continue;
        // 末层组件
        size_t last_component = e.is_dir ? comp.size() : comp.size() - 1;
        // 逐层目录
        std::string dparent;
        for (size_t k = 0; k < last_component; ++k) {
            std::string dir = dparent.empty() ? comp[k] : (dparent + "/" + comp[k]);
            h->dir_set.insert(ci_key(dir));
            std::string dkey = dparent.empty() ? comp[k] : (dparent + "/" + comp[k]);
            if (seen_child.insert(dkey).second) {
                auto dm = h->dir_mtime.find(ci_key(dir));
                h->dir_children[ci_key(dparent)].push_back(
                    { comp[k], 0, dm != h->dir_mtime.end() ? dm->second : 0 });   // 目录
            }
            dparent = dir;
        }
        // 末层
        // 循环注册完毕
        // readdir 即出现「目录套自
        if (!e.is_dir) {
            std::string leaf = comp.back();
            std::string lkey = dparent.empty() ? leaf : (dparent + "/" + leaf);
            if (seen_child.insert(lkey).second)
                h->dir_children[ci_key(dparent)].push_back({ leaf, (uint64_t)e.size, (uint64_t)e.mtime });
        }
        if (e.is_dir) h->dir_set.insert(ci_key(rel));
    }
    h->index_used_bytes = used;
    h->index_trash_bytes = trash;
}

// caller 持有 h->mtx
static void refresh_index_locked(VDiskHandle* h) {
    if (!h->unlocked) return;
    // 轮询节流
    // 200ms 内直接信任上次
    uint64_t now = now_ms();
    if (h->feindex_stamp_ms != 0 && now - h->feindex_stamp_ms < 200) return;
    h->feindex_stamp_ms = now;
    uint64_t mt = 0, sz = 0; bool sharded = false;
    index_stamp(h->library_dir, mt, sz, sharded);
    if (mt == h->feindex_mtime && sz == h->feindex_size && sharded == h->feindex_sharded) return;
    h->feindex_mtime = mt; h->feindex_size = sz; h->feindex_sharded = sharded;
    std::vector<VaultEntry> entries; std::string err;
    if (!vault_read_index(h->library_dir, h->meta, h->passphrase, entries, err)) return;
    h->index = std::move(entries);
    rebuild_index_caches(h);
    m7_refresh(h);          // 条目变
}

// 无条件对齐盘面
static void refresh_index_locked_force(VDiskHandle* h) {
    h->feindex_stamp_ms = 0;
    refresh_index_locked(h);
}

/*
 * 建库（等价 CLI 的 --vault-init）：写 vault.meta（随机盐 + KDF 参数）。
 * 幂等——已有 vault.meta 时按 vault_meta_init 语义直接加载，不覆盖既有身份与密码。
 * 无挂载平台（Android）必须先调本函数，vdisk_open 才不会因缺 vault.meta 失败。
 */
VDISK_API VDiskStatus vdisk_init(const char* library_dir) {
    if (!library_dir || !*library_dir) return VDISK_E_BADARG;
    try {
        VaultMeta meta;
        std::string err;
        if (!vault_meta_init(library_dir, library_dir, meta, err)) return VDISK_E_IO;
        return VDISK_OK;
    } catch (const std::bad_alloc&) { return VDISK_E_NOMEM; }
    catch (...) { return VDISK_E_INTERNAL; }
}

// 建库并落默认策
VDISK_API VDiskStatus vdisk_init_ex(const char* library_dir, int mode, int compress_policy) {
    if (!library_dir || !*library_dir) return VDISK_E_BADARG;
    if (!vd_mode_available(mode)) return VDISK_E_BADARG;
    try {
        VaultMeta meta;
        std::string err;
        if (!vault_meta_init(library_dir, library_dir, meta, err)) return VDISK_E_IO;
        meta.default_mode = vd_int_from_mode(vd_mode_from_int(mode));
        meta.compress_policy = compress_policy;
        if (!vault_meta_save(library_dir, meta, err)) return VDISK_E_IO;
        return VDISK_OK;
    } catch (...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_set_default_mode(VDiskHandle* h, int mode, int compress_policy) {
    if (!h) return VDISK_E_BADARG;
    if (mode != 0 && !vd_mode_available(mode)) return VDISK_E_BADARG;
    try {
        std::lock_guard<std::recursive_mutex> _lk(h->mtx);
        if (mode != 0) h->meta.default_mode = vd_int_from_mode(vd_mode_from_int(mode));
        if (compress_policy != VDISK_COMPRESS_DEFAULT) h->meta.compress_policy = compress_policy;
        std::string err;
        return vault_meta_save(h->library_dir, h->meta, err) ? VDISK_OK : VDISK_E_IO;
    } catch (...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskHandle* vdisk_open(const char* library_dir) {
    try {
    if (!library_dir || !*library_dir) return nullptr;   // 句柄尚未创建
    VDiskHandle* h = new (std::nothrow) VDiskHandle();
    if (!h) return nullptr;
    h->library_dir = library_dir;
    // 注册索引密钥缓
    set_index_key_cache_hook(index_key_cached, drop_index_key_cache);
    std::string err;
    if (!vault_meta_load(h->library_dir, h->meta, err)) { delete h; return nullptr; }
    cleanup_vault_temp_files(h->library_dir);   // M8
    return h;

    } catch(...) { return nullptr; }
}

VDISK_API void vdisk_close(VDiskHandle* h) {
    try {
    if (!h) return;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    do_lock(h);
    m7_release_all(h);   // M7
    delete h;

    } catch(...) {}
}

VDISK_API VDiskStatus vdisk_unlock(VDiskHandle* h, const char* passphrase, int use_recovery) {
    try {
    if (!h || !passphrase) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    SecureBuffer pw;
    if (use_recovery) {
        // §4.4
        std::string rerr;
        if (!vault_recovery_load(h->library_dir, passphrase, pw, rerr)) return VDISK_E_AUTH;
    } else {
        pw = SecureBuffer(passphrase, std::strlen(passphrase));
    }
    std::vector<VaultEntry> entries;
    std::string err;
    if (!vault_read_index(h->library_dir, h->meta, pw, entries, err)) {
        if (err.find("wrong password") != std::string::npos) return VDISK_E_AUTH;
        // 索引损坏/不可读
        // 用户进库后「重建
        entries.clear();
        h->index_damaged = true;
    } else {
        h->index_damaged = false;
    }
    h->passphrase = std::move(pw);
    h->index = std::move(entries);
    rebuild_index_caches(h);   // 解锁即构建派生
    index_stamp(h->library_dir, h->feindex_mtime, h->feindex_size, h->feindex_sharded);   // 记下当前版本
    h->last_activity_ms = now_ms();   // M5 空闲计时起点
    h->unlocked = true;
    if (h->meta.encrypted) {
        // 解锁拿到密码
        std::string derr;
        vault_meta_decrypt(h->meta, h->passphrase, derr);
    } else {
        // 旧明文盘首次解
        // 此后 open 仍无需密码
        std::vector<unsigned char> kek;
        std::string kerr;
        if (derive_index_key(h->passphrase, h->meta, kek, kerr) && !kek.empty()) {
            if (vault_meta_save_encrypted(h->library_dir, h->meta, kek, kerr))
                h->meta.encrypted = true;   // 与落盘格式保持
        }
        if (!kek.empty()) sodium_memzero(kek.data(), kek.size());
    }
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 只读口令校验
VDISK_API VDiskStatus vdisk_verify_password(VDiskHandle* h, const char* passphrase, int use_recovery) {
    try {
    if (!h || !passphrase) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    SecureBuffer pw;
    if (use_recovery) {
        std::string rerr;
        if (!vault_recovery_load(h->library_dir, passphrase, pw, rerr)) return VDISK_E_AUTH;
    } else {
        pw = SecureBuffer(passphrase, std::strlen(passphrase));
    }
    if (pw.size() != h->passphrase.size() || pw.empty()) return VDISK_E_AUTH;
    return sodium_memcmp(pw.data(), h->passphrase.data(), pw.size()) == 0
        ? VDISK_OK : VDISK_E_AUTH;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 索引是否处于「损
// 调用方
VDISK_API int vdisk_index_damaged(VDiskHandle* h) {
    if (!h) return 0;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    return h->index_damaged ? 1 : 0;
}

VDISK_API VDiskStatus vdisk_lock(VDiskHandle* h) {
    try {
    if (!h) return VDISK_E_BADARG;   // H2b
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    return do_lock(h);   // M34

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API void vdisk_purge_on_suspend(VDiskHandle* h) {
    try {
    if (!h) return;
    std::lock_guard<std::recursive_mutex> lk(h->mtx);   // H3
    do_lock(h);

    } catch(...) {}
}

VDISK_API VDiskStatus vdisk_reindex(VDiskHandle* h, const char* root) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string r = (root && *root) ? root : h->library_dir;
    std::string err;
    // 重建前先快照内
    // 盘面旧索引可能
    // 那时只有这份快
    std::vector<VaultEntry> hint = h->index;
    if (!vault_reindex(r, h->meta, h->passphrase, err, &hint)) return VDISK_E_IO;
    std::vector<VaultEntry> entries;
    if (!vault_read_index(r, h->meta, h->passphrase, entries, err)) return VDISK_E_IO;
    h->index = std::move(entries);
    h->index_damaged = false;   // 重建成功
    rebuild_index_caches(h);   // H4
    index_stamp(h->library_dir, h->feindex_mtime, h->feindex_size, h->feindex_sharded);
    m7_refresh(h);          // M7
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_reindex_ex(VDiskHandle* h, const char* root,
                                      VDiskProgressFn progress, void* user,
                                      VDiskCancelFn cancel, void* cancel_user) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string r = (root && *root) ? root : h->library_dir;
    std::string err;
    // 重建前先快照内
    std::vector<VaultEntry> hint = h->index;
    bool cancelled = false;
    if (!vault_reindex(r, h->meta, h->passphrase, err, &hint,
                       progress, user, cancel, cancel_user, &cancelled))
        return VDISK_E_IO;
    // 无论是否取消
    std::vector<VaultEntry> entries;
    if (!vault_read_index(r, h->meta, h->passphrase, entries, err)) return VDISK_E_IO;
    h->index = std::move(entries);
    h->index_damaged = false;   // 重建成功
    rebuild_index_caches(h);   // H4
    index_stamp(h->library_dir, h->feindex_mtime, h->feindex_size, h->feindex_sharded);
    m7_refresh(h);          // M7
    return cancelled ? VDISK_E_CANCELLED : VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_mount_readonly(VDiskHandle* h, const char* mount_point) {
    try {
    if (!h || !mount_point) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->mount_point = mount_point;
    h->mounted = true;
    h->rw = false;          // 显式只读
    m7_refresh(h);          // M7
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_unmount(VDiskHandle* h) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    m7_release_all(h);   // M7
    h->mounted = false;
    h->mount_point.clear();
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_readdir(VDiskHandle* h, const char* vpath,
                                    VDiskEntry** out_entries, uint64_t* out_count) {
    try {
    if (!h || !out_count) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!check_idle_only(h)) return VDISK_E_LOCKED;   // M5 只判超
    refresh_index_locked(h);   // 库外刚入盘
    std::string rel = vpath_to_rel(vpath);
    const std::vector<DirChild>* kids = nullptr;
    if (rel.empty()) {
        auto it = h->dir_children.find(std::string());
        if (it != h->dir_children.end()) kids = &it->second;
    } else {
        auto dit = h->dir_children.find(ci_key(rel));
        if (dit != h->dir_children.end()) kids = &dit->second;
        else if (h->index_map.find(ci_key(rel)) == h->index_map.end()) return VDISK_E_NOTFOUND;  // 既非目录
    }
    // 三端统一过滤
    // 仅当父目录本身
    std::vector<size_t> visible;
    if (kids) {
        bool hide_reserved = !rel_is_reserved(rel);
        visible.reserve(kids->size());
        for (size_t i = 0; i < kids->size(); ++i) {
            if (hide_reserved) {
                const std::string crel = rel.empty() ? (*kids)[i].name
                                                     : rel + "/" + (*kids)[i].name;
                if (rel_is_reserved(crel)) continue;
            }
            visible.push_back(i);
        }
    }
    uint64_t n = visible.size();

    uint64_t cap = out_entries ? *out_count : 0;
    *out_count = n;
    if (!out_entries) return VDISK_OK;        // 第一段
    if (cap < n) return VDISK_E_BADARG;       // 容量不足

    h->name_scratch.clear();
    h->name_scratch.reserve(n);
    for (size_t idx : visible) h->name_scratch.push_back((*kids)[idx].name);
    for (uint64_t i = 0; i < n; i++) {
        const DirChild& c = (*kids)[visible[i]];
        // 目录判定
        bool d = h->dir_set.count(ci_key(rel.empty() ? c.name : rel + "/" + c.name)) != 0;
        (*out_entries)[i].name = h->name_scratch[i].c_str();
        (*out_entries)[i].is_dir = d ? 1 : 0;
        (*out_entries)[i].size = d ? 0 : c.size;
        (*out_entries)[i].mtime = c.mtime;   // 目录 mtime 已
    }
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_getattr(VDiskHandle* h, const char* vpath,
                                    uint64_t* out_size, uint64_t* out_mtime, uint8_t* out_is_dir) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!check_idle_only(h)) return VDISK_E_LOCKED;   // M5 只判超
    refresh_index_locked(h);   // 同 readdir
    std::string rel = vpath_to_rel(vpath);
    uint64_t now = (uint64_t)time(nullptr);
    if (rel.empty()) {
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = now;
        if (out_is_dir) *out_is_dir = 1;
        return VDISK_OK;
    }
    auto it = h->index_map.find(ci_key(rel));   
    if (it != h->index_map.end()) {
        const VaultEntry& e = h->index[it->second];
        if (e.is_dir) {   // 显式目录条目
            if (out_size) *out_size = 0;
            if (out_mtime) *out_mtime = (uint64_t)e.mtime;
            if (out_is_dir) *out_is_dir = 1;
            return VDISK_OK;
        }
        if (out_size) *out_size = e.size;
        if (out_mtime) *out_mtime = (uint64_t)e.mtime;
        if (out_is_dir) *out_is_dir = 0;
        return VDISK_OK;
    }
    if (h->dir_set.count(ci_key(rel))) {   
        if (out_size) *out_size = 0;
        auto dm = h->dir_mtime.find(ci_key(rel));
        if (out_mtime) *out_mtime = dm != h->dir_mtime.end() ? dm->second : now;
        if (out_is_dir) *out_is_dir = 1;
        return VDISK_OK;
    }
    return VDISK_E_NOTFOUND;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_read_file(VDiskHandle* h, const char* vpath,
                                      uint64_t offset, uint8_t* out, uint64_t* len) {
    try {
    if (!h || !out || !len) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!touch_activity(h)) return VDISK_E_LOCKED;   // M5 空闲超时自动锁
    std::string rel = vpath_to_rel(vpath);
    const VaultEntry* e = find_entry(h->index, rel);
    if (!e) return VDISK_E_NOTFOUND;
    uint64_t want = *len;
    *len = 0;
    if (want == 0) return VDISK_OK;
    if (offset >= e->size) return VDISK_OK;
    // ptd 路径必须用索引
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);
    // §4.1
    unsigned char kek[32];
    bool have_kek = get_kek(h, ptd, kek);
    const unsigned char* pre_kek = have_kek ? kek : nullptr;
    // 读会话
    PtdReadSession* sess = (h->cache_on && h->cache_cap_bytes > 0)
        ? get_ptd_sess(h, ptd, pre_kek) : nullptr;

    // M5 预读缓存
    if (h->cache_on && h->cache_cap_bytes > 0) {
        // M36
        if (want > SIZE_MAX - offset) { *len = 0; return VDISK_E_BADARG; }
        uint64_t end = offset + want;
        uint64_t first = offset / SEG_SIZE, last = (end - 1) / SEG_SIZE;
        uint64_t written = 0;
        // 非压缩 miss 窗口填充
        uint64_t win_sz = win_bytes_for((uint64_t)e->size, h->cache_cap_bytes);
        auto fill_window = [&](uint64_t s) -> bool {
            uint64_t wstart = (s * SEG_SIZE) & ~(win_sz - 1);
            if (wstart >= (uint64_t)e->size) return false;
            uint64_t wlen = std::min<uint64_t>(win_sz, (uint64_t)e->size - wstart);
            if (wlen <= SEG_SIZE) return false;
            std::vector<unsigned char> win; bool wcomp = false;
            bool rok = sess ? ptd_session_read(sess, wstart, wlen, win, true)
                            : random_read_ptd(ptd, h->passphrase, wstart, wlen, win, &wcomp,
                                              /*silent=*/true, pre_kek);
            if (!rok || wcomp || win.empty()) return false;
            uint64_t s0 = wstart / SEG_SIZE;
            for (uint64_t k = 0; k * SEG_SIZE < win.size(); k++) {
                uint64_t from = k * SEG_SIZE;
                uint64_t n = std::min<uint64_t>(SEG_SIZE, win.size() - from);
                std::vector<unsigned char> seg(win.begin() + (size_t)from,
                                               win.begin() + (size_t)(from + n));
                seg_put(h, seg_key(rel, s0 + k), std::move(seg));
            }
            sodium_memzero(win.data(), win.size());
            return true;
        };
        for (uint64_t s = first; s <= last && written < want; s++) {
            std::string key = seg_key(rel, s);
            if (!seg_get(h, key)) {
                std::vector<unsigned char> tmp; bool comp = false;
                std::vector<unsigned char> full;
                if (sess) {
                    // 非压缩
                    if (!fill_window(s)) {
                        if (!ptd_session_read(sess, s * SEG_SIZE, SEG_SIZE, tmp, true) || tmp.empty()) {
                            sodium_memzero(kek, sizeof(kek));
                            return VDISK_E_IO;
                        }
                        seg_put(h, key, std::move(tmp));
                    }
                } else if (!random_read_ptd(ptd, h->passphrase, s * SEG_SIZE, SEG_SIZE, tmp, &comp,
                                            /*silent=*/true, pre_kek, &full)) {
                    sodium_memzero(kek, sizeof(kek));
                    return VDISK_E_IO;
                } else {
                    // 压缩文件一次解
                    if (!full.empty() && full.size() <= h->cache_cap_bytes) {
                        for (uint64_t k = 0; k * SEG_SIZE < full.size(); k++) {
                            uint64_t from = k * SEG_SIZE;
                            uint64_t n = std::min<uint64_t>(SEG_SIZE, full.size() - from);
                            std::vector<unsigned char> seg(full.begin() + (size_t)from,
                                                           full.begin() + (size_t)(from + n));
                            seg_put(h, seg_key(rel, k), std::move(seg));
                        }
                        // 缓存淘汰可能挤
                        if (!seg_get(h, key) && s * SEG_SIZE < full.size()) {
                            uint64_t from = s * SEG_SIZE;
                            uint64_t n = std::min<uint64_t>(SEG_SIZE, full.size() - from);
                            std::vector<unsigned char> seg(full.begin() + (size_t)from,
                                                           full.begin() + (size_t)(from + n));
                            seg_put(h, key, std::move(seg));
                        }
                        sodium_memzero(full.data(), full.size());
                    } else {
                        if (!full.empty()) sodium_memzero(full.data(), full.size());
                        seg_put(h, key, std::move(tmp));
                    }
                }
            }
            const std::vector<unsigned char>* seg = seg_get(h, key);
            if (!seg || seg->empty()) break;
            uint64_t from = (offset + written) - s * SEG_SIZE;
            uint64_t avail = (seg->size() > from) ? (seg->size() - from) : 0;
            uint64_t n = (avail < want - written) ? avail : (want - written);
            if (n > 0) std::memcpy(out + written, seg->data() + from, n);
            written += n;
            if (seg->size() < SEG_SIZE) break;      // 段不满 = EOF
        }
        for (uint32_t k = 1; k <= h->cache_ahead; k++) {
            uint64_t s = last + k;
            std::string key = seg_key(rel, s);
            if (seg_get(h, key)) continue;
            if (sess) {
                // 会话读
                if (!fill_window(s)) {
                    std::vector<unsigned char> tmp;
                    if (ptd_session_read(sess, s * SEG_SIZE, SEG_SIZE, tmp, true) && !tmp.empty())
                        seg_put(h, key, std::move(tmp));
                }
            } else {
                std::vector<unsigned char> tmp; bool comp = false;
                if (random_read_ptd(ptd, h->passphrase, s * SEG_SIZE, SEG_SIZE, tmp, &comp,
                                    /*silent=*/true, pre_kek) && !tmp.empty()) {
                    if (!comp && fill_window(s))
                        sodium_memzero(tmp.data(), tmp.size());
                    else
                        seg_put(h, key, std::move(tmp));
                }
            }
        }
        sodium_memzero(kek, sizeof(kek));
        *len = written;
        return VDISK_OK;
    }

    std::vector<unsigned char> buf;
    bool compressed = false;
    bool ok = random_read_ptd(ptd, h->passphrase, offset, want, buf, &compressed, /*silent=*/true,
                              pre_kek);
    sodium_memzero(kek, sizeof(kek));
    if (!ok) return VDISK_E_IO;   // 压缩块已
    uint64_t got = buf.size();
    if (got > want) got = want;
    if (got > 0) std::memcpy(out, buf.data(), got);
    sodium_memzero(buf.data(), buf.size());
    *len = got;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// M6 写支持
// 可写挂载要求文
// 策略
// 天然满足设计文
static constexpr uint32_t kM6Chunk = 65536;

// §4.5 安全擦除
// 原子替换目标
// Windows 用 MoveFileExW
static bool replace_file_atomic(const std::string& src, const std::string& dst) {
#ifdef _WIN32
    return MoveFileExW(utf8_to_wstring(src).c_str(), utf8_to_wstring(dst).c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return std::rename(src.c_str(), dst.c_str()) == 0;
#endif
}

static bool wipe_remove(const std::string& path) {
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    if (f) {
        f.seekg(0, std::ios::end);
        std::streamoff sz = f.tellg();
        const unsigned char pat[3] = {0x00, 0xFF, 0xAA};
        std::vector<unsigned char> buf(kM6Chunk, 0);
        for (int pass = 0; pass < 3 && sz > 0; pass++) {
            std::memset(buf.data(), pat[pass], buf.size());
            std::streamoff left = sz; f.seekg(0);
            while (left > 0) {
                std::streamsize n = (left > (std::streamoff)buf.size()) ? (std::streamsize)buf.size() : (std::streamsize)left;
                f.write((const char*)buf.data(), n); left -= n;
            }
            f.flush();
        }
        f.close();
    }
    return std::remove(path.c_str()) == 0;
}

static bool file_exists(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return f.good();
}

static void invalidate_ptd_caches(VDiskHandle* h, const std::string& rel, const std::string& ptd);   // 定义见

// 删除单个 .ptd
// （原 4MB 阈值只是妥协）
static bool unlink_ptd(const std::string& path) {
    return std::remove(path.c_str()) == 0;
}

// 移除某条目对应
// 只认 store
static bool remove_ptd_file(VDiskHandle* h, const std::string& rel, const std::string& store) {
    const std::string a = ptd_path_for(h->library_dir, rel, store);
    const std::string b = ptd_path_for(h->library_dir, rel, std::string());
    bool ok = true;
    const std::string* cand[2] = { &a, &b };
    for (int i = 0; i < 2; i++) {
        const std::string& p = *cand[i];
        if (p.empty() || (i == 1 && p == a)) continue;
        m7_release(h, p);
        wipe_remove(p + ".plain.tmp");   // 明文残片必须擦
        unlink_ptd(p + ".rw.tmp");       // 密文临时片
        if (file_exists(p)) {
            if (!unlink_ptd(p) || file_exists(p)) ok = false;   // 删完仍
            invalidate_ptd_caches(h, rel, p);
        }
    }
    return ok;
}

// 清掉某目录
// 只认 .ptd
static void purge_ptds_under(const std::string& dir) {
    std::error_code ec;
    if (!fs::is_directory(fs::u8path(dir), ec)) return;
    std::vector<std::string> victims;
    for (fs::recursive_directory_iterator it(fs::u8path(dir), ec), end; it != end; it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        std::string n = it->path().filename().u8string();
        bool hit = n.size() >= 4 && n.compare(n.size() - 4, 4, ".ptd") == 0;
        if (!hit && n.size() >= 4) hit = n.compare(n.size() - 4, 4, ".tmp") == 0;
        if (hit) victims.push_back(it->path().u8string());
    }
    for (const auto& v : victims) {
        // 明文残片必须覆
        std::string n = fs::path(v).filename().u8string();
        if (n.size() >= 11 && n.compare(n.size() - 11, 11, ".plain.tmp") == 0)
            wipe_remove(v);
        else
            unlink_ptd(v);
    }
}

// 删完自底向上清
static void prune_empty_dirs(const std::string& library_dir, std::string rel) {
    std::error_code ec;
    if (!fs::is_directory(fs::u8path(library_dir + "/" + rel), ec)) {
        size_t pos = rel.find_last_of('/');
        rel = (pos == std::string::npos) ? std::string() : rel.substr(0, pos);
    }
    while (!rel.empty()) {
        std::string d = library_dir + "/" + rel;
        if (!fs::is_directory(fs::u8path(d), ec)) break;
        if (!fs::is_empty(fs::u8path(d), ec)) break;   // 还有文件
        fs::remove(fs::u8path(d), ec);
        size_t pos = rel.find_last_of('/');
        rel = (pos == std::string::npos) ? std::string() : rel.substr(0, pos);
    }
}

static VaultEntry* find_mut(VDiskHandle* h, const std::string& rel) {
    for (auto& e : h->index) if (e.rel_path == rel) return &e;
    for (auto& e : h->index) if (ci_equal(e.rel_path, rel)) return &e;   // 驱动大写归一化
    return nullptr;
}

// 写/截断后使该文
static void invalidate_ptd_caches(VDiskHandle* h, const std::string& rel, const std::string& ptd) {
    h->kek_cache.erase(ptd);
    h->kek_lru.remove(ptd);
    ptd_sess_erase(h, ptd);   // 会话
    std::string prefix = seg_prefix(rel);
    for (auto it = h->seg_cache.begin(); it != h->seg_cache.end(); ) {
        if (it->first.compare(0, prefix.size(), prefix) == 0) {
            sodium_memzero(it->second.data(), it->second.size());
            size_t n = it->second.size();
            h->seg_bytes = h->seg_bytes > n ? h->seg_bytes - n : 0;
            auto pit = h->seg_lru_pos.find(it->first);
            if (pit != h->seg_lru_pos.end()) {
                h->seg_lru.erase(pit->second);
                h->seg_lru_pos.erase(pit);
            }
            it = h->seg_cache.erase(it);
        } else ++it;
    }
}

// 明文重加密原子
// footer_name
// 必须是逻辑名
static VDiskStatus rewrite_ptd(VDiskHandle* h, const std::string& ptd,
                               std::vector<unsigned char>& plain,
                               const std::string& footer_name,
                               CryptoMode* out_mode = nullptr) {
    std::string plain_tmp = ptd + ".plain.tmp";
    {
        std::ofstream pf(plain_tmp, std::ios::binary | std::ios::trunc);
        if (!pf) return VDISK_E_IO;
        if (!plain.empty()) pf.write((const char*)plain.data(), (std::streamsize)plain.size());
    }
    std::string ptd_tmp = ptd + ".rw.tmp";
    // 改写沿用该文件
    CryptoMode rw_mode = vd_write_mode(h);
    PtdMeta pm;
    if (read_ptd_metadata(ptd, pm) && pm.valid) rw_mode = pm.mode;
    if (out_mode) *out_mode = rw_mode;
    if (!encrypt_file(plain_tmp, ptd_tmp, h->passphrase, rw_mode,
                      nullptr, false, vd_compress_level(h), false, nullptr, nullptr,
                      nullptr, nullptr, kM6Chunk, nullptr, nullptr, &footer_name)) {
        wipe_remove(plain_tmp);
        return VDISK_E_IO;
    }
    // 原子替换
    // MoveFileExW
    if (!replace_file_atomic(ptd_tmp, ptd)) {
        wipe_remove(plain_tmp);
        return VDISK_E_IO;
    }
    if (!wipe_remove(plain_tmp)) return VDISK_E_WIPE;   // 明文残片擦除失
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_write_file(VDiskHandle* h, const char* vpath,
                                       uint64_t offset, const uint8_t* in, uint64_t len) {
    try {
    if (!h || !vpath || !in) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;   // M5 空闲超时自动锁
    std::string rel = vpath_to_rel(vpath);
    VaultEntry* e = find_mut(h, rel);
    if (!e) return VDISK_E_NOTFOUND;
    // H2a
    // 杜绝回绕后 resize 变小、memcpy
    constexpr uint64_t kMaxWriteExpand = 1ull << 40;   // 1TiB
    if (len > SIZE_MAX - offset) return VDISK_E_BADARG;
    uint64_t wlimit = kMaxWriteExpand;
    if (e->size <= SIZE_MAX - wlimit) wlimit += e->size;   // 上限 = 当前大小 + 允
    if (offset > wlimit || len > wlimit - offset) return VDISK_E_BADARG;
    // 同 read_file
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);
    std::vector<unsigned char> plain; bool comp = false;
    if (!random_read_ptd(ptd, h->passphrase, 0, e->size, plain, &comp, true, nullptr)) {
        return VDISK_E_IO;
    }
    try {
        if (offset + len > plain.size()) plain.resize(offset + len, 0);
        std::memcpy(plain.data() + offset, in, len);
    } catch (const std::length_error&) {
        return VDISK_E_BADARG;   // 超 vector 理论上限
    } catch (const std::bad_alloc&) {
        return VDISK_E_NOMEM;    // 扩容失败
    }
    m7_release(h, ptd);     // M7
    CryptoMode used_mode = vd_write_mode(h);
    VDiskStatus st = rewrite_ptd(h, ptd, plain, rel_basename(e->rel_path), &used_mode);
    if (st != VDISK_OK) return st;
    invalidate_ptd_caches(h, rel, ptd);
    m7_hold(h, ptd);        // M7
    e->size = plain.size();
    e->mtime = (int64_t)time(nullptr);
    e->algo = vault_mode_str(used_mode);
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, *e, err)) return VDISK_E_IO;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 创建核心
// （整目录移入保留
static VDiskStatus vdisk_create_core(VDiskHandle* h, const char* vpath, int is_dir_flag, int64_t mtime) {
    try {
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if (rel.empty()) return VDISK_E_BADARG;          // 不允许
    if (rel.find("..") != std::string::npos) return VDISK_E_BADARG;  // 纵深防御
    // 新建路径
    // 末段是用户起
    size_t cslash = rel.find_last_of('/');
    if (cslash != std::string::npos && cslash > 0) {
        std::string cp = rel.substr(0, cslash);
        for (auto& e : h->index)
            if (e.is_dir && ci_equal(e.rel_path, cp)) { rel = e.rel_path + rel.substr(cslash); break; }
        if (rel.substr(0, cslash) == cp) {   // 无显式目录条目
            std::string pfx = cp + "/";
            for (auto& e : h->index)
                if (e.rel_path.size() > pfx.size() && ci_starts_with(e.rel_path, pfx)) {
                    rel = e.rel_path.substr(0, cp.size()) + rel.substr(cslash);
                    break;
                }
        }
    }
    if (find_mut(h, rel)) return VDISK_E_BADARG;   // 已存
    bool is_dir = is_dir_flag != 0;
    if (is_dir) {
        // 目录
        create_directory_recursive(h->library_dir + "/" + rel);
        VaultEntry e;
        e.rel_path = rel; e.store = ""; e.is_dir = true;
        e.size = 0; e.mtime = mtime > 0 ? mtime : (int64_t)time(nullptr);
        std::string err;
        if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, e, err)) return VDISK_E_IO;
        h->index.push_back(e);
        rebuild_index_caches(h);   // 立即可见
        return VDISK_OK;
    }
    // 文件
    VaultEntry e;
    e.rel_path = rel;
    e.store    = random_store_name();
    e.size = 0; e.mtime = (int64_t)time(nullptr);
    e.algo = vault_mode_str(vd_write_mode(h)); e.kdf = "argon2id";
    std::string ptd = ptd_path_for(h->library_dir, rel, e.store);
    if (ptd.empty() || file_exists(ptd)) return VDISK_E_BADARG;
    {   // 目录结构沿用 rel
        size_t pp = ptd.find_last_of('/');
        if (pp != std::string::npos) create_directory_recursive(ptd.substr(0, pp));
    }
    std::vector<unsigned char> plain;
    VDiskStatus st = rewrite_ptd(h, ptd, plain, rel_basename(rel));
    if (st != VDISK_OK) return st;
    m7_hold(h, ptd);        // M7
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, e, err)) return VDISK_E_IO;
    h->index.push_back(e);
    rebuild_index_caches(h);   // 立即可见
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_create_file_ex(VDiskHandle* h, const char* vpath, int is_dir_flag) {
    return vdisk_create_core(h, vpath, is_dir_flag, 0);   // 旧签名
}

// 建目录并指定 mtime
// 库内目录一律显
VDISK_API VDiskStatus vdisk_mkdir_ex(VDiskHandle* h, const char* vpath, int64_t mtime) {
    return vdisk_create_core(h, vpath, 1, mtime);
}

VDISK_API VDiskStatus vdisk_create_file(VDiskHandle* h, const char* vpath) {
    return vdisk_create_core(h, vpath, 0, 0);   // 旧签名
}

VDISK_API VDiskStatus vdisk_delete_file(VDiskHandle* h, const char* vpath) {
    return vdisk_delete_file_ex(h, vpath, nullptr, nullptr, nullptr, nullptr);
}

VDISK_API VDiskStatus vdisk_delete_file_ex(VDiskHandle* h, const char* vpath,
                                           VDiskProgressFn progress, void* user,
                                           VDiskCancelFn cancel, void* cancel_user) {
    try {
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if (rel.empty()) return VDISK_E_BADARG;          // 不允许删库根
    if (const VaultEntry* self = find_mut(h, rel)) rel = self->rel_path;   // 驱动归一化路径
    std::string pfx = rel + "/";
    const VaultEntry* self0 = find_entry(h->index, rel);
    // 目录
    std::vector<std::string> kids;
    for (const auto& e : h->index)
        if (ci_starts_with(e.rel_path, pfx)) kids.push_back(e.rel_path);
    if (!self0 && kids.empty()) return VDISK_E_NOTFOUND;

    // rel → 条目 一次建表
    // 万级条目删大目
    std::unordered_map<std::string, const VaultEntry*> byRel;
    byRel.reserve(h->index.size() * 2);
    for (const auto& e : h->index) byRel.emplace(e.rel_path, &e);

    // 先快照待删条目
    std::vector<std::pair<std::string, bool>> targets;   // rel → is_dir
    for (const auto& k : kids) {
        auto it = byRel.find(k);
        targets.emplace_back(k, it != byRel.end() && it->second->is_dir);
    }
    if (self0) targets.emplace_back(rel, self0->is_dir);

    // 阶段一
    std::vector<std::string> removed;
    bool wipe_fail = false;
    bool cancelled = false;
    for (size_t ti = 0; ti < targets.size(); ti++) {
        const auto& t = targets[ti];
        if (cancel && cancel(cancel_user) != 0) { cancelled = true; break; }
        if (t.second) { removed.push_back(t.first); continue; }   // 目录条目
        auto it = byRel.find(t.first);
        std::string store = (it != byRel.end()) ? it->second->store : std::string();
        if (remove_ptd_file(h, t.first, store)) removed.push_back(t.first);
        else wipe_fail = true;   
        if (progress) progress((uint64_t)(ti + 1), (uint64_t)targets.size(), user);
    }
    // 阶段二
    std::string e2;
    if (!removed.empty() &&
        !vault_remove_entries(h->library_dir, h->meta, h->passphrase, removed, e2))
        return VDISK_E_IO;
    {
        std::unordered_set<std::string> removedSet(removed.begin(), removed.end());
        for (auto it = h->index.begin(); it != h->index.end(); ) {
            it = removedSet.count(it->rel_path) ? h->index.erase(it) : it + 1;
        }
    }
    // 阶段三
    purge_ptds_under(h->library_dir + "/" + rel);
    prune_empty_dirs(h->library_dir, rel);
    rebuild_index_caches(h);   // 删完立即重建派
    if (cancelled) return VDISK_E_CANCELLED;   // 已删
    return wipe_fail ? VDISK_E_WIPE : VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_truncate_file(VDiskHandle* h, const char* vpath, uint64_t new_size) {
    try {
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    VaultEntry* e = find_mut(h, rel);
    if (!e) return VDISK_E_NOTFOUND;
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);   // 存原始大小写
    std::vector<unsigned char> plain; bool comp = false;
    if (!random_read_ptd(ptd, h->passphrase, 0, e->size, plain, &comp, true, nullptr)) {
        return VDISK_E_IO;
    }
    try {
        plain.resize(new_size, 0);   // H2c
    } catch (const std::length_error&) {
        return VDISK_E_BADARG;   // new_size 超 vector 理论上限
    } catch (const std::bad_alloc&) {
        return VDISK_E_NOMEM;    // 目标过大
    }
    m7_release(h, ptd);     // M7
    CryptoMode used_mode = vd_write_mode(h);
    VDiskStatus st = rewrite_ptd(h, ptd, plain, rel_basename(e->rel_path), &used_mode);
    if (st != VDISK_OK) return st;
    invalidate_ptd_caches(h, rel, ptd);
    m7_hold(h, ptd);        // M7
    e->size = new_size;
    e->mtime = (int64_t)time(nullptr);
    e->algo = vault_mode_str(used_mode);
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, *e, err)) return VDISK_E_IO;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 流式导入/导出
// 旧路径 rewrite_ptd 要
// 大文件
// Linux 桌面同编
#if defined(__ANDROID__) || defined(__linux__)
namespace {

// fd 输入流缓冲
// 上层据此回退全
class VdFdInBuf : public std::streambuf {
public:
    explicit VdFdInBuf(int fd) : fd_(fd) {}
protected:
    int_type underflow() override {
        if(gptr() < egptr()) return traits_type::to_int_type(*gptr());
        ssize_t n = ::read(fd_, rbuf_, sizeof(rbuf_));
        if(n <= 0) return traits_type::eof();
        char* b = reinterpret_cast<char*>(rbuf_);
        setg(b, b, b + n);
        return traits_type::to_int_type(*gptr());
    }
    pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                     std::ios_base::openmode which) override {
        if(!(which & std::ios_base::in)) return pos_type(off_type(-1));
        int whence = (dir == std::ios_base::beg) ? SEEK_SET
                 : (dir == std::ios_base::cur) ? SEEK_CUR : SEEK_END;
        intptr_t r = ::lseek(fd_, (off_t)off, whence);
        if(r < 0) return pos_type(off_type(-1));
        setg(nullptr, nullptr, nullptr);   // 位置已变
        return pos_type(r);   // 必须回绝对位置
    }
private:
    int fd_;
    unsigned char rbuf_[64 * 1024];
};

// fd 输出流缓冲
class VdFdOutBuf : public std::streambuf {
public:
    explicit VdFdOutBuf(int fd) : fd_(fd) {}
protected:
    int_type overflow(int_type c) override {
        if(traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
        char ch = traits_type::to_char_type(c);
        if(::write(fd_, &ch, 1) != 1) return traits_type::eof();
        return traits_type::not_eof(c);
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        std::streamsize left = n;
        while(left > 0) {
            ssize_t w = ::write(fd_, s, (size_t)left);
            if(w <= 0) return n - left;
            s += w;
            left -= w;
        }
        return n;
    }
    int sync() override { return 0; }
    pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                     std::ios_base::openmode which) override {
        if(!(which & std::ios_base::out)) return pos_type(off_type(-1));
        int whence = (dir == std::ios_base::beg) ? SEEK_SET
                 : (dir == std::ios_base::cur) ? SEEK_CUR : SEEK_END;
        intptr_t r = ::lseek(fd_, (off_t)off, whence);
        if(r < 0) return pos_type(off_type(-1));
        return pos_type(r);   // 绝对位置
    }
private:
    int fd_;
};

// C 进度回调 → std
std::function<void(size_t, size_t)> vd_wrap_progress(VDiskProgressFn cb, void* user) {
    if(!cb) return [](size_t, size_t) {};
    return [cb, user](size_t done, size_t total) {
        cb((uint64_t)done, (uint64_t)total, user);
    };
}

}  // namespace

// 流式导入
// 与 create_file_ex 同策略生成随
static VDiskStatus import_fd_impl(VDiskHandle* h, const char* vpath, int in_fd,
                                  VDiskProgressFn progress, void* user,
                                  int mode, int compress_policy) {
    try {
    if(!h || !vpath || in_fd < 0) return VDISK_E_BADARG;
    const CryptoMode cm = mode ? vd_mode_from_int(mode) : vd_write_mode(h);
    const int comp = (compress_policy == VDISK_COMPRESS_DEFAULT)
                   ? vd_compress_level(h) : compress_policy;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if(!h->unlocked) return VDISK_E_LOCKED;
    if(!h->rw) return VDISK_E_RO;
    if(!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if(rel.empty()) return VDISK_E_BADARG;
    if(rel.find("..") != std::string::npos) return VDISK_E_BADARG;   // 纵深防御
    // 覆盖导入
    if(find_mut(h, rel)) {
        VDiskStatus st = vdisk_delete_file(h, rel.c_str());
        if(st != VDISK_OK) return st;
    }
    // 明文大小取输入
    struct stat st{};
    uint64_t plain_size = (::fstat(in_fd, &st) == 0) ? (uint64_t)st.st_size : 0;
    ::lseek(in_fd, 0, SEEK_SET);

    VaultEntry e;
    e.rel_path = rel;
    e.store    = vault_random_store_name();
    e.size     = plain_size;
    e.mtime    = (int64_t)time(nullptr);
    e.algo = vault_mode_str(cm); e.kdf = "argon2id";
    std::string ptd = ptd_path_for(h->library_dir, rel, e.store);
    if(ptd.empty()) return VDISK_E_BADARG;
    {
        size_t pp = ptd.find_last_of('/');
        if(pp != std::string::npos) create_directory_recursive(ptd.substr(0, pp));
    }

    // 流式加密
    std::string ptd_tmp = ptd + ".rw.tmp";
    int out_fd = ::open(ptd_tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(out_fd < 0) return VDISK_E_IO;
    bool ok = false;
    {
        VdFdInBuf in_buf(in_fd);
        std::istream in(&in_buf);
        VdFdOutBuf out_buf(out_fd);
        std::ostream out(&out_buf);
        auto prog = vd_wrap_progress(progress, user);
        // 名字信封写库内
        // 信封
        std::string footer_name = rel_basename(rel);
        try {
            ok = encrypt_file(std::string(), std::string(), h->passphrase, cm,
                              prog, /*resume=*/false, comp,
                              /*asym_mode=*/false, nullptr, nullptr, nullptr, nullptr,
                              kM6Chunk, &in, &out, &footer_name);
        } catch(...) { ok = false; }
        out.flush();
    }
    ::close(out_fd);
    if(!ok) { wipe_remove(ptd_tmp); return VDISK_E_IO; }

    if(!replace_file_atomic(ptd_tmp, ptd)) { wipe_remove(ptd_tmp); return VDISK_E_IO; }
    std::string err;
    if(!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, e, err)) {
        wipe_remove(ptd);   // 登记失败
        return VDISK_E_IO;
    }
    h->index.push_back(e);
    rebuild_index_caches(h);   // 立即可见
    m7_hold(h, ptd);           // 挂载态占用
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_import_fd(VDiskHandle* h, const char* vpath, int in_fd,
                                      VDiskProgressFn progress, void* user) {
    return import_fd_impl(h, vpath, in_fd, progress, user, 0, VDISK_COMPRESS_DEFAULT);
}

VDISK_API VDiskStatus vdisk_import_fd_ex(VDiskHandle* h, const char* vpath, int in_fd,
                                          VDiskProgressFn progress, void* user,
                                          int mode, int compress_policy) {
    if (mode != 0 && !vd_mode_available(mode)) return VDISK_E_BADARG;
    return import_fd_impl(h, vpath, in_fd, progress, user, mode, compress_policy);
}

// 属性面板
VDISK_API VDiskStatus vdisk_get_file_info(VDiskHandle* h, const char* vpath,
                                          int* out_mode, int* out_compression,
                                          int* out_comp_level) {
    if (!h || !vpath) return VDISK_E_BADARG;
    try {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    const VaultEntry* e = find_entry(h->index, rel);
    if (!e || e->is_dir) return VDISK_E_NOTFOUND;
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);
    PtdMeta pm;
    if (!read_ptd_metadata(ptd, pm) || !pm.valid) return VDISK_E_IO;
    if (out_mode) *out_mode = vd_int_from_mode(pm.mode);
    if (out_compression) *out_compression = pm.compression ? 1 : 0;
    if (out_comp_level) *out_comp_level = pm.compression ? (int)(signed char)pm.comp_level : 0;
    return VDISK_OK;
    } catch (...) { return VDISK_E_INTERNAL; }
}

// 批量并行导入
// 单文件成本
// 就是 N 倍耗
VDISK_API VDiskStatus vdisk_import_many(VDiskHandle* h, const VDiskImportItem* items, size_t count,
                                        VDiskProgressFn progress, void* user,
                                        VDiskStatus* results,
                                        VDiskItemDoneFn done, void* done_user) {
    // flags=0
    return vdisk_import_many_ex(h, items, count, progress, user, results, done, done_user,
                                nullptr, nullptr, 0);
}

// 批量导入实现
static VDiskStatus import_many_impl(VDiskHandle* h, const VDiskImportItem* items, size_t count,
                                           VDiskProgressFn progress, void* user,
                                           VDiskItemProgressFn item_progress, void* item_user,
                                           VDiskStatus* results,
                                           VDiskItemDoneFn done, void* done_user,
                                           VDiskCancelFn cancel, void* cancel_user,
                                           uint32_t flags,
                                           int mode, int compress_policy) {
    try {
    if (!h || (!items && count > 0)) return VDISK_E_BADARG;
    if (count == 0) return VDISK_OK;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    // 本批算法/压缩
    const CryptoMode batch_mode = mode ? vd_mode_from_int(mode) : vd_write_mode(h);
    const int batch_comp = (compress_policy == VDISK_COMPRESS_DEFAULT)
                         ? vd_compress_level(h) : compress_policy;

    struct Job {
        std::string rel, store, ptd;
        VaultEntry entry;
        uint64_t size = 0;
        VDiskStatus st = VDISK_OK;
    };
    std::vector<Job> jobs(count);
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < count; i++) {
        Job& j = jobs[i];
        const VDiskImportItem& it = items[i];
        if (!it.vpath || it.in_fd < 0) { j.st = VDISK_E_BADARG; continue; }
        std::string rel = vpath_to_rel(it.vpath);
        // 路径穿越/库根一
        if (rel.empty() || rel.find("..") != std::string::npos) { j.st = VDISK_E_BADARG; continue; }
        if (find_mut(h, rel)) {                       // 覆盖导入
            VDiskStatus ds = vdisk_delete_file(h, rel.c_str());
            if (ds != VDISK_OK) { j.st = ds; continue; }
        }
        struct stat st{};
        uint64_t sz = (::fstat(it.in_fd, &st) == 0) ? (uint64_t)st.st_size : 0;
        ::lseek(it.in_fd, 0, SEEK_SET);
        j.rel = rel; j.size = sz; j.store = vault_random_store_name();
        j.entry.rel_path = rel; j.entry.store = j.store; j.entry.size = sz;
        j.entry.mtime = (int64_t)time(nullptr);
        j.entry.algo = vault_mode_str(batch_mode); j.entry.kdf = "argon2id";
        j.ptd = ptd_path_for(h->library_dir, rel, j.store);
        if (j.ptd.empty()) { j.st = VDISK_E_BADARG; continue; }
        size_t pp = j.ptd.find_last_of('/');
        if (pp != std::string::npos) create_directory_recursive(j.ptd.substr(0, pp));
        total_bytes += sz;
    }

    // KEK 选用
    // 本批现派生一次
    // KEK 只包裹 DEK
    unsigned char local_salt[ARGON2_SALT_LEN];
    SecureBuffer  local_kek;
    const unsigned char* use_salt;
    const unsigned char* use_kek;
    if (h->import_active && !h->import_salt.empty() && !h->import_kek.empty()) {
        // 跨批共用
        use_salt = h->import_salt.data();
        use_kek  = h->import_kek.data();
    } else {
        unsigned int kdf_ops = ARGON2_OPS_DEFAULT, kdf_mem_kb = ARGON2_MEM_DEFAULT_KB;
        kdf_preset_params(global_config().kdf_preset, kdf_ops, kdf_mem_kb);
        randombytes_buf(local_salt, sizeof(local_salt));
        unsigned char raw_kek[ARGON2_OUTPUT_LEN];
        bool kek_ok = derive_key(h->passphrase.data(), h->passphrase.size(), local_salt, raw_kek,
                                 kdf_ops, (size_t)kdf_mem_kb * 1024, ARGON2_OUTPUT_LEN);
        local_kek = SecureBuffer(raw_kek, sizeof(raw_kek));
        sodium_memzero(raw_kek, sizeof(raw_kek));
        if (!kek_ok) return VDISK_E_NOMEM;
        use_salt = local_salt;
        use_kek  = local_kek.data();
    }

    // 并行加密写盘
    std::atomic<uint64_t> done_bytes{0};
    unsigned nthreads = std::thread::hardware_concurrency();
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 16) nthreads = 16;
    if (nthreads > count) nthreads = (unsigned)count;
    std::atomic<size_t> next{0};
    std::atomic<bool> stop{false};      // 取消即停
    std::atomic<int>  live{0};          // 存活 worker 数
    // 完成队列
    std::mutex q_mtx;
    std::condition_variable q_cv;
    std::deque<size_t> ready;
    auto enqueue = [&](size_t i) {
        { std::lock_guard<std::mutex> _q(q_mtx); ready.push_back(i); }
        q_cv.notify_one();
    };
    auto worker = [&]() {
        for (;;) {
            if (stop.load()) break;   // 已取消
            size_t i = next.fetch_add(1);
            if (i >= count) break;
            Job& j = jobs[i];
            // 取消探询
            // 剩余项不逐项标
            // 取消计数
            if (cancel && cancel(cancel_user) != 0) { stop.store(true); break; }
            if (j.st != VDISK_OK) { enqueue(i); continue; }
            std::string tmp = j.ptd + ".rw.tmp";
            int out_fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            // 必须入队
            if (out_fd < 0) { j.st = VDISK_E_IO; enqueue(i); continue; }
            bool ok = false;
            {
                VdFdInBuf in_buf(items[i].in_fd);
                std::istream in(&in_buf);
                VdFdOutBuf out_buf(out_fd);
                std::ostream out(&out_buf);
                uint64_t last = 0;   // 本项进度
                uint64_t last_item_ms = 0;
                // 逐项进度起点
                if (item_progress) item_progress(i, 0, j.size, item_user);
                std::function<void(size_t, size_t)> prog = [&](size_t d, size_t) {
                    uint64_t cur = (uint64_t)d;
                    if (cur > last) { done_bytes += (cur - last); last = cur; }
                    if (item_progress) {
                        uint64_t now = now_ms();
                        uint64_t show = cur > j.size ? j.size : cur;
                        // 每项
                        if (show >= j.size || now - last_item_ms >= 100) {
                            last_item_ms = now;
                            item_progress(i, show, j.size, item_user);
                        }
                    }
                };
                // 名字信封写库内
                // 信封
                std::string footer_name = rel_basename(j.rel);
                try {
                    ok = encrypt_file(std::string(), std::string(), h->passphrase,
                                      batch_mode, prog, /*resume=*/false,
                                      batch_comp, /*asym_mode=*/false,
                                      /*asym_recipients=*/nullptr, /*wm=*/nullptr,
                                      /*ext_salt=*/use_salt, /*ext_kek=*/use_kek,
                                      kM6Chunk, &in, &out, &footer_name);
                } catch(...) { ok = false; }
                out.flush();
            }
            ::close(out_fd);
            if (!ok) { wipe_remove(tmp); j.st = VDISK_E_IO; enqueue(i); continue; }
            if (!replace_file_atomic(tmp, j.ptd)) { wipe_remove(tmp); j.st = VDISK_E_IO; enqueue(i); continue; }
            if (item_progress) item_progress(i, j.size, j.size, item_user);  // 收尾
            enqueue(i);
        }
        live.fetch_sub(1);
        q_cv.notify_all();   // 唤醒消费者
    };

    // 进度汇报线程
    // 开着空闲超
    // 超过超时值
    std::atomic<bool> finished{false};
    std::thread reporter;
    if (progress || h->idle_timeout_s > 0) {
        reporter = std::thread([&]() {
            uint64_t last = 0;
            while (!finished.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
                if (h->idle_timeout_s > 0) h->last_activity_ms.store(now_ms());
                if (!progress) continue;
                uint64_t d = done_bytes.load();
                if (d != last) { last = d; progress(d, total_bytes, user); }
            }
            if (progress) progress(done_bytes.load(), total_bytes, user);
        });
    }
    std::vector<std::thread> pool;
    live.store((int)nthreads);
    for (unsigned t = 0; t < nthreads; t++) pool.emplace_back(worker);
    // 本线程边等边登
    std::string err;
    std::vector<uint8_t> settled(count, 0);   // 已出队结算
    size_t consumed = 0;
    while (consumed < count) {
        size_t i;
        {
            std::unique_lock<std::mutex> _q(q_mtx);
            q_cv.wait(_q, [&] { return !ready.empty() || (stop.load() && live.load() == 0); });
            if (ready.empty()) break;   // 取消且 worker 全退
            i = ready.front(); ready.pop_front();
        }
        settled[i] = 1;
        Job& j = jobs[i];
        if (j.st == VDISK_OK) {
            // flush=false 累积
            if (!vault_append_entry(h->library_dir, h->meta, h->passphrase, j.entry, err, false)) {
                wipe_remove(j.ptd);   // 登记失败
                j.st = VDISK_E_IO;
            } else {
                h->index.push_back(j.entry);
                m7_hold(h, j.ptd);
            }
        }
        if (results) results[i] = j.st;
        if (done) done(i, j.st, done_user);
        consumed++;
    }
    // 取消收尾
    if (stop.load())
        for (size_t i = 0; i < count; i++)
            if (!settled[i] && results) results[i] = VDISK_E_CANCELLED;
    for (auto& th : pool) if (th.joinable()) th.join();
    finished = true;
    if (reporter.joinable()) reporter.join();
    if (!vault_flush_index(h->library_dir, h->meta, h->passphrase, err)) return VDISK_E_IO;
    if (!(flags & VDISK_IMPORT_NO_FINALIZE)) rebuild_index_caches(h);   // 跨批中间批
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 旧签名
VDISK_API VDiskStatus vdisk_import_many_ex(VDiskHandle* h, const VDiskImportItem* items, size_t count,
                                           VDiskProgressFn progress, void* user,
                                           VDiskStatus* results,
                                           VDiskItemDoneFn done, void* done_user,
                                           VDiskCancelFn cancel, void* cancel_user,
                                           uint32_t flags) {
    return import_many_impl(h, items, count, progress, user, nullptr, nullptr,
                            results, done, done_user,
                            cancel, cancel_user, flags, 0, VDISK_COMPRESS_DEFAULT);
}

// 本批显式指定算
VDISK_API VDiskStatus vdisk_import_many_ex_mode(VDiskHandle* h, const VDiskImportItem* items, size_t count,
                                                VDiskProgressFn progress, void* user,
                                                VDiskStatus* results,
                                                VDiskItemDoneFn done, void* done_user,
                                                VDiskCancelFn cancel, void* cancel_user,
                                                uint32_t flags, int mode, int compress_policy) {
    if (mode != 0 && !vd_mode_available(mode)) return VDISK_E_BADARG;
    return import_many_impl(h, items, count, progress, user, nullptr, nullptr,
                            results, done, done_user,
                            cancel, cancel_user, flags, mode, compress_policy);
}

// 逐项进度版
VDISK_API VDiskStatus vdisk_import_many_ex2(VDiskHandle* h, const VDiskImportItem* items, size_t count,
                                            VDiskProgressFn progress, void* user,
                                            VDiskItemProgressFn item_progress, void* item_user,
                                            VDiskStatus* results,
                                            VDiskItemDoneFn done, void* done_user,
                                            VDiskCancelFn cancel, void* cancel_user,
                                            uint32_t flags, int mode, int compress_policy) {
    if (mode != 0 && !vd_mode_available(mode)) return VDISK_E_BADARG;
    return import_many_impl(h, items, count, progress, user, item_progress, item_user,
                            results, done, done_user,
                            cancel, cancel_user, flags, mode, compress_policy);
}

// 跨批导入开始
// 省掉每批一次 Argon2id
VDISK_API VDiskStatus vdisk_import_begin(VDiskHandle* h) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    // 重入 begin
    h->import_active = false;
    h->import_salt.clear();
    h->import_kek.clear();
    unsigned int kdf_ops = ARGON2_OPS_DEFAULT, kdf_mem_kb = ARGON2_MEM_DEFAULT_KB;
    kdf_preset_params(global_config().kdf_preset, kdf_ops, kdf_mem_kb);
    h->import_salt.resize(ARGON2_SALT_LEN);
    randombytes_buf(h->import_salt.data(), ARGON2_SALT_LEN);
    unsigned char raw_kek[ARGON2_OUTPUT_LEN];
    if (!derive_key(h->passphrase.data(), h->passphrase.size(), h->import_salt.data(), raw_kek,
                    kdf_ops, (size_t)kdf_mem_kb * 1024, ARGON2_OUTPUT_LEN)) {
        h->import_salt.clear();
        return VDISK_E_NOMEM;
    }
    h->import_kek = SecureBuffer(raw_kek, sizeof(raw_kek));
    sodium_memzero(raw_kek, sizeof(raw_kek));
    h->import_active = true;
    return VDISK_OK;
    } catch(...) { return VDISK_E_INTERNAL; }
}

// 跨批导入结束
// 无论成功/取消/异
VDISK_API VDiskStatus vdisk_import_end(VDiskHandle* h) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->import_active = false;
    h->import_salt.clear();
    h->import_kek.clear();
    rebuild_index_caches(h);   // 单批已 flush 索引
    return VDISK_OK;
    } catch(...) { return VDISK_E_INTERNAL; }
}

// 流式导出
// 与 64KB chunk
VDISK_API VDiskStatus vdisk_export_fd(VDiskHandle* h, const char* vpath, int out_fd,
                                      VDiskProgressFn progress, void* user) {
    try {
    if(!h || !vpath || out_fd < 0) return VDISK_E_BADARG;
    std::string ptd;
    SecureBuffer pw;                 // 锁内取密码、锁外
    unsigned char kek[32];
    bool have_kek = false;
    {
        std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
        if(!h->unlocked) return VDISK_E_LOCKED;
        if(!touch_activity(h)) return VDISK_E_LOCKED;
        std::string rel = vpath_to_rel(vpath);
        if(rel.empty()) return VDISK_E_BADARG;
        const VaultEntry* e = find_entry(h->index, rel);
        if(!e || e->is_dir) return VDISK_E_NOTFOUND;
        ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);
        if(ptd.empty()) return VDISK_E_BADARG;
        pw = SecureBuffer(h->passphrase.data(), h->passphrase.size());
        // salt 级缓存
        have_kek = get_kek(h, ptd, kek);
    }
    // 解密放到锁外
    // 「点开预览一片黑」
    int in_fd = ::open(ptd.c_str(), O_RDONLY);
    if(in_fd < 0) { sodium_memzero(kek, sizeof(kek)); return VDISK_E_IO; }
    int rc = fe_m_decrypt_fd_kek(in_fd, out_fd,
                             pw.cdata(), pw.size(),
                             have_kek ? kek : nullptr, have_kek ? sizeof(kek) : 0,
                             /*force_overwrite=*/0, /*preview_bytes=*/0,
                             progress, user);
    ::close(in_fd);
    sodium_memzero(kek, sizeof(kek));
    switch(rc) {
        case FE_M_OK:    return VDISK_OK;
        case FE_M_E_AUTH: return VDISK_E_AUTH;
        case FE_M_E_HASH: return VDISK_E_IO;   // 明文哈希不符
        default:          return VDISK_E_IO;
    }

    } catch(...) { return VDISK_E_INTERNAL; }
}
#endif  // __ANDROID__

// 单项移动内核
// 不落盘
// 本项失败只回滚
struct RenameMove { std::string new_ptd, old_ptd; };
struct RenamePlan { size_t idx; std::string old_rel, new_rel; };

static VDiskStatus rename_apply_locked(VDiskHandle* h,
    const std::string& old_vpath, const std::string& new_vpath,
    std::vector<RenameMove>& moved, std::vector<RenamePlan>& plan) {
    try {
    std::string old_rel = vpath_to_rel(old_vpath.c_str());
    std::string new_rel = vpath_to_rel(new_vpath.c_str());
    if (old_rel.empty() || new_rel.empty()) return VDISK_E_BADARG;          // 不动库根
    if (old_rel.find("..") != std::string::npos || new_rel.find("..") != std::string::npos) return VDISK_E_BADARG;  // 防穿越
    // WinFSP Rename 回调
    // 取回真实源路径
    if (VaultEntry* oe = find_mut(h, old_rel)) old_rel = oe->rel_path;
    else {   // 隐式目录
        std::string pfx = old_rel + "/";
        for (auto& e : h->index)
            if (e.rel_path.size() > pfx.size() && ci_starts_with(e.rel_path, pfx)) {
                old_rel = e.rel_path.substr(0, old_rel.size());
                break;
            }
    }
    if (old_rel == new_rel) return VDISK_OK;
    // 移动时 NewFileName
    // 大小写
    size_t nslash = new_rel.find_last_of('/');
    if (nslash != std::string::npos && nslash > 0) {
        std::string np = new_rel.substr(0, nslash);
        for (auto& e : h->index)
            if (e.is_dir && ci_equal(e.rel_path, np)) { new_rel = e.rel_path + new_rel.substr(nslash); break; }
        if (new_rel.substr(0, nslash) == np) {   // 无显式目录条目
            std::string pfx = np + "/";
            for (auto& e : h->index)
                if (e.rel_path.size() > pfx.size() && ci_equal(e.rel_path.substr(0, pfx.size()), pfx)) {
                    new_rel = e.rel_path.substr(0, np.size()) + new_rel.substr(nslash);
                    break;
                }
        }
    }
    // 目标已存
    for (auto& e : h->index) {
        if (e.rel_path == old_rel) continue;
        if (ci_equal(e.rel_path, new_rel)) return VDISK_E_EXIST;
    }
    if (is_dir(h->index, new_rel)) return VDISK_E_EXIST;   // 目标是非空目录

    // 收集受影响条目
    std::string pfx = old_rel + "/";
    std::vector<size_t> affected;
    for (size_t i = 0; i < h->index.size(); ++i) {
        const std::string& r = h->index[i].rel_path;
        if (r == old_rel || ci_starts_with(r, pfx)) affected.push_back(i);
    }
    if (affected.empty()) return VDISK_E_NOTFOUND;   // 源不存

    // M37
    // 任一搬运失败即
    size_t moved_base = moved.size();
    size_t plan_base = plan.size();
    for (size_t idx : affected) {
        VaultEntry& e = h->index[idx];
        std::string suffix = (e.rel_path == old_rel) ? std::string() : e.rel_path.substr(old_rel.size());
        std::string nrel = new_rel + suffix;
        plan.push_back({ idx, e.rel_path, nrel });
        if (!e.is_dir && !e.store.empty()) {   // 文件
            std::string old_ptd = ptd_path_for(h->library_dir, e.rel_path, e.store);
            std::string new_ptd = ptd_path_for(h->library_dir, nrel, e.store);
            if (old_ptd != new_ptd && !old_ptd.empty() && !new_ptd.empty()) {
                size_t np = new_ptd.find_last_of('/');
                if (np != std::string::npos) create_directory_recursive(new_ptd.substr(0, np));
                m7_release(h, old_ptd);        // M7
                if (std::rename(old_ptd.c_str(), new_ptd.c_str()) != 0) {
                    while (moved.size() > moved_base) {   // 批量语境
                        std::rename(moved.back().new_ptd.c_str(), moved.back().old_ptd.c_str());
                        moved.pop_back();
                    }
                    plan.resize(plan_base);
                    return VDISK_E_IO;
                }
                moved.push_back({ new_ptd, old_ptd });
                invalidate_ptd_caches(h, e.rel_path, old_ptd);   // 旧 rel 缓存失效
            }
        }
    }
    // M37
    for (size_t pi = plan_base; pi < plan.size(); ++pi)
        h->index[plan[pi].idx].rel_path = plan[pi].new_rel;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 批量提交
static VDiskStatus commit_rename_locked(VDiskHandle* h,
    std::vector<RenameMove>& moved, std::vector<RenamePlan>& plan) {
    try {
    // 只写受影响分片
    std::vector<std::string> folders;
    auto folder_of = [](const std::string& rel) {
        size_t p = rel.rfind('/');
        return p == std::string::npos ? std::string() : rel.substr(0, p);
    };
    for (const auto& p : plan) {
        folders.push_back(folder_of(p.old_rel));
        folders.push_back(folder_of(p.new_rel));
    }
    std::sort(folders.begin(), folders.end());
    folders.erase(std::unique(folders.begin(), folders.end()), folders.end());
    std::string err;
    if (!vault_write_index_folders(h->library_dir, h->meta, h->passphrase,
                                   folders, h->index, err)) {
        // M37
        for (auto mit = moved.rbegin(); mit != moved.rend(); ++mit)
            std::rename(mit->new_ptd.c_str(), mit->old_ptd.c_str());
        for (auto it = plan.rbegin(); it != plan.rend(); ++it)
            h->index[it->idx].rel_path = it->old_rel;
        return VDISK_E_IO;
    }
    rebuild_index_caches(h);
    m7_refresh(h);          // M7
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 重命名 / 移动
// 受影响条目一次
VDISK_API VDiskStatus vdisk_rename(VDiskHandle* h, const char* old_vpath, const char* new_vpath) {
    try {
    if (!h || !old_vpath || !new_vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    // 改名/移动
    // 库外
    refresh_index_locked_force(h);
    std::vector<RenameMove> moved;
    std::vector<RenamePlan> plan;
    VDiskStatus rc = rename_apply_locked(h, old_vpath, new_vpath, moved, plan);
    if (rc != VDISK_OK) return rc;
    return commit_rename_locked(h, moved, plan);

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 批量移动/重命名
// 逐项尽力
// 返回值只反映整
VDISK_API VDiskStatus vdisk_rename_many(VDiskHandle* h,
    const char* const* old_paths, const char* const* new_paths, uint32_t count,
    VDiskStatus* out_status) {
    try {
    if (!h || !old_paths || !new_paths) return VDISK_E_BADARG;
    if (count == 0) return VDISK_OK;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    refresh_index_locked_force(h);
    std::vector<RenameMove> moved;
    std::vector<RenamePlan> plan;
    for (uint32_t i = 0; i < count; ++i) {
        VDiskStatus rc = VDISK_E_BADARG;
        if (old_paths[i] && new_paths[i])
            rc = rename_apply_locked(h, old_paths[i], new_paths[i], moved, plan);
        if (out_status) out_status[i] = rc;
    }
    return commit_rename_locked(h, moved, plan);

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_mount_rw(VDiskHandle* h, const char* mount_point) {
    try {
    if (!h || !mount_point) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->mount_point = mount_point;
    h->mounted = true;
    h->rw = true;
    m7_refresh(h);          // M7
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 重写 .ptd 尾部
// 名字密钥口径
static bool rewrite_footer_name(VDiskHandle* h, const std::string& ptd,
                                const std::string& new_base) {
    std::ifstream f;
    if (!open_stream(f, ptd, std::ios::binary)) return false;
    unsigned char hdr[HEADER_SIZE_V6];
    if (!f.read(reinterpret_cast<char*>(hdr), 5)) return false;
    if (!verify_magic(hdr)) return false;
    unsigned char ver = hdr[4];
    size_t hs = header_size_for_version(ver);
    if (hs == (size_t)-1 || hs > sizeof(hdr)) return false;
    f.clear();
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(hdr), (std::streamsize)hs)) return false;
    f.close();

    // 盐紧随加密模式
    const unsigned char* salt = (ver == 1) ? (hdr + 6) : (hdr + 12);
    unsigned char kek[32];
    if (!get_kek(h, ptd, kek)) return false;
    unsigned char master[32];
    bool ok = true;
    if (ver == 6) {
        FileHeaderV6 h6 = load_header<FileHeaderV6>(hdr);
        ok = unwrap_dek(h6.dek_box, kek, h6.dek_nonce, master);
    } else {
        memcpy(master, kek, 32);
    }
    sodium_memzero(kek, sizeof(kek));
    if (!ok) { sodium_memzero(master, sizeof(master)); return false; }

    // 只去掉 FENX 信封本体
    uint64_t footer_len = 0;
    uint32_t wm_len = 0;
    uint64_t drop = 0;
    if (fe_peek_name_footer_len(ptd, footer_len, &wm_len) && footer_len > 0)
        drop = footer_len - (wm_len ? (uint64_t)wm_len + 4 : 0);
    if (drop > 0) {
        std::error_code ec;
        uint64_t sz = fs::file_size(fs::u8path(ptd), ec);
        if (ec || drop > sz) { sodium_memzero(master, sizeof(master)); return false; }
        fs::resize_file(fs::u8path(ptd), (std::uintmax_t)(sz - drop), ec);
        if (ec) { sodium_memzero(master, sizeof(master)); return false; }
    }
    std::ofstream out;
    out.open(ptd, std::ios::binary | std::ios::app);
    if (!out) { sodium_memzero(master, sizeof(master)); return false; }
    ok = fe_append_encrypted_name_footer(out, new_base, master, salt);
    out.close();
    sodium_memzero(master, sizeof(master));
    return ok;
}

// 库内文件复制
// 这样大文件复制
// rewrite_name != 0 时额外重写尾部
VDISK_API VDiskStatus vdisk_copy_file_ex(VDiskHandle* h, const char* from, const char* to,
                                         int rewrite_name,
                                         VDiskProgressFn progress, void* user,
                                         VDiskCancelFn cancel, void* cancel_user) {
    try {
    if (!h || !from || !to) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    refresh_index_locked_force(h);

    std::string src_rel = vpath_to_rel(from);
    std::string dst_rel = vpath_to_rel(to);
    if (src_rel.empty() || dst_rel.empty()) return VDISK_E_BADARG;
    if (src_rel.find("..") != std::string::npos || dst_rel.find("..") != std::string::npos)
        return VDISK_E_BADARG;
    if (rel_is_reserved(dst_rel)) return VDISK_E_BADARG;   // 保留命名空间只

    const VaultEntry* se = find_mut(h, src_rel);
    if (!se) return VDISK_E_NOTFOUND;
    src_rel = se->rel_path;
    if (se->is_dir) return VDISK_E_NOTIMPL;                // 目录复制
    for (auto& e : h->index)
        if (ci_equal(e.rel_path, dst_rel)) return VDISK_E_EXIST;

    // 目标父目录必须
    size_t nslash = dst_rel.find_last_of('/');
    if (nslash != std::string::npos && nslash > 0) {
        std::string parent = dst_rel.substr(0, nslash);
        if (!is_dir(h->index, parent)) return VDISK_E_BADARG;
    }

    std::string src_ptd = ptd_path_for(h->library_dir, src_rel, se->store);
    if (src_ptd.empty() || !file_exists(src_ptd)) return VDISK_E_IO;

    std::string store;
    std::string dst_ptd;
    for (int i = 0; i < 32; i++) {
        store = random_store_name();
        dst_ptd = ptd_path_for(h->library_dir, dst_rel, store);
        if (!dst_ptd.empty() && !file_exists(dst_ptd)) break;
        dst_ptd.clear();
    }
    if (dst_ptd.empty()) return VDISK_E_INTERNAL;
    size_t dp = dst_ptd.find_last_of('/');
    if (dp != std::string::npos) create_directory_recursive(dst_ptd.substr(0, dp));

    std::uintmax_t total = 0;
    { std::error_code ec; total = fs::file_size(src_ptd, ec); if (ec) total = 0; }
    // 进度
    uint64_t plain = se->size;
    if (progress) progress(0, plain, user);

    std::string tmp = dst_ptd + ".copy.tmp";
    {
        std::ifstream in(src_ptd, std::ios::binary);
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!in || !out) return VDISK_E_IO;
        std::vector<unsigned char> buf(256 * 1024);
        uint64_t done = 0;
        while (in) {
            if (cancel && cancel(cancel_user)) {
                out.close(); std::remove(tmp.c_str());
                return VDISK_E_CANCELLED;
            }
            in.read((char*)buf.data(), (std::streamsize)buf.size());
            std::streamsize n = in.gcount();
            if (n > 0) {
                out.write((const char*)buf.data(), n);
                if (!out) { out.close(); std::remove(tmp.c_str()); return VDISK_E_IO; }
                done += (uint64_t)n;
                if (progress) {
                    uint64_t pd = (total > 0)
                        ? (uint64_t)((double)done * (double)plain / (double)total)
                        : 0;
                    progress(pd, plain, user);
                }
            }
        }
        out.close();
    }
    if (!replace_file_atomic(tmp, dst_ptd)) {
        std::remove(tmp.c_str());
        return VDISK_E_IO;
    }

    // 替换成
    if (rewrite_name && !rewrite_footer_name(h, dst_ptd, rel_basename(dst_rel))) {
        std::remove(dst_ptd.c_str());
        return VDISK_E_IO;
    }

    VaultEntry e = *se;
    e.rel_path = dst_rel;
    e.store = store;
    e.is_dir = false;
    e.mtime = (int64_t)time(nullptr);
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, e, err)) {
        std::remove(dst_ptd.c_str());
        return VDISK_E_IO;
    }
    h->index.push_back(e);
    rebuild_index_caches(h);
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 兼容入口
VDISK_API VDiskStatus vdisk_copy_file(VDiskHandle* h, const char* from, const char* to,
                                      VDiskProgressFn progress, void* user,
                                      VDiskCancelFn cancel, void* cancel_user) {
    return vdisk_copy_file_ex(h, from, to, 1, progress, user, cancel, cancel_user);
}

/*
 * 全库完整性自检：逐文件 verify_ptd（只验不解、不落盘）+ 索引/盘面交叉核对。
 * 不修改索引、不刷新时间戳；进程内持库互斥量（与批量导入同口径），
 * 取消在每个文件边界生效（单个大文件的校验不可中断）。
 */
VDISK_API VDiskStatus vdisk_check_library_ex(VDiskHandle* h, VDiskCheckResult* out,
                                             VDiskProgressFn progress, void* user,
                                             VDiskNameFn on_file, void* name_user,
                                             VDiskCancelFn cancel, void* cancel_user) {
    try {
    if (!h) return VDISK_E_BADARG;
    if (out) memset(out, 0, sizeof(*out));
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    refresh_index_locked_force(h);

    std::vector<const VaultEntry*> files;
    files.reserve(h->index.size());
    for (const auto& e : h->index)
        if (!e.is_dir && !e.rel_path.empty()) files.push_back(&e);

    uint64_t total = (uint64_t)files.size();
    if (out) out->files_total = total;
    if (progress) progress(0, total, user);

    uint64_t done = 0, failed = 0, missing = 0, bytes = 0;
    VDiskStatus rc = VDISK_OK;
    for (const VaultEntry* e : files) {
        if (cancel && cancel(cancel_user)) { rc = VDISK_E_CANCELLED; break; }
        // 先报「正
        if (on_file) on_file(("/" + e->rel_path).c_str(), name_user);
        if (progress) progress(done, total, user);
        std::string p = ptd_path_for(h->library_dir, e->rel_path, e->store);
        std::error_code ec;
        if (p.empty() || !fs::exists(fs::u8path(p), ec)) missing++;
        else if (!verify_ptd(p, h->passphrase)) failed++;
        else bytes += e->size;
        done++;
        if (progress) progress(done, total, user);
    }
    if (rc != VDISK_OK) {
        // 取消
        if (out) {
            out->files_checked = done;
            out->files_failed = failed;
            out->files_missing = missing;
            out->bytes_checked = bytes;
        }
        return rc;
    }

    // 盘面孤儿
    uint64_t orphans = 0;
    {
        std::unordered_set<std::string> referenced;
        referenced.reserve(files.size());
        for (const VaultEntry* e : files) {
            std::string p = ptd_path_for(h->library_dir, e->rel_path, e->store);
            if (p.empty()) continue;
            std::error_code rec;
            std::string rel = fs::relative(fs::u8path(p), fs::u8path(h->library_dir), rec).u8string();
            if (!rec) referenced.insert(rel);
        }
        std::error_code ec;
        auto it = fs::recursive_directory_iterator(fs::u8path(h->library_dir), ec);
        if (!ec) {
            for (; it != fs::recursive_directory_iterator(); ++it) {
                if (cancel && cancel(cancel_user)) { rc = VDISK_E_CANCELLED; break; }
                auto& de = *it;
                if (de.is_directory() && rel_is_reserved(fs::relative(de.path(), fs::u8path(h->library_dir), ec).u8string())) {
                    it.disable_recursion_pending();
                    continue;
                }
                if (!de.is_regular_file()) continue;
                if (de.path().extension().u8string() != ".ptd") continue;
                std::error_code rec;
                std::string rel = fs::relative(de.path(), fs::u8path(h->library_dir), rec).u8string();
                if (!rec && referenced.find(rel) == referenced.end()) orphans++;
            }
        }
    }

    if (out) {
        out->files_checked = done;
        out->files_failed = failed;
        out->files_missing = missing;
        out->orphans = orphans;
        out->bytes_checked = bytes;
    }
    return rc;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// 兼容入口
VDISK_API VDiskStatus vdisk_check_library(VDiskHandle* h, VDiskCheckResult* out,
                                          VDiskProgressFn progress, void* user,
                                          VDiskCancelFn cancel, void* cancel_user) {
    return vdisk_check_library_ex(h, out, progress, user, nullptr, nullptr, cancel, cancel_user);
}

/*
 * 无挂载场景（Android 等无 WinFSP/FUSE 平台）开写权限：只置 rw 位，
 * 不设挂载点、不做 M7 占用（移动端无外部进程删 .ptd，占用反而徒增开销）。
 * 写操作统一判 h->rw，故解锁后必须调本函数才能建/写/删。
 */
VDISK_API VDiskStatus vdisk_set_writable(VDiskHandle* h, int rw) {
    try {
    if (!h) return VDISK_E_BADARG;   // H2b
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->rw = rw != 0;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API const char* vdisk_strerror(VDiskStatus s) {
    try {
    switch (s) {
        case VDISK_OK: return "ok";
        case VDISK_E_BADARG: return "invalid argument";
        case VDISK_E_AUTH: return "authentication failed (wrong passphrase)";
        case VDISK_E_LOCKED: return "vault is locked";
        case VDISK_E_NOMEM: return "out of memory";
        case VDISK_E_IO: return "I/O error";
        case VDISK_E_WIPE: return "secure wipe failed";
        case VDISK_E_NOTIMPL: return "not implemented";
        case VDISK_E_NOTFOUND: return "not found";
        case VDISK_E_RO: return "read-only volume (mount with --rw to write)";
        case VDISK_E_EXIST: return "target already exists (rename/move conflict)";
        case VDISK_E_CANCELLED: return "cancelled by caller";
        case VDISK_E_INTERNAL: return "internal error";
    }
    return "unknown error";

    } catch(...) { return ""; }
}

VDISK_API uint32_t vdisk_abi_version(void) {
    try { return VDISK_ABI_VERSION; 
    } catch(...) { return 0; }
}

// 保留命名空间查
VDISK_API const char* vdisk_reserved_name(void) {
    return VDISK_RESERVED_TRASH;
}

VDISK_API int vdisk_is_reserved_path(const char* vpath) {
    try {
        return rel_is_reserved(vpath_to_rel(vpath)) ? 1 : 0;
    } catch(...) { return 0; }
}

// M4 恢复密钥
VDISK_API VDiskStatus vdisk_recovery_gen(char* out_code, uint64_t code_cap) {
    try {
    if (!out_code || code_cap < 49) return VDISK_E_BADARG;
    std::string c = vault_recovery_gen_code();
    if (c.size() + 1 > code_cap) return VDISK_E_BADARG;
    std::memcpy(out_code, c.c_str(), c.size() + 1);
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_recovery_create(VDiskHandle* h, const char* code) {
    try {
    if (!h || !code) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string err;
    if (!vault_recovery_create(h->library_dir, h->passphrase, code, err)) {
        return (err.find("48 decimal") != std::string::npos) ? VDISK_E_BADARG : VDISK_E_IO;
    }
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_recovery_open(VDiskHandle* h, const char* code,
                                          char* out_pass, uint64_t* len) {
    try {
    if (!h || !code || !out_pass || !len || *len == 0) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    SecureBuffer pw; std::string err;
    if (!vault_recovery_load(h->library_dir, code, pw, err)) return VDISK_E_AUTH;
    uint64_t n = pw.size();
    if (n + 1 > *len) return VDISK_E_BADARG;   // 低危
    std::memcpy(out_pass, pw.cdata(), n);
    out_pass[n] = '\0';
    *len = n;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_recovery_remove(VDiskHandle* h) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    std::string err;
    if (!vault_recovery_remove(h->library_dir, err)) return VDISK_E_IO;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

// M5 增强
VDISK_API VDiskStatus vdisk_set_idle_timeout(VDiskHandle* h, uint32_t seconds) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    h->idle_timeout_s = seconds;
    h->last_activity_ms = now_ms();
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API uint32_t vdisk_idle_remaining(VDiskHandle* h) {
    try {
    if (!h || h->idle_timeout_s == 0 || !h->unlocked) return UINT32_MAX;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    uint64_t elapsed = (now_ms() - h->last_activity_ms) / 1000ull;
    if (elapsed >= h->idle_timeout_s) return 0;
    return h->idle_timeout_s - (uint32_t)elapsed;

    } catch(...) { return 0; }
}

// 取路径
// Windows 用 GetVolumePathNameW 解析盘
static bool host_free_bytes(const std::string& path, uint64_t& out_free) {
#ifdef _WIN32
    std::wstring wp = utf8_to_wstring(path);
    WCHAR vol[MAX_PATH] = {0};
    if (GetVolumePathNameW(wp.c_str(), vol, MAX_PATH)) {
        ULARGE_INTEGER fab = {0}, tb = {0}, tfb = {0};
        if (GetDiskFreeSpaceExW(vol, &fab, &tb, &tfb)) {
            out_free = (uint64_t)fab.QuadPart;
            return true;
        }
    }
    return false;
#else
    struct statvfs st;
    if (statvfs(path.c_str(), &st) != 0) return false;
    out_free = (uint64_t)st.f_bavail * (uint64_t)st.f_frsize;
    return true;
#endif
}

VDISK_API VDiskStatus vdisk_stat_space(VDiskHandle* h, uint64_t* out_used, uint64_t* out_total) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    // 容量上限 = 加密盘
    // 卷总容量 = 已存数
    // 报告可用 = 宿主
    // 取不到宿主盘
    const uint64_t kReserve = 2ull * 1024 * 1024 * 1024;   // 预留 2GiB
    const uint64_t kMin = 64ull << 20;
    refresh_index_locked(h);   // 库外新入盘 → 容量
    uint64_t used = h->index_used_bytes;   // 库内文件明文总
    uint64_t host_free = 0;
    uint64_t total;
    if (host_free_bytes(h->library_dir, host_free)) {
        uint64_t free_for_vault = (host_free > kReserve) ? (host_free - kReserve) : 0;
        total = used + free_for_vault;
        if (total < kMin) total = kMin;
    } else {
        total = used ? used * 2 : kMin;
        if (total < used + kMin) total = used + kMin;
    }
    if (out_used)  *out_used = used;
    if (out_total) *out_total = total;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_stat_space_ex(VDiskHandle* h, uint64_t* out_used,
                                          uint64_t* out_trash, uint64_t* out_total) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    const uint64_t kReserve = 2ull * 1024 * 1024 * 1024;
    const uint64_t kMin = 64ull << 20;
    refresh_index_locked(h);
    uint64_t used = h->index_used_bytes;
    uint64_t trash = h->index_trash_bytes;
    uint64_t host_free = 0;
    uint64_t total;
    if (host_free_bytes(h->library_dir, host_free)) {
        uint64_t free_for_vault = (host_free > kReserve) ? (host_free - kReserve) : 0;
        total = used + free_for_vault;
        if (total < kMin) total = kMin;
    } else {
        total = used ? used * 2 : kMin;
        if (total < used + kMin) total = used + kMin;
    }
    if (out_used)  *out_used = used;
    if (out_trash) *out_trash = trash;
    if (out_total) *out_total = total;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}

VDISK_API VDiskStatus vdisk_set_read_cache(VDiskHandle* h, uint64_t cap_bytes, uint32_t ahead_segments) {
    try {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b
    if (cap_bytes == 0) {                     // 关闭
        for (auto& kv : h->seg_cache) sodium_memzero(kv.second.data(), kv.second.size());
        h->seg_cache.clear(); h->seg_lru.clear(); h->seg_lru_pos.clear(); h->seg_bytes = 0;
        h->cache_on = false; h->cache_cap_bytes = 0; h->cache_ahead = 0;
        return VDISK_OK;
    }
    if (cap_bytes < SEG_SIZE) cap_bytes = SEG_SIZE;
    h->cache_cap_bytes = cap_bytes;
    h->cache_ahead = ahead_segments;
    h->cache_on = true;
    return VDISK_OK;

    } catch(...) { return VDISK_E_INTERNAL; }
}
