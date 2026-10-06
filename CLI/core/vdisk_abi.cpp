// libvdisk C ABI 实现（设计文档 §5.2）。由 FE-Mounter 动态加载；只读为主，写留 M6。
// VDISK_BUILD 由构建系统（CMake vdisk 目标）定义，不要在此重复 #define。
#include "vdisk.h"
#include "FileEncryptor.hpp"   // random_read_ptd, SecureBuffer
#include "vault_index.hpp"     // VaultMeta/VaultEntry/vault_*
#include <sodium.h>
#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <chrono>
#include <new>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <filesystem>
#ifdef _WIN32
#  include <windows.h>
#endif

namespace fs = std::filesystem;

// §4.1 KEK LRU：活跃 KEK 硬上限 64 个（各 32B），5 分钟无访问淘汰；锁定/休眠全清。
// 缓存的是每文件的 Argon2 输出（v6 作 KEK 解裹 DEK，v3–v5 直接作主密钥）。
namespace {
constexpr size_t   LRU_MAX = 64;
constexpr uint64_t LRU_TTL_MS = 5ull * 60 * 1000;   // 5 分钟
}

struct KekEntry {
    SecureBuffer kek;          // 32B Argon2id(密码, 文件盐)
    uint64_t last_used_ms = 0;
};

// 库内部状态：句柄在 holder（FE-Mounter）进程内持有，锁定/休眠全清密钥。
struct VDiskHandle {
    std::string library_dir;
    VaultMeta meta;
    bool unlocked = false;
    SecureBuffer passphrase;                 // 逐文件随机读用；lock 时 memzero 释放
    std::vector<VaultEntry> index;           // 解密后的索引常驻（不含任何 KEK）
    std::vector<std::string> name_scratch;   // readdir name 存储，生命周期到下次 readdir/lock
    std::unordered_map<std::string, KekEntry> kek_cache;
    std::list<std::string> kek_lru;          // front = 最近使用
    std::string mount_point;
    bool mounted = false;
    bool rw = false;          // M6 可写挂载标志（由 vdisk_mount_rw 置位）
#ifdef _WIN32
    // M7：挂载期间占用所有 .ptd（access=0、不共享 DELETE），禁止外部删除；
    // 经 Z: 删除走 vdisk_delete_file（先释放占用再删）；写路径 replace 前释放、后重占。
    std::unordered_map<std::string, void*> held_ptd;
#endif
    // M5 空闲超时自动锁
    uint64_t last_activity_ms = 0;
    uint32_t idle_timeout_s = 0;
    // M5 预读缓存（64KB 段，明文只在内存，lock 即清）
    bool     cache_on = false;
    uint64_t cache_cap_bytes = 0;
    uint32_t cache_ahead = 0;
    std::unordered_map<std::string, std::vector<unsigned char>> seg_cache;
    std::list<std::string> seg_lru;
    uint64_t seg_bytes = 0;
    // WinFsp dispatcher 是多线程（StartDispatcher(fs,0) 按 CPU 数），IPC 线程又能并发
    // lock/unlock/purge；index 与两个缓存都是普通容器，无锁并发读写即 UB。
    // 递归锁：写路径会回调 vdisk_* 自身（如 truncate→getattr 语义），不可用普通锁。
    std::recursive_mutex mtx;
};

namespace {

// 虚拟路径 → 索引 rel_path（去首尾 '/'，统一分隔符）；"" 表示根。
std::string vpath_to_rel(const char* vpath) {
    std::string s = (vpath && *vpath) ? vpath : "/";
    for (char& c : s) if (c == '\\') c = '/';
    size_t i = 0; while (i < s.size() && s[i] == '/') i++;
    s = s.substr(i);
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

const VaultEntry* find_entry(const std::vector<VaultEntry>& idx, const std::string& rel) {
    for (const auto& e : idx) if (e.rel_path == rel) return &e;
    return nullptr;
}

bool is_dir(const std::vector<VaultEntry>& idx, const std::string& rel) {
    if (rel.empty()) return true;
    if (find_entry(idx, rel)) return false;
    std::string pfx = rel + "/";
    for (const auto& e : idx) if (e.rel_path.size() > pfx.size() && e.rel_path.compare(0, pfx.size(), pfx) == 0) return true;
    return false;
}

// 实际 .ptd 路径 / 随机存储名：统一走 vault_index 公共实现，避免多处规则分叉。
std::string ptd_path_for(const std::string& library_dir, const std::string& rel, const std::string& store) {
    return vault_ptd_path(library_dir, rel, store);
}
std::string random_store_name() { return vault_random_store_name(); }

uint64_t now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// 取某 ptd 的 Argon2 密钥材料：命中 LRU 则免派生（跳过 Argon2id）。写入 out[32]。
bool get_kek(VDiskHandle* h, const std::string& ptd, unsigned char out[32]) {
    const uint64_t now = now_ms();
    // 顺带淘汰过期项（5 分钟未访问）
    for (auto it = h->kek_lru.begin(); it != h->kek_lru.end(); ) {
        auto ce = h->kek_cache.find(*it);
        if (ce == h->kek_cache.end() || now - ce->second.last_used_ms > LRU_TTL_MS) {
            if (ce != h->kek_cache.end()) h->kek_cache.erase(ce);   // SecureBuffer 析构 memzero
            it = h->kek_lru.erase(it);
        } else ++it;
    }
    auto f = h->kek_cache.find(ptd);
    if (f != h->kek_cache.end()) {
        f->second.last_used_ms = now;
        h->kek_lru.remove(ptd);
        h->kek_lru.push_front(ptd);
        memcpy(out, f->second.kek.data(), 32);
        return true;
    }
    // miss：跑一次 Argon2id 派生并入缓存
    unsigned char buf[32];
    if (!fe_ptd_argon2_key(ptd, h->passphrase, buf)) return false;
    h->kek_cache.emplace(ptd, KekEntry{ SecureBuffer(buf, 32), now });
    h->kek_lru.push_front(ptd);
    if (h->kek_cache.size() > LRU_MAX) {          // 硬上限 64，淘汰最久未用
        std::string victim = h->kek_lru.back();
        h->kek_lru.pop_back();
        h->kek_cache.erase(victim);
    }
    memcpy(out, buf, 32);
    sodium_memzero(buf, sizeof(buf));
    return true;
}

// ---- 索引密钥进程内缓存 ----
// 索引读写每次都跑 Argon2id(0.25s)，批量入盘即 N 次全量 KDF。按库盐记忆派生结果。
// do_lock 时清（§4.1）。g_ikm 不进 h->mtx：vault_index 内部也会用到它。
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
// 清空索引密钥缓存（do_lock 调用）
void drop_index_key_cache() {
    std::lock_guard<std::mutex> lk(g_ikm);
    if (!g_ikm_key.empty()) sodium_memzero(g_ikm_key.data(), g_ikm_key.size());
    g_ikm_key.clear();
    g_ikm_salt.clear();
}
}  // namespace

void do_lock(VDiskHandle* h) {
    // 锁定前先把索引镜像的待落盘改动刷盘——必须在 passphrase 清除之前，
    // 否则索引密钥算不出来，最后一批改动直接丢。
    { std::string e2; vault_flush_index(h->library_dir, h->meta, h->passphrase, e2); }
    forget_cached_index_keys();   // 经 hook 转发到本 TU 的索引密钥缓存（§4.1）
    vault_drop_index_mirror();   // 镜像含明文 JSON，锁定即丢
    h->passphrase.clear();      // SecureBuffer::clear → sodium_memzero + 释放
    h->index.clear();
    h->name_scratch.clear();
    h->kek_cache.clear();       // 每个 SecureBuffer 析构 memzero → 锁定态零 KEK
    h->kek_lru.clear();
    // M5 预读缓存同样持有明文，锁定必须一并清零（不能只清 KEK）
    for (auto& kv : h->seg_cache) sodium_memzero(kv.second.data(), kv.second.size());
    h->seg_cache.clear();
    h->seg_lru.clear();
    h->seg_bytes = 0;
    h->unlocked = false;
}

// M5 空闲超时：数据访问前调用，超时则先自动锁定并返回 false。
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

// M5 只判超时、不刷新计时：给 readdir/getattr 这类「后台元数据查询」用。
// Explorer 打开盘后会持续轮询目录与文件属性（vol.FileInfoTimeout=1000，即每秒一轮），
// 若这些也算「活动」，last_activity_ms 会被无限刷新，空闲超时永远不触发。
// 真正的用户活动（读/写/新建/删除/改大小）才走 touch_activity 刷新计时。
bool check_idle_only(VDiskHandle* h) {
    const uint64_t now = now_ms();
    if (h->idle_timeout_s > 0 && h->unlocked &&
        (now - h->last_activity_ms) > (uint64_t)h->idle_timeout_s * 1000ull) {
        do_lock(h);
        return false;
    }
    return true;
}

// ---- M5 预读缓存 ----
constexpr uint64_t SEG_SIZE = 64ull * 1024;

// 分隔符用 '\0' 而非 '#'：文件名可含 '#'，用可打印字符分隔会碰撞
// （a#b + seg0 与 a + #b#seg0 同键 → 开启预读缓存时可能读到别的文件的明文段）。
std::string seg_key(const std::string& rel, uint64_t seg_idx) {
    std::string k = rel;
    k.push_back('\0');
    k.append(std::to_string(seg_idx));
    return k;
}
// 前缀匹配必须与 seg_key 的构造一致（含结尾 '\0'），否则失效条目清不掉
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
    h->seg_lru.remove(key);
    h->seg_lru.push_front(key);
    while (h->seg_bytes > h->cache_cap_bytes && !h->seg_lru.empty()) {
        std::string victim = h->seg_lru.back(); h->seg_lru.pop_back();
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
    h->seg_lru.remove(key);
    h->seg_lru.push_front(key);
    return &it->second;
}

} // namespace

// 清理存储目录里写入中断留下的临时件（.rw.tmp/.plain.tmp/.ptd.tmp/.feindex.tmp，及任意 .tmp），
// 避免它们被 reindex 当 .ptd 索引进挂载视图，也避免盘里出现来历不明的 tmp。
static void cleanup_vault_temp_files(const std::string& dir);

// 安全擦除并删除（UTF-8 路径安全；.plain.tmp 含明文必须擦除，不能只删）。
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
        CloseHandle(h);
    }
    DeleteFileW(utf8_to_wstring(p).c_str());
#else
    { std::ofstream f(p, std::ios::binary); }   // 截断即擦除明文（POSIX 窄串即 UTF-8）
    std::remove(p.c_str());
#endif
}

static void cleanup_vault_temp_files(const std::string& dir) {
    std::error_code ec;
    fs::path vdir = fs::u8path(dir);
    // 先收集再删：递归迭代时删除文件可能使迭代器失效
    std::vector<std::string> dead;
    fs::recursive_directory_iterator it(vdir, ec);
    if (ec) return;
    for (auto& e : it) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension().u8string() != ".tmp") continue;
        // 进行中的索引写会留 .feindex.tmp，仅当 .feindex 已存在（旧索引完好）才清
        if (e.path().filename().u8string() == ".feindex.tmp") {
            if (!fs::exists(e.path().parent_path() / ".feindex")) continue;
        }
        dead.push_back(e.path().u8string());
    }
    for (const auto& p : dead) {
        std::string stem = fs::path(p).stem().u8string();   // 去 .tmp 后的名
        if (stem.size() >= 6 && stem.compare(stem.size() - 6, 6, ".plain") == 0)
            secure_wipe_remove(p);   // 明文残片：擦除后再删
        else
            fs::remove(fs::u8path(p), ec);
    }
}

// M7：挂载态占用 .ptd 防外部删除。共享模式不含 FILE_SHARE_DELETE，他进程 DeleteFile /
// 打开+DELETE / MoveFile 全部失败（实测 err=32 SHARING_VIOLATION）。
// 访问权必须给 GENERIC_READ：dwDesiredAccess=0 的「零权限句柄」不参与 Windows 共享冲突仲裁，
// 后续请求 DELETE 的打开照样放行（实测 access=0 → DELETE ALLOWED，GENERIC_READ → BLOCKED）。
// 非 Windows 为空操作（POSIX 共享语义不同，且本程序主要为 Windows 挂载场景）。
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

VDISK_API VDiskHandle* vdisk_open(const char* library_dir) {
    if (!library_dir || !*library_dir) return nullptr;   // 句柄尚未创建，无从加锁
    VDiskHandle* h = new (std::nothrow) VDiskHandle();
    if (!h) return nullptr;
    h->library_dir = library_dir;
    // 注册索引密钥缓存（H5）：命中即省 0.25s Argon2id，批量入盘不再 N 次全量 KDF
    set_index_key_cache_hook(index_key_cached, drop_index_key_cache);
    std::string err;
    if (!vault_meta_load(h->library_dir, h->meta, err)) { delete h; return nullptr; }
    cleanup_vault_temp_files(h->library_dir);   // M8：清掉写入中断残留的 .tmp，避免盘里出现来历不明文件
    return h;
}

VDISK_API void vdisk_close(VDiskHandle* h) {
    if (!h) return;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    do_lock(h);
    m7_release_all(h);   // M7：释放 .ptd 占用，避免句柄泄漏
    delete h;
}

VDISK_API VDiskStatus vdisk_unlock(VDiskHandle* h, const char* passphrase, int use_recovery) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !passphrase) return VDISK_E_BADARG;
    SecureBuffer pw;
    if (use_recovery) {
        // §4.4：用恢复密钥解出主密码副本，再用主密码解锁（恢复密钥 = 等价解锁凭证）
        std::string rerr;
        if (!vault_recovery_load(h->library_dir, passphrase, pw, rerr)) return VDISK_E_AUTH;
    } else {
        pw = SecureBuffer(passphrase, std::strlen(passphrase));
    }
    std::vector<VaultEntry> entries;
    std::string err;
    if (!vault_read_index(h->library_dir, h->meta, pw, entries, err)) {
        return (err.find("wrong password") != std::string::npos) ? VDISK_E_AUTH : VDISK_E_IO;
    }
    h->passphrase = std::move(pw);
    h->index = std::move(entries);
    h->last_activity_ms = now_ms();   // M5 空闲计时起点
    h->unlocked = true;
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_lock(VDiskHandle* h) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    do_lock(h);
    return VDISK_OK;
}

VDISK_API void vdisk_purge_on_suspend(VDiskHandle* h) { if (h) do_lock(h); }

VDISK_API VDiskStatus vdisk_reindex(VDiskHandle* h, const char* root) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string r = (root && *root) ? root : h->library_dir;
    std::string err;
    if (!vault_reindex(r, h->meta, h->passphrase, err)) return VDISK_E_IO;
    std::vector<VaultEntry> entries;
    if (!vault_read_index(r, h->meta, h->passphrase, entries, err)) return VDISK_E_IO;
    h->index = std::move(entries);
    m7_refresh(h);          // M7：索引变化后重算 .ptd 占用集（仅挂载态实际占用）
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_mount_readonly(VDiskHandle* h, const char* mount_point) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !mount_point) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->mount_point = mount_point;
    h->mounted = true;
    h->rw = false;          // 显式只读，配合 write_* 的 VDISK_E_RO 守卫
    m7_refresh(h);          // M7：占用全部 .ptd，禁止外部删除
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_unmount(VDiskHandle* h) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    m7_release_all(h);   // M7：卸载即释放 .ptd 占用，否则外部仍删不动
    h->mounted = false;
    h->mount_point.clear();
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_readdir(VDiskHandle* h, const char* vpath,
                                    VDiskEntry** out_entries, uint64_t* out_count) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !out_count) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!check_idle_only(h)) return VDISK_E_LOCKED;   // M5 只判超时，不刷新计时（Explorer 会持续轮询目录）
    std::string rel = vpath_to_rel(vpath);
    if (!rel.empty() && !is_dir(h->index, rel) && !find_entry(h->index, rel)) return VDISK_E_NOTFOUND;

    struct Item { std::string name; bool dir; uint64_t size; uint64_t mtime; };
    std::vector<Item> items;
    std::string pfx = rel.empty() ? std::string() : rel + "/";
    for (const auto& e : h->index) {
        if (!pfx.empty()) {
            if (e.rel_path.size() <= pfx.size()) continue;
            if (e.rel_path.compare(0, pfx.size(), pfx) != 0) continue;
        }
        std::string rest = pfx.empty() ? e.rel_path : e.rel_path.substr(pfx.size());
        size_t slash = rest.find('/');
        std::string first = (slash == std::string::npos) ? rest : rest.substr(0, slash);
        bool dir = (slash != std::string::npos);
        bool dup = false;
        for (const auto& it : items) if (it.name == first) { dup = true; break; }
        if (!dup) items.push_back({ first, dir, dir ? 0 : e.size, dir ? 0 : (uint64_t)e.mtime });
    }

    uint64_t n = items.size();
    uint64_t cap = out_entries ? *out_count : 0;
    *out_count = n;
    if (!out_entries) return VDISK_OK;        // 第一段：查询数量
    if (cap < n) return VDISK_E_BADARG;       // 容量不足，调用方应重试

    h->name_scratch.clear();
    h->name_scratch.reserve(n);
    for (const auto& it : items) h->name_scratch.push_back(it.name);
    for (uint64_t i = 0; i < n; i++) {
        (*out_entries)[i].name = h->name_scratch[i].c_str();
        (*out_entries)[i].is_dir = items[i].dir ? 1 : 0;
        (*out_entries)[i].size = items[i].size;
        (*out_entries)[i].mtime = items[i].mtime;
    }
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_getattr(VDiskHandle* h, const char* vpath,
                                    uint64_t* out_size, uint64_t* out_mtime, uint8_t* out_is_dir) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!check_idle_only(h)) return VDISK_E_LOCKED;   // M5 只判超时，不刷新计时（同上，属性查询属后台轮询）
    std::string rel = vpath_to_rel(vpath);
    uint64_t now = (uint64_t)time(nullptr);
    if (rel.empty()) {
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = now;
        if (out_is_dir) *out_is_dir = 1;
        return VDISK_OK;
    }
    if (const VaultEntry* e = find_entry(h->index, rel)) {
        if (out_size) *out_size = e->size;
        if (out_mtime) *out_mtime = (uint64_t)e->mtime;
        if (out_is_dir) *out_is_dir = 0;
        return VDISK_OK;
    }
    if (is_dir(h->index, rel)) {
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = now;
        if (out_is_dir) *out_is_dir = 1;
        return VDISK_OK;
    }
    return VDISK_E_NOTFOUND;
}

VDISK_API VDiskStatus vdisk_read_file(VDiskHandle* h, const char* vpath,
                                      uint64_t offset, uint8_t* out, uint64_t* len) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !out || !len) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!touch_activity(h)) return VDISK_E_LOCKED;   // M5 空闲超时自动锁
    std::string rel = vpath_to_rel(vpath);
    const VaultEntry* e = find_entry(h->index, rel);
    if (!e) return VDISK_E_NOTFOUND;
    uint64_t want = *len;
    *len = 0;
    if (want == 0) return VDISK_OK;
    if (offset >= e->size) return VDISK_OK;
    std::string ptd = ptd_path_for(h->library_dir, rel, e->store);
    // §4.1：优先取 LRU 缓存的 Argon2 材料（命中则跳过 Argon2id），否则派生并入缓存
    unsigned char kek[32];
    bool have_kek = get_kek(h, ptd, kek);
    const unsigned char* pre_kek = have_kek ? kek : nullptr;

    // M5 预读缓存：按 64KB 段命中/回填，读完顺带预取后续段
    if (h->cache_on && h->cache_cap_bytes > 0) {
        uint64_t end = offset + want;
        uint64_t first = offset / SEG_SIZE, last = (end - 1) / SEG_SIZE;
        uint64_t written = 0;
        for (uint64_t s = first; s <= last && written < want; s++) {
            std::string key = seg_key(rel, s);
            if (!seg_get(h, key)) {
                std::vector<unsigned char> tmp; bool comp = false;
                if (!random_read_ptd(ptd, h->passphrase, s * SEG_SIZE, SEG_SIZE, tmp, &comp,
                                     /*silent=*/true, pre_kek)) {
                    sodium_memzero(kek, sizeof(kek));
                    if (comp) return VDISK_E_NOTIMPL;
                    return VDISK_E_IO;
                }
                seg_put(h, key, std::move(tmp));
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
            std::vector<unsigned char> tmp; bool comp = false;
            if (random_read_ptd(ptd, h->passphrase, s * SEG_SIZE, SEG_SIZE, tmp, &comp,
                                /*silent=*/true, pre_kek) && !tmp.empty() && !comp)
                seg_put(h, key, std::move(tmp));
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
    if (!ok) {
        if (compressed) return VDISK_E_NOTIMPL;   // 压缩块需整文件解密，M2 未实现
        return VDISK_E_IO;
    }
    uint64_t got = buf.size();
    if (got > want) got = want;
    if (got > 0) std::memcpy(out, buf.data(), got);
    sodium_memzero(buf.data(), buf.size());
    *len = got;
    return VDISK_OK;
}

// ===================== M6 写支持 =====================
// 可写挂载要求文件为 64KB 非压缩对称块（可用 M4 vault-recrypt 预转换）。
// 策略：读出明文 → 应用改动 → encrypt_file 重写为 64KB 非压缩 .ptd.tmp → 原子 rename。
// 天然满足设计文档「非原地重加密 + 原子 rename」，崩溃可据 .rw.tmp 回滚。
static constexpr uint32_t kM6Chunk = 65536;

// §4.5 安全擦除：多遍覆写（0x00/0xFF/0xAA）后删除；任一写失败返回 false。
// 原子替换目标为 src（先删后 rename 会在两步之间崩溃导致目标永久丢失）。
// Windows 用 MoveFileExW(MOVEFILE_REPLACE_EXISTING) 单调用完成；POSIX rename 本身即原子覆盖。
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

static VaultEntry* find_mut(VDiskHandle* h, const std::string& rel) {
    for (auto& e : h->index) if (e.rel_path == rel) return &e;
    return nullptr;
}

// 写/截断后使该文件缓存失效：重加密会换 salt，旧 KEK 与明文段不再有效，否则后续读解密失败
static void invalidate_ptd_caches(VDiskHandle* h, const std::string& rel, const std::string& ptd) {
    h->kek_cache.erase(ptd);
    h->kek_lru.remove(ptd);
    std::string prefix = seg_prefix(rel);
    for (auto it = h->seg_cache.begin(); it != h->seg_cache.end(); ) {
        if (it->first.compare(0, prefix.size(), prefix) == 0) {
            sodium_memzero(it->second.data(), it->second.size());
            it = h->seg_cache.erase(it);
        } else ++it;
    }
}

// 把明文重加密为 64KB 非压缩 .ptd（XChaCha20），原子覆盖；明文临时文件用后即擦除。
static VDiskStatus rewrite_ptd(VDiskHandle* h, const std::string& ptd,
                               std::vector<unsigned char>& plain) {
    std::string plain_tmp = ptd + ".plain.tmp";
    {
        std::ofstream pf(plain_tmp, std::ios::binary | std::ios::trunc);
        if (!pf) return VDISK_E_IO;
        if (!plain.empty()) pf.write((const char*)plain.data(), (std::streamsize)plain.size());
    }
    std::string ptd_tmp = ptd + ".rw.tmp";
    if (!encrypt_file(plain_tmp, ptd_tmp, h->passphrase, CryptoMode::XCHACHA20,
                      nullptr, false, 0, false, nullptr, nullptr, nullptr, nullptr, kM6Chunk)) {
        wipe_remove(plain_tmp);
        return VDISK_E_IO;
    }
    // 原子替换：先删后 rename 在两步之间崩溃/断电会导致原 .ptd 永久丢失（§4.5 顺序被破坏）。
    // MoveFileExW(MOVEFILE_REPLACE_EXISTING) 单系统调用完成替换；POSIX 用 rename 覆盖即可。
    if (!replace_file_atomic(ptd_tmp, ptd)) {
        wipe_remove(plain_tmp);
        return VDISK_E_IO;
    }
    if (!wipe_remove(plain_tmp)) return VDISK_E_WIPE;   // 明文残片擦除失败按 §4.5 拒绝完成
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_write_file(VDiskHandle* h, const char* vpath,
                                       uint64_t offset, const uint8_t* in, uint64_t len) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !vpath || !in) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;   // M5 空闲超时自动锁
    std::string rel = vpath_to_rel(vpath);
    VaultEntry* e = find_mut(h, rel);
    if (!e) return VDISK_E_NOTFOUND;
    std::string ptd = ptd_path_for(h->library_dir, rel, e->store);
    std::vector<unsigned char> plain; bool comp = false;
    if (!random_read_ptd(ptd, h->passphrase, 0, e->size, plain, &comp, true, nullptr)) {
        if (comp) return VDISK_E_NOTIMPL;   // 压缩块不可随机写，需先 vault-recrypt
        return VDISK_E_IO;
    }
    if (offset + len > plain.size()) plain.resize(offset + len, 0);
    std::memcpy(plain.data() + offset, in, len);
    m7_release(h, ptd);     // M7：替换前先释放占用，否则 MoveFileEx REPLACE_EXISTING 被占用挡住
    VDiskStatus st = rewrite_ptd(h, ptd, plain);
    if (st != VDISK_OK) return st;
    invalidate_ptd_caches(h, rel, ptd);
    m7_hold(h, ptd);        // M7：重占（仅挂载态）
    e->size = plain.size();
    e->mtime = (int64_t)time(nullptr);
    e->algo = "XChaCha20";
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, *e, err)) return VDISK_E_IO;
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_create_file(VDiskHandle* h, const char* vpath) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !vpath) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if (find_mut(h, rel)) return VDISK_E_BADARG;   // 已存在则拒绝（避免覆盖）
    // 挂载新建同样用随机存储名，与入盘保持一致的命名策略
    VaultEntry e;
    e.rel_path = rel;
    e.store    = random_store_name();
    e.size = 0; e.mtime = (int64_t)time(nullptr);
    e.algo = "XChaCha20"; e.kdf = "argon2id";
    std::string ptd = ptd_path_for(h->library_dir, rel, e.store);
    if (file_exists(ptd)) return VDISK_E_BADARG;
    {   // 目录结构沿用 rel，需先建父目录
        size_t pp = ptd.find_last_of('/');
        if (pp != std::string::npos) create_directory_recursive(ptd.substr(0, pp));
    }
    std::vector<unsigned char> plain;
    VDiskStatus st = rewrite_ptd(h, ptd, plain);
    if (st != VDISK_OK) return st;
    m7_hold(h, ptd);        // M7：新建文件后占用（仅挂载态）
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, e, err)) return VDISK_E_IO;
    h->index.push_back(e);
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_delete_file(VDiskHandle* h, const char* vpath) {
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if (rel.empty()) return VDISK_E_BADARG;          // 不允许删库根
    std::string pfx = rel + "/";
    if (!find_mut(h, rel) && !is_dir(h->index, rel)) return VDISK_E_NOTFOUND;
    // 目录：先递归删子项（索引里目录无独立条目，只能按前缀收集）
    std::vector<std::string> kids;
    for (const auto& e : h->index)
        if (e.rel_path.compare(0, pfx.size(), pfx) == 0) kids.push_back(e.rel_path);
    for (const auto& k : kids) {                     // 逐个删文件（递归子目录由本函数处理）
        const VaultEntry* ke = find_entry(h->index, k);
        std::string kp = ptd_path_for(h->library_dir, k, ke ? ke->store : std::string());
        m7_release(h, kp);   // M7：删前释放占用，否则 wipe_remove 的 DeleteFile 被占用挡住
        wipe_remove(kp + ".plain.tmp"); wipe_remove(kp + ".rw.tmp");
        if (!wipe_remove(kp)) return VDISK_E_WIPE;
        invalidate_ptd_caches(h, k, kp);
        std::string e2;
        if (!vault_remove_entry(h->library_dir, h->meta, h->passphrase, k, e2)) return VDISK_E_IO;
        for (auto it = h->index.begin(); it != h->index.end(); ++it)
            if (it->rel_path == k) { h->index.erase(it); break; }
    }
    if (kids.empty()) {   // 普通文件
        const VaultEntry* fe = find_entry(h->index, rel);
        std::string ptd = ptd_path_for(h->library_dir, rel, fe ? fe->store : std::string());
        m7_release(h, ptd);   // M7：删前释放占用，否则 wipe_remove 的 DeleteFile 被占用挡住
        wipe_remove(ptd + ".plain.tmp");   // 清上一次异常残留
        wipe_remove(ptd + ".rw.tmp");
        if (!wipe_remove(ptd)) return VDISK_E_WIPE;
        invalidate_ptd_caches(h, rel, ptd);
        std::string err;
        if (!vault_remove_entry(h->library_dir, h->meta, h->passphrase, rel, err)) return VDISK_E_IO;
        for (auto it = h->index.begin(); it != h->index.end(); ++it)
            if (it->rel_path == rel) { h->index.erase(it); break; }
    }
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_truncate_file(VDiskHandle* h, const char* vpath, uint64_t new_size) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !vpath) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    VaultEntry* e = find_mut(h, rel);
    if (!e) return VDISK_E_NOTFOUND;
    std::string ptd = ptd_path_for(h->library_dir, rel, e->store);
    std::vector<unsigned char> plain; bool comp = false;
    if (!random_read_ptd(ptd, h->passphrase, 0, e->size, plain, &comp, true, nullptr)) {
        if (comp) return VDISK_E_NOTIMPL;
        return VDISK_E_IO;
    }
    plain.resize(new_size, 0);
    m7_release(h, ptd);     // M7：替换前先释放占用
    VDiskStatus st = rewrite_ptd(h, ptd, plain);
    if (st != VDISK_OK) return st;
    invalidate_ptd_caches(h, rel, ptd);
    m7_hold(h, ptd);        // M7：重占（仅挂载态）
    e->size = new_size;
    e->mtime = (int64_t)time(nullptr);
    e->algo = "XChaCha20";
    std::string err;
    if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, *e, err)) return VDISK_E_IO;
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_mount_rw(VDiskHandle* h, const char* mount_point) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !mount_point) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->mount_point = mount_point;
    h->mounted = true;
    h->rw = true;
    m7_refresh(h);          // M7：占用全部 .ptd，禁止外部删除
    return VDISK_OK;
}

VDISK_API const char* vdisk_strerror(VDiskStatus s) {
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
        case VDISK_E_INTERNAL: return "internal error";
    }
    return "unknown error";
}

// ===================== M4 恢复密钥（§4.4）=====================
VDISK_API VDiskStatus vdisk_recovery_gen(char* out_code, uint64_t code_cap) {
    if (!out_code || code_cap < 49) return VDISK_E_BADARG;
    std::string c = vault_recovery_gen_code();
    if (c.size() + 1 > code_cap) return VDISK_E_BADARG;
    std::memcpy(out_code, c.c_str(), c.size() + 1);
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_recovery_create(VDiskHandle* h, const char* code) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !code) return VDISK_E_BADARG;
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string err;
    if (!vault_recovery_create(h->library_dir, h->passphrase, code, err)) {
        return (err.find("48 decimal") != std::string::npos) ? VDISK_E_BADARG : VDISK_E_IO;
    }
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_recovery_open(VDiskHandle* h, const char* code,
                                          char* out_pass, uint64_t* len) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || !code || !out_pass || !len || *len == 0) return VDISK_E_BADARG;
    SecureBuffer pw; std::string err;
    if (!vault_recovery_load(h->library_dir, code, pw, err)) return VDISK_E_AUTH;
    uint64_t n = pw.size();
    if (n + 1 > *len) { *len = n + 1; return VDISK_E_BADARG; }   // 容量不足，回填所需
    std::memcpy(out_pass, pw.cdata(), n);
    out_pass[n] = '\0';
    *len = n;
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_recovery_remove(VDiskHandle* h) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    std::string err;
    if (!vault_recovery_remove(h->library_dir, err)) return VDISK_E_IO;
    return VDISK_OK;
}

// ===================== M5 增强 =====================
VDISK_API VDiskStatus vdisk_set_idle_timeout(VDiskHandle* h, uint32_t seconds) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    h->idle_timeout_s = seconds;
    h->last_activity_ms = now_ms();
    return VDISK_OK;
}

VDISK_API uint32_t vdisk_idle_remaining(VDiskHandle* h) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h || h->idle_timeout_s == 0 || !h->unlocked) return UINT32_MAX;
    uint64_t elapsed = (now_ms() - h->last_activity_ms) / 1000ull;
    if (elapsed >= h->idle_timeout_s) return 0;
    return h->idle_timeout_s - (uint32_t)elapsed;
}

VDISK_API VDiskStatus vdisk_stat_space(VDiskHandle* h, uint64_t* out_used, uint64_t* out_total) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    // 容量随内容动态扩展：下限 64MiB，按已用量的 2 倍留增长余量，最小增量 64MiB。
    // 固定值（如 1TiB）会让 explorer/磁盘管理显示与实际占用严重脱节。
    const uint64_t kMin = 64ull << 20, kStep = 64ull << 20;
    uint64_t used = 0;
    for (const auto& e : h->index) used += (e.size > 0) ? (uint64_t)e.size : 0;   // 索引内均为文件条目
    uint64_t total = used ? used * 2 : kMin;
    if (total < kMin) total = kMin;
    if (total < used + kStep) total = used + kStep;   // 至少留一档余量
    if (out_used)  *out_used = used;
    if (out_total) *out_total = total;
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_set_read_cache(VDiskHandle* h, uint64_t cap_bytes, uint32_t ahead_segments) {
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h) return VDISK_E_BADARG;
    if (cap_bytes == 0) {                     // 关闭：清零现存明文
        for (auto& kv : h->seg_cache) sodium_memzero(kv.second.data(), kv.second.size());
        h->seg_cache.clear(); h->seg_lru.clear(); h->seg_bytes = 0;
        h->cache_on = false; h->cache_cap_bytes = 0; h->cache_ahead = 0;
        return VDISK_OK;
    }
    if (cap_bytes < SEG_SIZE) cap_bytes = SEG_SIZE;
    h->cache_cap_bytes = cap_bytes;
    h->cache_ahead = ahead_segments;
    h->cache_on = true;
    return VDISK_OK;
}
