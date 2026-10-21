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
#include <unordered_set>
#include <chrono>
#include <new>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <filesystem>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <sys/statvfs.h>   // statvfs：POSIX 卷容量查询（host_free_bytes）
#endif

namespace fs = std::filesystem;

// §4.1 KEK LRU：活跃 KEK 硬上限 64 个（各 32B），5 分钟无访问淘汰；锁定/休眠全清。
// 缓存的是每文件的 Argon2 输出（v6 作 KEK 解裹 DEK，v3–v5 直接作主密钥）。
namespace {
constexpr size_t   LRU_MAX = 2048;   // 活跃 KEK 上限；多文件场景(数千张图)避免反复派生 Argon2
constexpr uint64_t LRU_TTL_MS = 5ull * 60 * 1000;   // 5 分钟
}

struct KekEntry {
    SecureBuffer kek;          // 32B Argon2id(密码, 文件盐)
    uint64_t last_used_ms = 0;
};

// 目录枚举的「直接子项」（readdir 一次性取用，避免每次全索引扫描 + 嵌套去重）
struct DirChild {
    std::string name;
    uint64_t size = 0;
    uint64_t mtime = 0;
};

// 库内部状态：句柄在 holder（FE-Mounter）进程内持有，锁定/休眠全清密钥。
struct VDiskHandle {
    std::string library_dir;
    VaultMeta meta;
    bool unlocked = false;
    SecureBuffer passphrase;                 // 逐文件随机读用；lock 时 memzero 释放
    std::vector<VaultEntry> index;           // 解密后的索引常驻（不含任何 KEK）
    std::vector<std::string> name_scratch;   // readdir name 存储，生命周期到下次 readdir/lock
    // 索引派生缓存：仅在索引重载时重建一次（O(N)），热点路径据此降到 O(1)/O(子项)。
    // 此前 readdir/getattr/stat_space 每次都对整个索引做线性扫描（甚至嵌套去重 O(N²)），
    // 文件数大 + Explorer 滚动反复调用时直接卡成 PPT。
    std::unordered_map<std::string, size_t> index_map;          // rel_path → h->index 下标
    std::unordered_map<std::string, std::vector<DirChild>> dir_children; // 父目录(""=根) → 直接子项
    std::unordered_set<std::string> dir_set;                   // 所有目录 rel（含根 ""）
    uint64_t index_used_bytes = 0;                             // 索引内文件明文总大小（stat_space 缓存）
    uint64_t feindex_stamp_ms = 0;                             // 索引 mtime 轮询节流时间戳（200ms）
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
    // 索引变更标记：分目录模式下为 .feindex.d 目录 mtime（任何 .idx 原子替换都会 bump 它）；
    // 旧单 .feindex 回退为 mtime+size。sharded 标记当前处于哪种模式。
    uint64_t feindex_mtime = 0;
    uint64_t feindex_size = 0;
    bool     feindex_sharded = false;
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

// Windows 语义大小写不敏感：查找键统一 ASCII 小写（CJK 不受驱动归一化影响）。
// WinFSP 驱动会把 FileName/新建路径大写归一化后传入，索引却存原始大小写，
// 精确匹配必然失配——所有查找键与查找函数一并 ci 化，显示仍用原始大小写。
std::string ci_key(const std::string& s) {
    std::string k = s;
    for (char& c : k) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return k;
}
// a 前 b.size() 个字符与 b 大小写不敏感相等（a 长度需 >= b）
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

// 大小写不敏感查找：先精确（快路径），后 ci 扫描
const VaultEntry* find_entry(const std::vector<VaultEntry>& idx, const std::string& rel) {
    for (const auto& e : idx) if (e.rel_path == rel) return &e;
    for (const auto& e : idx) if (ci_equal(e.rel_path, rel)) return &e;
    return nullptr;
}

bool is_dir(const std::vector<VaultEntry>& idx, const std::string& rel) {
    if (rel.empty()) return true;
    const VaultEntry* e = find_entry(idx, rel);
    if (e) return e->is_dir;   // 显式条目：以自身标志为准（目录/文件）
    std::string pfx = rel + "/";
    for (const auto& x : idx) if (x.rel_path.size() > pfx.size() && ci_starts_with(x.rel_path, pfx)) return true;
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

// M34：锁定返回 VDISK_E_IO 表示索引刷盘失败——密钥清理仍会执行（锁定态安全优先），
// 但最后一批索引改动已丢，调用方不得误报锁定成功。
VDiskStatus do_lock(VDiskHandle* h) {
    // 锁定前先把索引镜像的待落盘改动刷盘——必须在 passphrase 清除之前，
    // 否则索引密钥算不出来，最后一批改动直接丢。
    VDiskStatus st = VDISK_OK;
    {
        std::string e2;
        if (!vault_flush_index(h->library_dir, h->meta, h->passphrase, e2)) st = VDISK_E_IO;   // M34：刷盘失败不再静默丢弃——记录下来，锁完向调用方报 IO 错
    }
    forget_cached_index_keys();   // 经 hook 转发到本 TU 的索引密钥缓存（§4.1）
    vault_drop_index_mirror();   // 镜像含明文 JSON，锁定即丢
    h->passphrase.clear();      // SecureBuffer::clear → sodium_memzero + 释放
    h->index.clear();
    // M35：四个索引派生缓存一并清零，否则锁定后 stat_space/readdir 仍返回上一会话视图
    h->index_map.clear();
    h->dir_children.clear();
    h->dir_set.clear();
    h->index_used_bytes = 0;
    h->name_scratch.clear();
    h->kek_cache.clear();       // 每个 SecureBuffer 析构 memzero → 锁定态零 KEK
    h->kek_lru.clear();
    // M5 预读缓存同样持有明文，锁定必须一并清零（不能只清 KEK）
    for (auto& kv : h->seg_cache) sodium_memzero(kv.second.data(), kv.second.size());
    h->seg_cache.clear();
    h->seg_lru.clear();
    h->seg_bytes = 0;
    h->unlocked = false;
    return st;
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
// 跨平台一致：先零填充整个文件再删除，并强制落盘，使明文不在空闲空间/日志中残留。
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
        FlushFileBuffers(h);   // 强制落盘，确保零填充已写入介质
        CloseHandle(h);
    }
    DeleteFileW(utf8_to_wstring(p).c_str());
#else
    // POSIX：以 O_WRONLY 逐块零填充 + fsync，截断本身不保证介质擦除（日志/COW 会留明文）。
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

// ---- 索引新鲜度（挂载期间库外新增文件可见性）----
// 索引只在 vdisk_unlock 时解一次密进内存。挂载着的时候，另一个进程（GUI/CLI 的
// --into-vault）往库里加文件，本进程毫不知情 → 「已入盘的文件在挂载盘里看不见」。
// 分目录模式下按 .feindex.d 目录 mtime 判变化（任何 .idx 原子替换都会 bump 该目录 mtime），
// 变了就重载一次（索引密钥有进程内缓存，重载只是几次 secretbox 解密，不重跑 Argon2id）。
// 旧单 .feindex 盘回退为 mtime+size。路径必须走 u8path —— MSVC 的 std::filesystem 按 ACP
// 解释窄串，中文目录会失配。
static void index_stamp(const std::string& dir, uint64_t& mtime, uint64_t& size, bool& sharded) {
    std::error_code ec;
    fs::path sd = fs::u8path(dir + "/.feindex.d");
    auto t = fs::last_write_time(sd, ec);
    if (!ec) { mtime = (uint64_t)t.time_since_epoch().count(); size = 0; sharded = true; return; }
    fs::path p = fs::u8path(dir + "/.feindex");
    auto t2 = fs::last_write_time(p, ec);
    if (ec) { mtime = 0; size = 0; sharded = false; return; }
    mtime = (uint64_t)t2.time_since_epoch().count();
    auto s = fs::file_size(p, ec);
    size = ec ? 0 : (uint64_t)s;
    sharded = false;
}

// caller 持有 h->mtx。索引重载后调用一次：构建 rel→条目、父目录→子项、目录集合、已用字节。
// 替代原先每次 readdir/getattr 对整份索引的线性扫描（readdir 还嵌套去重 → O(N²)），
// 文件数大 + Explorer 滚动反复调用时直接卡成 PPT。
static void rebuild_index_caches(VDiskHandle* h) {
    h->index_map.clear();
    h->dir_children.clear();
    h->dir_set.clear();
    h->dir_set.insert("");   // 根永远是一个目录
    std::unordered_set<std::string> seen_child;   // 子项去重（parent+"/"+name），防畸形索引重复 rel
    uint64_t used = 0;
    for (size_t i = 0; i < h->index.size(); ++i) {
        const VaultEntry& e = h->index[i];
        const std::string& rel = e.rel_path;
        if (rel.empty()) continue;                 // 防御：空 rel 不进索引
        h->index_map[ci_key(rel)] = i;             // 键统一小写：查找大小写不敏感
        if (!e.is_dir) used += (e.size > 0) ? (uint64_t)e.size : 0;
        // 拆分层级组件（rel 已被 rel_path_safe 校验：无空段 / ./.. ，分隔符统一为 '/'）
        // rel = "perf_src/sub1/file.txt" → comp = ["perf_src","sub1","file.txt"]
        std::vector<std::string> comp;
        std::string cur;
        for (char c : rel) {
            if (c == '/') { if (!cur.empty()) comp.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) comp.push_back(cur);
        if (comp.empty()) continue;
        // 末层组件：目录条目本身也是目录，故目录循环覆盖全部组件；文件条目末层是文件。
        size_t last_component = e.is_dir ? comp.size() : comp.size() - 1;
        // 逐层目录：父目录用累积字符串 dparent 跟踪，避免把深层目录错当成顶级
        std::string dparent;
        for (size_t k = 0; k < last_component; ++k) {
            std::string dir = dparent.empty() ? comp[k] : (dparent + "/" + comp[k]);
            h->dir_set.insert(ci_key(dir));
            std::string dkey = dparent.empty() ? comp[k] : (dparent + "/" + comp[k]);
            if (seen_child.insert(dkey).second) h->dir_children[ci_key(dparent)].push_back({ comp[k], 0, 0 });  // 目录：size/mtime 占位 0；name 保留原始大小写
            dparent = dir;
        }
        // 末层：仅文件条目需在此登记。目录条目的全部组件（含末层）已在上面逐层
        // 循环注册完毕；若目录再走 leaf 分支，会把自身末层注册成自己的子项，
        // readdir 即出现「目录套自己」的幽灵条目。
        if (!e.is_dir) {
            std::string leaf = comp.back();
            std::string lkey = dparent.empty() ? leaf : (dparent + "/" + leaf);
            if (seen_child.insert(lkey).second)
                h->dir_children[ci_key(dparent)].push_back({ leaf, (uint64_t)e.size, (uint64_t)e.mtime });
        }
        if (e.is_dir) h->dir_set.insert(ci_key(rel));
    }
    h->index_used_bytes = used;
}

// caller 持有 h->mtx。读失败保留旧索引（宁可稍后重试，也不要把正在用的索引清空）
static void refresh_index_locked(VDiskHandle* h) {
    if (!h->unlocked) return;
    // 轮询节流：Explorer 滚动会高频调用 readdir/getattr，每次都 stat .feindex.d 纯属浪费。
    // 200ms 内直接信任上次结果；超时才重新比对 mtime/size。库外新入盘文件 200ms 内即见，无感。
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
    m7_refresh(h);          // 条目变了，占用集跟着重算（仅挂载态实际占用）
}

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
    if (!h || !passphrase) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
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
    rebuild_index_caches(h);   // 解锁即构建派生缓存，首个 readdir 不必再全索引扫描
    index_stamp(h->library_dir, h->feindex_mtime, h->feindex_size, h->feindex_sharded);   // 记下当前版本，便于后续判变更
    h->last_activity_ms = now_ms();   // M5 空闲计时起点
    h->unlocked = true;
    if (h->meta.encrypted) {
        // format==2：root/created 封在密文里，vault_meta_load 只留盐/KDF 明文。
        // 解锁拿到密码后必须解密回填，否则这两个字段在整个会话里恒为空。
        std::string derr;
        vault_meta_decrypt(h->meta, h->passphrase, derr);
    } else {
        // 旧明文盘首次解锁：把隐私字段（root/created）加密存回，透明升到 format==2。
        // 此后 open 仍无需密码即可读盐/KDF/mount_point，root/created 需密码解密。
        std::vector<unsigned char> kek;
        std::string kerr;
        if (derive_index_key(h->passphrase, h->meta, kek, kerr) && !kek.empty()) {
            if (vault_meta_save_encrypted(h->library_dir, h->meta, kek, kerr))
                h->meta.encrypted = true;   // 与落盘格式保持一致，避免下次重复升级
        }
        if (!kek.empty()) sodium_memzero(kek.data(), kek.size());
    }
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_lock(VDiskHandle* h) {
    if (!h) return VDISK_E_BADARG;   // H2b：先判空后加锁
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    return do_lock(h);   // M34：索引刷盘失败（VDISK_E_IO）向上传播，不再吞掉
}

VDISK_API void vdisk_purge_on_suspend(VDiskHandle* h) {
    if (!h) return;
    std::lock_guard<std::recursive_mutex> lk(h->mtx);   // H3：先持锁再清密钥，否则并发读路径对已释放的 SecureBuffer/无序容器构成 UAF 与 UB
    do_lock(h);
}

VDISK_API VDiskStatus vdisk_reindex(VDiskHandle* h, const char* root) {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string r = (root && *root) ? root : h->library_dir;
    std::string err;
    if (!vault_reindex(r, h->meta, h->passphrase, err)) return VDISK_E_IO;
    std::vector<VaultEntry> entries;
    if (!vault_read_index(r, h->meta, h->passphrase, entries, err)) return VDISK_E_IO;
    h->index = std::move(entries);
    rebuild_index_caches(h);   // H4：索引刚被整体替换，四个派生缓存必须立即重建；随后 index_stamp 会刷新 feindex 戳使 refresh_index_locked 提前返回，不会代劳
    index_stamp(h->library_dir, h->feindex_mtime, h->feindex_size, h->feindex_sharded);
    m7_refresh(h);          // M7：索引变化后重算 .ptd 占用集（仅挂载态实际占用）
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_mount_readonly(VDiskHandle* h, const char* mount_point) {
    if (!h || !mount_point) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    h->mount_point = mount_point;
    h->mounted = true;
    h->rw = false;          // 显式只读，配合 write_* 的 VDISK_E_RO 守卫
    m7_refresh(h);          // M7：占用全部 .ptd，禁止外部删除
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_unmount(VDiskHandle* h) {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    m7_release_all(h);   // M7：卸载即释放 .ptd 占用，否则外部仍删不动
    h->mounted = false;
    h->mount_point.clear();
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_readdir(VDiskHandle* h, const char* vpath,
                                    VDiskEntry** out_entries, uint64_t* out_count) {
    if (!h || !out_count) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!check_idle_only(h)) return VDISK_E_LOCKED;   // M5 只判超时，不刷新计时（Explorer 会持续轮询目录）
    refresh_index_locked(h);   // 库外刚入盘的文件立刻可见（节流后几乎零成本）
    std::string rel = vpath_to_rel(vpath);
    uint64_t n = 0;
    const std::vector<DirChild>* kids = nullptr;
    if (rel.empty()) {
        auto it = h->dir_children.find(std::string());
        if (it != h->dir_children.end()) kids = &it->second;
    } else {
        auto dit = h->dir_children.find(ci_key(rel));
        if (dit != h->dir_children.end()) kids = &dit->second;
        else if (h->index_map.find(ci_key(rel)) == h->index_map.end()) return VDISK_E_NOTFOUND;  // 既非目录也非文件
    }
    if (kids) n = kids->size();

    uint64_t cap = out_entries ? *out_count : 0;
    *out_count = n;
    if (!out_entries) return VDISK_OK;        // 第一段：查询数量
    if (cap < n) return VDISK_E_BADARG;       // 容量不足，调用方应重试

    h->name_scratch.clear();
    h->name_scratch.reserve(n);
    for (const auto& c : *kids) h->name_scratch.push_back(c.name);
    for (uint64_t i = 0; i < n; i++) {
        const DirChild& c = (*kids)[i];
        // 目录判定以 dir_set 为准（与 vdisk_getattr 的 is_dir 语义一致）
        bool d = h->dir_set.count(ci_key(rel.empty() ? c.name : rel + "/" + c.name)) != 0;
        (*out_entries)[i].name = h->name_scratch[i].c_str();
        (*out_entries)[i].is_dir = d ? 1 : 0;
        (*out_entries)[i].size = d ? 0 : c.size;
        (*out_entries)[i].mtime = d ? 0 : c.mtime;
    }
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_getattr(VDiskHandle* h, const char* vpath,
                                    uint64_t* out_size, uint64_t* out_mtime, uint8_t* out_is_dir) {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!check_idle_only(h)) return VDISK_E_LOCKED;   // M5 只判超时，不刷新计时（同上，属性查询属后台轮询）
    refresh_index_locked(h);   // 同 readdir：新入盘文件立即可打开（节流后几乎零成本）
    std::string rel = vpath_to_rel(vpath);
    uint64_t now = (uint64_t)time(nullptr);
    if (rel.empty()) {
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = now;
        if (out_is_dir) *out_is_dir = 1;
        return VDISK_OK;
    }
    auto it = h->index_map.find(ci_key(rel));   // O(1)：文件查表（键已 ci 化）
    if (it != h->index_map.end()) {
        const VaultEntry& e = h->index[it->second];
        if (e.is_dir) {   // 显式目录条目（挂载盘 mkdir / 拷贝文件夹）
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
    if (h->dir_set.count(ci_key(rel))) {   // O(1)：目录查集合（含派生目录）
        if (out_size) *out_size = 0;
        if (out_mtime) *out_mtime = now;
        if (out_is_dir) *out_is_dir = 1;
        return VDISK_OK;
    }
    return VDISK_E_NOTFOUND;
}

VDISK_API VDiskStatus vdisk_read_file(VDiskHandle* h, const char* vpath,
                                      uint64_t offset, uint8_t* out, uint64_t* len) {
    if (!h || !out || !len) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!touch_activity(h)) return VDISK_E_LOCKED;   // M5 空闲超时自动锁
    std::string rel = vpath_to_rel(vpath);
    const VaultEntry* e = find_entry(h->index, rel);
    if (!e) return VDISK_E_NOTFOUND;
    uint64_t want = *len;
    *len = 0;
    if (want == 0) return VDISK_OK;
    if (offset >= e->size) return VDISK_OK;
    // ptd 路径必须用索引存储的原始大小写：入参可能被驱动大写归一化，用错大小写会拼错目录段
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);
    // §4.1：优先取 LRU 缓存的 Argon2 材料（命中则跳过 Argon2id），否则派生并入缓存
    unsigned char kek[32];
    bool have_kek = get_kek(h, ptd, kek);
    const unsigned char* pre_kek = have_kek ? kek : nullptr;

    // M5 预读缓存：按 64KB 段命中/回填，读完顺带预取后续段
    if (h->cache_on && h->cache_cap_bytes > 0) {
        // M36：offset+want 回绕会使 last<first，循环被跳过、*len=0 返回 OK——巨大 want（guest IRP 可控）被当成 EOF 读到静默截断数据。先做加法回绕校验
        if (want > SIZE_MAX - offset) { *len = 0; return VDISK_E_BADARG; }
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
    for (auto& e : h->index) if (ci_equal(e.rel_path, rel)) return &e;   // 驱动大写归一化后的路径
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
    if (!h || !vpath || !in) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;   // M5 空闲超时自动锁
    std::string rel = vpath_to_rel(vpath);
    VaultEntry* e = find_mut(h, rel);
    if (!e) return VDISK_E_NOTFOUND;
    // H2a：入口校验——offset+len 先防回绕，再防超过「当前大小+允许扩展量」绝对上限（1TiB），
    // 杜绝回绕后 resize 变小、memcpy 在 data()+SIZE_MAX 处野写。
    constexpr uint64_t kMaxWriteExpand = 1ull << 40;   // 1TiB
    if (len > SIZE_MAX - offset) return VDISK_E_BADARG;
    uint64_t wlimit = kMaxWriteExpand;
    if (e->size <= SIZE_MAX - wlimit) wlimit += e->size;   // 上限 = 当前大小 + 允许扩展量
    if (offset > wlimit || len > wlimit - offset) return VDISK_E_BADARG;
    // 同 read_file：ptd 路径用索引存储的原始大小写，避免驱动归一化后拼错目录段
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);
    std::vector<unsigned char> plain; bool comp = false;
    if (!random_read_ptd(ptd, h->passphrase, 0, e->size, plain, &comp, true, nullptr)) {
        if (comp) return VDISK_E_NOTIMPL;   // 压缩块不可随机写，需先 vault-recrypt
        return VDISK_E_IO;
    }
    try {
        if (offset + len > plain.size()) plain.resize(offset + len, 0);
        std::memcpy(plain.data() + offset, in, len);
    } catch (const std::length_error&) {
        return VDISK_E_BADARG;   // 超 vector 理论上限（理论上已被 H2a 挡下，防御性映射）
    } catch (const std::bad_alloc&) {
        return VDISK_E_NOMEM;    // 扩容失败：内存不足，绝不让异常穿出 extern C 边界
    }
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

VDISK_API VDiskStatus vdisk_create_file_ex(VDiskHandle* h, const char* vpath, int is_dir_flag) {
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if (rel.empty()) return VDISK_E_BADARG;          // 不允许在库根建
    if (rel.find("..") != std::string::npos) return VDISK_E_BADARG;  // 纵深防御：拒绝穿越
    // 新建路径的父目录段同样可能被驱动大写归一化：还原为索引中的真实大小写，
    // 末段是用户起的新名保留原样——否则大小写不同的父目录会分裂成两个目录
    size_t cslash = rel.find_last_of('/');
    if (cslash != std::string::npos && cslash > 0) {
        std::string cp = rel.substr(0, cslash);
        for (auto& e : h->index)
            if (e.is_dir && ci_equal(e.rel_path, cp)) { rel = e.rel_path + rel.substr(cslash); break; }
        if (rel.substr(0, cslash) == cp) {   // 无显式目录条目：试隐式目录（有子条目）
            std::string pfx = cp + "/";
            for (auto& e : h->index)
                if (e.rel_path.size() > pfx.size() && ci_starts_with(e.rel_path, pfx)) {
                    rel = e.rel_path.substr(0, cp.size()) + rel.substr(cslash);
                    break;
                }
        }
    }
    if (find_mut(h, rel)) return VDISK_E_BADARG;   // 已存在则拒绝（ci 匹配防同形异名条目）
    bool is_dir = is_dir_flag != 0;
    if (is_dir) {
        // 目录：不建 .ptd（无内容），只登记目录条目并建磁盘父目录（供后续文件落盘）
        create_directory_recursive(h->library_dir + "/" + rel);
        VaultEntry e;
        e.rel_path = rel; e.store = ""; e.is_dir = true;
        e.size = 0; e.mtime = (int64_t)time(nullptr);
        std::string err;
        if (!vault_upsert_entry(h->library_dir, h->meta, h->passphrase, e, err)) return VDISK_E_IO;
        h->index.push_back(e);
        rebuild_index_caches(h);   // 立即可见：挂载盘 mkdir 后需立刻可进入
        return VDISK_OK;
    }
    // 文件：挂载新建同样用随机存储名，与入盘保持一致的命名策略
    VaultEntry e;
    e.rel_path = rel;
    e.store    = random_store_name();
    e.size = 0; e.mtime = (int64_t)time(nullptr);
    e.algo = "XChaCha20"; e.kdf = "argon2id";
    std::string ptd = ptd_path_for(h->library_dir, rel, e.store);
    if (ptd.empty() || file_exists(ptd)) return VDISK_E_BADARG;
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
    rebuild_index_caches(h);   // 立即可见
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_create_file(VDiskHandle* h, const char* vpath) {
    return vdisk_create_file_ex(h, vpath, 0);   // 旧签名：一律按文件创建（兼容既有调用方）
}

VDISK_API VDiskStatus vdisk_delete_file(VDiskHandle* h, const char* vpath) {
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    if (rel.empty()) return VDISK_E_BADARG;          // 不允许删库根
    if (const VaultEntry* self = find_mut(h, rel)) rel = self->rel_path;   // 驱动归一化路径：取回索引原始大小写
    std::string pfx = rel + "/";
    if (!find_mut(h, rel) && !is_dir(h->index, rel)) return VDISK_E_NOTFOUND;
    // 目录：先递归删子项（索引里目录无独立条目，只能按前缀收集；ci 前缀兼容归一化路径）
    std::vector<std::string> kids;
    for (const auto& e : h->index)
        if (ci_starts_with(e.rel_path, pfx)) kids.push_back(e.rel_path);
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
    // 删除显式目录条目（mkdir 产生的 is_dir 条目），避免残留空目录条目
    if (const VaultEntry* de = find_entry(h->index, rel)) {
        if (de->is_dir) {
            std::string e2;
            if (!vault_remove_entry(h->library_dir, h->meta, h->passphrase, rel, e2)) return VDISK_E_IO;
            for (auto it = h->index.begin(); it != h->index.end(); ++it)
                if (it->rel_path == rel) { h->index.erase(it); break; }
        }
    }
    if (kids.empty()) {   // 普通文件
        const VaultEntry* fe = find_entry(h->index, rel);
        std::string ptd = ptd_path_for(h->library_dir, fe ? fe->rel_path : rel, fe ? fe->store : std::string());
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
    if (!h || !vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string rel = vpath_to_rel(vpath);
    VaultEntry* e = find_mut(h, rel);
    if (!e) return VDISK_E_NOTFOUND;
    std::string ptd = ptd_path_for(h->library_dir, e->rel_path, e->store);   // 存原始大小写，防归一化拼错目录段
    std::vector<unsigned char> plain; bool comp = false;
    if (!random_read_ptd(ptd, h->passphrase, 0, e->size, plain, &comp, true, nullptr)) {
        if (comp) return VDISK_E_NOTIMPL;
        return VDISK_E_IO;
    }
    try {
        plain.resize(new_size, 0);   // H2c：new_size 由 guest 可控，resize 抛 length_error/bad_alloc 时映射为错误码，绝不让异常穿出 extern C 边界
    } catch (const std::length_error&) {
        return VDISK_E_BADARG;   // new_size 超 vector 理论上限
    } catch (const std::bad_alloc&) {
        return VDISK_E_NOMEM;    // 目标过大，内存不足
    }
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

// 重命名 / 移动：文件改名、目录改名（含递归子项批量改 rel + 搬 .ptd）。
// 受影响条目一次性重写索引，避免 N 次 upsert 的 O(N^2) 重加密。
VDISK_API VDiskStatus vdisk_rename(VDiskHandle* h, const char* old_vpath, const char* new_vpath) {
    if (!h || !old_vpath || !new_vpath) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);
    if (!h->unlocked) return VDISK_E_LOCKED;
    if (!h->rw) return VDISK_E_RO;                   // 只读挂载拒绝写
    if (!touch_activity(h)) return VDISK_E_LOCKED;
    std::string old_rel = vpath_to_rel(old_vpath);
    std::string new_rel = vpath_to_rel(new_vpath);
    if (old_rel.empty() || new_rel.empty()) return VDISK_E_BADARG;          // 不动库根
    if (old_rel.find("..") != std::string::npos || new_rel.find("..") != std::string::npos) return VDISK_E_BADARG;  // 防穿越
    // WinFSP Rename 回调的 FileName 是驱动归一化的大写形式，索引存原始大小写：
    // 取回真实源路径，否则后续精确前缀匹配与 .ptd 搬运全用错大小写
    if (VaultEntry* oe = find_mut(h, old_rel)) old_rel = oe->rel_path;
    else {   // 隐式目录：源是某条目父路径，取子条目的真实父段
        std::string pfx = old_rel + "/";
        for (auto& e : h->index)
            if (e.rel_path.size() > pfx.size() && ci_starts_with(e.rel_path, pfx)) {
                old_rel = e.rel_path.substr(0, old_rel.size());
                break;
            }
    }
    if (old_rel == new_rel) return VDISK_OK;
    // 移动时 NewFileName 的父目录段同样被驱动大写归一化：ci 匹配索引还原真实
    // 大小写；末段是用户起的新名，必须保留原样
    size_t nslash = new_rel.find_last_of('/');
    if (nslash != std::string::npos && nslash > 0) {
        std::string np = new_rel.substr(0, nslash);
        for (auto& e : h->index)
            if (e.is_dir && ci_equal(e.rel_path, np)) { new_rel = e.rel_path + new_rel.substr(nslash); break; }
        if (new_rel.substr(0, nslash) == np) {   // 无显式目录条目：试隐式目录（有子条目）
            std::string pfx = np + "/";
            for (auto& e : h->index)
                if (e.rel_path.size() > pfx.size() && ci_equal(e.rel_path.substr(0, pfx.size()), pfx)) {
                    new_rel = e.rel_path.substr(0, np.size()) + new_rel.substr(nslash);
                    break;
                }
        }
    }
    // 目标已存在→冲突；大小写不敏感比对（排除源自身），防仅大小写不同的重复条目
    for (auto& e : h->index) {
        if (e.rel_path == old_rel) continue;
        if (ci_equal(e.rel_path, new_rel)) return VDISK_E_EXIST;
    }
    if (is_dir(h->index, new_rel)) return VDISK_E_EXIST;   // 目标是非空目录（隐式）

    // 收集受影响条目：显式 old_rel 目录条目 + old_rel/ 前缀的所有条目
    // （ci 前缀：兼容历史遗留的大小写分叉条目，一并归并到新大小写）
    std::string pfx = old_rel + "/";
    std::vector<size_t> affected;
    for (size_t i = 0; i < h->index.size(); ++i) {
        const std::string& r = h->index[i].rel_path;
        if (r == old_rel || ci_starts_with(r, pfx)) affected.push_back(i);
    }
    if (affected.empty()) return VDISK_E_NOTFOUND;   // 源不存在

    // M37：两阶段提交——先把所有 .ptd 预搬到新位置，全部成功后才更新内存索引并落盘；
    // 任一搬运失败即把已搬走的原路回搬（只 rename 回自己刚搬的件，绝不删目标处既有文件），
    // 索引保持旧状态，杜绝「已搬 .ptd + 未更新索引」的脱同步与半搬状态。
    struct RenameMove { std::string new_ptd, old_ptd; };
    struct RenamePlan { size_t idx; std::string old_rel; std::string new_rel; };
    std::vector<RenameMove> moved;
    std::vector<RenamePlan> plan;
    for (size_t idx : affected) {
        VaultEntry& e = h->index[idx];
        std::string suffix = (e.rel_path == old_rel) ? std::string() : e.rel_path.substr(old_rel.size());
        std::string nrel = new_rel + suffix;
        plan.push_back({ idx, e.rel_path, nrel });
        if (!e.is_dir && !e.store.empty()) {   // 文件：搬 .ptd（store 不变，目录结构随 rel 重组）
            std::string old_ptd = ptd_path_for(h->library_dir, e.rel_path, e.store);
            std::string new_ptd = ptd_path_for(h->library_dir, nrel, e.store);
            if (old_ptd != new_ptd && !old_ptd.empty() && !new_ptd.empty()) {
                size_t np = new_ptd.find_last_of('/');
                if (np != std::string::npos) create_directory_recursive(new_ptd.substr(0, np));
                m7_release(h, old_ptd);        // M7：搬前释放占用，否则 rename 被占用挡住
                if (std::rename(old_ptd.c_str(), new_ptd.c_str()) != 0) {
                    for (auto mit = moved.rbegin(); mit != moved.rend(); ++mit)
                        std::rename(mit->new_ptd.c_str(), mit->old_ptd.c_str());      // M37：原路回搬已搬走的件（只 rename 回自己刚搬的，绝不删目标处既有文件）
                    return VDISK_E_IO;
                }
                moved.push_back({ new_ptd, old_ptd });
                invalidate_ptd_caches(h, e.rel_path, old_ptd);   // 旧 rel 缓存失效（在改 rel 前）
            }
        }
    }
    // M37：全部搬完才统一更新内存索引（两阶段提交的第二阶段）
    for (const auto& pr : plan) h->index[pr.idx].rel_path = pr.new_rel;

    // 一次性重写索引（内存 h->index 已是新状态）
    std::string js = vault_entries_to_json(h->index);
    std::string err;
    if (!vault_write_index(h->library_dir, h->meta, h->passphrase, js, err)) {
        // M37：索引落盘失败——回搬 .ptd 并恢复内存索引，保持改前状态
        for (auto mit = moved.rbegin(); mit != moved.rend(); ++mit)
            std::rename(mit->new_ptd.c_str(), mit->old_ptd.c_str());
        for (const auto& pr : plan) h->index[pr.idx].rel_path = pr.old_rel;
        return VDISK_E_IO;
    }
    rebuild_index_caches(h);
    m7_refresh(h);          // M7：占用集按新路径重算（仅挂载态实际占用）
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_mount_rw(VDiskHandle* h, const char* mount_point) {
    if (!h || !mount_point) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
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
        case VDISK_E_EXIST: return "target already exists (rename/move conflict)";
        case VDISK_E_INTERNAL: return "internal error";
    }
    return "unknown error";
}

VDISK_API uint32_t vdisk_abi_version(void) { return VDISK_ABI_VERSION; }

// ===================== M4 恢复密钥（§4.4）=====================
VDISK_API VDiskStatus vdisk_recovery_gen(char* out_code, uint64_t code_cap) {
    if (!out_code || code_cap < 49) return VDISK_E_BADARG;
    std::string c = vault_recovery_gen_code();
    if (c.size() + 1 > code_cap) return VDISK_E_BADARG;
    std::memcpy(out_code, c.c_str(), c.size() + 1);
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_recovery_create(VDiskHandle* h, const char* code) {
    if (!h || !code) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    if (!h->unlocked) return VDISK_E_LOCKED;
    std::string err;
    if (!vault_recovery_create(h->library_dir, h->passphrase, code, err)) {
        return (err.find("48 decimal") != std::string::npos) ? VDISK_E_BADARG : VDISK_E_IO;
    }
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_recovery_open(VDiskHandle* h, const char* code,
                                          char* out_pass, uint64_t* len) {
    if (!h || !code || !out_pass || !len || *len == 0) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    SecureBuffer pw; std::string err;
    if (!vault_recovery_load(h->library_dir, code, pw, err)) return VDISK_E_AUTH;
    uint64_t n = pw.size();
    if (n + 1 > *len) return VDISK_E_BADARG;   // 低危：容量不足时不改写 *len（保持调用方原值），避免 BADARG 后误读所需大小
    std::memcpy(out_pass, pw.cdata(), n);
    out_pass[n] = '\0';
    *len = n;
    return VDISK_OK;
}

VDISK_API VDiskStatus vdisk_recovery_remove(VDiskHandle* h) {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    std::string err;
    if (!vault_recovery_remove(h->library_dir, err)) return VDISK_E_IO;
    return VDISK_OK;
}

// ===================== M5 增强 =====================
VDISK_API VDiskStatus vdisk_set_idle_timeout(VDiskHandle* h, uint32_t seconds) {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    h->idle_timeout_s = seconds;
    h->last_activity_ms = now_ms();
    return VDISK_OK;
}

VDISK_API uint32_t vdisk_idle_remaining(VDiskHandle* h) {
    if (!h || h->idle_timeout_s == 0 || !h->unlocked) return UINT32_MAX;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    uint64_t elapsed = (now_ms() - h->last_activity_ms) / 1000ull;
    if (elapsed >= h->idle_timeout_s) return 0;
    return h->idle_timeout_s - (uint32_t)elapsed;
}

// 取路径所在卷的可用空间（字节）；成功返回 true 并写入 out_free。
// Windows 用 GetVolumePathNameW 解析盘符/挂载点根再查；POSIX 用 statvfs。
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
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
    // 容量上限 = 加密盘所在盘符可用空间 - 2GB：预留 2GB 给宿主系统，避免写满宿主盘。
    // 卷总容量 = 已存数据 + 可继续写入空间（≈ 宿主可用空间 - 2GB，写入时稳定）；
    // 报告可用 = 宿主可用空间 - 2GB，随写入自然下降，到 0 即触及预留线。
    // 取不到宿主盘可用空间时回落旧「已用量 2 倍」口径，保证不崩。
    const uint64_t kReserve = 2ull * 1024 * 1024 * 1024;   // 预留 2GiB
    const uint64_t kMin = 64ull << 20;
    refresh_index_locked(h);   // 库外新入盘 → 容量跟着涨（节流后几乎零成本）
    uint64_t used = h->index_used_bytes;   // 库内文件明文总大小（缓存）
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
}

VDISK_API VDiskStatus vdisk_set_read_cache(VDiskHandle* h, uint64_t cap_bytes, uint32_t ahead_segments) {
    if (!h) return VDISK_E_BADARG;
    std::lock_guard<std::recursive_mutex> _lk(h->mtx);   // H2b：先判空后加锁
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
