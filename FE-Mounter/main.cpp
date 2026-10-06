// FE-Mounter — 加密盘 holder 进程（设计文档 §5 / §5.1 / §7 M2–M3）。
// 本文件只做「命令行入口 + 模式分发 + FUSE(Linux) 挂载」；其余按职责拆到：
//   fe_common.h  共享声明   fe_vdisk  加载/工具   fe_ipc  §5.1 控制面
//   fe_service  服务注册   fe_winfsp  Windows 挂载
#include "fe_common.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <thread>

#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  include <windows.h>
#endif

#if FE_HAVE_FUSE
#  define FUSE_USE_VERSION 31      // fuse3 只支持 API ≥ 30；必须在包含 fuse.h 前定义
#  include <fuse3/fuse.h>
#  include <fuse3/fuse_lowlevel.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <cerrno>
static VDiskApi     g_v;
static VDiskHandle* g_h = nullptr;
static bool         g_rw = false;   // M6 可写挂载：由 mount --rw 置位
static int fe_getattr(const char* path, struct stat* st, struct fuse_file_info*) {
    uint64_t size = 0, mtime = 0; uint8_t isdir = 0;
    if (g_v.getattr(g_h, path, &size, &mtime, &isdir) != VDISK_OK) return -ENOENT;
    memset(st, 0, sizeof(*st));
    if (isdir) { st->st_mode = S_IFDIR | (g_rw ? 0755 : 0555); st->st_nlink = 2; }
    else       { st->st_mode = S_IFREG | (g_rw ? 0644 : 0444); st->st_nlink = 1; st->st_size = (off_t)size; }
    st->st_mtime = (time_t)mtime;
    return 0;
}
static int fe_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t,
                      struct fuse_file_info*, enum fuse_readdir_flags) {
    uint64_t n = 0;
    if (g_v.readdir(g_h, path, nullptr, &n) != VDISK_OK) return -ENOENT;
    std::vector<VDiskEntry> ents((size_t)n);
    VDiskEntry* parr = ents.data();
    if (n > 0 && g_v.readdir(g_h, path, &parr, &n) != VDISK_OK) return -ENOENT;
    filler(buf, ".", nullptr, 0, FUSE_FILL_DIR_PLUS);
    filler(buf, "..", nullptr, 0, FUSE_FILL_DIR_PLUS);
    for (uint64_t i = 0; i < n; i++) filler(buf, ents[i].name, nullptr, 0, FUSE_FILL_DIR_PLUS);
    return 0;
}
static int fe_open(const char*, struct fuse_file_info* fi) {
    if (!g_rw && (fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;   // 只读挂载拒绝写打开
    return 0;
}
static int fe_read(const char* path, char* buf, size_t size, off_t off, struct fuse_file_info*) {
    uint64_t len = size;
    VDiskStatus st = g_v.read_file(g_h, path, (uint64_t)off, (uint8_t*)buf, &len);
    if (st != VDISK_OK) return -EIO;
    return (int)len;
}

// ---- M6 写支持（仅 g_rw 时生效）----
static int fe_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info*) {
    if (!g_rw) return -EROFS;
    uint64_t len = size;
    VDiskStatus st = g_v.write_file(g_h, path, (uint64_t)off, (const uint8_t*)buf, len);
    if (st == VDISK_E_NOTFOUND) return -ENOENT;
    if (st != VDISK_OK) return -EIO;
    return (int)size;
}
static int fe_truncate(const char* path, off_t size, struct fuse_file_info*) {
    if (!g_rw) return -EROFS;
    VDiskStatus st = g_v.truncate_file(g_h, path, (uint64_t)size);
    if (st == VDISK_E_NOTFOUND) return -ENOENT;
    if (st != VDISK_OK) return -EIO;
    return 0;
}
static int fe_unlink(const char* path, struct fuse_file_info*) {
    if (!g_rw) return -EROFS;
    VDiskStatus st = g_v.delete_file(g_h, path);
    if (st == VDISK_E_NOTFOUND) return -ENOENT;
    if (st != VDISK_OK) return -EIO;
    return 0;
}
static int fe_create(const char* path, mode_t, struct fuse_file_info* fi) {
    if (!g_rw) return -EROFS;
    VDiskStatus st = g_v.create_file(g_h, path);
    if (st == VDISK_E_BADARG) return -EEXIST;   // 已存在则拒绝覆盖
    if (st != VDISK_OK) return -EIO;
    fi->fh = 0;
    return 0;
}
#endif // FE_HAVE_FUSE

static void usage() {
    fprintf(stderr,
        "FE-Mounter - encrypted vault holder process\n"
        "Usage:\n"
        "  selftest  --vault <d> --pass-file <f>              unlock + list dir + per-file FNV\n"
        "  cat       --vault <d> --pass-file <f> --path <v>   dump a file's plaintext to stdout\n"
        "  lifecycle --vault <d> --pass-file <f> [--path <v>] verify lock/suspend zeroing\n"
        "  bench     --vault <d> --pass-file <f> [--iters N] [--relock]  LRU warm/cold\n"
        "  m5test    --vault <d> --pass-file <f> [--path <v>] verify idle-timeout lock + read-ahead cache\n"
        "  m6test    --vault <d> --pass-file <f> [--path <v>] verify vault write (create/write/truncate/delete)\n"
        "  ipc-call  --vault <d> (status|unlock --pass-file <f>|unlockr <code>|lock|reindex|idle N|cache BYTES AHEAD)\n"
        "  vaults    list|add <dir>|remove <dir>             M5 multi-vault registry\n"
        "  recovery  --vault <d> (gen|create|open <code>|remove)  M4 recovery key (sec 4.4)\n"
        "  winmount  <drive> --vault <d> [--pass-file <f>] [--rw] [--idle-timeout SEC]\n"
        "                                                 Windows mount (M3; --rw = writable M6; --idle-timeout = auto-lock after idle, M5)\n"
        "  install-service <drive|mountpoint> --vault <d> [--pass-file <f>] / uninstall-service\n"
        "                                                 (Windows: admin service required; Linux: systemd --user unit)\n"
        "  mount     <mountpoint> --vault <d> --pass-file <f> [--rw]  FUSE3 mount (Linux; --rw = writable)\n"
        "  example   --vault <d>                              end-to-end demo (init/vault/mount/IPC/readback)\n");
}

int main(int argc, char** argv) {
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);   // 否则 cat 明文 \n 被文本模式转 \r\n
    SetConsoleOutputCP(CP_UTF8);            // 控制台默认 GBK 会把 UTF-8 中文解码乱码，强制 UTF-8
    SetConsoleCP(CP_UTF8);
#endif
    if (argc < 2) { usage(); return 1; }
    std::string mode = argv[1];
    std::string vault, pass, passfile, vpath, lib, tmp;
    bool relock_flag = false;
    int bench_iters = 10;
    uint32_t idle_timeout = 0;                 // M5 空闲超时自动锁（秒，0=关闭）
    uint64_t cache_bytes = 0;                  // M5 预读缓存容量（0=关闭）
    uint32_t cache_ahead = 4;                  // M5 预读段数
    bool rw_flag = false;                      // M6 可写挂载开关（--rw）
    std::vector<char*> fuse_args;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](std::string& dst) -> bool { if (i + 1 >= argc) return false; dst = argv[++i]; return true; };
        if (a == "--vault") { if (!next(vault)) { fprintf(stderr, "--vault needs arg\n"); return 1; } }
        else if (a == "--pass-file") { if (!next(passfile)) { fprintf(stderr, "--pass-file needs arg\n"); return 1; } }
        else if (a == "--pass") { if (!next(pass)) { fprintf(stderr, "--pass needs arg\n"); return 1; } }
        else if (a == "--path") { if (!next(vpath)) { fprintf(stderr, "--path needs arg\n"); return 1; } }
        else if (a == "--lib") { if (!next(lib)) { fprintf(stderr, "--lib needs arg\n"); return 1; } }
        else if (a == "--relock") { relock_flag = true; }
        else if (a == "--rw") { rw_flag = true; }
        else if (a == "--iters") { if (!next(tmp)) { fprintf(stderr, "--iters needs arg\n"); return 1; } bench_iters = atoi(tmp.c_str()); if (bench_iters < 1) bench_iters = 1; }
        else if (a == "--idle-timeout") { if (!next(tmp)) { fprintf(stderr, "--idle-timeout needs arg\n"); return 1; } idle_timeout = (uint32_t)strtoul(tmp.c_str(), nullptr, 10); }
        else if (a == "--cache-bytes") { if (!next(tmp)) { fprintf(stderr, "--cache-bytes needs arg\n"); return 1; } cache_bytes = strtoull(tmp.c_str(), nullptr, 10); }
        else if (a == "--cache-ahead") { if (!next(tmp)) { fprintf(stderr, "--cache-ahead needs arg\n"); return 1; } cache_ahead = (uint32_t)strtoul(tmp.c_str(), nullptr, 10); }
        else { fuse_args.push_back(argv[i]); }
    }
    std::string mountpoint;
    if (mode == "mount" || mode == "winmount" || mode == "install-service") { mountpoint = fuse_args.empty() ? "" : fuse_args[0]; }

    // M5 多库注册表：与具体库无关，需早于「--vault required」
    if (mode == "vaults") {
        std::string sub = fuse_args.empty() ? "list" : fuse_args[0];
        if (sub == "list") {
            auto vs = vaults_list();
            printf("registry: %s\n", vaults_registry_path().c_str());
            for (auto& d : vs) printf("  %s\n", d.c_str());
            if (vs.empty()) printf("  (empty)\n");
            return 0;
        }
        std::string dir = (fuse_args.size() > 1) ? fuse_args[1] : std::string();
        if (dir.empty()) { fprintf(stderr, "vaults %s needs a directory\n", sub.c_str()); return 1; }
        std::string err;
        bool ok = (sub == "add") ? vaults_add(dir, err) : (sub == "remove") ? vaults_remove(dir, err) : false;
        if (!ok) { fprintf(stderr, "vaults %s failed: %s\n", sub.c_str(), err.c_str()); return 1; }
        printf("vaults %s: %s\n", sub.c_str(), dir.c_str());
        return 0;
    }

    if (pass.empty()) {
        if (!passfile.empty()) { if (!read_pass_file(passfile, pass)) { fprintf(stderr, "cannot read pass file\n"); return 1; } }
        else if (const char* e = getenv("FE_MOUNTER_PASS")) { pass = e; }
    }
    if (vault.empty()) { fprintf(stderr, "--vault required\n"); return 1; }
    g_ipc_vault = vault;

    // IPC 客户端（纯管道，不需本地加载/解锁 vdisk）
    if (mode == "ipc-call") {
        if (fuse_args.empty()) { fprintf(stderr, "ipc-call needs a command (status|unlock|lock|reindex)\n"); return 1; }
        std::string cmd = fuse_args[0];
        std::string req = cmd;
        if (cmd == "unlock") {
            if (pass.empty()) { fprintf(stderr, "ipc-call unlock needs --pass-file\n"); return 1; }
            req = "unlock " + hex_encode(pass);
            secure_zero(pass.data(), pass.size());
        } else if (cmd == "unlockr") {
            std::string code = (fuse_args.size() > 1) ? fuse_args[1] : std::string();
            if (code.empty()) { fprintf(stderr, "ipc-call unlockr needs <code>\n"); return 1; }
            req = "unlockr " + hex_encode(code);
            secure_zero(code.data(), code.size());
        } else if (cmd == "idle") {
            if (fuse_args.size() < 2) { fprintf(stderr, "ipc-call idle needs <seconds>\n"); return 1; }
            req = std::string("idle ") + fuse_args[1];
        } else if (cmd == "cache") {
            if (fuse_args.size() < 3) { fprintf(stderr, "ipc-call cache needs <bytes> <ahead>\n"); return 1; }
            req = std::string("cache ") + fuse_args[1] + " " + fuse_args[2];
        }
        std::string resp = ipc_call(vault, req);
        printf("%s\n", resp.c_str());
        return (resp.rfind("OK", 0) == 0) ? 0 : 1;
    }

    if (mode == "install-service" || mode == "uninstall-service") {
        std::string err;
#if defined(_WIN32)
        if (mode == "install-service") {
            if (mountpoint.empty()) { fprintf(stderr, "install-service needs a drive letter\n"); return 1; }
            if (!install_service(vault, mountpoint, passfile, kSvcName, err)) { fprintf(stderr, "install-service failed: %s\n", err.c_str()); return 1; }
            printf("service '%s' installed and started\n", kSvcName);
        } else {
            if (!uninstall_service(kSvcName, err)) { fprintf(stderr, "uninstall-service failed: %s\n", err.c_str()); return 1; }
            printf("service '%s' removed\n", kSvcName);
        }
#else
        // Linux：写 systemd --user unit（无需 root）。挂载点是目录，不占本地 vdisk 句柄。
        if (mode == "install-service") {
            if (mountpoint.empty()) { fprintf(stderr, "install-service needs a mountpoint (e.g. install-service ~/fe-vault --vault ...)\n"); return 1; }
            if (!install_service(vault, mountpoint, passfile, err)) { fprintf(stderr, "install-service failed: %s\n", err.c_str()); return 1; }
            printf("systemd user unit installed and started for %s\n", mountpoint.c_str());
        } else {
            if (!uninstall_service(vault, err)) { fprintf(stderr, "uninstall-service failed: %s\n", err.c_str()); return 1; }
            printf("systemd user unit removed for %s\n", vault.c_str());
        }
#endif
        return 0;
    }

#if FE_HAVE_WINFSP
    // 「进程本身即服务」：SvcStart 自行从服务命令行打开/解锁 vault 并挂载（需 SCM 启动）
    if (mode == "winmount") {
        if (mountpoint.empty()) { fprintf(stderr, "winmount needs a drive letter or directory mountpoint (e.g. winmount V: or winmount C:\\mnt)\n"); return 1; }
        std::string mp = mountpoint;
        // 盘符规范化：裸 "V"/"V:" → "\\.\V:"（WinFsp Mount Manager 全局盘符，需管理员、
        // 跨会话/跨窗口可见，规避 DefineDosDeviceW 会话盘符在跨进程访问时 I/O 进不来的问题）。
        // 含路径分隔符（\ /）或已是 \\.\X: 则原样传（目录挂载点 / 显式全局盘符）。
        if (mp.find_first_of("\\/:") == std::string::npos) {
            std::string letter = (mp.size() == 2 && mp[1] == ':') ? std::string(1, mp[0]) : mp;
            if (letter.size() != 1 || !((letter[0] >= 'A' && letter[0] <= 'Z') || (letter[0] >= 'a' && letter[0] <= 'z'))) {
                fprintf(stderr, "winmount: bad drive letter '%s'\n", mp.c_str()); return 1;
            }
            mp = "\\\\.\\" + letter + ":";
        }
        g_svc_vault = vault; g_svc_pass = pass; g_svc_mp = mp; g_svc_rw = rw_flag;
        g_svc_idle = idle_timeout;   // M5 空闲自动锁：winmount 早于通用路径 return，须单独带进服务
        g_svc_lib = lib.empty() ? default_lib_path() : lib;
        return fe_winmount_service();
    }
#endif

    if (lib.empty()) lib = default_lib_path();
    VDiskApi v; std::string err;
    if (!vdisk_load(v, lib, err)) { fprintf(stderr, "load libvdisk failed (%s): %s\n", lib.c_str(), err.c_str()); return 2; }
    VDiskHandle* h = v.open(vault.c_str());
    if (!h) { fprintf(stderr, "vdisk_open failed (not a vault?)\n"); return 3; }

    // M4 恢复密钥（§4.4）：gen/open/remove 不需要解锁——忘密码正是恢复密钥的用途
    if (mode == "recovery") {
        std::string sub = fuse_args.empty() ? "" : fuse_args[0];
        if (sub == "gen") {
            if (!v.recovery_gen) { fprintf(stderr, "libvdisk lacks recovery API\n"); v.close(h); return 6; }
            char code[64] = {0};
            if (v.recovery_gen(code, sizeof code) != VDISK_OK) { fprintf(stderr, "gen failed\n"); v.close(h); return 6; }
            printf("%s\n", code);   // 48 位十进制恢复密钥，仅此一次显示
            v.close(h);
            return 0;
        }
        if (sub == "open") {
            std::string code = (fuse_args.size() > 1) ? fuse_args[1] : std::string();
            if (code.empty()) { fprintf(stderr, "recovery open needs <code>\n"); v.close(h); return 1; }
            char pw[512] = {0}; uint64_t cap = sizeof pw;
            VDiskStatus st = v.recovery_open ? v.recovery_open(h, code.c_str(), pw, &cap) : VDISK_E_NOTIMPL;
            v.close(h);
            if (st != VDISK_OK) { fprintf(stderr, "recovery open failed: %s\n", v.strerror(st)); return 1; }
            fwrite(pw, 1, cap, stdout); fputc('\n', stdout);   // 按实际长度输出（密码可能含非 NUL 安全字节）
            secure_zero(pw, sizeof pw);
            return 0;
        }
        if (sub == "remove") {
            VDiskStatus st = v.recovery_remove ? v.recovery_remove(h) : VDISK_E_NOTIMPL;
            v.close(h);
            if (st != VDISK_OK) { fprintf(stderr, "recovery remove failed: %s\n", v.strerror(st)); return 1; }
            printf("recovery file removed\n");
            return 0;
        }
        if (sub == "create") {
            // 需要当前密码：保险文件存的是主密码副本
            if (pass.empty()) { fprintf(stderr, "recovery create needs --pass-file\n"); v.close(h); return 1; }
            if (v.unlock(h, pass.c_str(), 0) != VDISK_OK) { fprintf(stderr, "unlock failed\n"); v.close(h); return 4; }
            std::string code = (fuse_args.size() > 1) ? fuse_args[1] : std::string();
            if (code.empty()) {
                char buf[64] = {0};
                if (!v.recovery_gen || v.recovery_gen(buf, sizeof buf) != VDISK_OK) {
                    fprintf(stderr, "cannot generate recovery code\n"); v.close(h); return 6;
                }
                code = buf;
            }
            VDiskStatus st = v.recovery_create ? v.recovery_create(h, code.c_str()) : VDISK_E_NOTIMPL;
            v.close(h);
            if (st != VDISK_OK) { fprintf(stderr, "recovery create failed: %s\n", v.strerror(st)); return 1; }
            printf("recovery file created, code=%s\n", code.c_str());
            printf("WARNING: 泄露恢复密钥 = 泄露盘访问权；请离线备份。\n");
            return 0;
        }
        fprintf(stderr, "recovery subcommand: gen|create|open <code>|remove\n"); v.close(h); return 1;
    }

    if (v.unlock(h, pass.c_str(), 0) != VDISK_OK) { fprintf(stderr, "unlock failed (wrong passphrase?)\n"); v.close(h); return 4; }

    // M5：空闲超时 + 预读缓存（挂载期间生效；ipc idle/cache 可运行时调整）
    if (idle_timeout > 0 && v.set_idle_timeout) v.set_idle_timeout(h, idle_timeout);
    if (cache_bytes > 0 && v.set_read_cache) v.set_read_cache(h, cache_bytes, cache_ahead);

    int rc = 0;
    if (mode == "selftest") {
        printf("FE-Mounter selftest  vault=%s\n", vault.c_str());
        walk(v, h, "/");
        printf("SELFTEST_OK\n");
    } else if (mode == "cat") {
        if (vpath.empty()) vpath = "/";
        std::vector<uint8_t> buf; std::string rerr;
        if (!read_whole(v, h, vpath, buf, rerr)) { fprintf(stderr, "cat %s: %s\n", vpath.c_str(), rerr.c_str()); rc = 5; }
        else { fwrite(buf.data(), 1, buf.size(), stdout); fflush(stdout); }
    } else if (mode == "lifecycle") {
        if (vpath.empty()) vpath = "/a.txt";
        int bad = 0;
        auto probe = [&](const char* what, VDiskStatus want) {
            VDiskStatus st = v.getattr(h, vpath.c_str(), nullptr, nullptr, nullptr);
            printf("%-28s -> %s\n", what, v.strerror(st));
            if (st != want) bad++;
        };
        probe("after unlock", VDISK_OK);
        v.purge_on_suspend(h);
        probe("after purge_on_suspend", VDISK_E_LOCKED);
        v.unlock(h, pass.c_str(), 0);
        probe("after re-unlock", VDISK_OK);
        v.lock(h);
        probe("after lock", VDISK_E_LOCKED);
        printf(bad ? "LIFECYCLE_FAIL(%d)\n" : "LIFECYCLE_OK\n", bad);
        rc = bad ? 7 : 0;
    } else if (mode == "bench") {
        if (vpath.empty()) vpath = "/a.txt";
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < bench_iters; i++) {
            if (relock_flag) { v.lock(h); v.unlock(h, pass.c_str(), 0); }
            uint64_t sz = 0, mt = 0; uint8_t isdir = 0;
            if (v.getattr(h, vpath.c_str(), &sz, &mt, &isdir) != VDISK_OK) { rc = 5; break; }
            std::vector<uint8_t> buf((size_t)sz); uint64_t len = sz;
            if (v.read_file(h, vpath.c_str(), 0, buf.data(), &len) != VDISK_OK) { rc = 5; break; }
        }
        double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        printf("BENCH %s iters=%d total=%.1fms avg=%.2fms\n",
               relock_flag ? "cold(relock)" : "warm(lru)", bench_iters, ms, ms / (bench_iters ? bench_iters : 1));
    } else if (mode == "m5test") {
        // M5 自测：空闲超时自动锁 + 预读缓存（不走挂载，Windows/Linux 都能跑）
        if (vpath.empty()) vpath = "/a.txt";
        int bad = 0;
        auto probe = [&](const char* what, VDiskStatus want) {
            VDiskStatus st = v.getattr(h, vpath.c_str(), nullptr, nullptr, nullptr);
            printf("%-30s -> %s\n", what, v.strerror(st));
            if (st != want) bad++;
        };
        if (!v.set_idle_timeout || !v.idle_remaining) { printf("idle timeout unsupported\n"); bad++; }
        else {
            v.set_idle_timeout(h, 2);
            probe("idle: just touched", VDISK_OK);
            uint32_t rem = v.idle_remaining(h);
            printf("%-30s -> %us\n", "idle: remaining", rem);
            if (rem == 0 || rem == (uint32_t)-1) bad++;
            std::this_thread::sleep_for(std::chrono::milliseconds(2500));
            probe("idle: after 2.5s idle", VDISK_E_LOCKED);
            v.unlock(h, pass.c_str(), 0);
            v.set_idle_timeout(h, 0);   // 关掉超时，免得干扰后面的读
        }
        uint64_t sz = 0, mt = 0; uint8_t isdir = 0;
        if (v.getattr(h, vpath.c_str(), &sz, &mt, &isdir) != VDISK_OK) { printf("getattr failed\n"); bad++; }
        else if (!v.set_read_cache) { printf("read cache unsupported\n"); bad++; }
        else {
            std::vector<uint8_t> a((size_t)sz), b((size_t)sz), c((size_t)sz);
            uint64_t la = sz, lb = sz, lc = sz;
            if (v.read_file(h, vpath.c_str(), 0, a.data(), &la) != VDISK_OK) { printf("read(cold) failed\n"); bad++; }
            else {
                v.set_read_cache(h, 1u << 20, 8);
                if (v.read_file(h, vpath.c_str(), 0, b.data(), &lb) != VDISK_OK) { printf("read(cached) failed\n"); bad++; }
                else if (la != lb || memcmp(a.data(), b.data(), (size_t)la) != 0) { printf("cache content mismatch\n"); bad++; }
                else printf("%-30s -> identical(%lluB)\n", "cache: vs direct read", (unsigned long long)la);
                // 锁定必须清掉明文段缓存：清不干净这里就会读到脏数据
                v.lock(h); v.unlock(h, pass.c_str(), 0);
                if (v.read_file(h, vpath.c_str(), 0, c.data(), &lc) != VDISK_OK) { printf("read(after relock) failed\n"); bad++; }
                else if (lc != la || memcmp(a.data(), c.data(), (size_t)la) != 0) { printf("post-lock content mismatch\n"); bad++; }
                else printf("%-30s -> identical\n", "cache: after lock/unlock");
            }
        }
        printf(bad ? "M5TEST_FAIL(%d)\n" : "M5TEST_OK\n", bad);
        rc = bad ? 7 : 0;
    } else if (mode == "m6test") {
        // M6 自测：库层写支持（不依赖挂载，Windows/Linux 都能跑）。
        int bad = 0;
        v.mount_rw(h, "/");   // 显式置可写标志，验证库层写路径（不真正挂载盘符）
        std::string tp = "/m6_probe.txt";
        {   // 1) 创建 + 写入 + 读回一致
            VDiskStatus st = v.create_file(h, tp.c_str());
            if (st != VDISK_OK) { printf("create: %s\n", v.strerror(st)); bad++; }
            else {
                const char* msg = "hello M6 writable vault";
                st = v.write_file(h, tp.c_str(), 0, (const uint8_t*)msg, strlen(msg));
                if (st != VDISK_OK) { printf("write: %s\n", v.strerror(st)); bad++; }
                else {
                    std::vector<uint8_t> buf(64); uint64_t len = buf.size();
                    if (v.read_file(h, tp.c_str(), 0, buf.data(), &len) != VDISK_OK) { printf("readback: fail\n"); bad++; }
                    else if (len != strlen(msg) || memcmp(buf.data(), msg, len) != 0) { printf("readback: mismatch\n"); bad++; }
                    else printf("create+write+readback -> identical(%lluB)\n", (unsigned long long)len);
                }
            }
        }
        {   // 覆盖写（短写不截断，仅校验前缀）
            const char* msg = "OVERWRITE-SAME-LEN";
            VDiskStatus st = v.write_file(h, tp.c_str(), 0, (const uint8_t*)msg, strlen(msg));
            if (st != VDISK_OK) { printf("overwrite: %s\n", v.strerror(st)); bad++; }
            else {
                std::vector<uint8_t> buf(64); uint64_t len = buf.size();
                if (v.read_file(h, tp.c_str(), 0, buf.data(), &len) != VDISK_OK) { printf("overwrite readback: fail\n"); bad++; }
                else if (len < strlen(msg) || memcmp(buf.data(), msg, strlen(msg)) != 0) { printf("overwrite readback: mismatch(len=%llu)\n", (unsigned long long)len); bad++; }
                else printf("overwrite -> prefix ok, size=%lluB\n", (unsigned long long)len);
            }
        }
        {   // 3) truncate 缩小 + 扩展
            VDiskStatus st = v.truncate_file(h, tp.c_str(), 4);
            if (st != VDISK_OK) { printf("truncate: %s\n", v.strerror(st)); bad++; }
            else {
                std::vector<uint8_t> buf(64); uint64_t len = buf.size();
                if (v.read_file(h, tp.c_str(), 0, buf.data(), &len) != VDISK_OK) { printf("trunc readback: fail\n"); bad++; }
                else if (len != 4) { printf("trunc readback: size=%llu want 4\n", (unsigned long long)len); bad++; }
                else printf("truncate(4) -> size=%llu\n", (unsigned long long)len);
            }
            st = v.truncate_file(h, tp.c_str(), 20);
            if (st != VDISK_OK) { printf("extend: %s\n", v.strerror(st)); bad++; }
            else {
                std::vector<uint8_t> buf(64); uint64_t len = buf.size();
                if (v.read_file(h, tp.c_str(), 0, buf.data(), &len) != VDISK_OK) { printf("extend readback: fail\n"); bad++; }
                else if (len != 20) { printf("extend readback: size=%llu want 20\n", (unsigned long long)len); bad++; }
                else printf("extend(20) -> size=%llu (zero-padded)\n", (unsigned long long)len);
            }
        }
        {   // 4) 删除后不可见
            VDiskStatus st = v.delete_file(h, tp.c_str());
            if (st != VDISK_OK) { printf("delete: %s\n", v.strerror(st)); bad++; }
            else {
                uint64_t sz = 0, mt = 0; uint8_t isdir = 0;
                VDiskStatus g = v.getattr(h, tp.c_str(), &sz, &mt, &isdir);
                if (g != VDISK_E_NOTFOUND) { printf("delete: still present (getattr=%s)\n", v.strerror(g)); bad++; }
                else printf("delete -> NOTFOUND as expected\n");
            }
        }
        printf(bad ? "M6TEST_FAIL(%d)\n" : "M6TEST_OK\n", bad);
        rc = bad ? 9 : 0;
    } else if (mode == "mount") {
#if FE_HAVE_FUSE
        if (mountpoint.empty()) { fprintf(stderr, "mountpoint required\n"); rc = 1; }
        else {
            g_rw = rw_flag;
            if (rw_flag) v.mount_rw(h, mountpoint.c_str());
            else         v.mount_readonly(h, mountpoint.c_str());
            g_v = v; g_h = h;
            // §5.1 控制面：FUSE 常驻期间供 ipc-call 做 lock/unlock/reindex
            g_ipc_v = &v; g_ipc_h = &g_h; g_ipc_unlocked = true; g_ipc_stop = false;
            std::thread(ipc_server_thread).detach();
            // 挂载点位置参数已在解析时取出，按 fuse 约定放于所有选项之后；
            // 其余 -f/-o 等原样转发给 fuse 解析。
            std::vector<char*> raw;
            raw.push_back(argv[0]);
            for (char* p : fuse_args) {
                if (p == argv[2]) continue;          // 跳过作为挂载点的位置参数
                raw.push_back(p);
            }
            raw.push_back(const_cast<char*>(mountpoint.c_str()));
            struct fuse_operations ops; memset(&ops, 0, sizeof(ops));
            ops.getattr = fe_getattr; ops.readdir = fe_readdir; ops.open = fe_open; ops.read = fe_read;
            if (rw_flag) {
                ops.write = fe_write; ops.truncate = fe_truncate;
                ops.unlink = fe_unlink; ops.create = fe_create;
            }
            rc = fuse_main((int)raw.size(), raw.data(), &ops, nullptr);
            v.unmount(h);
        }
#else
        fprintf(stderr, "mount: FUSE3 not available (Windows uses winmount/WinFSP).\n"); rc = 6;
#endif
    } else {
        usage();
        rc = 1;
    }
    v.close(h);
    return rc;
}
