// P1-2 多盘批量操作：对注册表里的全部加密盘做统一 status / lock / unlock。
//
// 现状是「每盘一个独立 FE-Mounter 进程」，故批量= 客户端扇出：对每个已注册 vault
// 各发一次 IPC，聚合结果。本模块不改变进程模型，只是把扇出逻辑收在一处，
// 供 CLI 与 GUI 共用，避免两端各写一遍。
//
// 输出为逐行 JSON 行（每盘一行对象），便于 GUI 直接解析（此前 GUI 只能靠
// Contains("unlocked=1") 子串匹配，是最脆弱的一环）。
#include "fe_common.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <filesystem>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

// 挂载状态文件目录（跨平台）。Windows: %LOCALAPPDATA%/FileEncryptor/mount；
// POSIX: $XDG_DATA_HOME/FileEncryptor/mount 或 $HOME/.local/share/FileEncryptor/mount。
// Linux 下 mounter 经 FUSE3 挂载、不写该状态文件，discover 自然返回空（等价原行为）。
static std::string mount_state_dir() {
#if defined(_WIN32)
    const char* la = getenv("LOCALAPPDATA");
    if (!la) return "";
    return std::string(la) + "\\FileEncryptor\\mount";
#else
    const char* xdg = getenv("XDG_DATA_HOME");
    std::string base;
    if (xdg && *xdg) base = xdg;
    else {
        const char* home = getenv("HOME");
        if (!home) return "";
        base = std::string(home) + "/.local/share";
    }
    return base + "/FileEncryptor/mount";
#endif
}

namespace {

// 读取某盘的实际挂载盘符（P0-2 状态文件）。未挂载返回空串。
std::string read_actual_mount(const std::string& vault) {
    std::string dir = mount_state_dir();
    if (dir.empty()) return "";
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : vault) { h ^= (unsigned char)c; h *= 0x100000001b3ULL; }
    char nm[80]; snprintf(nm, sizeof nm, "vault_%016llx.txt", (unsigned long long)h);
    std::filesystem::path path = std::filesystem::path(dir) / nm;
    FILE* f = fopen(path.string().c_str(), "rb");
    if (!f) return "";
    std::string mount;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        std::string s(line);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        if (s.rfind("mount=", 0) == 0) { mount = s.substr(6); break; }
    }
    fclose(f);
    return mount;
}

// JSON 字符串转义（路径含反斜杠与空格）
std::string jesc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:
            if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
            else o += c;
        }
    }
    return o;
}

// 解析 IPC status 响应 "OK unlocked=1 [idle=N]" / "OK unlocked=0" / "ERR ..."
struct OneStatus {
    bool        reachable=false;
    bool        unlocked=false;
    long long   idle=-1;          // 剩余秒数，未解锁时无意义
    std::string raw;
};
OneStatus parse_status(const std::string& resp) {
    OneStatus s; s.raw = resp;
    if (resp.rfind("OK", 0) != 0) return s;
    s.reachable = true;
    size_t p = resp.find("unlocked=");
    if (p != std::string::npos) s.unlocked = (resp[p + 9] == '1');
    size_t q = resp.find("idle=");
    if (q != std::string::npos) s.idle = atoll(resp.c_str() + q + 5);
    return s;
}

} // namespace

// 发现当前真实挂载的盘：扫描 mount_state_dir() 下 vault_*.txt 状态文件。
// mounter 挂载成功时写入这些文件（含 vault= / mount= 行），即便 GUI 漏登记也能据此列出。
// Windows(WinFSP) 会写；Linux(FUSE3) 不写，故 Linux 下返回空（等价原行为）。
// 返回 (vault路径, mount点) 列表。
std::vector<std::pair<std::string,std::string>> discover_mounted() {
    std::vector<std::pair<std::string,std::string>> out;
    std::string dir = mount_state_dir();
    if (dir.empty()) return out;
    std::error_code ec;
    std::filesystem::path d(dir);
    if (!std::filesystem::exists(d, ec)) return out;
    for (const auto& ent : std::filesystem::directory_iterator(d, ec)) {
        if (!ent.is_regular_file(ec)) continue;
        std::string name = ent.path().filename().string();
        if (name.rfind("vault_", 0) != 0) continue;
        if (name.size() < 4 || name.compare(name.size() - 4, 4, ".txt") != 0) continue;
        FILE* f = fopen(ent.path().string().c_str(), "rb");
        if (!f) continue;
        std::string vault, mount;
        long pid = 0;
        char line[512];
        while (fgets(line, sizeof line, f)) {
            std::string s(line);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
            if (s.rfind("vault=", 0) == 0) vault = s.substr(6);
            else if (s.rfind("mount=", 0) == 0) mount = s.substr(6);
            else if (s.rfind("pid=", 0) == 0) pid = strtol(s.c_str() + 4, nullptr, 10);
        }
        fclose(f);
        // 低危 C 组：状态文件内容无认证，同用户可伪造「已挂载」误导 GUI 与 status 聚合；写入方记录了 mounter 自身 pid，读取方校验其存活，否则忽略该文件（PID 重用窗口内仍可能误判，与 M20 同源）。
        if (!vault.empty() && fe_pid_alive(pid)) out.push_back({vault, mount});
    }
    return out;
}

// vaults status：已注册盘 + 真实挂载盘 合并去重（以 vault 路径为键），每盘一行 JSON
int vaults_status_json() {
    std::map<std::string, std::string> byVault;   // vault -> mount
    std::vector<std::string> order;
    auto add = [&](const std::string& v, const std::string& m) {
        if (byVault.find(v) == byVault.end()) order.push_back(v);
        if (byVault[v].empty()) byVault[v] = m;
    };
    for (auto& v : vaults_list()) add(v, "");          // 注册表（可能含未挂载盘）
    for (auto& p : discover_mounted()) add(p.first, p.second);  // 真实挂载盘

    printf("{\n  \"count\": %zu,\n  \"vaults\": [\n", order.size());
    for (size_t i = 0; i < order.size(); ++i) {
        const std::string& v = order[i];
        OneStatus st = parse_status(ipc_call(v, "status"));
        printf("    {\"vault\":\"%s\",\"mount\":\"%s\",\"reachable\":%s,\"unlocked\":%s",
               jesc(v).c_str(), jesc(byVault[v]).c_str(),
               st.reachable ? "true" : "false", st.unlocked ? "true" : "false");
        if (st.idle >= 0) printf(",\"idle\":%lld", st.idle);
        printf("}%s\n", (i + 1 < order.size()) ? "," : "");
    }
    printf("  ]\n}\n");
    return 0;
}

// vaults batch <lock|eject>：对全部已注册盘扇出该命令，聚合成功/失败
int vaults_batch(const std::string& cmd) {
    if (cmd != "lock" && cmd != "eject") {
        fprintf(stderr, "vaults batch: only 'lock' and 'eject' supported\n");
        return 2;
    }
    auto vs = vaults_list();
    int ok = 0, fail = 0;
    for (auto& d : vs) {
        std::string resp = ipc_call(d, cmd);
        if (resp.rfind("OK", 0) == 0) {
            printf("OK %s %s\n", cmd.c_str(), d.c_str());
            ++ok;
        } else {
            printf("ERR %s %s (%s)\n", cmd.c_str(), d.c_str(), resp.c_str());
            ++fail;
        }
    }
    printf("SUMMARY ok=%d fail=%d\n", ok, fail);
    return fail == 0 ? 0 : 1;
}
