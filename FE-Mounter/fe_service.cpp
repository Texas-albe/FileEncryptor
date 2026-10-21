// fe_service：把 FE-Mounter 注册为 Windows 服务（开机自启），供盘符常驻。
#include "fe_common.h"
#include <cstdio>
#include <cstring>
#if !defined(_WIN32)
#  include <sys/stat.h>   // mkdir(2)：取代 system("mkdir -p")（M1 无 shell）
#  include <errno.h>      // 区分 EEXIST（已存在）
#endif

#if defined(_WIN32)
// 服务名必须与 FspServiceRun 的 L"FE-Mount" 一致：WinFSP 服务模型要求 SCM 注册名
// 与进程内 FspServiceRun 名字匹配，否则服务启动后立即退出、盘符不出现。
const char* kSvcName = "FE-Mount";

// 服务以 LocalSystem 运行时工作目录是 %SystemRoot%\System32，相对路径会解析错→
// 注册前把 vault/pass-file 绝对化，否则服务进程 v.open 失败秒退。
static std::string abs_path(const std::string& p) {
    if (p.empty() || p.find(':') != std::string::npos || p[0] == '/' || p[0] == '\\') return p;
    wchar_t buf[MAX_PATH];
    DWORD n = GetFullPathNameW(utf8_to_wide(p).c_str(), MAX_PATH, buf, nullptr);
    if (n == 0 || n >= MAX_PATH) return p;
    return wide_to_utf8(buf);
}

bool install_service(const std::string& vault0, const std::string& drive,
                     const std::string& passfile0, const char* svcname, std::string& err) {
    std::string vault = abs_path(vault0);
    // §4.1 默认锁定：服务启动**不**带 --pass-file → 锁定启动、等 IPC unlock。
    // 不再支持开机自解锁：密码会随命令行进入服务进程并长期驻留内存，违反 §4.1。
    // 需要开机即挂载的场景由用户在解锁后手动 winmount，或后续用受控凭据方案（DPAPI/服务管理器）。
    wchar_t self[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) { err = "GetModuleFileName failed"; return false; }
    std::wstring cmd = L"\"";
    cmd += self; cmd += L"\" winmount ";
    cmd += utf8_to_wide(drive);
    cmd += L" --vault \"" + utf8_to_wide(vault) + L"\"";
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { err = "OpenSCManager failed (need Administrator)"; return false; }
    std::wstring wname = utf8_to_wide(svcname);
    SC_HANDLE svc = CreateServiceW(scm, wname.c_str(), wname.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) { err = "CreateService failed (already exists or need Administrator)"; CloseServiceHandle(scm); return false; }
    StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return true;
}

bool uninstall_service(const char* svcname, std::string& err) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { err = "OpenSCManager failed (need Administrator)"; return false; }
    SC_HANDLE svc = OpenServiceW(scm, utf8_to_wide(svcname).c_str(), SERVICE_ALL_ACCESS);
    if (!svc) { err = "service not found"; CloseServiceHandle(scm); return false; }
    ControlService(svc, SERVICE_CONTROL_STOP, nullptr);
    DeleteService(svc);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return true;
}

#else  // Linux

// Linux 常驻：systemd --user unit（无需 root，用户级自启）。
// 不用系统级 unit 是刻意选择：库路径/挂载点属用户数据，用户级 unit 免 root 且能按用户隔离。
static std::string unit_name_for(const std::string& vault) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : vault) { h ^= (unsigned char)c; h *= 0x100000001b3ULL; }
    char buf[32]; snprintf(buf, sizeof buf, "%016llx", (unsigned long long)h);
    return std::string("fe-mount-") + buf + ".service";
}

static std::string unit_dir() {
    const char* xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/systemd/user";
    const char* home = getenv("HOME");
    return std::string(home ? home : ".") + "/.config/systemd/user";
}

// M1：递归创建目录（不走 shell）。原实现 system("mkdir -p '<dir>'") 的 dir 由 XDG_CONFIG_HOME/HOME 派生，含单引号即 shell 注入；mkdir(2) 无此面。
static bool mkdir_p(const std::string& d) {
    if (d.empty()) return false;
    std::string cur;
    size_t i = 0;
    if (d[0] == '/') { cur = "/"; i = 1; }
    while (i < d.size()) {
        size_t j = d.find('/', i);
        if (j == std::string::npos) j = d.size();
        if (j > i) {
            if (!cur.empty() && cur.back() != '/') cur += '/';
            cur.append(d, i, j - i);
            if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return false;
        }
        i = j + 1;
    }
    return true;
}

// M2：systemd unit 指令注入防护。ExecStart 原样拼接这些路径：含 \n 可注入任意 unit 指令；% 是 systemd specifier 会被展开；$ / ` 触发命令展开。一律拒绝。
static bool unit_path_safe(const std::string& p) {
    for (char c : p)
        if (c == '\n' || c == '\r' || c == '%' || c == '$' || c == '`') return false;
    return true;
}

bool install_service(const std::string& vault0, const std::string& mountpoint,
                     const std::string& passfile0, std::string& err) {
    if (!getenv("XDG_RUNTIME_DIR") && access("/run/systemd/system", F_OK) != 0) {
        // 无 user manager 时 unit 写了也不会被拉起，明确报错让用户知道原因
        if (access("/run/user", F_OK) != 0) {
            err = "systemd user manager unavailable (need systemd session; e.g. run under a normal login session)";
            return false;
        }
    }
    char self[4096];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0) { err = "readlink /proc/self/exe failed"; return false; }
    self[n] = '\0';

    std::string dir = unit_dir();
    if (!mkdir_p(dir)) { err = "cannot create " + dir; return false; }

    // 绝对路径：unit 的工作目录不是调用者 cwd，相对路径会解析到 $HOME
    char cwd[4096];
    std::string vault = vault0, passfile = passfile0;
    if (!vault.empty() && vault[0] != '/') {
        if (getcwd(cwd, sizeof cwd)) vault = std::string(cwd) + "/" + vault;
    }
    if (!passfile.empty() && passfile[0] != '/') {
        if (getcwd(cwd, sizeof cwd)) passfile = std::string(cwd) + "/" + passfile;
    }
    // M2：先校验再落盘。含 \n 可注入任意 unit 指令，%（specifier 展开）/$ / `（命令展开）一律拒绝。
    if (!unit_path_safe(mountpoint) || !unit_path_safe(vault) || !unit_path_safe(passfile)) {
        err = "path contains characters unsafe for systemd unit (newline, '%', '$', '`')";
        return false;
    }
    std::string path = dir + "/" + unit_name_for(vault0);
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { err = "cannot write " + path; return false; }
    fprintf(f,
        "[Unit]\n"
        "Description=FE-Mounter encrypted vault (read-only)\n"
        "After=default.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s mount %s --vault %s%s%s\n"
        "Restart=on-failure\n"
        "RestartSec=3\n"
        "KillMode=process\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n",
        self, mountpoint.c_str(), vault.c_str(),
        passfile.empty() ? "" : (" --pass-file " + passfile).c_str(), "");
    fclose(f);

    if (system("systemctl --user daemon-reload >/dev/null 2>&1") != 0) {
        err = "unit written to " + path + " but 'systemctl --user daemon-reload' failed";
        return false;
    }
    if (system(("systemctl --user enable " + unit_name_for(vault0) + " >/dev/null 2>&1").c_str()) != 0) {
        err = "unit written but 'systemctl --user enable' failed";
        return false;
    }
    if (system(("systemctl --user restart " + unit_name_for(vault0) + " >/dev/null 2>&1").c_str()) != 0) {
        err = "unit enabled but 'systemctl --user restart' failed";
        return false;
    }
    return true;
}

bool uninstall_service(const std::string& vault, std::string& err) {
    std::string unit = unit_name_for(vault);
    int rc = system(("systemctl --user disable --now " + unit + " >/dev/null 2>&1").c_str());
    (void)rc;   // 单元可能本来就没启用；删文件成功即达成卸载
    std::string path = unit_dir() + "/" + unit;
    if (unlink(path.c_str()) != 0 && access(path.c_str(), F_OK) == 0) {
        err = "cannot remove " + path;
        return false;
    }
    int rc2 = system("systemctl --user daemon-reload >/dev/null 2>&1");
    (void)rc2;
    return true;
}
#endif
