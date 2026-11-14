#include "FileEncryptor.hpp"
#include "config.hpp"
#include "asym_crypto.hpp"
#include "keylib.hpp"
#include "password_policy.hpp"
#include "split_volumes.hpp"
#include "archive.hpp"
#include "keywrap.hpp"
#include "kdf.hpp"
#include "vault_index.hpp"
#include "progress_frame.hpp"
#include "../core/saf/saf_batch.hpp"
#include "util/hex.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <iterator>
#include <filesystem>
#include <system_error>
#include <sodium.h>
#include <stdexcept>
#include <ctime>
#include <sstream>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127 4251 4275 4702 26495 26451)
#endif
#include "CLI11.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef _WIN32
#include <windows.h>

#include <conio.h>
#include <shellapi.h>
#include <io.h>            // _chmod
#include <sys/stat.h>     // _S_IREAD
#include <aclapi.h>       // SetEntriesInAclW / SetNamedSecurityInfoW
#else
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>     // chmod
#endif

#ifdef _WIN32
// 交互控制台
// 会读控制台输入
static std::vector<char> get_password_win() {
    bool is_console=false;
    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0;
    if(hIn!=INVALID_HANDLE_VALUE && GetConsoleMode(hIn,&mode)) {
        is_console=true;
    }

    if(!is_console) {
        // 非交互
        std::string line;
        std::vector<char> pwd;
        if(std::getline(std::cin,line)) {
            if(!line.empty()&&line.back()=='\r') line.pop_back();
            pwd.assign(line.begin(),line.end());
        }
        sodium_memzero((void*)line.data(),line.size());
        line.clear();
        return pwd;
    }

    std::vector<char> pwd;
    auto pop_utf8=[&pwd]() {
        if(pwd.empty()) return;
        size_t i=pwd.size()-1;
        while(i>0 && (unsigned char)pwd[i]>=0x80 && (unsigned char)pwd[i]<=0xBF) --i;
        pwd.resize(i);
    };
    int ch;
    while((ch=_getch())!='\r'&&ch!='\n') {
        if(ch==0||ch==0xE0) { _getch(); continue; } // 扩展键
        if(ch=='\b') {
            pop_utf8();
            std::cout<<"\b \b";
            continue;
        }
        if(ch>=0) {
            pwd.push_back((char)(unsigned char)ch);
            std::cout<<'*';
        }
    }
    std::cout<<std::endl;
    return pwd;
}
#endif

// 确认询问
// 交互终端
// 宿主
// 宿主弹窗
// stdin 已被密码通道占
// WinUI 的「系统控制台」模
// 宿主根本看不到
static bool host_confirm_enabled() {
    const char* v=std::getenv("FILEENCRYPTOR_CONFIRM_FILE");
    return v&&v[0];
}

// 把问题写进握手
static bool host_confirm(const std::string& question) {
    const char* path=std::getenv("FILEENCRYPTOR_CONFIRM_FILE");
    if(!path||!path[0]) return false;
    const std::string f=path;
    {
        std::ofstream of;
        if(!open_stream(of,f,std::ios::out|std::ios::binary|std::ios::trunc)) {
            std::cerr<<"Error: cannot write the confirmation handshake file: "<<f<<"\n";
            return false;
        }
        of<<question<<"\n";
        of.flush();
        if(!of.good()) {
            std::cerr<<"Error: cannot write the confirmation handshake file: "<<f<<"\n";
            return false;
        }
    }
    // 上限 10 分钟
    // 答案只认严格
    // 若按首字符判断
    // 结果是立刻返回 false
    for(int i=0; i<6000; ++i) {
        std::ifstream in;
        std::string line;
        int verdict=-1;   
        if(open_stream(in,f,std::ios::in|std::ios::binary)&&std::getline(in,line)) {
            while(!line.empty()&&(line.back()=='\r'||line.back()==' '||line.back()=='\t')) line.pop_back();
            size_t b=0;
            while(b<line.size()&&(line[b]==' '||line[b]=='\t')) ++b;
            std::string ans=line.substr(b);
            std::string low;
            for(char c:ans) low+=(char)std::tolower((unsigned char)c);
            if(low=="y"||low=="yes") verdict=1;
            else if(low=="n"||low=="no") verdict=0;
        }
        if(verdict>=0) {
            // 吃掉应答
            std::ofstream clr;
            open_stream(clr,f,std::ios::out|std::ios::binary|std::ios::trunc);
            clr.flush();
            clr.close();
            return verdict==1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cerr<<"Error: timed out waiting for a confirmation answer.\n";
    return false;
}

static bool confirm_yes_no(const std::string& subject, const char* prompt_suffix) {
    // subject 可能是多行
    if(host_confirm_enabled()) return host_confirm(subject+"\n"+prompt_suffix);
    std::string suf=prompt_suffix;
    while(!suf.empty()&&(suf.back()==' ')) suf.pop_back();
    std::cout<<subject<<"\n"<<suf<<std::flush;
    char ch='n';
    if(!(std::cin>>ch)) return false;
    return ch=='y'||ch=='Y';
}

// 目录输入 + 删除类
// GUI 侧先弹窗并用 --source-delete
static bool confirm_source_dir_removal(const std::vector<std::string>& input_paths,
                                       int source_action) {
    std::vector<std::string> dirs;
    for(const auto& p : input_paths) if(fe_path_is_directory(p)) dirs.push_back(p);
    if(dirs.empty()) return true;
    const char* how = source_action==2 ? "securely erased"
                    : source_action==3 ? "moved to the Recycle Bin"
                    : "deleted";
    // 措辞
    // 空目录壳保留
    // .ptd
    std::string msg = "Files inside these directories will be ";
    msg += how;
    msg += " once encryption finishes (the directories themselves are kept; this cannot be undone):";
    const size_t shown = dirs.size() > 5 ? 5 : dirs.size();
    for(size_t k = 0 ; k < shown ; ++k) { msg += "\n  "; msg += dirs[k]; }
    if(dirs.size() > shown) {
        msg += "\n  ... ";
        msg += std::to_string(dirs.size() - shown);
        msg += " more";
    }
    return confirm_yes_no(msg, "Continue? (y/N): ");
}

#ifndef _WIN32
static std::vector<char> get_password_posix() {
    std::vector<char> pwd;
    struct termios oldt,newt;
    // 仅当 stdin 是 TTY 时才关闭
    // 若仍调用 tcsetattr
    bool term_ok=(tcgetattr(STDIN_FILENO,&oldt)==0);
#ifdef __ANDROID__
    // Android 没有交互终端
    // 与其让空密码继
    if(!term_ok) {
        std::cerr<<"Error: no interactive terminal on Android; "
                   "supply the passphrase with -k <keyfile> or --key-stdin.\n";
        std::exit(1);
    }
#endif
    if(term_ok) {
        newt=oldt;
        newt.c_lflag&=~ECHO;
        tcsetattr(STDIN_FILENO,TCSANOW,&newt);
    }
    std::string line;
    std::getline(std::cin,line);
    if(term_ok) {
        tcsetattr(STDIN_FILENO,TCSANOW,&oldt);
    }
    std::cout<<std::endl;
    pwd.assign(line.begin(),line.end());
    sodium_memzero((void*)line.data(),line.size());
    line.clear();
    return pwd;
}
#endif

static std::vector<char> get_password() {
#ifdef _WIN32
    return get_password_win();
#else
    return get_password_posix();
#endif
}

static bool file_exists_path(const std::string& p) {
    std::ifstream t;
    if(!open_stream(t,p,std::ios::in)) return false;
    t.close();
    return true;
}


// 机器可读契约
// 退出码
enum FeExit : int {
    FE_EXIT_OK = 0, FE_EXIT_USAGE = 2, FE_EXIT_AUTH = 3,
    FE_EXIT_IO = 4, FE_EXIT_PARTIAL = 5, FE_EXIT_CANCEL = 6
};

struct FeContract {
    bool json = false;
    bool dry_run = false;
    bool progress_events = false;
    std::string action = "none";
    std::vector<std::string> inputs;
    std::string output_dir;
    std::string cipher = "xchacha20";
    std::string device_id = "local";
    std::string audit_path;
    int compress_level = 0;
    uint64_t total_bytes = 0;
    size_t audit_events = 0;
};
static FeContract g_contract;

static std::string fe_json_escape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
            else o += (char)c;
        }
    }
    return o;
}

// 审计 JSONL
static void fe_audit_emit(const char* op, const std::string& key, int status,
                          uint64_t bytes, uint64_t elapsed_ms, int error_code) {
    if (g_contract.dry_run || g_contract.audit_path.empty()) return;
    static bool perms_done = false;
    std::ofstream f(g_contract.audit_path, std::ios::app);
    if (!f) return;
    f.close();
    if (!perms_done) {
        std::error_code ec;
        std::filesystem::permissions(g_contract.audit_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, ec);
        perms_done = true;
    }
    std::ofstream o(g_contract.audit_path, std::ios::app);
    if (!o) return;
    o << "{\"schema\":1,\"ts\":" << (unsigned long long)std::time(nullptr)
      << ",\"op\":\"" << fe_json_escape(op) << "\""
      << ",\"key\":\"" << fe_json_escape(key) << "\""
      << ",\"status\":" << status
      << ",\"bytes\":" << bytes
      << ",\"elapsed_ms\":" << elapsed_ms
      << ",\"error_code\":" << error_code
      << ",\"device_id\":\"" << fe_json_escape(g_contract.device_id) << "\""
      << "}\n";
    g_contract.audit_events++;
}

// 只读枚举
static uint64_t fe_collect_plan(const std::vector<std::string>& inputs,
                                std::vector<std::string>& files) {
    uint64_t total = 0;
    std::error_code ec;
    for (const auto& s : inputs) {
        std::filesystem::path fp = std::filesystem::u8path(s);
        if (std::filesystem::is_directory(fp, ec)) {
            std::filesystem::recursive_directory_iterator it(
                fp, std::filesystem::directory_options::skip_permission_denied, ec);
            std::filesystem::recursive_directory_iterator end;
            while (!ec && it != end) {
                if (it->is_regular_file(ec)) {
                    files.push_back(it->path().u8string());
                    total += (uint64_t)it->file_size(ec);
                    if (ec) ec.clear();
                }
                it.increment(ec);
            }
            ec.clear();
        } else {
            ec.clear();
            files.push_back(s);
            uintmax_t sz = std::filesystem::file_size(fp, ec);
            if (!ec) total += (uint64_t)sz;
            ec.clear();
        }
    }
    return total;
}

static void fe_print_plan(const std::vector<std::string>& files, uint64_t total) {
    std::cout << "[dry-run] action: " << g_contract.action << "\n"
              << "[dry-run] cipher: " << g_contract.cipher << "\n"
              << "[dry-run] output: " << (g_contract.output_dir.empty() ? "<source dir>" : g_contract.output_dir) << "\n"
              << "[dry-run] compress: " << g_contract.compress_level << "\n"
              << "[dry-run] inputs (" << files.size() << " files, " << total << " bytes):\n";
    for (const auto& f : files) std::cout << "  " << f << "\n";
    std::cout << "[dry-run] no files written.\n";
}

static std::string fe_result_json(int rc) {
    std::ostringstream o;
    o << "{\"schema\":1,\"ok\":" << (rc == 0 ? "true" : "false")
      << ",\"exit_code\":" << rc
      << ",\"action\":\"" << fe_json_escape(g_contract.action) << "\""
      << ",\"dry_run\":" << (g_contract.dry_run ? "true" : "false")
      << ",\"inputs\":[";
    for (size_t i = 0; i < g_contract.inputs.size(); ++i) {
        if (i) o << ",";
        o << "\"" << fe_json_escape(g_contract.inputs[i]) << "\"";
    }
    o << "],\"output_dir\":\"" << fe_json_escape(g_contract.output_dir) << "\""
      << ",\"cipher\":\"" << fe_json_escape(g_contract.cipher) << "\""
      << ",\"compress_level\":" << g_contract.compress_level
      << ",\"total_bytes\":" << g_contract.total_bytes
      << ",\"audit_events\":" << g_contract.audit_events
      << "}";
    return o.str();
}

static void print_usage() {
    std::cout<<"FileEncryptor v"<<FE_VERSION_STRING<<"\n\n"
        <<"Modes (file encryption / decryption):\n"
        <<"  -e                Encrypt single file\n"
        <<"  -d                Decrypt single file\n"
        <<"  -be               Batch encrypt directories/files\n"
        <<"  -bd               Batch decrypt directories/files\n\n"
        <<"Key management (asymmetric):\n"
        <<        "  -g                Generate asymmetric keypair: X25519 + ML-KEM-768 hybrid (default)\n"
        <<"                      classic X25519/X448 with --no-pqc\n"
        <<"  -G                Derive an X25519 keypair from a password (Argon2id)\n"
        <<"  -Y                Export public key from a private key file (-k)\n"
        <<"  -L, --keylib      Manage the local key library (list|add|remove|show|pub|export)\n"
        <<"  -H, --info        Show file header metadata of a .ptd (read-only, no decryption)\n"
        <<"  -V, --verify      Verify integrity of .ptd file(s) without writing plaintext\n"
        <<"  -R, --recover-name Recover the original filename from a .ptd (offline; add --rename to rename)\n\n"
        <<"Key wrapping (wraps a 32-byte data key, not file content):\n"
        <<"  --wrap-key <file> Wrap a 32-byte DEK into a FEKW blob\n"
        <<"  --unwrap-key <f>  Unwrap a .fekw blob back to the DEK\n"
        <<"  --wrap-alg <alg>  kwp (default, RFC 5649) | aes-kw (RFC 3394) | pubkey\n"
        <<"  --wrap-to <pub>   Recipient public key (or file) for --wrap-alg pubkey\n"
        <<"  --identity <priv> Recipient private key (or file) for --unwrap-key\n"
        <<"  --wrap-out <f>    Output path for --wrap-key (default: <input>.fekw)\n"
        <<"  --unwrap-out <f>  Output path for --unwrap-key (default: <blob>.dek)\n\n"
        <<"  -h, --help, -?    Show this help\n\n"
        <<"Post-quantum:\n"
        <<"  --pqc             Hybrid X25519+ML-KEM-768 recipients and ML-DSA-65 watermark\n"
        <<"                    signatures (default on)\n"
        <<"  --no-pqc          Classic only: X25519/X448 recipients and RSA watermark signatures\n\n"
        <<"Machine-readable contract:\n"
        <<"  --json            One JSON object on stdout; business stdout suppressed\n"
        <<"  -n, --dry-run     Print the operation plan, write nothing\n"
        <<"  --progress-events Emit JSONL progress frames on stderr\n"
        <<"  Exit codes: 0 ok | 2 usage | 3 auth | 4 I/O | 5 partial | 6 cancelled\n\n"
        <<"Options:\n"
        <<"  -o <dir>          Output directory (optional, default: source file's directory)\n"
        <<"  -de               Delete source after success: plaintext (encrypt) / .ptd (decrypt)\n"
        <<"  --wipe-source     Securely wipe (multi-pass overwrite) source after success (HDD only; SSD wear-leveling may prevent physical overwrite)\n"
        <<"  --recycle-source  Move source to system Recycle Bin after success\n"
        <<"  --rewrap <file>   Rotate key of a v6 container (payload untouched; old password via -k/env/interactive)\n"
        <<"  --new-key-file F  New password key file for --rewrap\n"
        <<"  --new-key-stdin   New password for --rewrap read from stdin\n"
        <<"  -m <mode>         Encryption mode: xchacha20 (default) | aegis256 | aes-gcm | sm4 | x25519 | x448\n"
        <<"                      x25519 | x448 = asymmetric: DEK wrapped to recipients (-r / -K)\n"
        <<"  -y, --force       Overwrite existing output files without asking\n"
        <<"  --force-decrypt   Decrypt corrupted files: skip failed chunks (zero-filled) and\n"
        <<"                    ignore final integrity hash. WARNING: output may be incomplete.\n"
        <<"  -k <keyfile>      Read key material from file (non-interactive; alt: ENCRYPTOR_KEY env / --key-stdin)\n"
        <<"                      asymmetric decrypt: this is the identity private key file (AGE-SECRET-KEY-... / X448SEC-...)\n"
        <<"  -K <name>[,...]   Resolve keys from the local key library:\n"
        <<"                      asymmetric encrypt: recipient/identity names, comma-separated\n"
        <<"                      asymmetric decrypt: one identity name (same as -k <library key>)\n"
        <<"  -r <pub|file>     Recipient public key: an \"age1...\" / \"X448-...\" / \"MLKEM1-...\"\n"
        <<"                      string, or a file holding one public key per line\n"
        <<"                      ('#' comments and publickey: ok)\n"
        <<"  -x448             Generate an X448 keypair with -g (default: X25519)\n"
        <<"  --key-stdin       Read the password from stdin until EOF (symmetric modes only)\n"
        <<"  --source-delete-ok  Source-directory removal already confirmed by the host;\n"
        <<"                    skip the interactive check\n"
        <<"  --salt <hex|file> Salt for -G: 32 hex chars, or a file holding them (default: random 16B)\n"
        <<"  --restore-name, -rn  Batch decrypt: restore full original filenames (slow: one KDF per file)\n"
        <<"  --obfuscate-name, -on  force an obfuscated output filename (<16hex>.<3 letters>.ptd)\n"
        <<"  -s, --split <size>  Encrypt, then cut the .ptd into volumes of <size>:\n"
        <<"                      2GB / 512MB / 100M / 1.5G / 4096 (1024-based; 1MB minimum)\n"
        <<"                      Decryption auto-detects volumes: pass any one of them.\n"
        <<"  --split-size <size>  Alias of --split\n"
        <<"  -p, --pack        Pack dir tree / files into ONE .ptd archive (encryption only)\n"
        <<"                      Decryption auto-detects archives and restores the tree\n"
        <<"  --no-extract       Keep a decrypted archive as a single file instead of unpacking\n"
        <<"  --sha256          Write a <out>.ptd.sha256 sidecar after successful encryption\n"
        <<"  --rename          With -R: rename the .ptd in place to its original name (content unchanged)\n"
        <<"  --as <name>       With -L add: library name for the imported key\n"
        <<"  --alias <text>    With -L add: display alias for the key\n"
        <<"  --notes <text>    With -L add: single-line note stored in the index\n"
        <<"  --watermark       Embed a signed watermark tail (machine ID + timestamp + signature)\n"
        <<"  --no-watermark    Do not embed a watermark (default)\n"
        <<"  --wm-sign <file>  With --watermark: ML-DSA-65 private key PEM (--no-pqc: RSA)\n"
        <<"  --wm-verify <file> With --watermark-extract: matching public key PEM to verify\n"
        <<"  --watermark-extract <file>  Read and verify the watermark tail (no key needed)\n"
        <<"  --wm-keygen <file>  Generate a signature key PEM and print its public key\n\n"
        <<"Config (YAML): log file/level, worker threads, path length/whitelist, progress\n"
        <<"  rotation, rate limit (max_speed), password policy (min_password_length /\n"
        <<"  min_password_classes), KDF preset (kdf_preset: fast|standard|strong),\n"
        <<"  and write_sha256 are configured in fileencryptor.yaml (see README).\n\n"
        <<"Input:\n"
        <<"  For single mode: provide the file path as positional argument\n"
        <<"  For batch mode:  provide directory paths via -i (multiple allowed)\n"
        <<"                   All files under directories will be processed recursively.\n\n"
        <<"Usage:\n"
        <<"  File encryption / decryption:\n"
        <<"    FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256|aes-gcm] [-y]\n"
        <<"    FileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256|aes-gcm] [-y]\n"
        <<"    FileEncryptor -e/-be <File> [-zstd] [--compression-level <N>]   (zstd: 1..22 normal, -1..-5 fast)\n"
        <<"    FileEncryptor -e <File> --split 4GB      (cut the .ptd into 4GB volumes)\n"
        <<"    FileEncryptor -e -p <Dir|File...>   (pack a whole tree into one .ptd)\n"
        <<"    FileEncryptor -e/-d -m x25519 -r <pub>|-k <priv> <File> [-o <Path>] [-y]\n"
        <<"  Key management (asymmetric):\n"
        <<"    FileEncryptor -g [-o <dir>] [-x448] [--no-pqc]\n"
        <<"    FileEncryptor -G [-o <dir>] [--salt <hex|file>]\n"
        <<"    FileEncryptor -Y -k <private key file>\n"
        <<"  Key wrapping:\n"
        <<"    FileEncryptor --wrap-key <dek32> [--wrap-out <f>] [--wrap-alg kwp|aes-kw|pubkey] [-k <pw>|--wrap-to <pub>]\n"
        <<"    FileEncryptor --unwrap-key <blob.fekw> [--unwrap-out <dek32>] [-k <pw>|--identity <priv>]\n"
        <<"\n  Watermark:\n"
        <<"    FileEncryptor -e --watermark --wm-sign <priv.pem> <File>\n"
        <<"    FileEncryptor --watermark-extract <File.ptd> [--wm-verify <pub.pem>]\n"
        <<"    FileEncryptor --wm-keygen <priv.pem>   (ML-DSA-65; add --no-pqc for RSA-3072)\n"
        <<"  Key library:\n"
        <<"    FileEncryptor -L list\n"
        <<"    FileEncryptor -L add <keyfile> --as <name> [--alias <text>] [--notes <text>]\n"
        <<"    FileEncryptor -L remove <name>\n"
        <<"    FileEncryptor -L show <name>\n"
        <<"    FileEncryptor -L pub <name|keyfile>    (derive and cache the recipient key)\n"
        <<"    FileEncryptor -L export <name> [dest_dir]\n"
        <<"    FileEncryptor -e -m x25519 -K <name>[,<name>...] <File>\n"
        <<"    FileEncryptor -d -k <identity file> <File.ptd>\n";
}

#ifdef _WIN32
// 将 Windows 命令行
// 使用标准 main 入口
static std::vector<std::string> get_utf8_argv() {
    std::vector<std::string> argv_utf8;
    int argc_w=0;
    wchar_t** argv_w=CommandLineToArgvW(GetCommandLineW(),&argc_w);
    if(argv_w) {
        argv_utf8.reserve((size_t)argc_w);
        for(int i=0; i<argc_w; ++i) {
            int len=WideCharToMultiByte(CP_UTF8,0,argv_w[i],-1,NULL,0,NULL,NULL);
            std::string arg(len>0?(size_t)(len-1):0,0);
            if(len>0) WideCharToMultiByte(CP_UTF8,0,argv_w[i],-1,&arg[0],len,NULL,NULL);
            argv_utf8.push_back(std::move(arg));
        }
        LocalFree(argv_w);
    }
    return argv_utf8;
}
#endif

// r 收件人公钥
// 每行一个公钥
static bool collect_recipients(const std::string& spec,
                               std::vector<std::string>& out,
                               std::string& err) {
    auto trim=[](const std::string& s)->std::string{
        size_t a=0,b=s.size();
        while(a<b && (unsigned char)s[a]<=0x20) ++a;
        while(b>a && (unsigned char)s[b-1]<=0x20) --b;
        return s.substr(a,b-a);
    };
    auto strip_prefix=[&trim](const std::string& s)->std::string{
        return (s.rfind("publickey:",0)==0) ? trim(s.substr(10)) : s;
    };
    auto is_pubkey=[&trim](const std::string& s)->bool{
        if(s.rfind("publickey:",0)==0) return true;
        std::string low=trim(s);
        // 前缀含大写
        std::transform(low.begin(),low.end(),low.begin(),
            [](unsigned char c){ return (char)std::tolower(c); });
        return low.rfind("age1",0)==0 || low.rfind("x448-",0)==0
            || low.rfind("mlkem1-",0)==0;
    };

    const std::string t=trim(spec);
    if(t.empty()) { err="Empty recipient specification."; return false; }

    if(is_pubkey(t)) {                      // 内联公钥
        std::string v=strip_prefix(t);
        if(v.empty()) { err="Empty recipient public key."; return false; }
        out.push_back(v);
        return true;
    }

    std::ifstream rf;                       
    if(!open_stream(rf,t,std::ios::in|std::ios::binary)) {
        err="Cannot open public key file: "+t;
        return false;
    }
    std::string line;
    while(std::getline(rf,line)) {
        if(!line.empty()&&line.back()=='\r') line.pop_back();
        std::string v=trim(line);
        if(v.empty()||v[0]=='#') continue;
        v=strip_prefix(v);
        if(v.empty()) continue;
        if(!is_pubkey(v)) {
            err="Invalid public key line (expected age1... / x448-... / mlkem1-...): "+v;
            return false;
        }
        out.push_back(v);
    }
    rf.close();
    if(out.empty()) { err="No public keys found in: "+t; return false; }
    return true;
}

// 把归档明文展开
// 先展开到同级暂
// 同名文件撞车
// 暂存目录
static bool unpack_archive(const std::string& plain_path, const std::string& dest_dir,
                           bool force_overwrite) {
    if (!create_directory_recursive(dest_dir)) {
        std::cerr << "Error: cannot create output directory: " << dest_dir << "\n";
        return false;
    }
    unsigned char rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    std::string tmp_dir = dest_dir + "/.unpack-" + fe::util::to_hex(rnd, sizeof(rnd));
    if (!create_directory_recursive(tmp_dir)) {
        std::cerr << "Error: cannot create a staging directory: " << tmp_dir << "\n";
        return false;
    }
    std::string err;

    std::cout << "Unpacking archive to: " << dest_dir << "\n";
    uint64_t last_pct = 100;
    std::function<void(uint64_t, uint64_t)> cb = [&](uint64_t done, uint64_t total) {
        if (total == 0) return;
        uint64_t pct = done * 100 / total;
        if (pct >= last_pct) return;              // 只在整数百分点
        last_pct = pct;
        fprintf(stderr, "\rExtracting: %llu%%", (unsigned long long)pct);
        fflush(stderr);
    };
    if (!archive_extract(plain_path, tmp_dir, force_overwrite, cb, err)) {
        fprintf(stderr, "\n");
        std::cerr << "Error: " << err << "\n";
        remove_file_utf8(plain_path);             // 半成品不留
        return false;
    }
    if (last_pct < 100) fprintf(stderr, "\rExtracting: 100%%");
    fprintf(stderr, "\n");

    // 展开成功才删
    remove_file_utf8(plain_path);

    // 把暂存目录里
    // rename 整个暂存目录
    // 顶层项逐个并入 dest_dir
    // dest_dir 里已有
    bool ok = true;
    std::vector<std::string> tops;
    if (!list_dir_names(tmp_dir, tops)) {
        std::cerr << "Error: cannot read the staging directory\n";
        return false;
    }
    for (const auto& name : tops) {
        std::string from = tmp_dir + "/" + name;
        std::string to = dest_dir + "/" + name;
        bool fdir = fe_path_is_directory(from);
        bool tdir = fe_path_is_directory(to);
        if (fdir && tdir) {
            std::string merr;
            if (!merge_dir_into(from, to, force_overwrite, merr)) {
                std::cerr << "Error: " << merr << "\n";
                ok = false;
            }
            continue;
        }
        if (tdir) remove_tree(to);                        // 同名目录挡路
        else if (!force_overwrite) {
            std::ifstream ex;
            if (open_stream(ex, to, std::ios::in | std::ios::binary) && ex.good()) {
                fprintf(stderr, "Skipped (exists): %s\n", to.c_str());
                continue;
            }
        } else {
            remove_file_utf8(to);
        }
        if (!replace_file_utf8(from, to)) {
            std::cerr << "Error: cannot move " << from << " to " << to << "\n";
            ok = false;
        }
    }
    // 暂存目录空了，删
    if (ok) remove_tree(tmp_dir);
    else std::cerr << "Incomplete items are left at: " << tmp_dir << "\n";
    return ok;
}

// -pack
// 归档字节流本身
static bool run_pack(const std::vector<std::string>& input_paths,
                     const std::string& output_dir,
                     const SecureBuffer& password,
                     CryptoMode mode,
                     int source_action,
                     bool force_overwrite,
                     int compress_level,
                     uint64_t split_bytes,
                     const WatermarkSpec* wm,
                     bool sha_sidecar) {
    // 输出名
    std::string out_base = "archive";
    if (input_paths.size() == 1) {
        const std::string& in = input_paths[0];
        size_t slash = in.find_last_of("/\\");
        std::string fname = (slash != std::string::npos) ? in.substr(slash + 1) : in;
        size_t dot = fname.find_last_of('.');
        if (dot != std::string::npos && dot > 0) fname = fname.substr(0, dot);
        if (!fname.empty()) out_base = fname;
    }
    std::string out_dir = output_dir;
    if (out_dir.empty()) out_dir = fe_path_is_directory(input_paths[0]) ? input_paths[0] : ".";
    if (!create_directory_recursive(out_dir)) {
        std::cerr << "Cannot create output directory: " << out_dir << "\n";
        return false;
    }
    std::string out_path = out_dir;
    if (!out_path.empty() && out_path.back() != '/' && out_path.back() != '\\')
        out_path += '/';
    out_path += out_base + ".ptd";
    out_path = to_native_path(out_path);

    if (!force_overwrite) {
        std::ifstream test;
        if (open_stream(test, out_path, std::ios::in | std::ios::binary) && test.good()) {
            if (!confirm_yes_no("Output file exists: " + out_path, "Overwrite? (y/N): ")) {
                std::cerr << "Aborted.\n";
                return false;
            }
        }
    }

    // 输出 .ptd
    std::vector<std::string> excludes;
    excludes.push_back(out_path);

    std::string tmp_archive;
    std::string err;
    if (!archive_make_temp("pack", tmp_archive, err)) {
        std::cerr << "Error: " << err << "\n";
        return false;
    }
    excludes.push_back(tmp_archive);

    std::vector<ArchiveEntry> entries;
    if (!archive_collect(input_paths, excludes, entries, err)) {
        std::cerr << "Error: " << err << "\n";
        remove_file_utf8(tmp_archive);
        return false;
    }

    uint64_t total_raw = 0;
    for (const auto& e : entries) if (!e.is_dir) total_raw += e.size;
    size_t file_count = entries.size();
    for (const auto& e : entries) if (e.is_dir) --file_count;
    std::cout << "Packing " << file_count << " file(s) from " << entries.size()
              << " entrie(s), " << format_size(total_raw).c_str() << " raw -> " << out_path << "\n";

    if (!archive_write(tmp_archive, entries, err)) {
        std::cerr << "Error: " << err << "\n";
        remove_file_utf8(tmp_archive);
        return false;
    }

    bool ok = true;
    try {
        ok = encrypt_file(tmp_archive, out_path, password, mode, nullptr, true,
                          compress_level, false, nullptr, wm);
    } catch (const std::exception& e) {
        fprintf(stderr, "Error: encryption failed: %s\n", e.what());
        ok = false;
    } catch (...) {
        fprintf(stderr, "Error: encryption failed (unexpected exception)\n");
        ok = false;
    }

    // 中间归档明文
    if (ok) secure_handle_source(tmp_archive, SourceDisposition::Wipe);
    else remove_file_utf8(tmp_archive);

    if (!ok) {
        remove_file_utf8(out_path);
        remove_file_utf8(out_path + ".prs");
        return false;
    }

    // 源文件处置
    // 故目录输入只提
    if (source_action != 0) {
        for (const auto& in : input_paths) {
            if (fe_path_is_directory(in)) {
                fprintf(stderr,
                        "Note: --pack does not remove source directories automatically; "
                        "removing a whole tree is left to you: %s\n", in.c_str());
                continue;
            }
            if (!secure_handle_source(in, static_cast<SourceDisposition>(source_action))) {
                std::cerr << "Error: could not process source file: " << in << "\n";
                ok = false;
            }
        }
    }
    if (ok && sha_sidecar) write_sha256_sidecar(out_path);
    if (ok && split_bytes > 0) {
        std::string serr;
        if (!finish_encrypt_split(out_path, split_bytes, sha_sidecar, serr)) {
            std::cerr << "Error: split failed: " << serr << "\n";
            ok = false;
        }
    }
    return ok;
}

// 非对称调度
// 路径校验 / 符号链
static bool run_asym(const std::vector<std::string>& input_paths,
                     const std::string& output_dir,
                     bool is_encrypt,
                     int source_action,
                     bool force_overwrite,
                     const std::string& recipient_spec,
                     const std::string& identity_file,
                     const SecureBuffer& key_material,
                     bool obfuscate_name=false,
                     const std::vector<std::string>& extra_recipients = {},
                     CryptoMode mode = CryptoMode::XCHACHA20,
                     int compress_level = 0,
                     uint64_t split_bytes = 0) {
    std::vector<std::string> recipients;
    if(is_encrypt) {
        // r 收件人
        // K 补充密钥库收件
        if(recipient_spec.empty()&&extra_recipients.empty()) {
            std::cerr<<"Asymmetric encryption requires -r <public key or public key file> "
                <<"or -K <library key name>.\n";
            return false;
        }
        std::string err;
        if(!recipient_spec.empty()&&!collect_recipients(recipient_spec,recipients,err)) {
            std::cerr<<err<<"\n";
            return false;
        }
        for(const auto& pk: extra_recipients) {
            if(std::find(recipients.begin(),recipients.end(),pk)==recipients.end())
                recipients.push_back(pk);
        }
        if(recipients.empty()) {
            std::cerr<<"No usable recipients (check -r / -K).\n";
            return false;
        }
    } else {
        // 解密私钥
        if(identity_file.empty()) {
            std::cerr<<"Asymmetric decryption requires a private key file: -k <identity file>.\n";
            return false;
        }
        if(key_material.empty()) {
            std::cerr<<"Private key file is empty or unreadable: "<<identity_file<<"\n";
            return false;
        }
    }

    bool all_ok=true;
    for(const std::string& in_path: input_paths) {
        // 分卷输入先合并
        // 只换读取源
        SplitPlan plan;
        MergedTemp merged;
        std::string src_path=in_path;
        if(!is_encrypt) {
            std::string perr;
            if(!resolve_decrypt_input(in_path,plan,perr)) {
                std::cerr<<"Error: "<<perr<<"\n";
                all_ok=false; continue;
            }
            if(plan.from_volumes) {
                merged.path=plan.merged_path;
                src_path=plan.merged_path;
            }
        }
        std::string out_path;
        if(is_encrypt) {
            std::string base=in_path;
            size_t pos=base.find_last_of("/\\");
            std::string fname=(pos!=std::string::npos)?base.substr(pos+1):base;
            // 容器自带文件名
            if(obfuscate_name) {
                fname=make_obfuscated_basename(in_path,key_material);
            }
            if(!output_dir.empty()) {
                if(!create_directory_recursive(output_dir)) {
                    std::cerr<<"Cannot create output directory: "<<output_dir<<"\n";
                    all_ok=false; break;
                }
                out_path=output_dir;
                if(out_path.back()!='/'&&out_path.back()!='\\') out_path+='/';
                out_path+=fname;
            } else {
                out_path=in_path;
            }
            out_path=to_native_path(out_path);   // 分隔符统一
            out_path+=".ptd";
        } else {
            std::string lower=in_path;
            std::transform(lower.begin(),lower.end(),lower.begin(),
                [](unsigned char c){ return (char)std::tolower(c); });
            if(lower.size()<4||lower.substr(lower.size()-4)!=".ptd") {
                std::cerr<<"Asymmetric decryption input must have .ptd extension: "<<in_path<<"\n";
                all_ok=false; continue;
            }
            std::string stem=in_path.substr(0,in_path.size()-4);
            size_t spos=stem.find_last_of("/\\");
            std::string stem_name=(spos!=std::string::npos)?stem.substr(spos+1):stem;
            if(!output_dir.empty()) {
                if(!create_directory_recursive(output_dir)) {
                    std::cerr<<"Cannot create output directory: "<<output_dir<<"\n";
                    all_ok=false; break;
                }
                out_path=output_dir;
                if(out_path.back()!='/'&&out_path.back()!='\\') out_path+='/';
                out_path+=stem_name;
            } else {
                out_path=stem;
            }
            out_path=to_native_path(out_path);   // 分隔符统一
            if(out_path==in_path) {
                std::cerr<<"Error: output path would overwrite input file.\n";
                all_ok=false; continue;
            }
        }

        // 路径策略校验 + 符
        // 输入路径
        if(!validate_io_paths(in_path,out_path,false)) {
            std::cerr<<"Path validation failed (config policy)\n";
            all_ok=false; continue;
        }
        if(path_is_symlink(out_path)) {
            std::cerr<<"Refusing to write through existing symlink: "<<out_path<<"\n";
            all_ok=false; continue;
        }

        // 覆盖确认
        if(!force_overwrite) {
            std::ifstream test;
            if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                test.close();
                if(!confirm_yes_no("Output file exists: "+out_path,"Overwrite? (y/N): ")) {
                    std::cerr<<"Aborted.\n"; all_ok=false; continue;
                }
            }
        }

        // 解密走 .prt 半成品 + 原
        // 失败
        bool ok=false;
        if(is_encrypt) {
            std::cout<<"Asymmetric encrypting: "<<in_path<<" -> "<<out_path<<"\n";
            try {
                ok=encrypt_file(src_path,out_path,SecureBuffer(),mode,nullptr,false,compress_level,
                                true,&recipients);
            } catch(const std::exception& e) {
                fprintf(stderr,"Error: asymmetric encryption failed: %s\n",e.what());
                ok=false;
            } catch(...) {
                fprintf(stderr,"Error: asymmetric encryption failed (unexpected exception)\n");
                ok=false;
            }
        } else {
            std::cout<<"Asymmetric decrypting: "<<in_path<<" -> "<<out_path<<"\n";
            std::string identity(key_material.cdata(), key_material.size());
            {   // 私钥文件可能带
                size_t a=0,b=identity.size();
                while(a<b && (unsigned char)identity[a]<=0x20) ++a;
                while(b>a && (unsigned char)identity[b-1]<=0x20) --b;
                if(b<identity.size()) identity.erase(b);
                if(a>0)               identity.erase(0,a);
            }
            try {
                ok=decrypt_file(src_path,out_path,SecureBuffer(),nullptr,
                                false,false,nullptr,nullptr,0,false,0,identity,force_overwrite);
            } catch(const std::exception& e) {
                fprintf(stderr,"Error: asymmetric decryption failed: %s\n",e.what());
                ok=false;
            } catch(...) {
                fprintf(stderr,"Error: asymmetric decryption failed (unexpected exception)\n");
                ok=false;
            }
            // resize 到 capacity
            identity.resize(identity.capacity());
            sodium_memzero(identity.data(),identity.size());
        }
        if(!ok) {
            std::cerr<<"Failed to process: "<<in_path<<"\n";
            // 解密失败时核心
            remove_file_utf8(out_path);
            all_ok=false; continue;
        }
        if(is_encrypt && source_action!=0) {
            if(!secure_handle_source(in_path, static_cast<SourceDisposition>(source_action))) {
                std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                all_ok=false;
            }
        }
        if(is_encrypt && split_bytes>0) {
            std::string serr;
            if(!finish_encrypt_split(out_path,split_bytes,write_sha256_enabled(),serr)) {
                std::cerr<<"Error: split failed: "<<serr<<"\n";
                all_ok=false;
            }
        }
    }
    return all_ok;
}

// 密钥包装
// 公钥路线不需要
static int run_keywrap(const std::string& in_path, const std::string& out_path,
                       const std::string& alg_name, const std::string& to_pub,
                       const SecureBuffer& password, bool force_overwrite) {
    if(!keywrap_available()) { std::cerr<<"Key wrap requires an OpenSSL-enabled build\n"; return 1; }
    const uint8_t by=keywrap_alg_from_name(alg_name);
    const bool is_pub = (by==2);
    if(!is_pub && password.empty()) {
        std::cerr<<"--wrap-key needs a password (-k / ENCRYPTOR_KEY / --key-stdin)\n";
        return 1;
    }
    if(is_pub && to_pub.empty()) {
        std::cerr<<"--wrap-key --wrap-alg pubkey needs --wrap-to <recipient public key>\n";
        return 1;
    }

    std::vector<unsigned char> dek;
    if(!keywrap_read_file(in_path, dek)) {
        std::cerr<<"Cannot read: "<<in_path<<"\n";
        return 1;
    }
    while(!dek.empty() && (dek.back()=='\n'||dek.back()=='\r')) dek.pop_back();
    if(dek.size()!=32) {
        std::cerr<<"Expected a 32-byte DEK, got " << dek.size() << " bytes\n";
        sodium_memzero(dek.data(), dek.size());
        return 1;
    }

    // 公钥串本身或存
    std::string pub_s;
    if(is_pub) {
        pub_s = to_pub;
        std::vector<unsigned char> raw;
        if(keywrap_read_file(to_pub, raw)) {
            while(!raw.empty() && (raw.back()=='\n'||raw.back()=='\r')) raw.pop_back();
            if(!raw.empty()) pub_s.assign((const char*)raw.data(), raw.size());
        }
    }

    unsigned char kek[ARGON2_OUTPUT_LEN];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    bool have_kek=false;
    if(!is_pub) {
        randombytes_buf(salt, sizeof salt);
        unsigned int ops=ARGON2_OPS_DEFAULT; unsigned int mem_kb=ARGON2_MEM_DEFAULT_KB;
        kdf_preset_params(global_config().kdf_preset, ops, mem_kb);
        size_t mem=(size_t)mem_kb*1024;
        if(!derive_key((const unsigned char*)password.data(), password.size(),
                       salt, kek, ops, mem)) {
            std::cerr<<"Key derivation failed\n";
            sodium_memzero(dek.data(), dek.size());
            return 1;
        }
        have_kek=true;
    }

    std::vector<unsigned char> blob;
    std::string err;
    const bool ok=keywrap_pack(dek.data(), dek.size(),
                               have_kek?kek:nullptr, by,
                               pub_s,
                               is_pub?nullptr:salt, is_pub?0:sizeof salt,
                               blob, err);
    sodium_memzero(dek.data(), dek.size());
    if(have_kek) sodium_memzero(kek, sizeof kek);
    if(!ok) { std::cerr<<err<<"\n"; return 1; }

    if(!force_overwrite && file_exists_path(out_path)) {
        std::cerr<<"Refusing to overwrite: " << out_path << "\nUse -y to overwrite.\n";
        return 1;
    }
    if(!keywrap_write_file_exclusive(out_path, blob.data(), blob.size())) {
        std::cerr<<"Cannot write: " << out_path << "\n";
        return 1;
    }
    tighten_file_permissions(out_path);
    std::cerr<<"Wrapped DEK written to: " << out_path << "\n";
    std::cerr<<"Algorithm: " << keywrap_alg_name(by) << "\n";
    return 0;
}

// 解包装
static int run_unwrapkey(const std::string& in_path, const std::string& out_path,
                         const SecureBuffer& password, const std::string& priv_path,
                         bool force_overwrite) {
    if(!keywrap_available()) { std::cerr<<"Key wrap requires an OpenSSL-enabled build\n"; return 1; }
    std::vector<unsigned char> blob;
    if(!keywrap_read_file(in_path, blob)) {
        std::cerr<<"Cannot read: " << in_path << "\n";
        return 1;
    }
    if(blob.size()<6 || memcmp(blob.data(), "FEKW", 4)!=0) {
        std::cerr<<"Not a FEKW blob: " << in_path << "\n";
        return 1;
    }
    const uint8_t by=blob[5];
    const bool is_pub = (by==2);

    if(!is_pub && password.empty()) {
        std::cerr<<"This blob needs a password (-k / ENCRYPTOR_KEY / --key-stdin)\n";
        return 1;
    }

    // 密码路线
    unsigned char kek[ARGON2_OUTPUT_LEN];
    bool have_kek=false;
    if(!is_pub) {
        const size_t salt_len=((size_t)blob[8]<<8)|blob[9];
        if(salt_len!=crypto_pwhash_SALTBYTES || blob.size()<12+salt_len) {
            std::cerr<<"Blob has no usable KDF salt\n";
            return 1;
        }
        unsigned int ops=ARGON2_OPS_DEFAULT; unsigned int mem_kb=ARGON2_MEM_DEFAULT_KB;
        kdf_preset_params(global_config().kdf_preset, ops, mem_kb);
        size_t mem=(size_t)mem_kb*1024;
        if(!derive_key((const unsigned char*)password.data(), password.size(),
                       blob.data()+12, kek, ops, mem)) {
            std::cerr<<"Key derivation failed\n";
            return 1;
        }
        have_kek=true;
    }

    // 身份私钥串本身
    std::string priv_s;
    if(is_pub) {
        if(priv_path.empty()) {
            std::cerr<<"This blob needs the recipient identity: --identity <file or private key string>\n";
            return 1;
        }
        priv_s = priv_path;
        std::vector<unsigned char> raw;
        if(keywrap_read_file(priv_path, raw)) {
            while(!raw.empty() && (raw.back()=='\n'||raw.back()=='\r')) raw.pop_back();
            if(!raw.empty()) priv_s.assign((const char*)raw.data(), raw.size());
        }
    }

    std::vector<unsigned char> dek;
    uint8_t got_alg=1;
    std::string err;
    const bool ok=keywrap_unpack(blob.data(), blob.size(),
                                 have_kek?kek:nullptr, priv_s,
                                 dek, got_alg, err);
    if(have_kek) sodium_memzero(kek, sizeof kek);
    if(!ok) { std::cerr<<err<<"\n"; return 1; }
    if(dek.size()!=32) {
        std::cerr<<"Unwrapped DEK has unexpected length\n";
        sodium_memzero(dek.data(), dek.size());
        return 1;
    }

    if(!force_overwrite && file_exists_path(out_path)) {
        std::cerr<<"Refusing to overwrite: " << out_path << "\nUse -y to overwrite.\n";
        sodium_memzero(dek.data(), dek.size());
        return 1;
    }
    const bool w=keywrap_write_file_exclusive(out_path, dek.data(), dek.size());
    sodium_memzero(dek.data(), dek.size());
    if(!w) { std::cerr<<"Cannot write: " << out_path << "\n"; return 1; }
    tighten_file_permissions(out_path);
    std::cerr<<"DEK written to: " << out_path << "\n";
    return 0;
}


static bool run_keygen(const std::string& output_dir,bool force_overwrite,uint8_t algo) {
    std::string pub, priv;
    AsymOutcome o=fe_generate_keypair(algo,pub,priv);
    if(!o.ok) {
        std::cerr<<"Key generation failed: "<<o.error<<"\n";
        return false;
    }

    std::string dir=output_dir;
    if(!dir.empty()) {
        if(!create_directory_recursive(dir)) {
            std::cerr<<"Cannot create output directory: "<<dir<<"\n";
            sodium_memzero(priv.data(),priv.size());
            return false;
        }
        if(dir.back()!='/'&&dir.back()!='\\') dir+='/';
    }

    auto write_line=[](const std::string& path,const std::string& content)->bool{
        clear_readonly_attribute(path);   // 旧版本可能
        std::ofstream of;
        if(!open_stream(of,path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            std::cerr<<"Cannot write: "<<path<<"\n";
            return false;
        }
        of<<content<<"\n";
        of.flush();
        const bool bad=!of.good();
        of.close();
        return !bad;
    };

    // H5c
    // 即便 -y
    // 不可解密
    auto write_line_exclusive=[](const std::string& path,const std::string& content)->bool{
#ifdef _WIN32
        const std::wstring wp=utf8_to_wstring(path);
        int fd=_wopen(wp.c_str(),_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY,_S_IREAD|_S_IWRITE);
        if(fd<0) {
            std::cerr<<(errno==EEXIST
                ? "Private key file already exists (delete it or choose another directory): "
                : "Cannot create: ")<<path<<"\n";
            return false;
        }
        FILE* fp=_fdopen(fd,"wb");
        if(!fp) { _close(fd); _wunlink(wp.c_str()); std::cerr<<"Cannot write: "<<path<<"\n"; return false; }
#else
        int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if(fd<0) {
            std::cerr<<(errno==EEXIST
                ? "Private key file already exists (delete it or choose another directory): "
                : "Cannot create: ")<<path<<"\n";
            return false;
        }
        FILE* fp=fdopen(fd,"wb");
        if(!fp) { ::close(fd); ::unlink(path.c_str()); std::cerr<<"Cannot write: "<<path<<"\n"; return false; }
#endif
        const std::string line=content+"\n";
        const size_t n=std::fwrite(line.data(),1,line.size(),fp);
        bool ok=(n==line.size());
        if(std::fclose(fp)!=0) ok=false;
        if(!ok) {
#ifdef _WIN32
            _wunlink(wp.c_str());
#else
            ::unlink(path.c_str());
#endif
            std::cerr<<"Cannot write: "<<path<<"\n";
        }
        return ok;
    };

    const std::string priv_path=dir+"rage_private.txt";

    // v2.1.2
    // .age 文件
    if(!force_overwrite&&file_exists_path(priv_path)) {
        std::cerr<<"Refusing to overwrite existing private key file: "<<priv_path
            <<"\nDelete it or choose another directory first.\n";
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    if(!write_line_exclusive(priv_path,priv)) {
        sodium_memzero(priv.data(),priv.size());
        return false;
    }
    tighten_file_permissions(priv_path);   // 收紧密钥文件权

    // 公钥
    const std::string pub_path=dir+"rage_public.txt";
    if(!write_line(pub_path,pub)) {
        std::cerr<<"Cannot write: "<<pub_path<<"\n";
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    // stdout 只输出公钥
    std::cout<<pub<<"\n";
    std::cout.flush();
    // stderr 输出其余信息
    std::cerr<<"Private key file: "<<priv_path<<"\n";
    std::cerr<<"Public key file : "<<pub_path<<"\n";
    std::cerr<<"Public key ("<<(algo==RECIP_ALGO_MLKEM?"MLKEM1-...":algo==RECIP_ALGO_X448?"X448-...":"age1...")
        <<") printed above - share it freely; the private key decrypts.\n";

    sodium_memzero(priv.data(),priv.size());
    return true;
}

// 解析 --salt
static bool parse_salt(const std::string& spec,std::vector<unsigned char>& out) {
    auto trim=[](const std::string& s)->std::string{
        size_t a=0,b=s.size();
        while(a<b&&(unsigned char)s[a]<=0x20) ++a;      // 吃掉 CR / LF / 空格
        while(b>a&&(unsigned char)s[b-1]<=0x20) --b;
        return s.substr(a,b-a);
    };
    auto is_hex=[](const std::string& s)->bool{
        if(s.empty()) return false;
        for(char c: s) if(!std::isxdigit((unsigned char)c)) return false;
        return true;
    };
    std::string t=trim(spec);
    if(t.size()!=32||!is_hex(t)) {                       // 不是裸 hex
        std::ifstream f;
        if(!open_stream(f,t,std::ios::in)) {
            std::cerr<<"Cannot open salt file: "<<t<<"\n";
            return false;
        }
        std::getline(f,t);
        f.close();
        t=trim(t);
    }
    if(t.size()!=32||!is_hex(t)) {
        std::cerr<<"Invalid salt: expected 16 bytes written as 32 hex characters (got \""<<t<<"\").\n";
        return false;
    }
    out.assign(16,0);
    size_t bin_len=0;
    if(sodium_hex2bin(out.data(),out.size(),t.c_str(),t.size(),NULL,&bin_len,NULL)!=0||bin_len!=16) {
        std::cerr<<"Invalid salt hex: "<<t<<"\n";
        return false;
    }
    return true;
}

static bool run_derive(const std::string& output_dir,
                       const SecureBuffer& password,
                       const std::string& salt_spec,
                       bool force_overwrite) {
    std::vector<unsigned char> salt;
    const bool reuse_salt=!salt_spec.empty();
    if(reuse_salt&&!parse_salt(salt_spec,salt)) return false;

    std::string pub,priv;
    AsymOutcome o=fe_derive_keypair(password.cdata(),password.size(),salt,pub,priv);
    if(!o.ok) {
        std::cerr<<"Key derivation failed: "<<o.error<<"\n";
        return false;
    }

    std::string dir=output_dir;
    if(!dir.empty()) {
        if(!create_directory_recursive(dir)) {
            std::cerr<<"Cannot create output directory: "<<dir<<"\n";
            sodium_memzero(priv.data(),priv.size());
            return false;
        }
        if(dir.back()!='/'&&dir.back()!='\\') dir+='/';
    }

    auto file_exists=[](const std::string& p)->bool{
        return file_exists_path(p);
    };
    auto write_line=[](const std::string& path,const std::string& content)->bool{
        clear_readonly_attribute(path);   // 旧版本可能
        std::ofstream of;
        if(!open_stream(of,path,std::ios::out|std::ios::binary|std::ios::trunc)) {
            std::cerr<<"Cannot write: "<<path<<"\n";
            return false;
        }
        of<<content<<"\n";
        of.flush();
        const bool bad=!of.good();
        of.close();
        return !bad;
    };
    // H5c
    // 即便 -y
    // 不可解密
    auto write_line_exclusive=[](const std::string& path,const std::string& content)->bool{
#ifdef _WIN32
        const std::wstring wp=utf8_to_wstring(path);
        int fd=_wopen(wp.c_str(),_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY,_S_IREAD|_S_IWRITE);
        if(fd<0) {
            std::cerr<<(errno==EEXIST
                ? "Private key file already exists (delete it or choose another directory): "
                : "Cannot create: ")<<path<<"\n";
            return false;
        }
        FILE* fp=_fdopen(fd,"wb");
        if(!fp) { _close(fd); _wunlink(wp.c_str()); std::cerr<<"Cannot write: "<<path<<"\n"; return false; }
#else
        int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if(fd<0) {
            std::cerr<<(errno==EEXIST
                ? "Private key file already exists (delete it or choose another directory): "
                : "Cannot create: ")<<path<<"\n";
            return false;
        }
        FILE* fp=fdopen(fd,"wb");
        if(!fp) { ::close(fd); ::unlink(path.c_str()); std::cerr<<"Cannot write: "<<path<<"\n"; return false; }
#endif
        const std::string line=content+"\n";
        const size_t n=std::fwrite(line.data(),1,line.size(),fp);
        bool ok=(n==line.size());
        if(std::fclose(fp)!=0) ok=false;
        if(!ok) {
#ifdef _WIN32
            _wunlink(wp.c_str());
#else
            ::unlink(path.c_str());
#endif
            std::cerr<<"Cannot write: "<<path<<"\n";
        }
        return ok;
    };

    const std::string priv_path=dir+"rage_private.txt";
    const std::string salt_path=dir+"rage_derive_salt.txt";
    if(!force_overwrite&&(file_exists(priv_path)||file_exists(salt_path))) {
        std::cerr<<"Refusing to overwrite existing key files in: "
            <<(dir.empty()?std::string("."):dir)<<"\nUse -y to overwrite.\n";
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    char salt_hex[33];
    if(sodium_bin2hex(salt_hex,sizeof(salt_hex),salt.data(),salt.size())==NULL) {
        std::cerr<<"Failed to encode the salt.\n";
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    bool ok=write_line_exclusive(priv_path,priv);
    if(ok) ok=write_line(salt_path,std::string(salt_hex));
    if(ok) tighten_file_permissions(priv_path);   // 收紧密钥文件权

    sodium_memzero(salt_hex,sizeof(salt_hex));
    sodium_memzero(salt.data(),salt.size());
    if(!ok) {
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    std::cout<<pub<<"\n";
    std::cout.flush();
    std::cerr<<"Private key file: "<<priv_path<<"\n";
    std::cerr<<"Salt file:        "<<salt_path<<"\n";
    std::cerr<<(reuse_salt
        ? "Re-derived with the given salt: the same password + salt always yields this keypair.\n"
        : "Derived with a fresh random salt. Keep BOTH files: the salt is required to re-derive.\n");

    sodium_memzero(priv.data(),priv.size());
    return true;
}

static bool run_pubkey(const SecureBuffer& identity) {
    std::string id(identity.cdata(),identity.size());
    {   // 私钥文件可能带
        size_t a=0,b=id.size();
        while(a<b&&(unsigned char)id[a]<=0x20) ++a;
        while(b>a&&(unsigned char)id[b-1]<=0x20) --b;
        if(a!=0) id.erase(0,a);
        if(b<id.size()) id.erase(b);
    }
    std::string pub;
    AsymOutcome o=fe_identity_to_recipient(id,pub);
    sodium_memzero(id.data(),id.size());
    if(!o.ok) {
        std::cerr<<"Cannot derive the public key: "<<o.error<<"\n";
        return false;
    }
    std::cout<<pub<<"\n";
    std::cout.flush();
    std::cerr<<"Public key printed above; it corresponds to the given private key.\n";
    return true;
}

// 功能2
// 原始大小/明文 Blake2b/
static bool run_info(const std::string& path) {
    PtdMeta meta;
    if(!read_ptd_metadata(path, meta)) {
        std::cerr<<"Cannot read header (not a FileEncryptor file): "<<path<<"\n";
        return false;
    }
    const char* mode_str = (meta.mode==CryptoMode::XCHACHA20)?"XChaCha20"
                         : (meta.mode==CryptoMode::AEGIS256)?"AEGIS-256"
                         : (meta.mode==CryptoMode::SM4)?"SM4-GCM"
                         : (meta.mode==CryptoMode::AES_GCM)?"AES-256-GCM":"unknown";
    std::cout<<"File: "<<path<<"\n";
    std::cout<<"  version          : "<<(int)meta.version<<"\n";
    std::cout<<"  mode             : "<<mode_str<<"\n";
    if(meta.version>=2) {
        std::cout<<"  argon2 opslimit  : "<<meta.opslimit<<"\n";
        std::cout<<"  argon2 memlimit  : "<<meta.memlimit_kb<<" KB\n";
    }
    std::cout<<"  salt (hex)       : "<<(meta.salt_hex.empty()?"-":meta.salt_hex)<<"\n";
    std::cout<<"  iv/nonce (hex)   : "<<(meta.iv_hex.empty()?"-":meta.iv_hex)<<"\n";
    if(meta.version>=3)
        std::cout<<"  original size    : "<<meta.orig_size<<" bytes\n";
    if(meta.dek_wrapped)
        std::cout<<"  key version      : "<<meta.key_version<<" (DEK wrapped; rewrap-able)\n";
    if(!meta.plaintext_hash_hex.empty())
        std::cout<<"  plaintext Blake2b : "<<meta.plaintext_hash_hex<<"\n";
    std::cout<<"  encrypted name    : "<<(meta.has_name_footer?"yes":"no")<<"\n";
    if(meta.compression>0) {
        std::cout<<"  compression       : zstd";
        if(meta.comp_level!=0) std::cout<<" (level "<<(int)meta.comp_level<<")";
        std::cout<<"\n";
    } else {
        std::cout<<"  compression       : none\n";
    }
    std::cout<<"  (metadata only; key correctness is NOT verified)\n";
    return true;
}

// 水印查看器
static bool run_watermark(const std::string& path, const std::string& pub_pem, bool pqc) {
    WatermarkInfo wm;
    if(!read_watermark(path, wm, pub_pem, pqc)) {
        std::cerr<<"No watermark found in: "<<path<<"\n";
        return false;
    }
    std::cout<<"File: "<<path<<"\n";
    std::cout<<"  signed     : "<<(wm.has_signature?"yes":"no")<<"\n";
    if(wm.has_signature) {
        if(!wm.verify_attempted)
            std::cout<<"  signature  : not checked (no --wm-verify public key)\n";
        else
            std::cout<<"  signature  : "<<(wm.verify_ok?"verified":"VERIFICATION FAILED")<<"\n";
    }
    if(!wm.error.empty())
        std::cout<<"  note       : "<<wm.error<<"\n";
    std::cout<<"  machine id : "<<(wm.machine_id_hex.empty()?"-":wm.machine_id_hex)<<"\n";
    std::cout<<"  sources    : MAC="<<((wm.flags&0x01)?"yes":"no")
             <<"  mainboard="<<((wm.flags&0x02)?"yes":"no")<<"\n";
    std::cout<<"  timestamp  : "<<(wm.timestamp?wm_timestamp_text(wm.timestamp):std::string("-"))<<"\n";
    std::cout<<"  nonce      : "<<(wm.nonce_hex.empty()?"-":wm.nonce_hex)<<"\n";
    return wm.verify_ok || wm.error.empty();
}

// 身份私钥常
// V/-R 会误报「解密失败」
static std::string normalize_identity(const SecureBuffer& buf) {
    const unsigned char* p=reinterpret_cast<const unsigned char*>(buf.cdata());
    size_t a=0, b=buf.size();
    while(a<b && p[a]<=0x20) ++a;
    while(b>a && p[b-1]<=0x20) --b;
    return std::string(reinterpret_cast<const char*>(p+a), b-a);
}

// 密码材料本身
static bool looks_like_identity(const SecureBuffer& buf) {
    const std::string s=normalize_identity(buf);
    return s.rfind("AGE-SECRET-KEY-",0)==0 || s.rfind("MLKEM1SEC-",0)==0
        || s.rfind("X448SEC-",0)==0;
}

// 功能3
static bool run_verify(const std::string& path, const SecureBuffer& pw,
                       const std::string& asym_identity) {
    if(verify_ptd(path, pw, asym_identity)) {
        std::cout<<"OK    "<<path<<"\n";
        return true;
    }
    std::cout<<"FAILED "<<path<<"\n";
    return false;
}

// 功能15
// 带 --rename
static bool run_recover(const std::string& path, const SecureBuffer& pw, bool do_rename,
                        const std::string& asym_identity) {
    std::string orig;
    if(!read_original_name(path, orig, pw, nullptr, 0, nullptr, asym_identity)) {
        std::cerr<<"Cannot recover original name (wrong key or no name envelope): "<<path<<"\n";
        return false;
    }
    std::cout<<"Original name: "<<orig<<"\n";
    if(do_rename) {
        // orig 来自密文尾部文
        // "<..\..\evil>.ptd"
        bool bad = orig.empty() || orig.find_first_of("/\\") != std::string::npos
                || orig.find("..") != std::string::npos
                || orig.front() == '/' || orig.front() == '\\';
#ifdef _WIN32
        if(!bad && orig.size() >= 2 && orig[1] == ':') bad = true;   // 盘符 X
#endif
        if(bad) {
            std::cerr<<"Refusing to rename: original name contains path elements: "<<orig<<"\n";
            return false;
        }
        // 重命名 .ptd 本身
        std::string dir=path;
        size_t bs=dir.find_last_of("/\\");
        std::string base=(bs!=std::string::npos)?dir.substr(0,bs+1):"";
        std::string newpath=base+orig+".ptd";
        if(newpath==path) {
            std::cerr<<"Already named correctly: "<<path<<"\n";
            return true;
        }
        if(file_exists_path(newpath)) {
            std::cerr<<"Refusing to rename: target already exists: "<<newpath<<"\n";
            return false;
        }
        if(replace_file_utf8(path,newpath)) {
            std::cout<<"Renamed to: "<<newpath<<"\n";
        } else {
            std::cerr<<"Rename failed: "<<newpath<<"\n";
            return false;
        }
    }
    return true;
}

// 功能1
// 索引
static bool run_keylib(const std::vector<std::string>& words,
                       const std::string& as_name,
                       const std::string& alias,
                       const std::string& notes) {
    if(words.empty()) {
        std::cerr<<"Missing -L subcommand (list|add|remove|show|pub|export).\n";
        return false;
    }
    const std::string& sub=words[0];

    if(sub=="list") {
        std::vector<KeyLibEntry> entries; std::string err;
        if(!keylib_load(entries,err)) { std::cerr<<err<<"\n"; return false; }
        const std::string dir=keylib_dir();
        if(dir.empty()) { std::cerr<<"No user config directory available.\n"; return false; }
        std::cout<<"Key library: "<<dir<<"\n";
        if(entries.empty()) {
            std::cout<<"  (empty; import one with: -L add <keyfile> --as <name>)\n";
            return true;
        }
        for(const auto& e: entries) {
            std::cout<<"  "<<e.name<<"  ["<<e.kind<<"]";
            if(!e.alias.empty())   std::cout<<"  alias: "<<e.alias;
            if(!e.created.empty()) std::cout<<"  created: "<<e.created;
            std::cout<<"\n";
            if(!e.notes.empty())      std::cout<<"      notes : "<<e.notes<<"\n";
            if(!e.public_key.empty()) std::cout<<"      public: "<<e.public_key<<"\n";
        }
        return true;
    }

    if(sub=="add") {
        if(words.size()<2) {
            std::cerr<<"Usage: -L add <keyfile> --as <name> [--alias <text>] [--notes <text>]\n";
            return false;
        }
        std::string name=as_name;
        if(name.empty()) {
            std::string base=words[1];
            size_t pos=base.find_last_of("/\\");
            if(pos!=std::string::npos) base=base.substr(pos+1);
            size_t dot=base.find_last_of('.');
            if(dot!=std::string::npos&&dot>0) base=base.substr(0,dot);
            name.clear();
            for(unsigned char c: base) {
                if(std::isalnum(c)||c=='.'||c=='_'||c=='-') name.push_back((char)c);
            }
        }
        std::string err;
        if(!keylib_add(words[1],name,alias,notes,err)) { std::cerr<<err<<"\n"; return false; }
        std::cout<<"Added key '"<<name<<"' to the library.\n";
        return true;
    }

    if(sub=="remove") {
        if(words.size()<2) { std::cerr<<"Usage: -L remove <name>\n"; return false; }
        std::string err;
        if(!keylib_remove(words[1],err)) { std::cerr<<err<<"\n"; return false; }
        std::cout<<"Removed key '"<<words[1]<<"'.\n";
        return true;
    }

    if(sub=="show") {
        if(words.size()<2) { std::cerr<<"Usage: -L show <name>\n"; return false; }
        std::vector<KeyLibEntry> entries; std::string err;
        if(!keylib_load(entries,err)) { std::cerr<<err<<"\n"; return false; }
        KeyLibEntry e;
        if(!keylib_find(entries,words[1],&e)) {
            std::cerr<<"No such key in library: "<<words[1]<<"\n";
            return false;
        }
        std::cout<<"name    : "<<e.name<<"\n";
        std::cout<<"kind    : "<<e.kind<<"\n";
        std::cout<<"file    : "<<keylib_dir()<<"/"<<e.file<<"\n";
        std::cout<<"alias   : "<<(e.alias.empty()?"-":e.alias)<<"\n";
        std::cout<<"notes   : "<<(e.notes.empty()?"-":e.notes)<<"\n";
        std::cout<<"created : "<<(e.created.empty()?"-":e.created)<<"\n";
        std::cout<<"public  : "<<(e.public_key.empty()?"-":e.public_key)<<"\n";
        std::cout<<"(key material is never printed; use -L export to copy it out)\n";
        return true;
    }

    if(sub=="pub") {
        if(words.size()<2) {
            std::cerr<<"Usage: -L pub <name|keyfile>\n";
            return false;
        }
        // 读取身份材料
        auto read_trimmed=[&](const std::string& path,std::string& out,std::string& err)->bool{
            std::ifstream f;
            if(!open_stream(f,path,std::ios::in|std::ios::binary)) {
                err="Cannot open key file: "+path; return false;
            }
            // 流式读取身份材
            std::string buf;
            {
                char chunk[4096];
                while(f.read(chunk,sizeof(chunk))||f.gcount()>0) {
                    std::streamsize got=f.gcount();
                    if(got>0) {
                        buf.append(chunk,(size_t)got);
                        if(buf.size()>size_t(256*1024)) {
                            f.close();
                            err="Key file too large (>256 KB): "+path;
                            return false;
                        }
                    }
                }
            }
            f.close();
            size_t a=0,b=buf.size();
            while(a<b&&(unsigned char)buf[a]<=0x20) ++a;
            while(b>a&&(unsigned char)buf[b-1]<=0x20) --b;
            out=buf.substr(a,b-a);
            sodium_memzero(buf.data(),buf.size());
            if(out.empty()) { err="Key file is empty: "+path; return false; }
            return true;
        };

        std::vector<KeyLibEntry> entries; std::string err;
        if(!keylib_load(entries,err)) { std::cerr<<err<<"\n"; return false; }
        KeyLibEntry e;
        const bool in_library=keylib_find(entries,words[1],&e);
        const std::string path=in_library ? keylib_dir()+"/"+e.file : words[1];

        std::string id;
        if(!read_trimmed(path,id,err)) { std::cerr<<err<<"\n"; return false; }
        std::string pub;
        AsymOutcome o=fe_identity_to_recipient(id,pub);
        sodium_memzero(id.data(),id.size());
        if(!o.ok) {
            std::cerr<<"Cannot derive the public key: "<<o.error<<"\n";
            return false;
        }
        std::cout<<pub<<"\n";
        if(in_library) {
            // 回写缓存
            if(!keylib_set_public(words[1],pub,err))
                std::cerr<<"Warning: could not cache the public key in the index: "<<err<<"\n";
            std::cerr<<"Public key (age1...) cached for '"<<words[1]<<"'.\n";
        } else {
            std::cerr<<"Public key (age1...) printed above.\n";
        }
        return true;
    }

    if(sub=="export") {
        if(words.size()<2) { std::cerr<<"Usage: -L export <name> [dest_dir]\n"; return false; }
        const std::string dest=(words.size()>=3)?words[2]:std::string(".");
        std::string err;
        if(!keylib_export(words[1],dest,err)) { std::cerr<<err<<"\n"; return false; }
        std::cout<<"Exported '"<<words[1]<<"' to "<<dest<<"\n";
        return true;
    }

    std::cerr<<"Unknown -L subcommand: "<<sub<<"\n";
    return false;
}

// 国庆节祝福
// 为什么用 RAII 替换 std
// 逐出口补打印既
// 写过内容」
// 祝福只进 stdout
static std::tm local_now() {
    std::time_t t = std::time(nullptr);
    std::tm lt{};
#ifdef _WIN32
    localtime_s(&lt, &t);
#else
    localtime_r(&t, &lt);
#endif
    return lt;
}

static bool is_national_day_week() {
    std::tm lt = local_now();
    return lt.tm_mon == 9 /* 10 月（0 基）*/ && lt.tm_mday >= 1 && lt.tm_mday <= 7;
}

// 中华人民共和国 1949-10
static int motherland_age() {
    return local_now().tm_year + 1900 - 1949;
}

struct NationalDaySuffix {
    std::streambuf* old_ = nullptr;
    struct TrackingBuf : std::streambuf {
        std::streambuf* real_ = nullptr;
        bool any_ = false;
        int overflow(int c) override {
            if (c != EOF) { any_ = true; return real_->sputc(static_cast<char>(c)); }
            return 0;
        }
        std::streamsize xsputn(const char* s, std::streamsize n) override {
            if (n > 0) any_ = true;
            return real_->sputn(s, n);
        }
        int sync() override { return real_ ? real_->pubsync() : 0; }
    } buf_;
    NationalDaySuffix() {
        old_ = std::cout.rdbuf();
        buf_.real_ = old_;
        std::cout.rdbuf(&buf_);
    }
    ~NationalDaySuffix() {
        std::cout.rdbuf(old_);   // 先恢复真实缓冲
        if (buf_.any_ && is_national_day_week()) {
            // 空行隔开
            // 祝福走 stderr
            std::cerr << "\nHappy " << motherland_age()
                      << "th Birthday to the People's Republic of China!\n";
            std::cerr.flush();
        }
    }
};

static int main_impl(int argc,char* argv[]) {
#ifdef _WIN32
    // 让控制台
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    // 改用 UTF-8 参数向量
    std::vector<std::string> argv_store=get_utf8_argv();
#else
    std::vector<std::string> argv_store(argv, argv+argc);
#endif
    // CLI11 2.7.2 拒绝「单横线 + 多字
    // 在交给 CLI11
    // 必须
    {
        static const std::pair<const char*,const char*> kDashRewrite[] = {
            {"-be","--be"}, {"-bd","--bd"}, {"-x448","--x448"}, {"-de","--de"},
            {"-zstd","--zstd"}, {"-cl","--cl"}, {"-rn","--rn"}, {"-on","--on"}
        };
        for(auto& s: argv_store)
            for(auto& kv: kDashRewrite)
                if(s==kv.first) s=kv.second;
    }
    {
        static std::vector<char*> argv_ptr;
        argv_ptr.clear();
        argv_ptr.reserve(argv_store.size()+1);
        for(auto& s: argv_store) argv_ptr.push_back(const_cast<char*>(s.c_str()));
        argv_ptr.push_back(nullptr);
        argc=(int)argv_store.size();
        argv=argv_ptr.data();
    }

    anti_debug_check();

    NationalDaySuffix nds;   // 进程退出

    if(sodium_init()<0) {
        std::cerr<<"libsodium initialization failed.\n";
        return 1;
    }

    // 加载 YAML 配置
    Config cfg=load_config();
    set_global_config(cfg);
    init_logger(cfg.log_file,cfg.log_level);
    init_rate_limiter(cfg.max_speed); // 进程级限速

    enum {
        ACTION_NONE,ACTION_ENCRYPT,ACTION_DECRYPT,
        ACTION_BATCH_ENCRYPT,ACTION_BATCH_DECRYPT,ACTION_KEYGEN,
        ACTION_DERIVE,ACTION_PUBKEY,ACTION_INFO,ACTION_VERIFY,ACTION_RECOVER,
        ACTION_KEYLIB,ACTION_REWRAP,ACTION_WATERMARK,ACTION_WRAPKEY,ACTION_UNWRAPKEY,ACTION_RANDOM_READ,
        ACTION_VAULT_INIT,ACTION_VAULT_LIST,ACTION_VAULT_REINDEX,ACTION_VAULT_MOUNT,
        ACTION_VAULT_RECOVERY,ACTION_VAULT_REKEY,ACTION_VAULT_RECRYPT,ACTION_VAULT_FORMAT
    } action=ACTION_NONE;

    std::vector<std::string> input_paths;
    std::string output_dir;
    CryptoMode mode=CryptoMode::XCHACHA20;
    // 未显式指定 -m
    {
        const std::string& dc = global_config().default_cipher;
        if (dc == "aegis256") mode = CryptoMode::AEGIS256;
        else if (dc == "sm4") mode = CryptoMode::SM4;
        else if (dc == "aes-gcm") mode = CryptoMode::AES_GCM;
    }
    int source_action=0;          // 源处置
    bool force_overwrite=false;
    bool force_decrypt=false;
    int num_threads=0;
    bool restore_name=false;     // 还原文件名
    bool obfuscate_name=false;   // 混淆文件名
    std::string keyfile_path;   // 密钥文件
    bool asym_mode=false;       // 非对称
    bool x448_mode=false;        // X448曲线
    std::string recipient_spec; // 收件人公钥
    bool key_from_stdin=false;  // 密钥走输入
    bool preview_mode=false;    // 预览明文
    size_t preview_max=4096;    // 预览字节数
    std::string salt_spec;      // 派生盐
    bool force_sha256=false;    // 生成校验单
    bool recover_rename=false;  // 原地重命名
    bool pqc_on=true;           // 后量子
    WatermarkSpec wm_spec;      // 水印
    std::string wm_verify_pem;  // 水印验签
    bool wm_keygen_mode=false;  // 生成水印密钥
    std::string wm_keygen_path; // 水印密钥路径
    // 密钥包装层
    std::string wrap_path, unwrap_path, unwrap_out, wrap_out;
    std::string wrap_alg = "kwp";   // 包装算法
    std::string wrap_to, unwrap_identity;
    bool wrap_mode = false, unwrap_mode = false;
    std::string keylib_refs;    // 密钥库引用
    std::string keylib_as;      // 库内名称
    std::string keylib_alias;   // 展示别名
    std::string keylib_notes;   // 备注
    int compress_level=0;       // 压缩级别
    uint64_t split_bytes=0;     // 分卷大小
    bool pack_mode=false;       // 打包归档
    bool yes_source_delete=false;// 删源已确认
    bool no_extract=false;      // 不展开目录
    std::string new_keyfile_path; // 新密钥文件
    bool new_key_from_stdin=false;// 新密钥输入

    // 帮助 / 无参数
    if(argc<=1) { print_usage(); return 0; }
    for(int k=1; k<argc; ++k) {
        std::string a=argv[k];
        if(a=="-h"||a=="-?"||a=="--help") { print_usage(); return 0; }
    }

    CLI::App app("FileEncryptor command-line interface");

    // 临时布尔
    bool f_encrypt=false, f_decrypt=false, f_bencrypt=false, f_bdecrypt=false,
         f_keygen=false, f_derive=false, f_pubkey=false, f_info=false,
         f_verify=false, f_recover=false, f_keylib=false, f_rewrap=false, f_randomread=false;
    bool f_preview=false, f_pqc=false, f_nopqc=false, f_wm=false, f_nowm=false,
         f_compress=false, f_verbose=false, f_stdout=false;
    std::vector<std::string> mode_strs;
    std::string split_str;
    uint64_t random_offset=0, random_length=65536;
    std::string random_out; uint32_t random_repeat=1;
    // 加密盘
    std::string vault_init_dir, vault_list_dir, vault_reindex_dir, into_vault_dir;
    // M3 挂载点持久化 / M4 恢
    std::string vault_mount_dir, vault_mount_point;
    std::string vault_recovery_dir, vault_recovery_arg;
    std::string vault_rekey_dir, vault_recrypt_dir;
    std::string vault_format_dir;
    std::string wm_extract_path;
    std::vector<std::string> explicit_inputs;
    bool src_del=false, src_wipe=false, src_recycle=false;
    bool features_mode=false;
    bool f_json=false, f_dry_run=false, f_progress_events=false;
    bool cl_given=false;

    // 动作
    app.add_flag("-e,--encrypt", f_encrypt);                    // 加密
    app.add_flag("-d,--decrypt", f_decrypt);                    // 解密
    app.add_flag("--be,--batch-encrypt", f_bencrypt);           // 批量加密
    app.add_flag("--bd,--batch-decrypt", f_bdecrypt);           // 批量解密
    app.add_flag("-g,--keygen", f_keygen);                      // 生成密钥
    app.add_flag("-G,--derive", f_derive);                      // 派生密钥
    app.add_flag("-Y,--pubkey", f_pubkey);                      // 导出公钥
    app.add_flag("-H,--info", f_info);                          // 文件信息
    app.add_flag("-V,--verify", f_verify);                      // 校验文件
    app.add_flag("-R,--recover-name", f_recover);               // 恢复文件名
    app.add_flag("-L,--keylib", f_keylib);                      // 密钥库
    app.add_flag("--rw,--rewrap", f_rewrap);                    // 重包密钥

    // 通用选项
    app.add_option("-m,--mode", mode_strs, "crypto mode: xchacha20|aegis256|aes-gcm|sm4|x25519|x448")  // 加密模式
        ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);
    app.add_flag("-X,--x448", x448_mode);                       // X448曲线
    app.add_option("-o,--output", output_dir, "output directory");  // 输出目录
    app.add_flag("--de,--delete-source", src_del);              // 删除源文件
    app.add_flag("--ws,--wipe-source", src_wipe);               // 安全擦除源
    app.add_flag("--rs,--recycle-source", src_recycle);         // 源入回收站
    app.add_option("--nk,--new-key-file", new_keyfile_path, "rewrap new key file");  // 新密钥文件
    app.add_flag("--ns,--new-key-stdin", new_key_from_stdin);   // 新密钥输入
    app.add_option("-A,--as,--keylib-as", keylib_as, "keylib entry name");  // 库内名称
    app.add_option("--al,--alias", keylib_alias, "keylib display alias");  // 展示别名
    app.add_option("--nt,--notes", keylib_notes, "keylib notes");  // 备注
    app.add_option("-K,--keylib-ref", keylib_refs, "-K <name>[,...]");  // 密钥库引用
    app.add_option("--st,--salt", salt_spec, "-G derive salt <hex|file>");  // 派生盐
    app.add_option("-k,--keyfile", keyfile_path, "key file -k <file>");  // 密钥文件
    app.add_option("-r,--recipient", recipient_spec, "recipient -r <pub|file>");  // 收件人公钥
    app.add_flag("--ks,--key-stdin", key_from_stdin);           // 密钥走输入
    app.add_flag("--rn,--restore-name", restore_name);          // 还原文件名
    app.add_flag("--on,--obfuscate-name", obfuscate_name);      // 混淆文件名
    app.add_flag("-q,--sha256", force_sha256);                  // 生成校验单
    app.add_flag("--ren,--rename", recover_rename);             // 原地重命名
    app.add_flag("-z,--compress", f_compress);                  // 压缩
    app.add_flag("--zstd,--use-zstd", f_compress);              // zstd压缩
    app.add_option("--cl,--compression-level", compress_level, "zstd level 1..22 or -1..-5")  // 压缩级别
        ->each([&](std::string){ cl_given=true; });
    app.add_flag("-p,--pack,--archive", pack_mode);             // 打包归档
    app.add_flag("--sd,--source-delete-ok", yes_source_delete); // 删源已确认
    app.add_flag("--ne,--no-extract", no_extract);              // 不展开目录
    app.add_option("-s,--split,--split-size", split_str, "split volume size, e.g. 4GB");  // 分卷大小
    app.add_flag("-f,--features", features_mode);               // 能力探测
    app.add_flag("--json", f_json);                             // 机器可读输出
    app.add_flag("-n,--dry-run", f_dry_run);                    // 只出计划不写盘
    app.add_flag("--progress-events", f_progress_events);        // JSONL 进度旁路
    app.add_flag("--pv,--preview", f_preview);                  // 预览明文
    app.add_flag("--so,--stdout", f_stdout);                    // 写标准输出
    app.add_option("--mb,--max-bytes", preview_max, "preview max bytes (default 4096)");  // 预览字节数
    app.add_flag("--fd,--force-decrypt", force_decrypt);        // 强制解密
    app.add_flag("-y,--force", force_overwrite);                // 覆盖已有
    app.add_flag("-v,--verbose", f_verbose);                    // 详细输出
    app.add_flag("--pqc,--post-quantum", f_pqc);                // 后量子
    app.add_flag("--npqc,--no-post-quantum", f_nopqc);          // 关后量子
    app.add_flag("--wm,--watermark", f_wm);                     // 水印
    app.add_flag("--nwm,--no-watermark", f_nowm);               // 关水印
    app.add_option("--wms,--wm-sign", wm_spec.sign_key, "watermark signing key (ML-DSA-65/RSA)");  // 水印签名密钥
    app.add_option("--wmv,--wm-verify", wm_verify_pem, "watermark verify public key PEM");  // 水印验签
    app.add_option("--wmk,--wm-keygen", wm_keygen_path, "generate watermark keypair");  // 生成水印密钥
    app.add_option("--wk,--wrap-key", wrap_path, "wrap a 32-byte DEK into a FEKW blob");  // 包装密钥
    app.add_option("--uk,--unwrap-key", unwrap_path, "unwrap a FEKW blob back to the DEK");  // 解包密钥
    app.add_option("--uo,--unwrap-out", unwrap_out, "output path for --unwrap-key");  // 解包输出
    app.add_option("--wo,--wrap-out", wrap_out, "output path for --wrap-key (default: <input>.fekw)");  // 包装输出
    app.add_option("--wa,--wrap-alg", wrap_alg, "wrap algorithm: kwp|aes-kw|pubkey");  // 包装算法
    app.add_option("--wt,--wrap-to", wrap_to, "recipient public key (or file) for --wrap-key --wrap-alg pubkey");  // 包装收件人
    app.add_option("--id,--identity", unwrap_identity, "recipient identity (private key or file) for --unwrap-key");  // 解包身份
    app.add_option("--wme,--watermark-extract", wm_extract_path, "extract tail watermark (read-only)");  // 提取水印
    app.add_option("-i,--input", explicit_inputs, "explicit input path");  // 显式输入
    app.add_option("inputs", input_paths, "input files or directories");  // 输入路径
    app.add_flag("--rr,--random-read", f_randomread, "random-read: extract a plaintext range from a .ptd (compressed containers use a decrypt window)");  // 随机读片段
    app.add_option("--off,--offset", random_offset, "byte offset to start reading (random-read)");  // 起始偏移
    app.add_option("--len,--length", random_length, "bytes to read (random-read, default 65536)");  // 读取长度
    app.add_option("--out,--random-out", random_out, "write extracted plaintext to file (default: stdout)");  // 片段输出
    app.add_option("--rep,--repeat", random_repeat, "repeat count for benchmarking (random-read)");  // 重复次数
    // 加密盘
    app.add_option("--vi,--vault-init", vault_init_dir, "initialize a vault at <dir> (creates vault.meta with random salt)");  // 建加密盘
    app.add_option("--vl,--vault-list", vault_list_dir, "decrypt and list the vault index at <dir>");  // 列盘内文件
    app.add_option("--vri,--vault-reindex", vault_reindex_dir, "rescan <dir> and rebuild the encrypted index from .ptd headers");  // 重建索引
    app.add_option("--iv,--into-vault", into_vault_dir, "encrypt into <dir> as a vault: write each .ptd and append an index entry");  // 加密入盘
    // 挂载点
    app.add_option("--vm,--vault-mount", vault_mount_dir, "record/clear the mount point of <dir> (use with --mount-point)");  // 记挂载点
    app.add_option("--mp,--mount-point", vault_mount_point, "mount point to record (drive letter like V: or a Linux dir; '-' clears)");  // 挂载点
    // 恢复密钥
    app.add_option("--vrec,--vault-recovery", vault_recovery_dir,
        "recovery key ops on <dir>: gen|create [code]|open <code>|remove (use with --recovery-arg)");  // 恢复密钥
    app.add_option("--ra,--recovery-arg", vault_recovery_arg, "argument for --vault-recovery (subcommand / code)");  // 恢复密钥参数
    // 改密/重加密
    app.add_option("--vrk,--vault-rekey", vault_rekey_dir, "change vault passphrase: rewrap every .ptd + re-seal index (needs old+new key)");  // 改盘密码
    app.add_option("--vrc,--vault-recrypt", vault_recrypt_dir, "re-encrypt vault contents to 64KB blocks (non-compressed), eliminating 1MiB legacy path");  // 盘内重加密
    // 格式化盘
    app.add_option("--vf,--vault-format", vault_format_dir, "format the vault at <dir>: wipe every stored file and reset the index (keeps vault.meta/password)");  // 格式化盘

    try {
        app.parse(argc, argv);
    } catch(const CLI::CallForHelp&) {
        return 0;
    } catch(const CLI::ParseError& e) {
        std::cerr<<e.what()<<"\n";
        return FE_EXIT_USAGE;
    }

    for(auto& s: explicit_inputs) input_paths.push_back(s);

    // 机器可读契约初
    g_contract.json = f_json;
    g_contract.dry_run = f_dry_run;
    g_contract.progress_events = f_progress_events;
    if (f_progress_events) {
        // 非 tty 下旧帧模式默
        // 旧帧仍
#ifdef _WIN32
        _putenv_s("FILEENCRYPTOR_PROGRESS_EVENTS", "1");
        _putenv_s(FE_FRAME_ENV, "1");
#else
        setenv("FILEENCRYPTOR_PROGRESS_EVENTS", "1", 1);
        setenv(FE_FRAME_ENV, "1", 1);
#endif
    }
    {
        const char* env_audit = std::getenv("FE_AUDIT_LOG");
        if (env_audit && *env_audit) g_contract.audit_path = env_audit;
        else if (!cfg.log_file.empty()) g_contract.audit_path = cfg.log_file + ".audit.jsonl";
        const char* did = std::getenv("FE_DEVICE_ID");
        g_contract.device_id = (did && *did) ? did : "local";
        saf_set_audit_hook([](const SafAuditEvent& ev) {
            fe_audit_emit(ev.op.c_str(), ev.key, (int)ev.status,
                          ev.bytes, ev.elapsed_ms, ev.error_code);
        });
    }

    // 解析后合并/校验
    if(features_mode) {
#ifdef FE_WITH_ZSTD
        std::cout<<"zstd=1\n";
#else
        std::cout<<"zstd=0\n";
#endif
        std::cout<<"aegis="<<(aegis256_supported()?1:0)<<"\n";
        std::cout<<"aesgcm="<<(aes_gcm_supported()?1:0)<<"\n";
        std::cout<<"sm4="<<(sm4_supported()?1:0)<<"\n";
        std::cout<<"pqc="<<(pqc_supported()?1:0)<<"\n";
        std::cout<<"keywrap="<<(keywrap_available()?1:0)<<"\n";
        std::cout<<"split=1\n";
        std::cout<<"pack=1\n";
        std::cout<<"confirm=1\n";
        std::cout<<"vault=1\n";      // 加密盘能力
        std::cout<<"vault_rw=1\n";   // 加密盘可写挂载
        return 0;
    }

    if(f_verbose) set_verbose(true);

    // m 模式校验
    for(auto& ms : mode_strs) {
        if(ms=="xchacha20") mode=CryptoMode::XCHACHA20;
        else if(ms=="aegis256") mode=CryptoMode::AEGIS256;
        else if(ms=="aes-gcm"||ms=="aesgcm") mode=CryptoMode::AES_GCM;
        else if(ms=="sm4") mode=CryptoMode::SM4;
        else if(ms=="x25519"||ms=="x448") asym_mode=true;
        else { std::cerr<<"Unknown mode: "<<ms<<"\n"; return 1; }
    }

    // 互斥动作合并
    {
        const int n_act = (f_encrypt?1:0)+(f_decrypt?1:0)+(f_bencrypt?1:0)+(f_bdecrypt?1:0)
            +(f_keygen?1:0)+(f_derive?1:0)+(f_pubkey?1:0)+(f_info?1:0)+(f_verify?1:0)+(f_randomread?1:0)
            +(f_recover?1:0)+(f_keylib?1:0)+(f_rewrap?1:0)
            +(!vault_init_dir.empty()?1:0)+(!vault_list_dir.empty()?1:0)+(!vault_reindex_dir.empty()?1:0)
            +(!vault_mount_dir.empty()?1:0)+(!vault_recovery_dir.empty()?1:0)
            +(!vault_rekey_dir.empty()?1:0)+(!vault_recrypt_dir.empty()?1:0)
            +(!vault_format_dir.empty()?1:0);
        if(n_act>1) { std::cerr<<"Multiple modes specified.\n"; return 1; }
        if(f_encrypt) action=ACTION_ENCRYPT;
        else if(f_decrypt) action=ACTION_DECRYPT;
        else if(f_bencrypt) action=ACTION_BATCH_ENCRYPT;
        else if(f_bdecrypt) action=ACTION_BATCH_DECRYPT;
        else if(f_keygen) action=ACTION_KEYGEN;
        else if(f_derive) action=ACTION_DERIVE;
        else if(f_pubkey) action=ACTION_PUBKEY;
        else if(f_info) action=ACTION_INFO;
        else if(f_verify) action=ACTION_VERIFY;
        else if(f_recover) action=ACTION_RECOVER;
        else if(f_keylib) action=ACTION_KEYLIB;
        else if(f_rewrap) action=ACTION_REWRAP;
        else if(f_randomread) action=ACTION_RANDOM_READ;
        else if(!vault_init_dir.empty()) action=ACTION_VAULT_INIT;
        else if(!vault_list_dir.empty()) action=ACTION_VAULT_LIST;
        else if(!vault_reindex_dir.empty()) action=ACTION_VAULT_REINDEX;
        else if(!vault_mount_dir.empty()) action=ACTION_VAULT_MOUNT;
        else if(!vault_recovery_dir.empty()) action=ACTION_VAULT_RECOVERY;
        else if(!vault_rekey_dir.empty()) action=ACTION_VAULT_REKEY;
        else if(!vault_recrypt_dir.empty()) action=ACTION_VAULT_RECRYPT;
        else if(!vault_format_dir.empty()) action=ACTION_VAULT_FORMAT;
    }


    {
        static const char* const kActNames[] = {
            "none","encrypt","decrypt","batch-encrypt","batch-decrypt","keygen","derive",
            "pubkey","info","verify","recover","keylib","rewrap","watermark","wrap-key",
            "unwrap-key","random-read","vault-init","vault-list","vault-reindex","vault-mount",
            "vault-recovery","vault-rekey","vault-recrypt","vault-format"
        };
        g_contract.action = kActNames[(int)action];
        g_contract.inputs = input_paths;
        g_contract.output_dir = output_dir;
        g_contract.compress_level = compress_level;
        switch (mode) {
        case CryptoMode::XCHACHA20: g_contract.cipher = "xchacha20"; break;
        case CryptoMode::AEGIS256:  g_contract.cipher = "aegis256"; break;
        case CryptoMode::AES_GCM:   g_contract.cipher = "aes-gcm"; break;
        case CryptoMode::SM4:       g_contract.cipher = "sm4"; break;
        default: g_contract.cipher = asym_mode ? "asymmetric" : "xchacha20"; break;
        }
    }

    // -watermark-extract：只读尾部水
    if(!wm_extract_path.empty()) {
        if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
        action=ACTION_WATERMARK;
        input_paths.push_back(wm_extract_path);
    }

    if(f_preview) { preview_mode=true; if(action==ACTION_NONE) action=ACTION_DECRYPT; }
    if(f_compress && compress_level==0) compress_level=1;
    if(f_pqc) { pqc_on=true; wm_spec.pqc=true; }
    if(f_nopqc) { pqc_on=false; wm_spec.pqc=false; }
    if(f_wm) { wm_spec.enabled=true; wm_spec.pqc=pqc_on; }
    if(f_nowm) { wm_spec.enabled=false; }
    if(!wm_spec.sign_key.empty()) { wm_spec.enabled=true; wm_spec.pqc=pqc_on; }
    if(!wm_keygen_path.empty()) wm_keygen_mode=true;
    if(!wrap_path.empty()) wrap_mode=true;
    if(!unwrap_path.empty()) unwrap_mode=true;

    {
        int cnt=(src_del?1:0)+(src_wipe?1:0)+(src_recycle?1:0);
        if(cnt>1) {
            std::cerr<<"Conflicting source handling options (-de / --wipe-source / --recycle-source).\n";
            return 1;
        }
        if(src_del) source_action=1;
        else if(src_wipe) source_action=2;
        else if(src_recycle) source_action=3;
    }

    if(!output_dir.empty() && path_has_traversal(output_dir)) {
        std::cerr<<"Output directory contains directory traversal (..): "<<output_dir<<"\n";
        return 1;
    }

    if(!split_str.empty()) {
        std::string serr;
        if(!parse_split_size(split_str,split_bytes,serr)) {
            std::cerr<<"Invalid --split size: "<<serr<<"\n";
            return 1;
        }
    }

    if(cl_given && compress_level==0) {
        std::cerr<<"--compression-level requires a non-zero integer: "
            "zstd level 1..22 (normal) or -1..-5 (fast).\n";
        return 1;
    }

    if(preview_max==0) {
        std::cerr<<"--max-bytes requires a positive integer.\n";
        return 1;
    }
    bool is_batch=(action==ACTION_BATCH_ENCRYPT||action==ACTION_BATCH_DECRYPT);
    bool is_encrypt=(action==ACTION_ENCRYPT||action==ACTION_BATCH_ENCRYPT);
    bool is_decrypt=(action==ACTION_DECRYPT||action==ACTION_BATCH_DECRYPT);

    // dry-run
    if (g_contract.dry_run) {
        if (action == ACTION_NONE) { print_usage(); return FE_EXIT_OK; }
        std::vector<std::string> files;
        g_contract.total_bytes = fe_collect_plan(input_paths, files);
        fe_print_plan(files, g_contract.total_bytes);
        return FE_EXIT_OK;
    }
    fe_audit_emit("cli_action", g_contract.action, FE_EXIT_OK, 0, 0, 0);

if(wrap_mode || unwrap_mode) {
        // 包装层
        // -wrap-alg pubkey
        const bool pub_route = wrap_mode && keywrap_alg_from_name(wrap_alg) == 2;
        // 解包路线要读 blob 头
        bool unwrap_pub = false;
        if(unwrap_mode) {
            std::vector<unsigned char> probe;
            if(keywrap_read_file(unwrap_path, probe) && probe.size() >= 6
               && memcmp(probe.data(), "FEKW", 4) == 0)
                unwrap_pub = (probe[5] == 2);
        }
        SecureBuffer wrap_pwd;
        if(!pub_route && !unwrap_pub) {
            // 密钥源优先级沿
            if(!keyfile_path.empty()) {
                // 与主流程同口径
                std::ifstream kf;
                if(!open_stream(kf, keyfile_path, std::ios::binary)) {
                    std::cerr<<"Cannot open key file: "<<keyfile_path<<"\n";
                    return 1;
                }
                std::vector<char> kbuf;
                const size_t kMaxKeyBytes = size_t(1) << 20;
                char chunk[4096];
                while(kf.read(chunk, sizeof(chunk)) || kf.gcount()>0) {
                    const std::streamsize got = kf.gcount();
                    if(got > 0) {
                        kbuf.insert(kbuf.end(), chunk, chunk + got);
                        if(kbuf.size() > kMaxKeyBytes) {
                            std::cerr<<"Key file too large (>1 MB): "<<keyfile_path<<"\n";
                            return 1;
                        }
                    }
                }
                kf.close();
                while(!kbuf.empty() && (kbuf.back()=='\n'||kbuf.back()=='\r')) kbuf.pop_back();
                if(kbuf.empty()) { std::cerr<<"No key material in: "<<keyfile_path<<"\n"; return 1; }
                wrap_pwd = SecureBuffer(kbuf.data(), kbuf.size());
                sodium_memzero(kbuf.data(), kbuf.size());
            }
            else if(const char* ek=std::getenv("ENCRYPTOR_KEY")) {
                if(*ek) wrap_pwd = SecureBuffer(ek, std::strlen(ek));
            }
            else if(key_from_stdin) {
                std::vector<char> sbuf;
                char c;
                while(std::cin.get(c)) sbuf.push_back(c);
                while(!sbuf.empty() && (sbuf.back()=='\n'||sbuf.back()=='\r')) sbuf.pop_back();
                if(!sbuf.empty()) wrap_pwd = SecureBuffer(sbuf.data(), sbuf.size());
                sodium_memzero(sbuf.data(), sbuf.size());
            }
            if(wrap_pwd.empty()) {
                std::cout<<"Enter key wrap password: ";
                std::vector<char> p = get_password();
                while(!p.empty() && (p.back()=='\n'||p.back()=='\r')) p.pop_back();
                if(p.empty()) { std::cerr<<"No key material provided.\n"; return 1; }
                wrap_pwd = SecureBuffer(p.data(), p.size());
                sodium_memzero(p.data(), p.size());
                p.clear();
            }
        }
        if(wrap_mode) {
            // -wrap-out 优先
            std::string out = wrap_out.empty() ? (wrap_path + ".fekw") : wrap_out;
            if(wrap_out.empty() && !output_dir.empty()) {
                if(!create_directory_recursive(output_dir)) {
                    std::cerr<<"Cannot create output directory: "<<output_dir<<"\n";
                    return 1;
                }
                out = output_dir;
                if(out.back()!='/' && out.back()!='\\') out += '/';
                out += "wrapped.fekw";
            }
            return run_keywrap(wrap_path, out, wrap_alg, wrap_to, wrap_pwd, force_overwrite);
        }
        const std::string out = unwrap_out.empty() ? (unwrap_path + ".dek") : unwrap_out;
        return run_unwrapkey(unwrap_path, out, wrap_pwd, unwrap_identity, force_overwrite);
    }
    if(wm_keygen_mode) {
        std::string pub_pem, err;
        if(!wm_generate_keypair(wm_keygen_path, pqc_on, pub_pem, err)) {
            std::cerr<<err<<"\n";
            return 1;
        }
        std::cout<<pub_pem;
        std::cout.flush();
        std::cerr<<"Private key written to: "<<wm_keygen_path<<"\n";
        std::cerr<<"Public key (PEM) printed above - save it for --wm-verify.\n";
        return 0;
    }

    if(action==ACTION_NONE) {
        print_usage();
        return 0;
    }

    // 密钥生成无需输
    if(action==ACTION_KEYGEN) {
        uint8_t kalgo = RECIP_ALGO_X25519;
        if(pqc_on)                     kalgo = RECIP_ALGO_MLKEM;   // 默认
        else if(x448_mode)             kalgo = RECIP_ALGO_X448;
        return run_keygen(output_dir,force_overwrite,kalgo) ? 0 : 1;
    }
    // -wm-keygen 分支已上移至

    // 功能1
    if(action==ACTION_KEYLIB) {
        return run_keylib(input_paths,keylib_as,keylib_alias,keylib_notes) ? 0 : 1;
    }

    // 功能2
    if(action==ACTION_INFO) {
        if(input_paths.empty()) { std::cerr<<"No input files specified.\n"; return 1; }
        bool all=true;
        for(const auto& p: input_paths) if(!run_info(p)) all=false;
        return all?0:1;
    }

    // 水印查看
    if(action==ACTION_WATERMARK) {
        if(input_paths.empty()) { std::cerr<<"No input files specified.\n"; return 1; }
        bool all=true;
        for(const auto& p: input_paths) if(!run_watermark(p, wm_verify_pem, pqc_on)) all=false;
        return all?0:1;
    }

    if(input_paths.empty()&&action!=ACTION_DERIVE&&action!=ACTION_PUBKEY
       &&action!=ACTION_VERIFY&&action!=ACTION_RECOVER&&action!=ACTION_INFO
       &&action!=ACTION_WATERMARK
       &&action!=ACTION_VAULT_INIT&&action!=ACTION_VAULT_LIST&&action!=ACTION_VAULT_REINDEX
       &&action!=ACTION_VAULT_MOUNT&&action!=ACTION_VAULT_RECOVERY
       &&action!=ACTION_VAULT_REKEY&&action!=ACTION_VAULT_RECRYPT
       &&action!=ACTION_VAULT_FORMAT) {
        std::cerr<<"No input paths specified.\n";
        print_usage();
        return 1;
    }

    // -pack 本来
    if(!is_batch&&!pack_mode&&input_paths.size()>1) {
        std::cerr<<"Single mode accepts only one input path.\n";
        return 1;
    }

    // 源文件处置对加

    // 压缩选项校验
    if(compress_level!=0) {
#ifndef FE_WITH_ZSTD
        std::cerr<<"Compression requested but this build was compiled without zstd support.\n";
        return 1;
#endif
        if(!is_encrypt) {
            std::cerr<<"-z/--compression-level is only valid for encryption (-e/-be).\n";
            return 1;
        }
        // zstd 级别范围
        if(compress_level<-5 || compress_level>22) {
            std::cerr<<"Invalid compression level "<<compress_level
                <<": zstd accepts 1..22 (normal) or -1..-5 (fast).\n";
            return 1;
        }
    }

    // 归档打包
    if(pack_mode) {
        if(!is_encrypt) {
            std::cerr<<"--pack is only valid for encryption (-e/-be).\n";
            return 1;
        }
        if(input_paths.empty()) {
            std::cerr<<"--pack requires at least one file or directory to pack.\n";
            return 1;
        }
    }
    if(no_extract&&!is_decrypt) {
        std::cerr<<"--no-extract is only valid for decryption (-d/-bd).\n";
        return 1;
    }

    // 分卷校验
    if(split_bytes>0) {
        if(!is_encrypt) {
            std::cerr<<"--split is only valid for encryption (-e/-be).\n";
            return 1;
        }
        if(split_bytes<(1ull<<20)) {
            std::cerr<<"--split size must be at least 1MB.\n";
            return 1;
        }
    }

    // 功能1
    // 必须
    std::vector<std::string> lib_recipients;
    if(!keylib_refs.empty()&&action!=ACTION_KEYLIB) {
        std::vector<std::string> names;
        {   // 逗号 / 分号分隔
            std::string cur;
            for(char c: keylib_refs) {
                if(c==','||c==';') { names.push_back(cur); cur.clear(); }
                else cur.push_back(c);
            }
            names.push_back(cur);
        }
        names.erase(std::remove_if(names.begin(),names.end(),
            [](const std::string& s){ return s.empty(); }),names.end());
        if(names.empty()) {
            std::cerr<<"-K requires at least one library key name.\n";
            return 1;
        }
        if(!asym_mode) {
            std::cerr<<"-K applies only to -m x25519/x448 mode.\n";
            return 1;
        }
        std::string kerr;
        if(is_encrypt) {
            if(!keylib_recipients(names,lib_recipients,kerr)) {
                std::cerr<<kerr<<"\n";
                return 1;
            }
        } else {
            if(names.size()!=1) {
                std::cerr<<"-K decrypt accepts exactly one identity name.\n";
                return 1;
            }
            if(!keyfile_path.empty()) {
                std::cerr<<"Use either -k or -K, not both.\n";
                return 1;
            }
            if(!keylib_key_path(names[0],keyfile_path,kerr)) {
                std::cerr<<kerr<<"\n";
                return 1;
            }
            std::cerr<<"Using identity '"<<names[0]<<"' from the key library.\n";
        }
    }

    // AEGIS-256 可用性
    // cron）明确拒绝并
    if(is_encrypt&&mode==CryptoMode::AEGIS256) {
        bool interactive = stdin_is_interactive() && !key_from_stdin;
        bool refuse=false;
        std::string aegis_msg;
        mode = resolve_encrypt_mode(mode, interactive, refuse, aegis_msg);
        if(refuse) {
            std::cerr<<aegis_msg<<"\n";
            return 4;   // 语义化退出码
        }
    }

    // 密码输入
    // 密钥来源优先级
    SecureBuffer password;
    bool used_key_source=false; // 非交互密钥源
    if(!keyfile_path.empty()) {
        // 读取密钥文件原
        std::ifstream kf;
        if(!open_stream(kf,keyfile_path,std::ios::binary)) {
            std::cerr<<"Cannot open key file: "<<keyfile_path<<"\n";
            return 1;
        }
        // 流式读取密钥文
        std::vector<char> kbuf;
        {
            const size_t kMaxKeyBytes = size_t(1) << 20;
            char chunk[4096];
            while(kf.read(chunk,sizeof(chunk))||kf.gcount()>0) {
                std::streamsize got=kf.gcount();
                if(got>0) {
                    kbuf.insert(kbuf.end(),chunk,chunk+got);
                    if(kbuf.size()>kMaxKeyBytes) {
                        kf.close();
                        std::cerr<<"Key file too large (>1 MB): "<<keyfile_path<<"\n";
                        return 1;
                    }
                }
            }
        }
        kf.close();
        if(kbuf.empty()) {
            std::cerr<<"Key file is empty: "<<keyfile_path<<"\n";
            return 1;
        }
        password = SecureBuffer(kbuf.data(), kbuf.size());
        sodium_memzero(kbuf.data(), kbuf.size()); kbuf.clear();
        used_key_source=true;
        log_event(LOG_INFO,"key_source",{{"type","keyfile"},{"path",keyfile_path}});
    }
    else if(key_from_stdin) {
        // 安全通道
        // age 身份
        // 流式读取并封顶 1 MB
        std::vector<char> sbuf;
        {
            const size_t kMaxStdinKeyBytes = size_t(1) << 20;
            char chunk[4096];
            while(std::cin.read(chunk,sizeof(chunk))||std::cin.gcount()>0) {
                std::streamsize got=std::cin.gcount();
                if(got>0) {
                    sbuf.insert(sbuf.end(),chunk,chunk+got);
                    if(sbuf.size()>kMaxStdinKeyBytes) {
                        std::cerr<<"Key material from stdin too large (>1 MB).\n";
                        return 1;
                    }
                }
            }
        }
        // 交互
        // 剥离尾部换行
        while(!sbuf.empty() && (sbuf.back()=='\n'||sbuf.back()=='\r')) sbuf.pop_back();
        if(sbuf.empty()) {
            std::cerr<<"No key material received from stdin (--key-stdin).\n";
            return 1;
        }
        password = SecureBuffer(sbuf.data(), sbuf.size());
        sodium_memzero(sbuf.data(), sbuf.size()); sbuf.clear();
        used_key_source=true;
        log_event(LOG_INFO,"key_source",{{"type","stdin"}});
    }
    else {
        const char* ek=std::getenv("ENCRYPTOR_KEY");
        if(ek&&*ek) {
            password = SecureBuffer(ek, std::strlen(ek));
            used_key_source=true;
            log_event(LOG_INFO,"key_source",{{"type","env"}});
            // 已拷入 SecureBuffer
#ifdef _WIN32
            _putenv("ENCRYPTOR_KEY=");
#else
            unsetenv("ENCRYPTOR_KEY");
#endif
        }
    }

    // 解密侧自动识别
    // 不必
    if(!asym_mode && !is_encrypt && used_key_source && looks_like_identity(password)) {
        for(const std::string& p: input_paths) {
            std::string low=p;
            std::transform(low.begin(),low.end(),low.begin(),
                [](unsigned char c){ return (char)std::tolower(c); });
            if(low.size()>=4 && low.compare(low.size()-4,4,".ptd")==0) {
                asym_mode=true;
                log_event(LOG_INFO,"asym_mode",{{"auto","identity"}});
                break;
            }
        }
    }

    // ACTION_RANDOM_READ
    // 压缩容器
    if(action==ACTION_RANDOM_READ) {
        if(input_paths.empty()) {
            std::cerr<<"No input .ptd specified for random-read.\n";
            return 1;
        }
        if(!used_key_source) {
            std::cout<<"Enter password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        if(password.size()<6) {
            std::cerr<<"Password too short.\n";
            return 1;
        }
        const std::string& in=input_paths.front();
        std::vector<unsigned char> buf; bool compressed=false;
        bool ok=false;
        auto t0=std::chrono::steady_clock::now();
        for(uint32_t r=0;r<random_repeat;++r) {
            buf.clear();
            ok=random_read_ptd(in,password,random_offset,random_length,buf,&compressed,false);
            if(!ok) break;
        }
        auto t1=std::chrono::steady_clock::now();
        if(!ok) {
            std::cerr<<"Random read failed (wrong password or unsupported container).\n";
            return 1;
        }
        // 压缩容器已
        if(compressed)
            std::cerr<<"random-read: compressed container, whole-file decrypt window used.\n";
        // 二进制输出
        if(random_out.empty()) {
#ifdef _WIN32
            _setmode(_fileno(stdout),_O_BINARY);
#endif
            std::cout.write(reinterpret_cast<const char*>(buf.data()),(std::streamsize)buf.size());
            std::cout.flush();
        } else {
            // 低危
            if(!fe_create_output_no_follow(random_out)) return 1;
            std::ofstream of;
            if(!open_stream(of,random_out,std::ios::out|std::ios::binary|std::ios::trunc)) {
                std::cerr<<"Cannot open output file: "<<random_out<<"\n"; return 1;
            }
            of.write(reinterpret_cast<const char*>(buf.data()),(std::streamsize)buf.size());
        }
        double secs=std::chrono::duration<double>(t1-t0).count();
        double mbps=(random_repeat>0 && secs>0)
            ? (double(random_length)*random_repeat/(1024.0*1024.0))/secs : 0.0;
        std::cerr<<"random-read: offset="<<random_offset
                 <<" len="<<random_length
                 <<" got="<<buf.size()
                 <<" repeats="<<random_repeat
                 <<" "<<mbps<<" MiB/s\n";
        sodium_memzero(buf.data(),buf.size());
        return 0;
    }

    // 加密盘库管理动
    if(action==ACTION_VAULT_MOUNT) {
        if(vault_mount_dir.empty()||vault_mount_point.empty()) {
            std::cerr<<"--vault-mount requires a vault dir and a mount point (drive letter like V: or a Linux mount dir).\n";
            return 1;
        }
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_mount_dir, meta, err)) { std::cerr<<"vault-mount failed: "<<err<<"\n"; return 1; }
        if(vault_mount_point=="-") {
            meta.mount_point.clear();
            std::cout<<"Mount point cleared for "<<vault_mount_dir<<"\n";
        } else {
            meta.mount_point=vault_mount_point;
            std::cout<<"Mount point for "<<vault_mount_dir<<" set to "<<vault_mount_point<<"\n";
        }
        if(!vault_meta_save(vault_mount_dir, meta, err)) { std::cerr<<"vault-mount failed: "<<err<<"\n"; return 1; }
        return 0;
    }
    // M4 恢复密钥
    if(action==ACTION_VAULT_RECOVERY) {
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_recovery_dir, meta, err)) {
            std::cerr<<"vault-recovery failed: "<<err<<"\n"; return 1;
        }
        std::string arg = vault_recovery_arg.empty() ? std::string("gen") : vault_recovery_arg;
        size_t sp = arg.find(' ');
        std::string sub = (sp==std::string::npos) ? arg : arg.substr(0,sp);
        std::string rest = (sp==std::string::npos) ? std::string() : arg.substr(sp+1);
        if(sub=="gen") {
            std::cout<<vault_recovery_gen_code()<<"\n";
            std::cout<<"（48 位恢复密钥，只显示一次；泄露它 = 泄露盘访问权）\n";
            return 0;
        }
        if(sub=="remove") {
            if(!vault_recovery_remove(vault_recovery_dir, err)) {
                std::cerr<<"vault-recovery remove failed: "<<err<<"\n"; return 1;
            }
            std::cout<<"Recovery file removed.\n"; return 0;
        }
        if(sub=="open") {
            if(rest.empty()) { std::cerr<<"--recovery-arg \"open <48-digit code>\"\n"; return 1; }
            SecureBuffer pw;
            if(!vault_recovery_load(vault_recovery_dir, rest, pw, err)) {
                std::cerr<<"vault-recovery open failed: "<<err<<"\n"; return 1;
            }
            std::cout.write(pw.cdata(), (std::streamsize)pw.size())<<"\n";   // cdata
            std::cout<<"（上面是主密码；请立即改密并重新生成恢复密钥）\n";
            return 0;
        }
        if(sub=="create") {
            if(!used_key_source) {
                std::cout<<"Enter vault password: ";
                std::vector<char> p=get_password();
                if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
                password=SecureBuffer(p.data(),p.size());
                sodium_memzero(p.data(),p.size()); p.clear();
            }
            std::string code = rest.empty() ? vault_recovery_gen_code() : rest;
            if(!vault_recovery_create(vault_recovery_dir, password, code, err)) {
                std::cerr<<"vault-recovery create failed: "<<err<<"\n"; return 1;
            }
            std::cout<<"Recovery file created.\nRecovery code: "<<code<<"\n";
            std::cout<<"警告：泄露恢复密钥即泄露盘访问权；请离线多处备份。\n";
            return 0;
        }
        std::cerr<<"vault-recovery: unknown subcommand '"<<sub<<"' (gen|create [code]|open <code>|remove)\n";
        return 1;
    }

    // M4 改主密码
    if(action==ACTION_VAULT_REKEY) {
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_rekey_dir, meta, err)) {
            std::cerr<<"vault-rekey failed: "<<err<<"\n"; return 1;
        }
        if(!used_key_source) {
            std::cout<<"Enter CURRENT vault password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        std::vector<VaultEntry> entries;
        if(!vault_read_index(vault_rekey_dir, meta, password, entries, err)) {
            std::cerr<<"vault-rekey: cannot unlock index ("<<err<<")\n"; return 1;
        }
        SecureBuffer newpw;
        if(new_key_from_stdin) {                 // 非交互
            std::vector<char> sbuf((std::istreambuf_iterator<char>(std::cin)),
                                   std::istreambuf_iterator<char>());
            if(sbuf.empty()) { std::cerr<<"No new key material received from stdin.\n"; return 1; }
            newpw=SecureBuffer(sbuf.data(), sbuf.size());
            sodium_memzero(sbuf.data(), sbuf.size()); sbuf.clear();
        } else {
            std::cout<<"Enter NEW vault password: ";
            std::vector<char> np=get_password();
            if(np.empty()) { std::cerr<<"No new password provided.\n"; return 1; }
            newpw=SecureBuffer(np.data(), np.size());
            sodium_memzero(np.data(), np.size()); np.clear();
        }

        size_t n_ok=0, n_fail=0;
        for(const auto& e : entries) {
            std::string ptd = vault_ptd_path(vault_rekey_dir, e.rel_path, e.store);
            if(rewrap_file_with(ptd, password, newpw, /*quiet=*/true)) n_ok++;
            else { n_fail++; std::cerr<<"  rewrap failed: "<<e.rel_path<<"\n"; }
        }
        if(n_fail) { std::cerr<<"vault-rekey aborted: "<<n_fail<<" container(s) failed, index untouched.\n"; return 1; }
        // 索引换盐重封 + 保
        VaultMeta nm = meta;
        nm.salt.assign(crypto_pwhash_SALTBYTES, 0);
        randombytes_buf(nm.salt.data(), nm.salt.size());
        std::string js = vault_entries_to_json(entries);
        if(!vault_meta_save(vault_rekey_dir, nm, err) ||
           !vault_write_index(vault_rekey_dir, nm, newpw, js, err)) {
            std::cerr<<"vault-rekey: index re-seal failed: "<<err<<"\n"; return 1;
        }
        if(vault_recovery_exists(vault_rekey_dir)) {
            // 保险文件里是旧
            std::string rerr;
            vault_recovery_remove(vault_rekey_dir, rerr);
            std::cout<<"注意：原恢复密钥已随旧密码失效并移除，请用 --vault-recovery create 重新生成。\n";
        }
        std::cout<<"Vault rekeyed: "<<n_ok<<" container(s) rotated, index re-sealed.\n";
        return 0;
    }

    // M4 库内重加密
    if(action==ACTION_VAULT_RECRYPT) {
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_recrypt_dir, meta, err)) {
            std::cerr<<"vault-recrypt failed: "<<err<<"\n"; return 1;
        }
        if(!used_key_source) {
            std::cout<<"Enter vault password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        std::vector<VaultEntry> entries;
        if(!vault_read_index(vault_recrypt_dir, meta, password, entries, err)) {
            std::cerr<<"vault-recrypt: cannot unlock index ("<<err<<")\n"; return 1;
        }
        // 只对「压缩」或「块 > 64KB」
        const uint32_t kTargetChunk = 64u*1024u;
        std::error_code ec;
        auto U = [](const std::string& s){ return std::filesystem::u8path(s); };
        // M18
        // 反斜杠让明文落
        auto rel_safe = [](const std::string& rel) {
            if (rel.empty()) return false;
            if (rel.find('\\') != std::string::npos) return false;
            if (rel[0] == '/' || rel[0] == '\\') return false;
            if (rel.size() >= 2 && rel[1] == ':') return false;
            size_t i = 0;
            while (i < rel.size()) {
                size_t j = rel.find('/', i);
                if (j == std::string::npos) j = rel.size();
                if (rel.compare(i, j - i, "..") == 0) return false;
                i = j + 1;
            }
            return true;
        };
        std::string tmpdir = vault_recrypt_dir + "/.recrypt.tmp";
        // M18
        // 会跟随，明文便
        if (path_is_symlink(tmpdir)) {
            std::cerr << "vault-recrypt: refusing to use a symlinked temp dir: " << tmpdir << "\n";
            return 1;
        }
        std::filesystem::create_directories(U(tmpdir), ec);
        if (ec) {
            std::cerr << "vault-recrypt: cannot create temp dir: " << tmpdir << "\n";
            return 1;
        }
        size_t converted=0, skipped=0, failed=0;
        for(const auto& e : entries) {
            // 随机命名
            std::string ptd = vault_ptd_path(vault_recrypt_dir, e.rel_path, e.store);
            PtdMeta pm;
            if(!read_ptd_metadata(ptd, pm)) { failed++; continue; }
            if(pm.version>=3 && pm.compression==0 && pm.chunk_size<=kTargetChunk) { skipped++; continue; }
            if (!rel_safe(e.rel_path)) {
                std::cerr << "  unsafe rel_path in index, skipping: " << e.rel_path << "\n";
                failed++; continue;
            }
            std::string plain = tmpdir + "/" + e.rel_path;
            // M18
            // create_directories 会跟随已存
            // "tmpdir/sub -> 库外" 这类预置
            // TOCTOU
            {
                std::string acc = tmpdir;
                std::string rest = plain.substr(tmpdir.size());
                bool linked = false;
                while (!rest.empty() && !linked) {
                    size_t s = rest.find_first_of("/\\");
                    std::string comp = (s == std::string::npos) ? rest : rest.substr(0, s);
                    rest = (s == std::string::npos) ? std::string() : rest.substr(s + 1);
                    if (!comp.empty()) {
                        acc += "/" + comp;
                        if (path_is_symlink(acc)) linked = true;
                    }
                }
                if (linked) {
                    std::cerr << "  symlinked parent in temp dir, skipping: " << e.rel_path << "\n";
                    failed++; continue;
                }
            }
            std::filesystem::create_directories(U(plain).parent_path(), ec);
            if (ec) { std::cerr << "  cannot create temp subdir for: " << e.rel_path << "\n"; failed++; continue; }
            if (path_is_symlink(plain)) {
                std::cerr << "  refusing symlinked temp target, skipping: " << e.rel_path << "\n";
                failed++; continue;
            }
            if(!decrypt_file(ptd, plain, password, nullptr, /*silent=*/true)) {
                std::cerr<<"  decrypt failed: "<<e.rel_path<<"\n"; failed++; continue;
            }
            std::string newptd = tmpdir + "/" + e.rel_path + ".new.ptd";
            bool ok = encrypt_file(plain, newptd, password, CryptoMode::XCHACHA20, nullptr,
                                   /*resume=*/false, /*compress_level=*/0, /*asym=*/false,
                                   nullptr, nullptr, nullptr, nullptr, kTargetChunk);
            std::filesystem::remove(U(plain), ec);
            if(!ok) { std::cerr<<"  re-encrypt failed: "<<e.rel_path<<"\n"; failed++; continue; }
            // 原子替换旧容器
            // M19
            // rename 本身即原子覆盖
            std::filesystem::rename(U(newptd), U(ptd), ec);
            if(ec) { std::cerr<<"  replace failed: "<<e.rel_path<<"\n"; failed++; continue; }
            converted++;
        }
        std::filesystem::remove_all(U(tmpdir), ec);
        std::cout<<"recrypt: converted="<<converted<<" already-fine="<<skipped<<" failed="<<failed
                 <<" (target chunk="<<kTargetChunk<<" bytes, non-compressed)\n";
        std::string rerr;
        if(!vault_reindex(vault_recrypt_dir, meta, password, rerr)) {
            std::cerr<<"vault-recrypt: index rebuild failed: "<<rerr<<"\n"; return 1;
        }
        std::cout<<"Index rebuilt after recrypt.\n";
        return failed?1:0;
    }

    if(action==ACTION_VAULT_INIT) {
        if(vault_init_dir.empty()) { std::cerr<<"--vault-init requires a directory.\n"; return 1; }
        VaultMeta meta; std::string err;
        if(!vault_meta_init(vault_init_dir, vault_init_dir, meta, err)) {
            std::cerr<<"vault-init failed: "<<err<<"\n"; return 1;
        }
        if(!vault_mount_point.empty()&&meta.mount_point.empty()) {
            meta.mount_point=vault_mount_point;
            if(!vault_meta_save(vault_init_dir, meta, err)) {
                std::cerr<<"vault-init warning: cannot record mount point: "<<err<<"\n";
            }
        }
        std::cout<<"Vault initialized at "<<vault_init_dir<<"\n";
        if(!meta.mount_point.empty()) std::cout<<"Mount point: "<<meta.mount_point<<"\n";
        return 0;
    }
    if(action==ACTION_VAULT_LIST) {
        if(vault_list_dir.empty()) { std::cerr<<"--vault-list requires a directory.\n"; return 1; }
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_list_dir, meta, err)) { std::cerr<<"vault-list failed: "<<err<<"\n"; return 1; }
        if(!used_key_source) {
            std::cout<<"Enter vault password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        std::vector<VaultEntry> entries;
        if(!vault_read_index(vault_list_dir, meta, password, entries, err)) {
            std::cerr<<"vault-list failed: "<<err<<"\n"; return 1;
        }
        std::cout<<"Vault index ("<<entries.size()<<" entries):\n";
        for(const auto& e: entries) {
            // 三端统一过滤
            if(rel_first_reserved(e.rel_path)) continue;
            std::cout<<"  "<<e.rel_path<<"  ["<<e.algo<<"]  "<<e.size<<" bytes\n";
        }
        return 0;
    }
    if(action==ACTION_VAULT_REINDEX) {
        if(vault_reindex_dir.empty()) { std::cerr<<"--vault-reindex requires a directory.\n"; return 1; }
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_reindex_dir, meta, err)) { std::cerr<<"vault-reindex failed: "<<err<<"\n"; return 1; }
        if(!used_key_source) {
            std::cout<<"Enter vault password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        if(!vault_reindex(vault_reindex_dir, meta, password, err)) {
            std::cerr<<"vault-reindex failed: "<<err<<"\n"; return 1;
        }
        std::cout<<"Vault reindexed.\n";
        return 0;
    }
    // 格式化
    // 与「删库」不同
    if(action==ACTION_VAULT_FORMAT) {
        if(vault_format_dir.empty()) { std::cerr<<"--vault-format requires a directory.\n"; return 1; }
        VaultMeta meta; std::string err;
        if(!vault_meta_load(vault_format_dir, meta, err)) { std::cerr<<"vault-format failed: "<<err<<"\n"; return 1; }
        if(!used_key_source) {
            std::cout<<"Enter vault password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No password provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        std::vector<VaultEntry> entries;
        if(!vault_read_index(vault_format_dir, meta, password, entries, err)) {
            std::cerr<<"vault-format failed: "<<err<<"\n"; return 1;
        }
        size_t removed=0, failed_n=0;
        // 全盘扫描删除
        // 仅按索引删
        // 扫目录删全部 .ptd
        {
            std::error_code ec;
            std::filesystem::path vdir = std::filesystem::u8path(vault_format_dir);
            if (std::filesystem::exists(vdir, ec)) {
                std::filesystem::recursive_directory_iterator it(vdir, ec);
                for (auto& e : it) {
                    if (!e.is_regular_file()) continue;
                    if (e.path().extension().u8string() != ".ptd") continue;
                    // 只读属性
                    clear_readonly_attribute(e.path().u8string());
                    if (remove_file_utf8(e.path().u8string())) removed++;
                    else { failed_n++; std::cerr<<"Warning: cannot remove "<<e.path().u8string()<<"\n"; }
                }
            }
        }
        // 铁律
        // 「格式化失败后文
        // 失败时索引原样
        if (failed_n) {
            std::cerr<<"vault-format failed: "<<failed_n<<" 个 .ptd 文件无法删除"
                     <<"（盘可能正被挂载或文件被占用）。索引未改动，盘内文件仍可访问；\n"
                     <<"请先卸载该加密盘后重试；若索引与盘面已不一致，可执行 --vault-reindex 重建索引。\n";
            return 1;
        }
        if(!vault_write_index(vault_format_dir, meta, password, "[]", err)) {
            std::cerr<<"vault-format failed: "<<err<<"\n"; return 1;
        }
        std::cout<<"Vault formatted: "<<removed<<" file(s) removed.\n";
        return 0;
    }

    // 因此必须
    if(action==ACTION_DERIVE||action==ACTION_PUBKEY||
       action==ACTION_VERIFY||action==ACTION_RECOVER) {
        if(!used_key_source) {
            std::cout<<(action==ACTION_DERIVE
                ? "Enter derivation password (min 6 characters): "
                : "Enter private key (AGE-SECRET-KEY-...): ");
            if(action==ACTION_VERIFY||action==ACTION_RECOVER)
                std::cout<<"Enter password: ";
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No key material provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        if(action==ACTION_DERIVE) {
            {
                std::string preason;
                const Config& cfg = global_config();
                size_t min_len = (cfg.min_password_length > 0)
                    ? (size_t)cfg.min_password_length : 8;
                int min_classes = (cfg.min_password_classes > 0) ? cfg.min_password_classes : 2;
                if(!fe::password_policy::meets_policy(password.cdata(), password.size(), min_len, min_classes, preason)) {
                    std::cerr<<preason<<"\n";
                    return 1;
                }
            }
            return run_derive(output_dir,password,salt_spec,force_overwrite)?0:1;
        }
        if(action==ACTION_PUBKEY) return run_pubkey(password)?0:1;
        if(action==ACTION_VERIFY) {
            // 非对称容器
            const std::string ident = (asym_mode||looks_like_identity(password))
                ? normalize_identity(password) : std::string();
            bool all=true;
            for(const auto& p: input_paths) if(!run_verify(p,password,ident)) all=false;
            return all?0:1;
        }
        // ACTION_RECOVER
        {
            const std::string ident = (asym_mode||looks_like_identity(password))
                ? normalize_identity(password) : std::string();
            bool all=true;
            for(const auto& p: input_paths)
                if(!run_recover(p,password,recover_rename,ident)) all=false;
            return all?0:1;
        }
    }

    set_write_sha256(cfg.write_sha256 || force_sha256); // 功能10

    if(is_encrypt && !asym_mode) {
        if(used_key_source) {
            // M27
            // password_policy 的 min_len
            // 6 位短口令经非交
            std::string preason;
            const Config& cfg = global_config();
            size_t min_len = (cfg.min_password_length > 0)
                ? (size_t)cfg.min_password_length : 8;
            int min_classes = (cfg.min_password_classes > 0) ? cfg.min_password_classes : 2;
            if(!fe::password_policy::meets_policy(password.cdata(), password.size(), min_len, min_classes, preason)) {
                std::cerr<<preason<<"\n";
                return 1;
            }
        }
        else {
            std::cout<<"Enter password (min 8 characters, strong recommended): ";
            std::vector<char> pw1=get_password();
            {
                std::string preason;
                const Config& cfg = global_config();
                size_t min_len = (cfg.min_password_length > 0)
                    ? (size_t)cfg.min_password_length : 8;
                int min_classes = (cfg.min_password_classes > 0) ? cfg.min_password_classes : 2;
                if(!fe::password_policy::meets_policy(pw1.data(), pw1.size(), min_len, min_classes, preason)) {
                    std::cerr<<preason<<"\n";
                    sodium_memzero(pw1.data(),pw1.size()); pw1.clear();
                    return 1;
                }
            }

            std::cout<<"Re-enter password: ";
            std::vector<char> pw2=get_password();
            if(pw1!=pw2) {
                std::cerr<<"Passwords do not match.\n";
                sodium_memzero(pw1.data(),pw1.size()); pw1.clear();
                sodium_memzero(pw2.data(),pw2.size()); pw2.clear();
                return 1;
            }
            password = SecureBuffer(pw1.data(), pw1.size());
            sodium_memzero(pw1.data(),pw1.size()); pw1.clear();
            sodium_memzero(pw2.data(),pw2.size()); pw2.clear();
        }
    }
    else if(!asym_mode) {
        if(!used_key_source) {
            std::cout<<"Enter password (min 6 characters): ";
            std::vector<char> ipw=get_password();
            password = SecureBuffer(ipw.data(), ipw.size());
            sodium_memzero(ipw.data(),ipw.size()); ipw.clear();
        }
        if(password.size()<6) {
            std::cerr<<"Password too short.\n";
            return 1;
        }
    }

    bool all_ok=true;

    // 密钥轮换
    // 新密码必须显式
    if(action==ACTION_REWRAP) {
        if(new_keyfile_path.empty()&&!new_key_from_stdin) {
            std::cerr<<"--rewrap requires a new key source: --new-key-file <file> or --new-key-stdin.\n";
            return 1;
        }
        bool all=true;
        for(const auto& p: input_paths) {
            if(!rewrap_file(p,password,new_keyfile_path,new_key_from_stdin)) all=false;
        }
        return all?0:1;
    }

    // 目录输入 + 删除类
    if(is_encrypt && source_action!=0 && !pack_mode && !yes_source_delete) {
        if(!confirm_source_dir_removal(input_paths, source_action)) {
            std::cerr<<"Aborted.\n";
            return 1;
        }
    }

    g_force_decrypt=force_decrypt;

    // 加密盘入盘
    if(!into_vault_dir.empty() && is_encrypt) {
        // 挂载读已支持压
        int vault_comp = compress_level;
        if(!cl_given && !f_compress) vault_comp = FE_COMPRESS_AUTO;
        // 入盘守卫
        std::string g_path = into_vault_dir;
        while (!g_path.empty() && (g_path.back()=='/' || g_path.back()=='\\')) g_path.pop_back();
        bool is_drive_root = (g_path.size()==2 && g_path[1]==':' && isalpha((unsigned char)g_path[0]));
        if (is_drive_root) {
            std::cerr<<"加密盘错误：'"<<into_vault_dir<<"' 为盘符挂载点（解密视图），并非加密盘存储目录。\n"
                     <<"请指定加密盘的存储目录（例如 D:\\Vault），而非已挂载的盘符。\n";
            return 1;
        }
        VaultMeta meta; std::string err;
        std::error_code ec_g;
        std::string meta_path = g_path + "/vault.meta";
        bool has_meta = std::filesystem::exists(std::filesystem::u8path(meta_path), ec_g);
        if (!has_meta) {
            bool dir_empty = true;
            std::error_code ec2;
            for (auto it = std::filesystem::directory_iterator(std::filesystem::u8path(g_path), ec2);
                 it != std::filesystem::directory_iterator(); ++it) { dir_empty = false; break; }
            if (!dir_empty) {
                std::cerr<<"加密盘错误：'"<<into_vault_dir<<"' 不含 vault.meta 且非空，非合法加密盘，已拒绝写入以防误损数据。\n"
                         <<"若该盘已挂载，请改用其存储目录；若需新建加密盘，请提供空目录。\n";
                return 1;
            }
        }
        if(!vault_meta_init(into_vault_dir, into_vault_dir, meta, err)) {
            std::cerr<<"加密盘初始化失败： "<<err<<"\n"; return 1;
        }
        // MSVC 窄串
        auto fs_p = [](const std::string& s){ return std::filesystem::u8path(s); };
        // 收集文件
        std::vector<std::string> files;
        for(const auto& p: input_paths) {
            std::error_code ec;
            if(fe_path_is_directory(p)) {
                for(auto& de: std::filesystem::recursive_directory_iterator(fs_p(p), ec)) {
                    if(de.is_regular_file()) files.push_back(de.path().u8string());
                }
            } else {
                files.push_back(p);
            }
        }
        if(files.empty()) { std::cerr<<"未找到可入盘的源文件。\n"; return 1; }
        if(password.empty()) {
            std::cout<<"请输入密码：";
            std::vector<char> pw=get_password();
            if(pw.empty()){ std::cerr<<"未提供密码。\n"; return 1; }
            password=SecureBuffer(pw.data(),pw.size());
            sodium_memzero(pw.data(),pw.size()); pw.clear();
        }
        auto norm = [](const std::string& s)->std::string {
#ifdef _WIN32
            std::string o=s; for(char&c:o) if(c=='\\') c='/'; return o;
#else
            return s;
#endif
        };
        auto rel_of = [&](const std::string& src) -> std::string {
            std::string rel;
            std::filesystem::path srcp = fs_p(src);
            // 词法相对库根
            // lexically_relative 纯词法、不碰 I/O，跨盘/
            std::filesystem::path r = srcp.lexically_relative(fs_p(into_vault_dir));
            if (!r.empty() && r.u8string().compare(0, 2, "..") != 0) {
                rel = norm(r.u8string());
            } else {
                // 外部源/跨盘
                // 带盘符才能区分
                std::filesystem::path r2 = srcp.lexically_relative(srcp.root_path());
                std::string tail = r2.empty() ? srcp.filename().u8string() : norm(r2.u8string());
                std::string rn = srcp.root_name().u8string();   // Windows: "D:"；UNC: "\\srv\share"
                while (!rn.empty() && (rn.back() == ':' || rn.back() == '/')) rn.pop_back();
                const size_t np = rn.find_first_not_of('/');    // UNC 去掉前导分隔符
                if (np == std::string::npos) rn.clear(); else if (np > 0) rn = rn.substr(np);
                rn = norm(rn);
                rel = (rn.empty() || tail.empty() || tail == ".") ? tail : norm(rn + "/" + tail);
            }
            return rel;
        };

        // 目录条目
        // 整条消失
        {
            std::vector<std::string> dirs;
            for (const auto& p : input_paths) {
                std::error_code dec;
                if (!fe_path_is_directory(p)) continue;
                for (auto& de : std::filesystem::recursive_directory_iterator(fs_p(p), dec)) {
                    if (de.is_directory()) dirs.push_back(de.path().u8string());
                }
            }
            for (const auto& d : dirs) {
                std::string rel = rel_of(d);
                if (rel.empty() || rel == ".") continue;
                VaultEntry dent;
                dent.rel_path = rel;
                dent.is_dir = true;
                dent.mtime = (int64_t)std::time(nullptr);
                dent.enc_ts = (uint64_t)dent.mtime;
                std::string derr;
                if (!vault_upsert_entry(into_vault_dir, meta, password, dent, derr))
                    std::cerr << "目录登记失败：" << d << "\n";
            }
        }

        // 帧式进度
        uint64_t total_bytes=0;
        for(const auto& s: files) {
            std::error_code sec;
            uintmax_t fs_sz=std::filesystem::file_size(fs_p(s), sec);
            if(!sec && fs_sz!=(uintmax_t)-1) total_bytes += (uint64_t)fs_sz;   // 量不到
        }
        // 并行
        int cfg_threads = global_config().worker_threads;
        int nt = cfg_threads > 0 ? cfg_threads : 0;
        if (nt <= 0) {
            int hc = (int)std::thread::hardware_concurrency();
            nt = hc > 0 ? hc : 4;
        }
        if (global_config().max_open_files > 0) {
            int cap = (int)(global_config().max_open_files / 3);
            if (nt > cap) nt = cap;
        }
        if ((size_t)nt > files.size()) nt = (int)files.size();
        if (nt < 1) nt = 1;

        // 整批共享一份随
        // 仅 ~53MB/s
        // 挂载盘读取时 KEK 缓
        unsigned char shared_salt[crypto_pwhash_SALTBYTES];
        unsigned char shared_kek[ARGON2_OUTPUT_LEN];
        randombytes_buf(shared_salt, sizeof(shared_salt));
        unsigned int vops = ARGON2_OPS_DEFAULT, vmem_kb = ARGON2_MEM_DEFAULT_KB;
        kdf_preset_params(global_config().kdf_preset, vops, vmem_kb);
        if (!derive_key((const unsigned char*)password.data(), password.size(),
                        shared_salt, shared_kek, vops, (size_t)vmem_kb * 1024)) {
            std::cerr << "密钥派生失败。\n";
            return 1;
        }

        feui::BatchProgress prog;
        const bool use_frame = prog.begin(nt, total_bytes);
        const size_t total_files = files.size();
        std::atomic<size_t> done{0}, failed{0}, processed_bytes{0}, next_idx{0};
        std::atomic<bool> any_fail{false};
        const auto vault_start = std::chrono::steady_clock::now();
        std::atomic<bool> display_stop{false};
        // worker 告警先入队
        std::mutex note_mtx;
        std::vector<std::string> notes;
        auto note = [&](const std::string& s) { std::lock_guard<std::mutex> lk(note_mtx); notes.push_back(s); };

        // 显示线程
        std::thread display_thread;
        if (use_frame) {
            display_thread = std::thread([&] {
                while (!display_stop.load(std::memory_order_relaxed)) {
                    prog.setProcessed(processed_bytes.load(std::memory_order_relaxed));
                    prog.setFileStats(done.load(std::memory_order_relaxed),
                                      failed.load(std::memory_order_relaxed), 0, total_files);
                    prog.render(false);
                    std::this_thread::sleep_for(std::chrono::milliseconds(40));
                }
            });
        } else {
            display_thread = std::thread([&] {
                while (!display_stop.load(std::memory_order_relaxed)) {
                    print_progress((size_t)processed_bytes.load(std::memory_order_relaxed),
                                   (size_t)total_bytes, vault_start, false);
                    std::this_thread::sleep_for(std::chrono::milliseconds(40));
                }
            });
        }

        auto worker = [&](int slot) {
            while (true) {
                size_t i = next_idx.fetch_add(1);
                if (i >= files.size()) break;
                const auto& src = files[i];
                std::string rel = rel_of(src);
                // 防御
                if (rel.empty()) rel = fs_p(src).filename().u8string();
                // 存储名
                std::error_code ec;
                std::string store = vault_random_store_name();
                std::string target = vault_ptd_path(into_vault_dir, rel, store);
                for (int guard = 0; guard < 8 && std::filesystem::exists(fs_p(target), ec); ++guard) {
                    store = vault_random_store_name();
                    target = vault_ptd_path(into_vault_dir, rel, store);
                }
                std::filesystem::create_directories(fs_p(target).parent_path(), ec);
                // 源元数据
                uint64_t src_size = 0; int64_t src_mtime = 0;
                {
                    std::error_code sec;
                    uintmax_t fs_sz = std::filesystem::file_size(fs_p(src), sec);
                    if (sec || fs_sz == (uintmax_t)-1) {
                        note("警告：无法获取源文件大小：" + src);
                        src_size = 0;
                    } else src_size = (uint64_t)fs_sz;
                    std::error_code mec;
                    auto mt = std::filesystem::last_write_time(fs_p(src), mec);
                    src_mtime = mec ? 0 :
                        (int64_t)std::chrono::time_point_cast<std::chrono::seconds>(mt).time_since_epoch().count();
                }
                if (use_frame) prog.setSlot(slot, src, 0, src_size, true);
                size_t last_pd = 0;
                bool ok = false;
                try {
                    ok = encrypt_file(src, target, password, mode,
                        [&](size_t pd, size_t tt) {
                            size_t inc = (pd > last_pd) ? pd - last_pd : 0;
                            last_pd = pd;
                            processed_bytes.fetch_add(inc, std::memory_order_relaxed);
                            if (use_frame) prog.setSlot(slot, src, pd, tt, true);
                        },
                        true, vault_comp, false, nullptr, wm_spec.enabled ? &wm_spec : nullptr,
                        shared_salt, shared_kek);
                } catch (const std::exception& e) {
                    note(std::string("Error: ") + e.what()); ok = false;
                }
                if (!ok) {
                    note("加密失败：" + src);
                    failed.fetch_add(1, std::memory_order_relaxed);
                    any_fail.store(true, std::memory_order_relaxed);
                    if (use_frame) prog.setSlot(slot, std::string(), 0, 0, false);
                    continue;
                }
                VaultEntry e;
                e.rel_path = rel; e.store = store; e.orig_abs = src; e.size = src_size; e.mtime = src_mtime;
                e.enc_ts = (uint64_t)time(nullptr); e.algo = vault_mode_str(mode); e.kdf = "argon2id";
                std::string aerr;
                // flush=false
                if (!vault_append_entry(into_vault_dir, meta, password, e, aerr, false)) {
                    note("索引追加失败：" + aerr);
                    failed.fetch_add(1, std::memory_order_relaxed);
                    any_fail.store(true, std::memory_order_relaxed);
                    if (use_frame) prog.setSlot(slot, std::string(), 0, 0, false);
                    continue;
                }
                // 周期性落盘
                // 而源文件
                // 最坏只丢尾批
                if (((i + 1) & 15) == 0) {
                    std::string ferr;
                    if (!vault_flush_index(into_vault_dir, meta, password, ferr))
                        note("索引周期性落盘失败：" + ferr);
                }
                // 收尾对齐
                processed_bytes.fetch_add((src_size > last_pd) ? (src_size - last_pd) : 0, std::memory_order_relaxed);
                done.fetch_add(1, std::memory_order_relaxed);
                if (use_frame) prog.setSlot(slot, src, src_size, src_size, false);
                if (source_action != 0) {
                    if (!secure_handle_source(src, static_cast<SourceDisposition>(source_action))) {
                        note("警告：源文件处理失败：" + src);
                    }
                }
            }
        };

        std::vector<std::thread> workers;
        for (int slot = 0; slot < nt; ++slot)
            workers.emplace_back(worker, slot);
        for (auto& w : workers) w.join();

        display_stop.store(true, std::memory_order_relaxed);
        if (display_thread.joinable()) display_thread.join();
        if (use_frame) {
            // 末帧用
            // 以最终值刷新
            prog.setFileStats(done.load(std::memory_order_relaxed),
                              failed.load(std::memory_order_relaxed), 0, total_files);
            prog.render(true);   // 收尾强制
            prog.finish();
        }
        else if (total_bytes > 0) print_progress((size_t)total_bytes, (size_t)total_bytes, vault_start, true);
        // 帧已收尾
        {
            std::lock_guard<std::mutex> lk(note_mtx);
            for (const auto& s : notes) std::cerr << s << "\n";
        }

        // 显式 flush 索引
        // 失败必须判负
        // 只 Warning
        {
            std::string ferr;
            if (!vault_flush_index(into_vault_dir, meta, password, ferr)) {
                std::cerr << "入盘失败：索引末尾落盘失败（" << ferr << "）。\n"
                          << "最后一批文件的索引条目未写入，但其 .ptd 已在盘上、源文件已按策略处置。\n"
                          << "请立即对 " << into_vault_dir << " 执行 --vault-reindex 从 .ptd 文件头重建索引找回。\n";
                return 1;
            }
        }
        const size_t n_done = done.load(), n_fail = failed.load();
        // 写宿主统计文件
        // 与 process_files 一致：经
        if (const char* stats_path = std::getenv("FILEENCRYPTOR_STATS_FILE")) {
            // 低危
            // ，创建走 no
            std::string sp(stats_path);
            bool blocked = path_is_symlink(sp);
            if (!blocked) {
                std::string cur = sp;
                for (;;) {
                    std::string::size_type slash = cur.find_last_of("/\\");
                    if (slash == std::string::npos) break;
                    cur = cur.substr(0, slash);
                    if (cur.empty() || cur.back() == ':') break;   // 根目录 / 盘符根
                    if (path_is_symlink(cur)) { blocked = true; break; }
                }
            }
            if (blocked) {
                std::cerr << "拒绝通过符号链接写入统计：" << stats_path << "\n";
            } else if (!fe_create_output_no_follow(sp)) {
                std::cerr << "Cannot create stats file: " << sp << "\n";
            } else {
                FILE* sf = fopen(sp.c_str(), "wb");
                if (sf) {
                    fprintf(sf, "{\"total_bytes\":%llu,\"files_done\":%llu,\"files_failed\":%llu,"
                              "\"files_skipped\":%llu,\"total_files\":%llu}\n",
                        (unsigned long long)total_bytes,
                        (unsigned long long)n_done,
                        (unsigned long long)n_fail,
                        (unsigned long long)0,
                        (unsigned long long)total_files);
                    fclose(sf);
                }
            }
        }
        // 退出码语义
        // 视为任务完成
        if (n_done == 0 && n_fail > 0) {
            std::cerr << "入盘失败：未写入任何文件，失败 " << n_fail << " 个（详见上方日志）。\n";
            return 1;
        }
        // 收尾统计必显式
        // 仅靠帧内 FILES 行
        std::cout << "入盘完成：" << n_done << "/" << total_files << " 个文件已写入 " << into_vault_dir;
        if (n_fail > 0) std::cout << "（" << n_fail << " 个失败，详见上方日志）";
        std::cout << "\n" << std::flush;
        all_ok=true;
    }
    else if(asym_mode) {
        // 输出名策略
        all_ok=run_asym(input_paths,output_dir,is_encrypt,source_action,force_overwrite,recipient_spec,keyfile_path,password,
            obfuscate_name||global_config().obfuscate_names,lib_recipients,mode,compress_level,split_bytes);
    }
    else if(pack_mode) {
        all_ok=run_pack(input_paths,output_dir,password,mode,source_action,
                        force_overwrite,compress_level,split_bytes,
                        wm_spec.enabled?&wm_spec:nullptr,force_sha256||write_sha256_enabled());
    }
    else if(is_batch) {
        all_ok=process_files(input_paths,output_dir,password,mode,is_encrypt,source_action,force_overwrite,num_threads,restore_name,compress_level,wm_spec.enabled?&wm_spec:nullptr,split_bytes);
    }
    else {
        // 单文件处理放入 lambda
        // 跨过带非平凡析
        all_ok = [&]() -> bool {
            const std::string& in_path=input_paths[0];
            // 管道输入
            std::istream* pipe_in=nullptr;
            if(in_path=="-") {
#ifdef _WIN32
                (void)_setmode(_fileno(stdin),_O_BINARY);
#endif
                // 解开 cerr/cin 对 cout
                // 与 AggWriter
                std::cerr.tie(nullptr);
                std::cin.tie(nullptr);
                pipe_in=&std::cin;
            }
            // -stdout
            if(f_stdout) {
                std::cerr.tie(nullptr);
                std::cin.tie(nullptr);
            }
            // 目录不属于单文
            // 会打印 "Encrypting: <目录>"
            if(fe_path_is_directory(in_path)) {
                std::cerr<<"Input is a directory: "<<in_path<<"\n"
                         <<"Use -be / -bd (batch) to process directories.\n";
                return false;
            }
            // 分卷输入
            // 合并产物
            SplitPlan plan;
            MergedTemp merged;
            std::string src_path=in_path;
            if(action==ACTION_DECRYPT) {
                std::string perr;
                if(!resolve_decrypt_input(in_path,plan,perr)) {
                    std::cerr<<"Error: "<<perr<<"\n";
                    return false;
                }
                if(plan.from_volumes) {
                    merged.path=plan.merged_path;
                    src_path=plan.merged_path;
                    std::cout<<"Found "<<plan.volumes.size()
                             <<" volume(s), merging before decryption.\n";
                }
            }
            // 输出名
            std::string name_path=plan.from_volumes ? base_ptd_of(in_path) : in_path;
            if(name_path.empty()) name_path=in_path;
            if(in_path=="-") name_path="stdin";   // 管道输入无真实

            std::string out_path;
            if(!output_dir.empty()) {
                if(!create_directory_recursive(output_dir)) {
                    std::cerr<<"Cannot create output directory: "<<output_dir<<"\n";
                    return false;
                }
                std::string base=name_path;
                size_t pos=base.find_last_of("/\\");
                std::string fname=(pos!=std::string::npos) ? base.substr(pos+1) : base;
                out_path=output_dir;
                if(!out_path.empty()&&out_path.back()!='/'&&out_path.back()!='\\')
                    out_path+='/';
                out_path+=fname;
            }
            else {
                out_path=name_path;
            }
            out_path=to_native_path(out_path);   // Windows 下把 '/' 统一

            if(action==ACTION_DECRYPT) {
                std::string lower=in_path;
                // 仅对 ASCII 字节转小写
                std::transform(lower.begin(),lower.end(),lower.begin(),
                    [](unsigned char c){ return (char)std::tolower(c); });
                if(lower.size()<4||lower.substr(lower.size()-4)!=".ptd") {
                    std::cerr<<"Error: Decryption input must have .ptd extension.\n";
                    return false;
                }
                if(out_path.size()>=4&&
                    (out_path.substr(out_path.size()-4)==".ptd"||
                        out_path.substr(out_path.size()-4)==".PTD")) {
                    out_path=out_path.substr(0,out_path.size()-4);
                }
                // 混淆文件名
                {
                    std::string orig_name;
                    if(read_original_name(src_path,orig_name,password)&&!orig_name.empty()) {
                        out_path=replace_basename(out_path,orig_name);
                    }
                }
                if(out_path==in_path) {
                    std::cerr<<"Error: Output path would overwrite input file.\n";
                    return false;
                }
            }
            else {
                if(global_config().obfuscate_names) {
                    out_path=replace_basename(out_path,
                        make_obfuscated_basename(in_path,password));
                }
                out_path+=".ptd";
            }

            // 续传无缝衔接
            // 跳过覆盖确认
            bool has_resume_meta=false;
            {
                // M21
                // <out>.fe_tmp_<FNV>.prs
                // 续传场景
                // 短路、静默覆盖已
                ProgressInfo pi;
                if(fe_load_progress(is_encrypt?atomic_output_tmp_path(out_path):out_path,pi)) {
                    if(is_encrypt) has_resume_meta=true;
                    else {
                        std::ifstream out;
                        if(open_stream(out,out_path+".prt",std::ios::in|std::ios::binary)&&out.good()) {
                            out.close();
                            has_resume_meta=true;
                        }
                    }
                }
            }

            // 覆盖提示
            // 预览模式不落盘
            if(!force_overwrite && !has_resume_meta && !preview_mode) {
                std::ifstream test;
                if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                    test.close();
                    if(!confirm_yes_no("Output file exists: "+out_path,"Overwrite? (y/N): ")) {
                        std::cerr<<"Aborted.\n";
                        return false;
                    }
                }
            }

            bool ok;
            if(is_encrypt) {
                if(f_stdout) {
                    // 管道输出
                    // 走 RawStreamBuf
                    std::cerr<<"Encrypting to stdout: "<<in_path<<"\n";
                    RawStreamBuf raw(stdout);
                    std::ostream data_out(&raw);
                    try {
                        ok=encrypt_file(in_path, std::string(), password, mode, nullptr, true, compress_level,
                                        false,nullptr,wm_spec.enabled?&wm_spec:nullptr,
                                        nullptr,nullptr,0,pipe_in,&data_out);
                    } catch(const std::exception& e) {
                        fprintf(stderr,"Error: encryption failed: %s\n",e.what());
                        ok=false;
                    } catch(...) {
                        fprintf(stderr,"Error: encryption failed (unexpected exception)\n");
                        ok=false;
                    }
                    std::cout.flush();   // 密文全部刷出
                    fflush(stdout);
                } else {
                std::cout<<"Encrypting: "<<in_path<<" -> "<<out_path<<"\n";
                // 原子落盘
                // 替换到
                // 路径
                AtomicOutput atomic_out(out_path);
                const std::string enc_target = atomic_out.path();
                // 防御性兜底
                // 而非未捕获导致 std
                try {
                    ok=encrypt_file(in_path,enc_target,password,mode,nullptr,true,compress_level,
                                    false,nullptr,wm_spec.enabled?&wm_spec:nullptr,
                                    nullptr,nullptr,0,pipe_in);
                } catch(const std::exception& e) {
                    fprintf(stderr,"Error: encryption failed: %s\n",e.what());
                    ok=false;
                } catch(...) {
                    fprintf(stderr,"Error: encryption failed (unexpected exception)\n");
                    ok=false;
                }
                // 自校验已过才提
                if(ok && !atomic_out.commit()) ok=false;
                if(ok && source_action!=0) {
                    if(!secure_handle_source(in_path, static_cast<SourceDisposition>(source_action))) {
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
                }
                if(ok && !f_stdout && write_sha256_enabled()) write_sha256_sidecar(out_path); // 功能10
                if(ok && !f_stdout && split_bytes>0) {
                    std::string serr;
                    if(!finish_encrypt_split(out_path,split_bytes,
                                             write_sha256_enabled(),serr)) {
                        std::cerr<<"Error: split failed: "<<serr<<"\n";
                        ok=false;
                    }
                }
            }
            else {
                if(f_stdout) {
                    // 管道输出
                    // 走 RawStreamBuf
                    std::cerr<<"Decrypting to stdout: "<<src_path<<"\n";
                    RawStreamBuf raw(stdout);
                    std::ostream data_out(&raw);
                    try {
                        // 状态走 stderr
                        std::function<void(size_t,size_t)> noop_cb=[](size_t,size_t){};
                        ok=decrypt_file(src_path, std::string(), password,
                            preview_mode?noop_cb:nullptr, /*silent=*/true, /*resume=*/true,
                            nullptr,nullptr,0,false,preview_mode?preview_max:0,std::string(),force_overwrite,
                            &data_out);
                    } catch(const std::exception& e) {
                        fprintf(stderr,"Error: decryption failed: %s\n",e.what());
                        ok=false;
                    } catch(...) {
                        fprintf(stderr,"Error: decryption failed (unexpected exception)\n");
                        ok=false;
                    }
                    fflush(stdout);   // 明文全部刷出
                    return ok;
                }
                if(preview_mode) {
                    std::cerr<<"Previewing first "<<preview_max<<" bytes of: "<<in_path<<"\n";
                } else {
                    std::cout<<"Decrypting: "<<in_path<<" -> "<<out_path<<"\n";
                }
                try {
                    // 预览
                    std::function<void(size_t,size_t)> noop_cb=[](size_t,size_t){};
                    ok=decrypt_file(src_path,out_path,password,
                        preview_mode?noop_cb:nullptr,false,true,
                        nullptr,nullptr,0,false,preview_mode?preview_max:0,std::string(),force_overwrite);
                } catch(const std::exception& e) {
                    fprintf(stderr,"Error: decryption failed: %s\n",e.what());
                    ok=false;
                } catch(...) {
                    fprintf(stderr,"Error: decryption failed (unexpected exception)\n");
                    ok=false;
                }
                // 归档容器
                // 放在源处置
                if(ok && !no_extract && !preview_mode && archive_probe(out_path)) {
                    // 归档铺进 -o 指定
                    std::string dest_dir = output_dir;
                    if(dest_dir.empty()) {
                        size_t sl = src_path.find_last_of("/\\");
                        dest_dir = (sl!=std::string::npos) ? src_path.substr(0,sl) : ".";
                    }
                    if(!create_directory_recursive(dest_dir)) {
                        std::cerr<<"Error: cannot create output directory: "<<dest_dir<<"\n";
                        ok=false;
                    } else {
                        ok=unpack_archive(out_path,dest_dir,force_overwrite);
                    }
                }
                // 解密成功后同样
                // -wipe-source 安全擦除、-
                if(ok && source_action!=0) {
                    // 输入来自分卷
                    // 归一没认出分卷
                    std::vector<std::string> victims=plan.from_volumes
                        ? plan.volumes : std::vector<std::string>{in_path};
                    if(!plan.from_volumes) {
                        std::string vb=base_ptd_of(in_path);
                        std::vector<std::string> vols=find_volumes(vb.empty()?in_path:vb);
                        if(!vols.empty()) victims=vols;
                    }
                    for(const auto& v:victims) {
                        if(!secure_handle_source(v, static_cast<SourceDisposition>(source_action))) {
                            std::cerr<<"Error: could not process source file: "<<v<<"\n";
                            ok=false;
                        }
                    }
                }
            }
            return ok;
        }();
    }

    return all_ok ? 0 : 1;
}

#ifdef _WIN32
#define FE_DUP   _dup
#define FE_DUP2  _dup2
#define FE_FNO   _fileno
#define FE_CLOSE _close
#else
#define FE_DUP   dup
#define FE_DUP2  dup2
#define FE_FNO   fileno
#define FE_CLOSE close
#endif

// -json
// 批量进度帧走 fputs
// 既有 return 点
int main(int argc, char* argv[]) {
    bool json = false, help = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        if (a == "-h" || a == "-?" || a == "--help") help = true;
    }
    g_contract.json = json;
    std::ostringstream sink;
    std::streambuf* old = nullptr;
    int saved_fd = -1;
    FILE* sink_file = nullptr;
    if (json && !help) {
        std::fflush(stdout);
        saved_fd = FE_DUP(FE_FNO(stdout));
        sink_file = std::tmpfile();
        if (saved_fd >= 0 && sink_file) FE_DUP2(FE_FNO(sink_file), FE_FNO(stdout));
        else saved_fd = -1;
        old = std::cout.rdbuf(sink.rdbuf());
    }
    int rc = main_impl(argc, argv);
    if (json && !help) {
        std::fflush(stdout);
        std::cout.flush();
        if (saved_fd >= 0) { FE_DUP2(saved_fd, FE_FNO(stdout)); FE_CLOSE(saved_fd); }
        std::cout.rdbuf(old);
        std::cout << fe_result_json(rc) << "\n";
        std::cout.flush();
    }
    return rc;
}
