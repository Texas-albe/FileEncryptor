#include "FileEncryptor.hpp"
#include "config.hpp"
#include "asym_crypto.hpp"
#include "keylib.hpp"
#include "password_policy.hpp"
#include "split_volumes.hpp"
#include "archive.hpp"
#include "util/hex.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <chrono>
#include <thread>
#include <iterator>
#include <sodium.h>
#include <stdexcept>
#include <ctime>

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
#include <io.h>            // _chmod（收紧密钥文件权限）
#include <sys/stat.h>     // _S_IREAD
#include <aclapi.h>       // SetEntriesInAclW / SetNamedSecurityInfoW（真正的 DACL 收紧）
#else
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>     // chmod（收紧密钥文件权限）
#endif

#ifdef _WIN32
// 交互控制台：逐键读取密码并回显 '*'，退格按 UTF-8 码点删除，而非按字节 当 stdin 被重定向（管道 / 文件 / winpty PTY）时，_getch()
// 会读控制台输入 缓冲区而挂起，故先检测 stdin 是否为控制台：不是则退化为从 std::cin 读一行
static std::vector<char> get_password_win() {
    bool is_console=false;
    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode=0;
    if(hIn!=INVALID_HANDLE_VALUE && GetConsoleMode(hIn,&mode)) {
        is_console=true;
    }

    if(!is_console) {
        // 非交互（管道 / 重定向 / PTY）：直接读取一行密码（原始 UTF-8 字节）
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
        if(ch==0||ch==0xE0) { _getch(); continue; } // 扩展键（方向键等）
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

// ===== 确认询问 =====
// 交互终端：纯文本提示 + std::cin 读一个字符。
// 宿主（GUI）：FILEENCRYPTOR_CONFIRM_FILE 指向一个来回文件 —— CLI 把问题写进去，
// 宿主弹窗后把 y/n 写回来。走文件而非 stdin/stdout 有两个硬理由：
//   1) stdin 已被口令通道占满（--key-stdin 读到 EOF 为止），关掉写端后 CLI 读到的是 EOF；
//   2) WinUI 的「系统控制台」模式只重定向 stdin，stdout/stderr 直接进控制台窗口，
//      宿主根本看不到提示，也没法把应答送回去。
static bool host_confirm_enabled() {
    const char* v=std::getenv("FILEENCRYPTOR_CONFIRM_FILE");
    return v&&v[0];
}

// 把问题写进握手文件，再轮询等应答。宿主写回以覆盖截断，故读到的首行即答案。
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
    // 上限 10 分钟：宿主窗口被用户最小化时不该把 CLI 永久挂住。
    // 答案只认严格的 y/yes/n/no：第一次轮询很可能读回上面刚写的**问题本身**，
    // 若按首字符判断，「Source directories...」会被当成回答（既不是 y 也不是 n，
    // 结果是立刻返回 false，用户还没来得及答就被判为拒绝）。
    for(int i=0; i<6000; ++i) {
        std::ifstream in;
        std::string line;
        int verdict=-1;   // 0=否 1=是 -1=还没收到答案
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
            // 吃掉应答，免得下一次询问读到上一轮的残留
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
    // subject 可能是多行（目录清单），必须换行接提示，否则最后一条路径与提示符连成一行
    if(host_confirm_enabled()) return host_confirm(subject+"\n"+prompt_suffix);
    std::string suf=prompt_suffix;
    while(!suf.empty()&&(suf.back()==' ')) suf.pop_back();
    std::cout<<subject<<"\n"<<suf<<std::flush;
    char ch='n';
    if(!(std::cin>>ch)) return false;
    return ch=='y'||ch=='Y';
}

// 目录输入 + 删除类源文件处置：整棵树会被清掉，动手前必须确认一次。
// GUI 侧先弹窗并用 --source-delete-ok 免掉这里的询问；--pack 不删目录，故不适用。
static bool confirm_source_dir_removal(const std::vector<std::string>& input_paths,
                                       int source_action) {
    std::vector<std::string> dirs;
    for(const auto& p : input_paths) if(fe_path_is_directory(p)) dirs.push_back(p);
    if(dirs.empty()) return true;
    const char* how = source_action==2 ? "securely erased"
                    : source_action==3 ? "moved to the Recycle Bin"
                    : "deleted";
    // 措辞与实现对齐：-de 只逐个删除目录树里的文件（secure_handle_source 作用于文件），
    // 空目录壳保留。不写 "directories will be deleted"，否则默认输出到源目录时
    // .ptd 就落在目录里、目录根本不会空，承诺与行为对不上。
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
    // 仅当 stdin 是 TTY 时才关闭回显；管道/CI 等非 TTY 场景下 tcgetattr 会失败，
    // 此时若仍调用 tcsetattr 会把未初始化的 oldt 写回，行为不可预期。故先检查返回值。
    bool term_ok=(tcgetattr(STDIN_FILENO,&oldt)==0);
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
        <<"  -h, --help, -?    Show this help\n\n"
        <<"Post-quantum:\n"
        <<"  --pqc             Hybrid X25519+ML-KEM-768 recipients and ML-DSA-65 watermark\n"
        <<"                    signatures (default on)\n"
        <<"  --no-pqc          Classic only: X25519/X448 recipients and RSA watermark signatures\n\n"
        <<"Options:\n"
        <<"  -o <dir>          Output directory (optional, default: source file's directory)\n"
        <<"  -de               Delete source after success: plaintext (encrypt) / .ptd (decrypt)\n"
        <<"  --wipe-source     Securely wipe (multi-pass overwrite) source after success (HDD only; SSD wear-leveling may prevent physical overwrite)\n"
        <<"  --recycle-source  Move source to system Recycle Bin after success\n"
        <<"  --rewrap <file>   Rotate key of a v6 container (payload untouched; old password via -k/env/interactive)\n"
        <<"  --new-key-file F  New password key file for --rewrap\n"
        <<"  --new-key-stdin   New password for --rewrap read from stdin\n"
        <<"  -m <mode>         Encryption mode: xchacha20 (default) | aegis256 | sm4 | x25519 | x448\n"
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
        <<"    FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\n"
        <<"    FileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\n"
        <<"    FileEncryptor -e/-be <File> [-zstd] [--compression-level <N>]   (zstd: 1..22 normal, -1..-5 fast)\n"
        <<"    FileEncryptor -e <File> --split 4GB      (cut the .ptd into 4GB volumes)\n"
        <<"    FileEncryptor -e -p <Dir|File...>   (pack a whole tree into one .ptd)\n"
        <<"    FileEncryptor -e/-d -m x25519 -r <pub>|-k <priv> <File> [-o <Path>] [-y]\n"
        <<"  Key management (asymmetric):\n"
        <<"    FileEncryptor -g [-o <dir>] [-x448] [--no-pqc]\n"
        <<"    FileEncryptor -G [-o <dir>] [--salt <hex|file>]\n"
        <<"    FileEncryptor -Y -k <private key file>\n"
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
// 将 Windows 命令行（UTF-16）转换为 UTF-8 参数向量，保证非 ASCII 路径正确解析。
// 使用标准 main 入口（而非 MSVC 专属的 wmain），以便 MinGW / Clang 等编译器也能构建。
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

// Resolve -r into a list of recipient public keys. The value is either a literal public key ("age1...", optionally prefixed with "publickey:") or
// a path to a file holding one public key per line ('#' comments and a "publickey:" prefix are tolerated).
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
        // 前缀含大写，统一小写后再比对（age1... / x448-... / mlkem1-... 均视为内联公钥）
        std::transform(low.begin(),low.end(),low.begin(),
            [](unsigned char c){ return (char)std::tolower(c); });
        return low.rfind("age1",0)==0 || low.rfind("x448-",0)==0
            || low.rfind("mlkem1-",0)==0;
    };

    const std::string t=trim(spec);
    if(t.empty()) { err="Empty recipient specification."; return false; }

    if(is_pubkey(t)) {                      // inline public key
        std::string v=strip_prefix(t);
        if(v.empty()) { err="Empty recipient public key."; return false; }
        out.push_back(v);
        return true;
    }

    std::ifstream rf;                       // otherwise: a file of public keys
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

// 把归档明文展开到 dest_dir（行为同 unzip：直接铺进去，不再套一层同名目录）。
//
// 先展开到同级暂存目录再逐项搬过去：归档里的条目可能与 dest_dir 下已有的
// 同名文件撞车，边展开边覆盖会在中途失败时留下半新半旧的状态。
// 暂存目录与目标同级，收尾是同卷改名，不用整树复制。
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
        if (pct >= last_pct) return;              // 只在整数百分点跳变时刷一行
        last_pct = pct;
        fprintf(stderr, "\rExtracting: %llu%%", (unsigned long long)pct);
        fflush(stderr);
    };
    if (!archive_extract(plain_path, tmp_dir, force_overwrite, cb, err)) {
        fprintf(stderr, "\n");
        std::cerr << "Error: " << err << "\n";
        remove_file_utf8(plain_path);             // 半成品不留，明文也别留在盘上
        return false;
    }
    if (last_pct < 100) fprintf(stderr, "\rExtracting: 100%%");
    fprintf(stderr, "\n");

    // 展开成功才删中间明文：失败时它还在，用户可以 --no-extract 再取一次
    remove_file_utf8(plain_path);

    // 把暂存目录里的顶层项搬进 dest_dir：目录树可能有好几层，
    // 直接 rename 整个暂存目录会把 dest_dir 本身换掉
    // 顶层项逐个并入 dest_dir：同名目录递归并（不整体替换，免得丢掉
    // dest_dir 里已有的其它内容），文件按 -y 决定跳过还是替换
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
    // 暂存目录空了，删掉；里面还剩东西说明上面有失败，保留给用户查看
    if (ok) remove_tree(tmp_dir);
    else std::cerr << "Incomplete items are left at: " << tmp_dir << "\n";
    return ok;
}

// --pack：把目录树 / 多个文件打成单个归档明文，再走常规加密成单个 .ptd。
// 归档字节流本身是普通明文，所以压缩、分卷、水印、密钥轮换都照常生效。
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
    // 输出名：单根输入取其基名，多根输入给个通用名
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

    // 输出 .ptd 与中间归档件都得排除：同目录时会把刚生成的产物打进包里
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

    // 中间归档明文：无论成败都不留（成功时它是完整的明文目录内容）
    if (ok) secure_handle_source(tmp_archive, SourceDisposition::Wipe);
    else remove_file_utf8(tmp_archive);

    if (!ok) {
        remove_file_utf8(out_path);
        remove_file_utf8(out_path + ".prs");
        return false;
    }

    // 源文件处置：逐个输入走一遍，目录则交给 secure_handle_source 递归不了，
    // 故目录输入只提示（要清源请用 -de 配 -be 逐文件处理）
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

// 非对称调度：DEK 以收件人公钥（X25519/X448）包装进 v6 容器（.ptd）。
// 路径校验 / 符号链接守卫 / .prt 原子落盘复用对称路径同一套。
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
        // -r takes the public key itself ("age1..." / "X448-...") or a file of public keys;
        // -K 补充密钥库收件人（二者至少其一）。重复公钥去重。
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
        // Decryption takes the private key as a file (-k), never as an inline string.
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
        // 分卷输入先合并成完整件；解密输出的名字仍按原卷名推导，
        // 所以只换读取源，不动 in_path 的展示名
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
            // 容器自带文件名信封（与对称路径一致），混淆名需 --obfuscate-name 显式开启。
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
            out_path=to_native_path(out_path);   // 分隔符统一（Windows）
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
            out_path=to_native_path(out_path);   // 分隔符统一（Windows）
            if(out_path==in_path) {
                std::cerr<<"Error: output path would overwrite input file.\n";
                all_ok=false; continue;
            }
        }

        // 路径策略校验 + 符号链接守卫（与对称路径同一套）
        // 输入路径的 ".." 交由 validate_io_paths 的白名单前缀比较裁决
        if(!validate_io_paths(in_path,out_path,false)) {
            std::cerr<<"Path validation failed (config policy)\n";
            all_ok=false; continue;
        }
        if(path_is_symlink(out_path)) {
            std::cerr<<"Refusing to write through existing symlink: "<<out_path<<"\n";
            all_ok=false; continue;
        }

        // 覆盖确认（与对称路径一致；GUI 带 -y 跳过）
        if(!force_overwrite) {
            std::ifstream test;
            if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                test.close();
                if(!confirm_yes_no("Output file exists: "+out_path,"Overwrite? (y/N): ")) {
                    std::cerr<<"Aborted.\n"; all_ok=false; continue;
                }
            }
        }

        // 先写 .prt 再原子替换，避免中断时留下半截（明文）输出被误认为成品。
        const std::string part_path=out_path+".prt";
        if(path_is_symlink(part_path)) {
            std::cerr<<"Refusing to write through existing symlink: "<<part_path<<"\n";
            all_ok=false; continue;
        }
        remove_file_utf8(part_path);   // 清掉上次残留

        bool ok=false;
        if(is_encrypt) {
            std::cout<<"Asymmetric encrypting: "<<in_path<<" -> "<<out_path<<"\n";
            try {
                ok=encrypt_file(src_path,part_path,SecureBuffer(),mode,nullptr,false,compress_level,
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
            {   // 私钥文件可能带尾随换行 / 空格；就地 erase 避免缓冲残留（审计问题 9）
                size_t a=0,b=identity.size();
                while(a<b && (unsigned char)identity[a]<=0x20) ++a;
                while(b>a && (unsigned char)identity[b-1]<=0x20) --b;
                if(b<identity.size()) identity.erase(b);
                if(a>0)               identity.erase(0,a);
            }
            try {
                ok=decrypt_file(src_path,part_path,SecureBuffer(),nullptr,
                                false,false,nullptr,nullptr,0,false,0,identity);
            } catch(const std::exception& e) {
                fprintf(stderr,"Error: asymmetric decryption failed: %s\n",e.what());
                ok=false;
            } catch(...) {
                fprintf(stderr,"Error: asymmetric decryption failed (unexpected exception)\n");
                ok=false;
            }
            // resize 到 capacity() 再清零，覆盖字符串容量尾部的私钥残留
            identity.resize(identity.capacity());
            sodium_memzero(identity.data(),identity.size());
        }
        if(!ok) {
            std::cerr<<"Failed to process: "<<in_path<<"\n";
            remove_file_utf8(part_path);
            all_ok=false; continue;
        }
        if(!replace_file_utf8(part_path,out_path)) {
            std::cerr<<"Cannot finalize output file: "<<out_path<<"\n";
            remove_file_utf8(part_path);
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

// -g：随机生成密钥对。公钥写 stdout（干净一行，可重定向），私钥写 <dir>/rage_private.txt。
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
        clear_readonly_attribute(path);   // 旧版本可能把文件设成了只读
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

    const std::string priv_path=dir+"rage_private.txt";

    // v2.1.2：补上与 run_derive 一致的覆盖保护 私钥一旦被静默覆盖，用它加密的
    // 所有 .age 文件将永久不可解密。
    if(!force_overwrite&&file_exists_path(priv_path)) {
        std::cerr<<"Refusing to overwrite existing private key file: "<<priv_path
            <<"\nUse -y to overwrite.\n";
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    if(!write_line(priv_path,priv)) {
        sodium_memzero(priv.data(),priv.size());
        return false;
    }
    tighten_file_permissions(priv_path);   // 收紧密钥文件权限（仅拥有者可读）

    // 公钥也落盘（与私钥同目录、同名风格）：stdout 只 serving 管道用途，存文件才方便复用
    const std::string pub_path=dir+"rage_public.txt";
    if(!write_line(pub_path,pub)) {
        std::cerr<<"Cannot write: "<<pub_path<<"\n";
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    // stdout: the public key alone, so it can be piped straight into -r or a file
    std::cout<<pub<<"\n";
    std::cout.flush();
    // stderr: everything else, so redirecting stdout still yields a clean key
    std::cerr<<"Private key file: "<<priv_path<<"\n";
    std::cerr<<"Public key file : "<<pub_path<<"\n";
    std::cerr<<"Public key ("<<(algo==RECIP_ALGO_MLKEM?"MLKEM1-...":algo==RECIP_ALGO_X448?"X448-...":"age1...")
        <<") printed above - share it freely; the private key decrypts.\n";

    sodium_memzero(priv.data(),priv.size());
    return true;
}

// 解析 --salt：32 个十六进制字符，或存放它们的文件（rage_derive_salt.txt）。
static bool parse_salt(const std::string& spec,std::vector<unsigned char>& out) {
    auto trim=[](const std::string& s)->std::string{
        size_t a=0,b=s.size();
        while(a<b&&(unsigned char)s[a]<=0x20) ++a;      // 同时吃掉 CR / LF / 空格
        while(b>a&&(unsigned char)s[b-1]<=0x20) --b;
        return s.substr(a,b-a);
    };
    auto is_hex=[](const std::string& s)->bool{
        if(s.empty()) return false;
        for(char c: s) if(!std::isxdigit((unsigned char)c)) return false;
        return true;
    };
    std::string t=trim(spec);
    if(t.size()!=32||!is_hex(t)) {                       // 不是裸 hex，就当作文件读取
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

// -G：由口令派生密钥对。输出同 -g，另写 <dir>/rage_derive_salt.txt（复现同一密钥对必需）。
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
        clear_readonly_attribute(path);   // 旧版本可能把文件设成了只读
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

    bool ok=write_line(priv_path,priv);
    if(ok) ok=write_line(salt_path,std::string(salt_hex));
    if(ok) tighten_file_permissions(priv_path);   // 收紧密钥文件权限（仅拥有者可读）

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

// -Y：由身份私钥导出收件人公钥。
static bool run_pubkey(const SecureBuffer& identity) {
    std::string id(identity.cdata(),identity.size());
    {   // 私钥文件可能带尾随换行 / 空格；就地 erase 避免 substr 产生无法擦除的临时副本
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

// 功能2：文件头信息查看器（只读、不解密）。展示版本/模式/Argon2 参数/salt/iv（十六进制）/
// 原始大小/明文 Blake2b/是否带加密名尾部。纯元数据预览，不验证密钥正确性。
static bool run_info(const std::string& path) {
    PtdMeta meta;
    if(!read_ptd_metadata(path, meta)) {
        std::cerr<<"Cannot read header (not a FileEncryptor file?): "<<path<<"\n";
        return false;
    }
    const char* mode_str = (meta.mode==CryptoMode::XCHACHA20)?"XChaCha20"
                         : (meta.mode==CryptoMode::AEGIS256)?"AEGIS-256"
                         : (meta.mode==CryptoMode::SM4)?"SM4-GCM"
                         : (meta.mode==CryptoMode::AES_GCM)?"AES-GCM(legacy)":"unknown";
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

// 水印查看器（只读尾部记录，不需口令）。带公钥时验签，验签失败即记录被改过或公钥不对。
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

// 身份私钥常以文件/终端输入传入，尾部必带换行；带 \r\n 时 EVP 解码出的密钥是垃圾，
// -V/-R 会误报「解密失败」，故统一先裁剪首尾空白再当身份使用。
static std::string normalize_identity(const SecureBuffer& buf) {
    const unsigned char* p=reinterpret_cast<const unsigned char*>(buf.cdata());
    size_t a=0, b=buf.size();
    while(a<b && p[a]<=0x20) ++a;
    while(b>a && p[b-1]<=0x20) --b;
    return std::string(reinterpret_cast<const char*>(p+a), b-a);
}

// 口令材料本身是身份私钥串时按非对称通道处理：省得 -V/-R 漏写 -m x25519 直接失败。
static bool looks_like_identity(const SecureBuffer& buf) {
    const std::string s=normalize_identity(buf);
    return s.rfind("AGE-SECRET-KEY-",0)==0 || s.rfind("MLKEM1SEC-",0)==0
        || s.rfind("X448SEC-",0)==0;
}

// 功能3：完整性校验（只验不解）。对单文件解密到临时文件比对明文哈希，不落盘明文。
static bool run_verify(const std::string& path, const SecureBuffer& pw,
                       const std::string& asym_identity) {
    if(verify_ptd(path, pw, asym_identity)) {
        std::cout<<"OK    "<<path<<"\n";
        return true;
    }
    std::cout<<"FAILED "<<path<<"\n";
    return false;
}

// 功能15：离线还原混淆文件名（不改内容）。用口令恢复 .ptd 尾部信封中的原始文件名并打印；
// 带 --rename 时把 .ptd 自身重命名为 <原始名>.ptd（内容不变）。
static bool run_recover(const std::string& path, const SecureBuffer& pw, bool do_rename,
                        const std::string& asym_identity) {
    std::string orig;
    if(!read_original_name(path, orig, pw, nullptr, 0, nullptr, asym_identity)) {
        std::cerr<<"Cannot recover original name (wrong key or no name envelope): "<<path<<"\n";
        return false;
    }
    std::cout<<"Original name: "<<orig<<"\n";
    if(do_rename) {
        // orig 来自密文尾部文件名信封（数据可控）：拼接前必须拒绝任何目录成分/绝对路径，
        // 否则 "<..\..\evil>.ptd" 会把 .ptd 重命名逃逸出原目录。
        bool bad = orig.empty() || orig.find_first_of("/\\") != std::string::npos
                || orig.find("..") != std::string::npos
                || orig.front() == '/' || orig.front() == '\\';
#ifdef _WIN32
        if(!bad && orig.size() >= 2 && orig[1] == ':') bad = true;   // 盘符 X: 绝对路径
#endif
        if(bad) {
            std::cerr<<"Refusing to rename: original name contains path elements: "<<orig<<"\n";
            return false;
        }
        // 重命名 .ptd 本身（不触碰内容）：<原始名>.ptd，置于同目录
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

// 功能1：密钥库管理（-L）。子命令经位置参数传入：list|add|remove|show|pub|export。
// 索引与材料布局见 core/keylib.hpp；本函数只做 CLI 侧的表现层（打印/校验/派生回写）。
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
        // 读取身份材料（库内名称或任意路径），派生收件人公钥
        auto read_trimmed=[&](const std::string& path,std::string& out,std::string& err)->bool{
            std::ifstream f;
            if(!open_stream(f,path,std::ios::in|std::ios::binary)) {
                err="Cannot open key file: "+path; return false;
            }
            // 流式读取身份材料并封顶 256 KB，与 keylib 侧上限一致，避免大文件全量入内存
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
            // 回写缓存：之后 -K <name> 加密无需再接触私钥
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

// 国庆节祝福（每年 10/1–10/7 自动追加到 stdout 输出末尾）
// 为什么用 RAII 替换 std::cout 的 streambuf：main 有数十个提前 return 的出口，
// 逐出口补打印既繁琐又易漏；替换缓冲区可统一捕获「本进程是否真的向 stdout
// 写过内容」，进程退出时仅在确有输出的情况下追加一行祝福。
// 祝福只进 stdout：stderr 的错误信息不属于「有输出的文本」。
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

// 中华人民共和国 1949-10-01 成立；国庆周内的祖国年龄 = 当前年份 − 1949
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
        std::cout.rdbuf(old_);   // 先恢复真实缓冲区，再追加祝福行
        if (buf_.any_ && is_national_day_week()) {
            // 空行隔开，避免与前面的业务输出粘连
            // 祝福走 stderr：stdout 要留干净，否则重定向公钥/公钥串进文件时会把祝福写进数据
            std::cerr << "\nHappy " << motherland_age()
                      << "th Birthday to the People's Republic of China!\n";
            std::cerr.flush();
        }
    }
};

int main(int argc,char* argv[]) {
#ifdef _WIN32
    // 让控制台以 UTF-8 输出，确保中文提示正确显示
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    // 改用 UTF-8 参数向量（覆盖默认 ANSI 代码页的 argv）
    std::vector<std::string> argv_utf8=get_utf8_argv();
    // CLI11 2.7.2 拒绝「单横线 + 多字符」选项名（-be/-bd/-x448/-de/-zstd/-cl/-rn/-on），
    // 这里在交给 CLI11 之前改写成双横线形式；对外接口（CLI/GUI 仍用 -be 等）保持不变。
    {
        static const std::pair<const char*,const char*> kDashRewrite[] = {
            {"-be","--be"}, {"-bd","--bd"}, {"-x448","--x448"}, {"-de","--de"},
            {"-zstd","--zstd"}, {"-cl","--cl"}, {"-rn","--rn"}, {"-on","--on"}
        };
        for(auto& s: argv_utf8)
            for(auto& kv: kDashRewrite)
                if(s==kv.first) s=kv.second;
    }
    std::vector<char*> argv_ptr;
    argv_ptr.reserve(argv_utf8.size()+1);
    for(auto& s:argv_utf8) argv_ptr.push_back(const_cast<char*>(s.c_str()));
    argv_ptr.push_back(nullptr);
    argc=(int)argv_utf8.size();
    argv=argv_ptr.data();
#endif

    anti_debug_check();

    NationalDaySuffix nds;   // 进程退出时按需追加国庆节祝福（机制见 struct 注释）

    if(sodium_init()<0) {
        std::cerr<<"libsodium initialization failed.\n";
        return 1;
    }

    // 加载 YAML 配置（日志/并发/路径策略等运维参数统一走配置文件，CLI 不可覆盖）
    Config cfg=load_config();
    set_global_config(cfg);
    init_logger(cfg.log_file,cfg.log_level);
    init_rate_limiter(cfg.max_speed); // 进程级限速（YAML max_speed；0 = 不限速）

    enum {
        ACTION_NONE,ACTION_ENCRYPT,ACTION_DECRYPT,
        ACTION_BATCH_ENCRYPT,ACTION_BATCH_DECRYPT,ACTION_KEYGEN,
        ACTION_DERIVE,ACTION_PUBKEY,ACTION_INFO,ACTION_VERIFY,ACTION_RECOVER,
        ACTION_KEYLIB,ACTION_REWRAP,ACTION_WATERMARK
    } action=ACTION_NONE;

    std::vector<std::string> input_paths;
    std::string output_dir;
    CryptoMode mode=CryptoMode::XCHACHA20;
    // 未显式指定 -m 时，加密默认算法取 YAML crypto.default_cipher（空 = xchacha20）
    {
        const std::string& dc = global_config().default_cipher;
        if (dc == "aegis256") mode = CryptoMode::AEGIS256;
        else if (dc == "sm4") mode = CryptoMode::SM4;
    }
    int source_action=0;          // 0=保留 1=删除(-de) 2=安全擦除(--wipe-source) 3=回收站(--recycle-source)
    bool force_overwrite=false;
    bool force_decrypt=false;
    int num_threads=0;
    bool restore_name=false;     // 批量解密是否还原完整原始文件名（默认 false：仅保留扩展名，省去每文件 KDF）
    bool obfuscate_name=false;   // -on：强制混淆输出文件名（另受配置 obfuscate_names 控制）
    std::string keyfile_path;   // 一.1：密钥文件输入（-k）
    bool asym_mode=false;       // -m x25519/x448：非对称（DEK 由收件人公钥包裹进 v6 容器）
    bool x448_mode=false;        // -x448：非对称 ECDH 曲线用 X448（默认 X25519）
    std::string recipient_spec; // -r <pub|file>: public key (age1... / X448-...) or a file of them (encrypt)
    bool key_from_stdin=false;  // --key-stdin：从 stdin 读取密钥材料（密码或 age 身份私钥）
    bool preview_mode=false;    // --preview：仅解密并输出明文前缀到 stdout，不落盘
    size_t preview_max=4096;    // --max-bytes N：预览字节数上限（默认 4 KiB）
    std::string salt_spec;      // --salt <hex|file>：-G 派生的盐（空 = 生成随机盐）
    bool force_sha256=false;    // --sha256：本次加密生成 <out>.ptd.sha256 校验单（功能10）
    bool recover_rename=false;  // --rename：配合 -R 原地重命名 .ptd（内容不变）
    bool pqc_on=true;           // --pqc / --no-pqc：后量子（混合 KEM + ML-DSA 签名），默认开启
    WatermarkSpec wm_spec;      // --watermark / --no-watermark / --wm-sign：尾部水印
    std::string wm_verify_pem;  // --wm-verify：<--watermark-extract> 验签用的签名公钥 PEM
    bool wm_keygen_mode=false;  // --wm-keygen <file>：生成水印签名密钥（ML-DSA-65/RSA）
    std::string wm_keygen_path; // --wm-keygen 的私钥落盘路径
    std::string keylib_refs;    // -K <name>[,...]：密钥库引用（加密=收件人；解密=身份）
    std::string keylib_as;      // --as <name>：-L add 的库内名称
    std::string keylib_alias;   // --alias <text>：-L add 的展示别名
    std::string keylib_notes;   // --notes <text>：-L add 的备注
    int compress_level=0;       // -z/--compress 或 --compression-level N：zstd 级别；0=不压缩
    uint64_t split_bytes=0;     // --split <size>：加密后分卷大小（0=不分卷）；只走命令行，不进 yaml
    bool pack_mode=false;       // --pack：把目录树/多文件打成单个归档再加密
    bool yes_source_delete=false;// --source-delete-ok：源目录删除已由宿主确认过
    bool no_extract=false;      // --no-extract：解密归档时只出单文件，不展开目录树
    std::string new_keyfile_path; // --new-key-file <file>：rewrap 的新口令密钥文件
    bool new_key_from_stdin=false;// --new-key-stdin：rewrap 的新口令从 stdin 读取

    // 帮助 / 无参数：保持原 print_usage() 文案，解析前短路（CLI11 不触发自带 help）
    if(argc<=1) { print_usage(); return 0; }
    for(int k=1; k<argc; ++k) {
        std::string a=argv[k];
        if(a=="-h"||a=="-?"||a=="--help") { print_usage(); return 0; }
    }

    CLI::App app("FileEncryptor command-line interface");

    // Temp bools: CLI11 add_flag binds bool targets; merged into action / switches after parse
    bool f_encrypt=false, f_decrypt=false, f_bencrypt=false, f_bdecrypt=false,
         f_keygen=false, f_derive=false, f_pubkey=false, f_info=false,
         f_verify=false, f_recover=false, f_keylib=false, f_rewrap=false;
    bool f_preview=false, f_pqc=false, f_nopqc=false, f_wm=false, f_nowm=false,
         f_compress=false, f_verbose=false;
    std::vector<std::string> mode_strs;
    std::string split_str;
    std::string wm_extract_path;
    std::vector<std::string> explicit_inputs;
    bool src_del=false, src_wipe=false, src_recycle=false;
    bool features_mode=false;
    bool cl_given=false;

    // ===== actions (mutually exclusive; merged after parse) =====
    app.add_flag("-e", f_encrypt);
    app.add_flag("-d", f_decrypt);
    app.add_flag("--be", f_bencrypt);
    app.add_flag("--bd", f_bdecrypt);
    app.add_flag("-g", f_keygen);
    app.add_flag("-G", f_derive);
    app.add_flag("-Y", f_pubkey);
    app.add_flag("-H,--info", f_info);
    app.add_flag("-V,--verify", f_verify);
    app.add_flag("-R,--recover-name", f_recover);
    app.add_flag("-L,--keylib", f_keylib);
    app.add_flag("--rewrap", f_rewrap);

    // ===== common options =====
    app.add_option("-m,--mode", mode_strs, "crypto mode: xchacha20|aegis256|sm4|x25519|x448")
        ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);
    app.add_flag("--x448", x448_mode);
    app.add_option("-o,--output", output_dir, "output directory");
    app.add_flag("--de", src_del);
    app.add_flag("--wipe-source", src_wipe);
    app.add_flag("--recycle-source", src_recycle);
    app.add_option("--new-key-file", new_keyfile_path, "rewrap new key file");
    app.add_flag("--new-key-stdin", new_key_from_stdin);
    app.add_option("--as", keylib_as, "keylib entry name");
    app.add_option("--alias", keylib_alias, "keylib display alias");
    app.add_option("--notes", keylib_notes, "keylib notes");
    app.add_option("-K", keylib_refs, "-K <name>[,...]");
    app.add_option("--salt", salt_spec, "-G derive salt <hex|file>");
    app.add_option("-k,--keyfile", keyfile_path, "key file -k <file>");
    app.add_option("-r,--recipient", recipient_spec, "recipient -r <pub|file>");
    app.add_flag("--key-stdin", key_from_stdin);
    app.add_flag("--restore-name,--rn", restore_name);
    app.add_flag("--obfuscate-name,--on", obfuscate_name);
    app.add_flag("--sha256", force_sha256);
    app.add_flag("--rename", recover_rename);
    app.add_flag("-z,--compress", f_compress);
    app.add_flag("--zstd", f_compress);
    app.add_option("--compression-level,--cl", compress_level, "zstd level 1..22 or -1..-5")
        ->each([&](std::string){ cl_given=true; });
    app.add_flag("-p,--pack,--archive", pack_mode);
    app.add_flag("--source-delete-ok", yes_source_delete);
    app.add_flag("--no-extract", no_extract);
    app.add_option("-s,--split,--split-size", split_str, "split volume size, e.g. 4GB");
    app.add_flag("--features", features_mode);
    app.add_flag("--preview", f_preview);
    app.add_option("--max-bytes", preview_max, "preview max bytes (default 4096)");
    app.add_flag("--force-decrypt", force_decrypt);
    app.add_flag("-y,--force", force_overwrite);
    app.add_flag("-v,--verbose", f_verbose);
    app.add_flag("--pqc", f_pqc);
    app.add_flag("--no-pqc", f_nopqc);
    app.add_flag("--watermark", f_wm);
    app.add_flag("--no-watermark", f_nowm);
    app.add_option("--wm-sign", wm_spec.sign_key, "watermark signing key (ML-DSA-65/RSA)");
    app.add_option("--wm-verify", wm_verify_pem, "watermark verify public key PEM");
    app.add_option("--wm-keygen", wm_keygen_path, "generate watermark keypair");
    app.add_option("--watermark-extract", wm_extract_path, "extract tail watermark (read-only)");
    app.add_option("-i,--input", explicit_inputs, "explicit input path");
    app.add_option("inputs", input_paths, "input files or directories");

    try {
        app.parse(argc, argv);
    } catch(const CLI::CallForHelp&) {
        return 0;
    } catch(const CLI::ParseError& e) {
        std::cerr<<e.what()<<"\n";
        return 1;
    }

    for(auto& s: explicit_inputs) input_paths.push_back(s);

    // ===== merge / validate after parse =====
    if(features_mode) {
#ifdef FE_WITH_ZSTD
        std::cout<<"zstd=1\n";
#else
        std::cout<<"zstd=0\n";
#endif
        std::cout<<"aegis="<<(aegis256_supported()?1:0)<<"\n";
        std::cout<<"sm4="<<(sm4_supported()?1:0)<<"\n";
        std::cout<<"pqc="<<(pqc_supported()?1:0)<<"\n";
        std::cout<<"split=1\n";
        std::cout<<"pack=1\n";
        std::cout<<"confirm=1\n";
        return 0;
    }

    if(f_verbose) set_verbose(true);

    // -m mode validation (order preserved; asym can appear with a payload mode)
    for(auto& ms : mode_strs) {
        if(ms=="xchacha20") mode=CryptoMode::XCHACHA20;
        else if(ms=="aegis256") mode=CryptoMode::AEGIS256;
        else if(ms=="sm4") mode=CryptoMode::SM4;
        else if(ms=="x25519"||ms=="x448") asym_mode=true;
        else { std::cerr<<"Unknown mode: "<<ms<<"\n"; return 1; }
    }

    // mutually exclusive action merge
    {
        const int n_act = (f_encrypt?1:0)+(f_decrypt?1:0)+(f_bencrypt?1:0)+(f_bdecrypt?1:0)
            +(f_keygen?1:0)+(f_derive?1:0)+(f_pubkey?1:0)+(f_info?1:0)+(f_verify?1:0)
            +(f_recover?1:0)+(f_keylib?1:0)+(f_rewrap?1:0);
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
    }

    // --watermark-extract: read-only tail watermark, not a regular action
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

    // --wm-keygen <file> 不设置 action（它单独完成一次签名密钥生成），
    // 必须排在 usage 短路之前，否则只有这一个开关时会被当成无动作直接打印帮助。
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

    // Key generation needs no input file: -g [-o <dir>] [-x448] [--no-pqc]
    if(action==ACTION_KEYGEN) {
        uint8_t kalgo = RECIP_ALGO_X25519;
        if(pqc_on)                     kalgo = RECIP_ALGO_MLKEM;   // 默认：X25519 + ML-KEM-768
        else if(x448_mode)             kalgo = RECIP_ALGO_X448;
        return run_keygen(output_dir,force_overwrite,kalgo) ? 0 : 1;
    }
    // --wm-keygen 分支已上移至 usage 短路之前（见上方）

    // 功能1：密钥库管理（-L）。子命令与操作数走位置参数（list/add/remove/show/pub/export）
    if(action==ACTION_KEYLIB) {
        return run_keylib(input_paths,keylib_as,keylib_alias,keylib_notes) ? 0 : 1;
    }

    // 功能2：文件头信息查看器（只读，无需密钥）
    if(action==ACTION_INFO) {
        if(input_paths.empty()) { std::cerr<<"No input files specified.\n"; return 1; }
        bool all=true;
        for(const auto& p: input_paths) if(!run_info(p)) all=false;
        return all?0:1;
    }

    // 水印查看：--watermark-extract（尾部只读，可批量）
    if(action==ACTION_WATERMARK) {
        if(input_paths.empty()) { std::cerr<<"No input files specified.\n"; return 1; }
        bool all=true;
        for(const auto& p: input_paths) if(!run_watermark(p, wm_verify_pem, pqc_on)) all=false;
        return all?0:1;
    }

    // -G（口令派生）/ -Y（公钥导出）/ -V（校验）/ -R（还原名）/ -H（查看头）只需密钥材料或输入文件
    if(input_paths.empty()&&action!=ACTION_DERIVE&&action!=ACTION_PUBKEY
       &&action!=ACTION_VERIFY&&action!=ACTION_RECOVER&&action!=ACTION_INFO
       &&action!=ACTION_WATERMARK) {
        std::cerr<<"No input paths specified.\n";
        print_usage();
        return 1;
    }

    // --pack 本来就是「多输入打成一个」，不受单文件模式的单路径限制
    if(!is_batch&&!pack_mode&&input_paths.size()>1) {
        std::cerr<<"Single mode accepts only one input path.\n";
        return 1;
    }

    // 源文件处置对加密（删明文）与解密（删 .ptd）均有效，非对称分支同样支持。

    // 压缩选项校验：仅对称加密可用；未集成 zstd 时拒绝；级别需在 zstd 支持范围内
    if(compress_level!=0) {
#ifndef FE_WITH_ZSTD
        std::cerr<<"Compression requested but this build was compiled without zstd support.\n";
        return 1;
#endif
        if(!is_encrypt) {
            std::cerr<<"-z/--compression-level is only valid for encryption (-e/-be).\n";
            return 1;
        }
        // zstd 级别范围：常规 1..22，快速档 -1..-5（“参照 zstd”约定）
        if(compress_level<-5 || compress_level>22) {
            std::cerr<<"Invalid compression level "<<compress_level
                <<": zstd accepts 1..22 (normal) or -1..-5 (fast).\n";
            return 1;
        }
    }

    // 归档打包：仅单文件加密可用（批量逐个加密再各自成包不是这个开关的含义）
    if(pack_mode) {
        if(action!=ACTION_ENCRYPT) {
            std::cerr<<"--pack is only valid for encryption (-e).\n";
            return 1;
        }
        if(input_paths.empty()) {
            std::cerr<<"--pack requires at least one file or directory to pack.\n";
            return 1;
        }
    }
    if(no_extract&&action!=ACTION_DECRYPT) {
        std::cerr<<"--no-extract is only valid for decryption (-d/-bd).\n";
        return 1;
    }

    // 分卷校验：仅加密可用；下限 1MB（容器头 + 至少一个数据块）
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

    // 功能1：-K 从密钥库解析收件人（加密）或身份（解密）。
    // 必须在密钥文件加载（-k 读取）之前完成，解密路径才能直接复用 -k 通道。
    std::vector<std::string> lib_recipients;
    if(!keylib_refs.empty()&&action!=ACTION_KEYLIB) {
        std::vector<std::string> names;
        {   // 逗号 / 分号分隔，去空项
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

    // AEGIS-256 可用性：缺 AES-NI 时，交互终端询问是否降级（默认降级）； 非交互（GUI 管道 / --key-stdin /
    // cron）明确拒绝并以非零码退出，绝不自动降级。 同时覆盖单文件与批量两种入口，process_files 内部仅作防御性兜底。
    if(is_encrypt&&mode==CryptoMode::AEGIS256) {
        bool interactive = stdin_is_interactive() && !key_from_stdin;
        bool refuse=false;
        std::string aegis_msg;
        mode = resolve_encrypt_mode(mode, interactive, refuse, aegis_msg);
        if(refuse) {
            std::cerr<<aegis_msg<<"\n";
            return 4;   // 语义化退出码：硬件不支持且非交互，禁止自动降级
        }
    }

    // 密码输入（RAII SecureBuffer 持有，析构自动清零 + 解锁）
    // 密钥来源优先级：-k <keyfile> > ENCRYPTOR_KEY 环境变量 > 交互式输入
    SecureBuffer password;
    bool used_key_source=false; // 非交互密钥源（密钥文件或环境变量）
    if(!keyfile_path.empty()) {
        // 读取密钥文件原始字节作为密码材料（适合无人值守 / 自动化场景）
        std::ifstream kf;
        if(!open_stream(kf,keyfile_path,std::ios::binary)) {
            std::cerr<<"Cannot open key file: "<<keyfile_path<<"\n";
            return 1;
        }
        // 流式读取密钥文件并封顶 1 MB，防止超大文件/管道耗尽内存
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
        // Secure channel: read entire stdin (binary-safe, until EOF) as key material. Symmetric mode -> password; asymmetric decrypt ->
        // age identity. GUI pipes via this channel to avoid leaking through env vars / command line.
        // 流式读取并封顶 1 MB，防止恶意大管道撑爆内存。
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
        // 交互与 GUI 管道常以回车结尾（PowerShell 管道会附加换行、终端输入按回车确认），
        // 剥离尾部换行，否则密码含 \r\n 导致派生出的 KEK 与加密时不一致、解不开文件。
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
            // 已拷入 SecureBuffer：立即从进程环境块擦除原串，缩短明文残留窗口
            // （env 方式本就不如 --key-stdin，仅作兼容保留）。
#ifdef _WIN32
            _putenv("ENCRYPTOR_KEY=");
#else
            unsetenv("ENCRYPTOR_KEY");
#endif
        }
    }

    // 解密侧自动识别非对称：输入是 .ptd 且密钥材料本身就是身份私钥时走非对称通道，
    // 不必再显式写 -m x25519（两个 GUI 都只给「私钥文件」一个入口直接解密）。
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

    // 口令派生 / 公钥导出 / 完整性校验 / 文件名还原：只消费密钥材料，不读写任何输入文件，
    // 因此必须在下面的“对称密码交互输入”之前拦截。
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
            // 非对称容器的校验要用身份私钥解裹 DEK，对称口令文件不适用
            const std::string ident = (asym_mode||looks_like_identity(password))
                ? normalize_identity(password) : std::string();
            bool all=true;
            for(const auto& p: input_paths) if(!run_verify(p,password,ident)) all=false;
            return all?0:1;
        }
        // ACTION_RECOVER：--rename 启用原地重命名（内容不变）
        {
            const std::string ident = (asym_mode||looks_like_identity(password))
                ? normalize_identity(password) : std::string();
            bool all=true;
            for(const auto& p: input_paths)
                if(!run_recover(p,password,recover_rename,ident)) all=false;
            return all?0:1;
        }
    }

    set_write_sha256(cfg.write_sha256 || force_sha256); // 功能10：校验单开关（--sha256 覆盖 YAML）

    if(is_encrypt && !asym_mode) {
        if(used_key_source) {
            // 非交互密钥源：不二次确认、不做强度提示
            if(password.size()<6) {
                std::cerr<<"Key too short (min 6 characters)\n";
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

    // 密钥轮换：v6 容器 DEK 重裹（载荷密文不动）。旧口令走常规密码通道，
    // 新口令必须显式提供（--new-key-file / --new-key-stdin），避免交互式中途输入歧义。
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

    // 目录输入 + 删除类源处置：先确认一次，避免批量模式静默清掉整棵树。
    if(is_encrypt && source_action!=0 && !pack_mode && !yes_source_delete) {
        if(!confirm_source_dir_removal(input_paths, source_action)) {
            std::cerr<<"Aborted.\n";
            return 1;
        }
    }

    g_force_decrypt=force_decrypt;

    if(asym_mode) {
        // 输出名策略与对称路径一致：配置 obfuscate_names 默认开启时非对称也混淆，-on 可强制
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
        // 单文件处理放入 lambda：用 early-return 替代 goto cleanup_password，
        // 避免跨过带非平凡析构的 std::ifstream 声明（严格 C++ 下 ill-formed，MSVC -W4 报 C4533）。
        all_ok = [&]() -> bool {
            const std::string& in_path=input_paths[0];
            // 目录不属于单文件动作：批量动作（-be/-bd）才有目录递归展开，
            // 否则会打印 "Encrypting: <目录>" 后才报打不开，语义误导
            if(fe_path_is_directory(in_path)) {
                std::cerr<<"Input is a directory: "<<in_path<<"\n"
                         <<"Use -be / -bd (batch) to process directories.\n";
                return false;
            }
            // 分卷输入（foo.ptd 不存在、只有 foo.001.ptd）先合并成完整件。
            // 合并产物在本 lambda 结束时由 MergedTemp 删掉。
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
            // 输出名按 base 推导：输入 foo.003.ptd 时应得 foo，而不是 foo.003
            std::string name_path=plan.from_volumes ? base_ptd_of(in_path) : in_path;
            if(name_path.empty()) name_path=in_path;

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
            out_path=to_native_path(out_path);   // Windows 下把 '/' 统一为 '\'，避免 "E:\1/name.ptd" 混排

            if(action==ACTION_DECRYPT) {
                std::string lower=in_path;
                // 仅对 ASCII 字节转小写（UTF-8 多字节字节值为负，直接传 ::tolower 是 UB）
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
                // 混淆文件名的逆过程：密文末尾若存有原始文件名，则还原它（兼容多语言文件名）
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

            // 续传无缝衔接：若检测到续传元数据（加密看 .prs；解密需 .prs + .prt），
            // 跳过覆盖确认，直接交给 encrypt/decrypt_file 续传，避免大文件中断后重跑被“覆盖？”打断。
            bool has_resume_meta=false;
            {
                std::ifstream pf;
                if(open_stream(pf,out_path+".prs",std::ios::in|std::ios::binary)&&pf.good()) {
                    pf.close();
                    if(is_encrypt) has_resume_meta=true;
                    else {
                        std::ifstream part;
                        if(open_stream(part,out_path+".prt",std::ios::in|std::ios::binary)&&part.good()) {
                            part.close();
                            has_resume_meta=true;
                        }
                    }
                }
            }

            // 覆盖提示：基于最终输出路径（加密问 .ptd、解密问明文文件）
            // 预览模式不落盘，无需覆盖确认
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
                std::cout<<"Encrypting: "<<in_path<<" -> "<<out_path<<"\n";
                // 防御性兜底：任何未预期异常（如编码转换失败）都以干净错误退出，
                // 而非未捕获导致 std::terminate/fastfail（GUI 侧表现为"进程崩溃"）。
                try {
                    ok=encrypt_file(in_path,out_path,password,mode,nullptr,true,compress_level,
                                    false,nullptr,wm_spec.enabled?&wm_spec:nullptr);
                } catch(const std::exception& e) {
                    fprintf(stderr,"Error: encryption failed: %s\n",e.what());
                    ok=false;
                } catch(...) {
                    fprintf(stderr,"Error: encryption failed (unexpected exception)\n");
                    ok=false;
                }
                if(ok && source_action!=0) {
                    if(!secure_handle_source(in_path, static_cast<SourceDisposition>(source_action))) {
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
                if(ok && write_sha256_enabled()) write_sha256_sidecar(out_path); // 功能10：校验单
                if(ok && split_bytes>0) {
                    std::string serr;
                    if(!finish_encrypt_split(out_path,split_bytes,
                                             write_sha256_enabled(),serr)) {
                        std::cerr<<"Error: split failed: "<<serr<<"\n";
                        ok=false;
                    }
                }
            }
            else {
                if(preview_mode) {
                    std::cerr<<"Previewing first "<<preview_max<<" bytes of: "<<in_path<<"\n";
                } else {
                    std::cout<<"Decrypting: "<<in_path<<" -> "<<out_path<<"\n";
                }
                try {
                    // 预览：传入 preview_max，并用空回调抑制进度条（避免污染 stdout 的明文前缀）
                    std::function<void(size_t,size_t)> noop_cb=[](size_t,size_t){};
                    ok=decrypt_file(src_path,out_path,password,
                        preview_mode?noop_cb:nullptr,false,true,
                        nullptr,nullptr,0,false,preview_mode?preview_max:0);
                } catch(const std::exception& e) {
                    fprintf(stderr,"Error: decryption failed: %s\n",e.what());
                    ok=false;
                } catch(...) {
                    fprintf(stderr,"Error: decryption failed (unexpected exception)\n");
                    ok=false;
                }
                // 归档容器：明文落地后识别魔数，是归档就展开成目录树并删掉中间件。
                // 放在源处置之前：展开成功才算真正拿到明文，此时 .ptd 才能删。
                if(ok && !no_extract && !preview_mode && archive_probe(out_path)) {
                    // 归档铺进 -o 指定的目录；未给 -o 时用密文所在目录（同 unzip）
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
                // 解密成功后同样按所选方式处理源文件（此处为 .ptd）：-de 删除、
                // --wipe-source 安全擦除、--recycle-source 移入回收站。
                if(ok && source_action!=0) {
                    // 输入来自分卷时，每一卷都要按所选方式处置；
                    // 归一没认出分卷时按 base 名兜底枚举，避免只删掉被挑中的那一卷
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
