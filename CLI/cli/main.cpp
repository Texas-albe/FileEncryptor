#include "FileEncryptor.hpp"
#include "config.hpp"
#include "asym_crypto.hpp"
#include "keylib.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <sodium.h>
#include <stdexcept>

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
// 交互控制台：逐键读取密码并回显 '*'，退格按 UTF-8 码点删除，而非按字节
// 当 stdin 被重定向（管道 / 文件 / winpty PTY）时，_getch() 会读控制台输入
// 缓冲区而挂起，故先检测 stdin 是否为控制台：不是则退化为从 std::cin 读一行
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

// 口令强策略（功能7：与 GUI PasswordStrength::meetsPolicy 共用同一套规则，避免两端不一致）：
//   最小长度来自 YAML min_password_length（默认 8）；至少包含 min_password_classes 类字符
//   （小写/大写/数字/符号），或长度 >= 16。非 ASCII（多字节）口令熵足够，直接放行。
static bool password_meets_policy(const std::string& pw, std::string& reason) {
    const Config& cfg = global_config();
    const size_t min_len = (cfg.min_password_length > 0)
        ? (size_t)cfg.min_password_length : 8;
    const int min_classes = (cfg.min_password_classes > 0) ? cfg.min_password_classes : 2;
    if (pw.size() < min_len) {
        reason = "Password too short (min " + std::to_string(min_len) + " characters).";
        return false;
    }
    bool lower = false, upper = false, digit = false, symbol = false, non_ascii = false;
    for (unsigned char c : pw) {
        if (c <= 0x7F) {
            if (islower(c))       lower = true;
            else if (isupper(c))  upper = true;
            else if (isdigit(c))  digit = true;
            else if (ispunct(c))  symbol = true;
        } else {
            non_ascii = true;     // 多字节字符（如 UTF-8 中文）熵足够
        }
    }
    if (non_ascii) return true;
    const int kinds = (lower ? 1 : 0) + (upper ? 1 : 0) +
                      (digit ? 1 : 0) + (symbol ? 1 : 0);
    if (kinds >= min_classes || pw.size() >= 16) return true;
    reason = "Password too weak: use at least " + std::to_string(min_classes) +
             " character classes (lower/upper/digit/symbol) or length >= 16.";
    return false;
}

static void print_usage() {
    std::cout<<"FileEncryptor v"<<FE_VERSION_STRING<<"\n\n"
        <<"Modes (file encryption / decryption):\n"
        <<"  -e                Encrypt single file\n"
        <<"  -d                Decrypt single file\n"
        <<"  -be               Batch encrypt directories/files\n"
        <<"  -bd               Batch decrypt directories/files\n\n"
        <<"Key management (rage/age):\n"
        <<"  -g                Generate an X25519 keypair (public key -> stdout)\n"
        <<"  -G                Derive an X25519 keypair from a password (Argon2id)\n"
        <<"  -Y                Export public key from a private key file (-k)\n"
        <<"  -L, --keylib      Manage the local key library (list|add|remove|show|pub|export)\n"
        <<"  -H, --info        Show file header metadata of a .ptd (read-only, no decryption)\n"
        <<"  -V, --verify      Verify integrity of .ptd file(s) without writing plaintext\n"
        <<"  -R, --recover-name Recover the original filename from a .ptd (offline; add --rename to rename)\n\n"
        <<"  -h, --help, -?    Show this help\n\n"
        <<"Options:\n"
        <<"  -o <dir>          Output directory (optional, default: source file's directory)\n"
        <<"  -de               Delete source after success: plaintext (encrypt) / .ptd (decrypt)\n"
        <<"  --wipe-source     Securely wipe (multi-pass overwrite) source after success\n"
        <<"  --recycle-source  Move source to system Recycle Bin after success\n"
        <<"  --rewrap <file>   Rotate key of a v6 container (payload untouched; old password via -k/env/interactive)\n"
        <<"  --new-key-file F  New password key file for --rewrap\n"
        <<"  --new-key-stdin   New password for --rewrap read from stdin\n"
        <<"  -m <mode>         Encryption mode: xchacha20 (default) | aegis256 | rage\n"
        <<"                      rage = asymmetric hybrid encryption: a random file key\n"
  <<"                             is wrapped to X25519 recipients (rage/age format)\n"
        <<"  -y, --force       Overwrite existing output files without asking\n"
        <<"  -k <keyfile>      Read key material from file (non-interactive; alt: ENCRYPTOR_KEY env / --key-stdin)\n"
        <<"                      -m rage decrypt: this is the private key file (AGE-SECRET-KEY-...)\n"
        <<"  -K <name>[,...]   Resolve keys from the local key library (功能1):\n"
        <<"                      -m rage encrypt: recipient/identity names, comma-separated\n"
        <<"                      -m rage decrypt: one identity name (same as -k <library key>)\n"
        <<"  -r <pub|file>     Public key for -m rage encrypt: an \"age1...\" string, or a file\n"
        <<"                      holding one public key per line ('#' comments and publickey: ok)\n"
        <<"  --key-stdin       Read the password from stdin until EOF (symmetric modes only)\n"
        <<"  --salt <hex|file> Salt for -G: 32 hex chars, or a file holding them (default: random 16B)\n"
        <<"  --restore-name, -rn  Batch decrypt: restore full original filenames (slow: one KDF per file)\n"
        <<"  --obfuscate-name, -on  -m rage only: hide the output filename (original name unrecoverable)\n"
        <<"  --sha256          Write a <out>.ptd.sha256 sidecar after successful encryption\n"
        <<"  --rename          With -R: rename the .ptd in place to its original name (content unchanged)\n"
        <<"  --as <name>       With -L add: library name for the imported key\n"
        <<"  --alias <text>    With -L add: display alias for the key\n"
        <<"  --notes <text>    With -L add: single-line note stored in the index\n\n"
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
        <<"    FileEncryptor -e/-d -m rage -r <pub>|-k <priv> <File> [-o <Path>] [-y]\n"
        <<"  Key management (rage/age):\n"
        <<"    FileEncryptor -g [-o <dir>]\n"
        <<"    FileEncryptor -G [-o <dir>] [--salt <hex|file>]\n"
        <<"    FileEncryptor -Y -k <private key file>\n"
        <<"  Key library:\n"
        <<"    FileEncryptor -L list\n"
        <<"    FileEncryptor -L add <keyfile> --as <name> [--alias <text>] [--notes <text>]\n"
        <<"    FileEncryptor -L remove <name>\n"
        <<"    FileEncryptor -L show <name>\n"
        <<"    FileEncryptor -L pub <name|keyfile>    (derive and cache the recipient key)\n"
        <<"    FileEncryptor -L export <name> [dest_dir]\n"
        <<"    FileEncryptor -e -m rage -K <name>[,<name>...] <File>\n"
        <<"    FileEncryptor -d -m rage -K <identity name> <File.age>\n";
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

// Resolve -r into a list of recipient public keys.
// The value is either a literal public key ("age1...", optionally prefixed with
// "publickey:") or a path to a file holding one public key per line ('#' comments
// and a "publickey:" prefix are tolerated).
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
        std::transform(low.begin(),low.end(),low.begin(),
            [](unsigned char c){ return (char)std::tolower(c); });
        return low.rfind("age1",0)==0;
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
        if(!is_pubkey(v)) { err="Invalid public key line (expected age1...): "+v; return false; }
        out.push_back(v);
    }
    rf.close();
    if(out.empty()) { err="No public keys found in: "+t; return false; }
    return true;
}

// Asymmetric (hybrid) dispatch built on rage/age (X25519 + ChaCha20-Poly1305).
//   encrypt : wrap the file key to the public key given by -r (an "age1..." string,
//             or a file holding public keys) -> <name>.age
//   decrypt : unwrap with the private key file given by -k ("AGE-SECRET-KEY-...")
//
// v2.1.2 加固（对应安全审计 1 / 5 / 6）：
//   - 此前本函数完全绕过 validate_io_paths()，即绕过路径白名单与 max_path_length；
//   - 输出无符号链接守卫、无 .prt 原子落盘（对称路径三处守卫 + 原子替换全无）；
//   - 输出文件名恒为明文（对称模式默认混淆）。现加 --obfuscate-name 显式开启，
//     未开启时打印元数据泄露提示。
static bool run_asym(const std::vector<std::string>& input_paths,
                     const std::string& output_dir,
                     bool is_encrypt,
                     int source_action,
                     bool force_overwrite,
                     const std::string& recipient_spec,
                     const std::string& identity_file,
                     const SecureBuffer& key_material,
                     bool obfuscate_name=false,
                     const std::vector<std::string>& extra_recipients = {}) {
    std::vector<std::string> recipients;
    if(is_encrypt) {
        // -r takes the public key itself ("age1...") or a file of public keys;
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
        std::string out_path;
        if(is_encrypt) {
            std::string base=in_path;
            size_t pos=base.find_last_of("/\\");
            std::string fname=(pos!=std::string::npos)?base.substr(pos+1):base;
            // v2.1.2：rage 模式没有"加密文件名信封"（对称模式的文件名存在密文尾部，
            // 可无损还原），一旦混淆就**永久丢失**文件名。因此不跟随 obfuscate_names
            // 默认值直接启用，必须由 --obfuscate-name 显式开启。
            if(obfuscate_name) {
                fname=make_obfuscated_basename(in_path,key_material);
            } else {
                std::cerr<<"Note: -m rage output keeps the original filename in cleartext "
                    "(no encrypted name envelope). Use --obfuscate-name to hide it "
                    "(the original name is then unrecoverable).\n";
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
            out_path+=".age";
        } else {
            std::string lower=in_path;
            std::transform(lower.begin(),lower.end(),lower.begin(),
                [](unsigned char c){ return (char)std::tolower(c); });
            if(lower.size()<4||lower.substr(lower.size()-4)!=".age") {
                std::cerr<<"Asymmetric decryption input must have .age extension: "<<in_path<<"\n";
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

        // v2.1.2：路径策略校验 + 符号链接守卫（此前 rage 分支完全没有，可整体绕过白名单）
        //  1) 输入路径的 ".." 穿越（此前仅 -o 在参数解析处查过，in_path 从未查）
        if(path_has_traversal(in_path)) {
            std::cerr<<"Path contains directory traversal (..): "<<in_path<<"\n";
            all_ok=false; continue;
        }
        //  2) 白名单 / max_path_length（与对称路径同一套 validate_io_paths）
        if(!validate_io_paths(in_path,out_path,false)) {
            std::cerr<<"Path validation failed (config policy)\n";
            all_ok=false; continue;
        }
        //  3) 拒绝写入既有的符号链接 / 重解析点（否则明文会被重定向到攻击者指定路径）
        if(path_is_symlink(out_path)) {
            std::cerr<<"Refusing to write through existing symlink: "<<out_path<<"\n";
            all_ok=false; continue;
        }

        // 覆盖确认（与对称路径一致；GUI 带 -y 跳过）
        if(!force_overwrite) {
            std::ifstream test;
            if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                test.close();
                std::cout<<"Output file exists: "<<out_path<<"\nOverwrite? (y/N): ";
                char ch='n'; std::cin>>ch;
                if(ch!='y'&&ch!='Y') { std::cerr<<"Aborted.\n"; all_ok=false; continue; }
            }
        }

        // v2.1.2：先写 .prt 再原子替换——避免中断时留下半截（明文）输出被误认为成品。
        const std::string part_path=out_path+".prt";
        remove_file_utf8(part_path);   // 清掉上次残留

        AsymOutcome o;
        if(is_encrypt) {
            printf("Asymmetric encrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            o=fe_asym_encrypt(recipients,in_path,part_path);
        } else {
            printf("Asymmetric decrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            std::string identity(key_material.cdata(), key_material.size());
            {   // the private key file may carry a trailing newline / spaces
                // 就地 erase（而非 substr）：substr 会另开缓冲，原缓冲里的完整私钥
                // 无法再被擦除，旧版本正是因此留下内存残片（审计问题 9）。
                size_t a=0,b=identity.size();
                while(a<b && (unsigned char)identity[a]<=0x20) ++a;
                while(b>a && (unsigned char)identity[b-1]<=0x20) --b;
                if(b<identity.size()) identity.erase(b);
                if(a>0)               identity.erase(0,a);
            }
            o=fe_asym_decrypt(identity,in_path,part_path);
            sodium_memzero(identity.data(),identity.size());
        }
        if(!o.ok) {
            std::cerr<<"Failed: "<<o.error<<"\n";
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
    }
    return all_ok;
}

// Generate an X25519 keypair (rage/age).
//   stdout                     -> recipient public key "age1..." only (safe to pipe/redirect)
//   <output_dir>/rage_private.txt -> identity "AGE-SECRET-KEY-..." (keep secret)
// Everything informational goes to stderr so stdout stays a clean public key.
static bool run_keygen(const std::string& output_dir,bool force_overwrite) {
    std::string pub, priv;
    AsymOutcome o=fe_generate_keypair(pub,priv);
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

    // v2.1.2：补上与 run_derive 一致的覆盖保护——私钥一旦被静默覆盖，用它加密的
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

    // stdout: the public key alone, so it can be piped straight into -r or a file
    std::cout<<pub<<"\n";
    std::cout.flush();
    // stderr: everything else, so redirecting stdout still yields a clean key
    std::cerr<<"Private key file: "<<priv_path<<"\n";
    std::cerr<<"Public key (age1...) printed above - share it freely; the private key decrypts.\n";

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

// 由口令确定性派生 X25519 密钥对（-G）。
//   stdout                     -> 公钥 "age1..."（可直接重定向 / 管道）
//   <dir>/rage_private.txt     -> 私钥 "AGE-SECRET-KEY-..."
//   <dir>/rage_derive_salt.txt -> 16 字节随机盐（hex）；复现同一密钥对必需
// 同口令 + 同盐 ⇒ 完全相同的密钥对，因此不保存私钥也能靠口令找回。
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

// 由身份私钥导出收件人公钥（-Y），等价于 rage-keygen -y。
static bool run_pubkey(const SecureBuffer& identity) {
    std::string id(identity.cdata(),identity.size());
    {   // 私钥文件可能带尾随换行 / 空格
        size_t a=0,b=id.size();
        while(a<b&&(unsigned char)id[a]<=0x20) ++a;
        while(b>a&&(unsigned char)id[b-1]<=0x20) --b;
        if(a!=0||b!=id.size()) id=id.substr(a,b-a);
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
    std::cerr<<"Public key (age1...) printed above; it corresponds to the given private key.\n";
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
    std::cout<<"  (metadata only; key correctness is NOT verified)\n";
    return true;
}

// 功能3：完整性校验（只验不解）。对单文件解密到临时文件比对明文哈希，不落盘明文。
static bool run_verify(const std::string& path, const SecureBuffer& pw) {
    if(verify_ptd(path, pw)) {
        std::cout<<"OK    "<<path<<"\n";
        return true;
    }
    std::cout<<"FAILED "<<path<<"\n";
    return false;
}

// 功能15：离线还原混淆文件名（不改内容）。用口令恢复 .ptd 尾部信封中的原始文件名并打印；
// 带 --rename 时把 .ptd 自身重命名为 <原始名>.ptd（内容不变）。
static bool run_recover(const std::string& path, const SecureBuffer& pw, bool do_rename) {
    std::string orig;
    if(!read_original_name(path, orig, pw)) {
        std::cerr<<"Cannot recover original name (wrong key or no name envelope): "<<path<<"\n";
        return false;
    }
    std::cout<<"Original name: "<<orig<<"\n";
    if(do_rename) {
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
            std::string buf((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
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

int main(int argc,char* argv[]) {
#ifdef _WIN32
    // 让控制台以 UTF-8 输出，确保中文提示正确显示
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    // 改用 UTF-8 参数向量（覆盖默认 ANSI 代码页的 argv）
    std::vector<std::string> argv_utf8=get_utf8_argv();
    std::vector<char*> argv_ptr;
    argv_ptr.reserve(argv_utf8.size()+1);
    for(auto& s:argv_utf8) argv_ptr.push_back(const_cast<char*>(s.c_str()));
    argv_ptr.push_back(nullptr);
    argc=(int)argv_utf8.size();
    argv=argv_ptr.data();
#endif

    anti_debug_check();

    if(sodium_init()<0) {
        std::cerr<<"libsodium initialization failed.\n";
        return 1;
    }

    // 加载 YAML 配置（日志/并发/路径策略等运维参数统一走配置文件，CLI 不可覆盖）
    Config cfg=load_config();
    set_global_config(cfg);
    init_logger(cfg.log_file,cfg.log_level);
    init_rate_limiter(cfg.max_speed); // 进程级限速（YAML max_speed；0 = 不限速）

    if(argc==1) {
        print_usage();
        return 0;
    }

    for(int i=1; i<argc; ++i) {
        std::string arg=argv[i];
        if(arg=="-h"||arg=="-?"||arg=="--help") {
            print_usage();
            return 0;
        }
    }

    enum {
        ACTION_NONE,ACTION_ENCRYPT,ACTION_DECRYPT,
        ACTION_BATCH_ENCRYPT,ACTION_BATCH_DECRYPT,ACTION_KEYGEN,
        ACTION_DERIVE,ACTION_PUBKEY,ACTION_INFO,ACTION_VERIFY,ACTION_RECOVER,
        ACTION_KEYLIB,ACTION_REWRAP
    } action=ACTION_NONE;

    std::vector<std::string> input_paths;
    std::string output_dir;
    CryptoMode mode=CryptoMode::XCHACHA20;
    int source_action=0;          // 0=保留 1=删除(-de) 2=安全擦除(--wipe-source) 3=回收站(--recycle-source)
    bool force_overwrite=false;
    int num_threads=0;
    bool restore_name=false;     // 批量解密是否还原完整原始文件名（默认 false：仅保留扩展名，省去每文件 KDF）
    bool obfuscate_name=false;   // -m rage：是否混淆输出文件名（原始名不可恢复，故需显式开启）
    std::string keyfile_path;   // 一.1：密钥文件输入（-k）
    bool asym_mode=false;       // -m age：非对称混合加密（rage/age，X25519 + ChaCha20-Poly1305）
    std::string recipient_spec; // -r <pub|file>: public key (age1...) or a file of them (encrypt)
    bool key_from_stdin=false;  // --key-stdin：从 stdin 读取密钥材料（密码或 age 身份私钥）
    std::string salt_spec;      // --salt <hex|file>：-G 派生的盐（空 = 生成随机盐）
    bool force_sha256=false;    // --sha256：本次加密生成 <out>.ptd.sha256 校验单（功能10）
    bool recover_rename=false;  // --rename：配合 -R 原地重命名 .ptd（内容不变）
    std::string keylib_refs;    // -K <name>[,...]：密钥库引用（rage 加密=收件人；解密=身份）
    std::string keylib_as;      // --as <name>：-L add 的库内名称
    std::string keylib_alias;   // --alias <text>：-L add 的展示别名
    std::string keylib_notes;   // --notes <text>：-L add 的备注
    int compress_level=0;       // -z/--compress 或 --compression-level N：zstd 级别；0=不压缩
    std::string new_keyfile_path; // --new-key-file <file>：rewrap 的新口令密钥文件
    bool new_key_from_stdin=false;// --new-key-stdin：rewrap 的新口令从 stdin 读取

    for(int i=1; i<argc; ++i) {
        std::string arg=argv[i];
        if(arg=="-e") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_ENCRYPT;
        }
        else if(arg=="-d") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_DECRYPT;
        }
        else if(arg=="-be") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_BATCH_ENCRYPT;
        }
        else if(arg=="-bd") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_BATCH_DECRYPT;
        }
        else if(arg=="-g") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_KEYGEN;
        }
        else if(arg=="-G") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_DERIVE;
        }
        else if(arg=="-Y") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_PUBKEY;
        }
        else if(arg=="-H"||arg=="--info") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_INFO;
        }
        else if(arg=="-V"||arg=="--verify") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_VERIFY;
        }
        else if(arg=="-R"||arg=="--recover-name") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_RECOVER;
        }
        else if(arg=="-L"||arg=="--keylib") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_KEYLIB;
        }
        else if(arg=="--rewrap") {
            if(action!=ACTION_NONE) { std::cerr<<"Multiple modes specified.\n"; return 1; }
            action=ACTION_REWRAP;
        }
        else if(arg=="--new-key-file"&&i+1<argc) {
            new_keyfile_path=argv[++i];
        }
        else if(arg=="--new-key-stdin") {
            new_key_from_stdin=true;
        }
        else if(arg=="--as"&&i+1<argc) {
            keylib_as=argv[++i];
        }
        else if(arg=="--alias"&&i+1<argc) {
            keylib_alias=argv[++i];
        }
        else if(arg=="--notes"&&i+1<argc) {
            keylib_notes=argv[++i];
        }
        else if(arg=="-K"&&i+1<argc) {
            keylib_refs=argv[++i];
        }
        else if(arg=="--salt"&&i+1<argc) {
            salt_spec=argv[++i];
        }
        else if(arg=="-o"&&i+1<argc) {
            output_dir=argv[++i];
            if(path_has_traversal(output_dir)) {
                std::cerr<<"Output directory contains directory traversal (..): "<<output_dir<<"\n";
                return 1;
            }
        }
        else if(arg=="-de") {
            if(source_action!=0 && source_action!=1) {
                std::cerr<<"Conflicting source handling options (-de / --wipe-source / --recycle-source).\n";
                return 1;
            }
            source_action=1;
        }
        else if(arg=="--wipe-source") {
            if(source_action!=0 && source_action!=2) {
                std::cerr<<"Conflicting source handling options (-de / --wipe-source / --recycle-source).\n";
                return 1;
            }
            source_action=2;
        }
        else if(arg=="--recycle-source") {
            if(source_action!=0 && source_action!=3) {
                std::cerr<<"Conflicting source handling options (-de / --wipe-source / --recycle-source).\n";
                return 1;
            }
            source_action=3;
        }
        else if(arg=="-m"&&i+1<argc) {
            std::string m=argv[++i];
            if(m=="xchacha20") mode=CryptoMode::XCHACHA20;
            else if(m=="aegis256") mode=CryptoMode::AEGIS256;
            else if(m=="rage"||m=="age") asym_mode=true;   // "rage" canonical; "age" kept as alias
            else { std::cerr<<"Unknown mode: "<<m<<"\n"; return 1; }
        }
        else if(arg=="-i"&&i+1<argc) {
            input_paths.push_back(argv[++i]);
        }
        else if(arg=="-y"||arg=="--force") {
            force_overwrite=true;
        }
        else if(arg=="-v"||arg=="--verbose") {
            set_verbose(true);
        }
        else if(arg=="-k"&&i+1<argc) {
            keyfile_path=argv[++i];
        }
        else if(arg=="-r"&&i+1<argc) {
            recipient_spec=argv[++i];
        }
        else if(arg=="--key-stdin") {
            key_from_stdin=true;
        }
        else if(arg=="--restore-name"||arg=="-rn") {
            restore_name=true;
        }
        else if(arg=="--obfuscate-name"||arg=="-on") {
            obfuscate_name=true;   // 仅 -m rage：混淆输出文件名（原始名不可恢复）
        }
        else if(arg=="--sha256") {
            force_sha256=true;     // 功能10：本次加密生成校验单
        }
        else if(arg=="--rename") {
            recover_rename=true;   // 配合 -R：原地重命名 .ptd 为原始名（内容不变）
        }
        // -zstd 是布尔开关（不带参数值）；-z / --compress 为其等价别名。
        // 级别只能由 --compression-level <N> 单独指定，未指定时用 zstd 默认级别 1。
        else if(arg=="-zstd"||arg=="-z"||arg=="--compress") {
            if(compress_level==0) compress_level=1;
        }
        else if((arg=="--compression-level"||arg=="-cl")&&i+1<argc) {
            compress_level=std::atoi(argv[++i]);
            if(compress_level==0) {
                std::cerr<<"--compression-level requires a non-zero integer: "
                    "zstd level 1..22 (normal) or -1..-5 (fast).\n";
                return 1;
            }
        }
        else if(arg=="--features") {
            // 供 GUI 探测能力（如 zstd / aegis 是否可用）；每行 key=value
#ifdef FE_WITH_ZSTD
            std::cout<<"zstd=1\n";
#else
            std::cout<<"zstd=0\n";
#endif
            std::cout<<"aegis="<<(aegis256_supported()?1:0)<<"\n";
            return 0;
        }
        else if(arg[0]!='-') {
            input_paths.push_back(arg);
        }
        else {
            std::cerr<<"Unknown option: "<<arg<<"\n";
            print_usage();
            return 1;
        }
    }

    bool is_batch=(action==ACTION_BATCH_ENCRYPT||action==ACTION_BATCH_DECRYPT);
    bool is_encrypt=(action==ACTION_ENCRYPT||action==ACTION_BATCH_ENCRYPT);

    if(action==ACTION_NONE) {
        print_usage();
        return 0;
    }

    // Key generation needs no input file: -g [-o <dir>]
    if(action==ACTION_KEYGEN) {
        return run_keygen(output_dir,force_overwrite) ? 0 : 1;
    }

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

    // -G（口令派生）/ -Y（公钥导出）/ -V（校验）/ -R（还原名）/ -H（查看头）只需密钥材料或输入文件
    if(input_paths.empty()&&action!=ACTION_DERIVE&&action!=ACTION_PUBKEY
       &&action!=ACTION_VERIFY&&action!=ACTION_RECOVER&&action!=ACTION_INFO) {
        std::cerr<<"No input paths specified.\n";
        print_usage();
        return 1;
    }

    if(!is_batch&&input_paths.size()>1) {
        std::cerr<<"Single mode accepts only one input path.\n";
        return 1;
    }

    // 源文件处置对加密（删明文）与解密（删 .ptd）均有效；仅 rage 非对称分支不适用。
    if(source_action!=0&&asym_mode) {
        std::cerr<<"Source handling options (-de / --wipe-source / --recycle-source) "
                   "are not supported for -m rage (asymmetric).\n";
        return 1;
    }

    // 压缩选项校验：仅对称加密可用；未集成 zstd 时拒绝；级别需在 zstd 支持范围内
    if(compress_level!=0) {
#ifndef FE_WITH_ZSTD
        std::cerr<<"Compression requested but this build was compiled without zstd support.\n";
        return 1;
#endif
        if(asym_mode) {
            std::cerr<<"Compression (-z/--compression-level) is only available for symmetric modes, not -m rage/age.\n";
            return 1;
        }
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
            std::cerr<<"-K applies only to -m rage mode.\n";
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

    // AEGIS-256 可用性：缺 AES-NI 时，交互终端询问是否降级（默认降级）；
    // 非交互（GUI 管道 / --key-stdin / cron）明确拒绝并以非零码退出，绝不自动降级。
    // 同时覆盖单文件与批量两种入口，process_files 内部仅作防御性兜底。
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

    // ---------- 密码输入（RAII SecureBuffer 持有，析构自动清零 + 解锁） ----------
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
        std::vector<char> kbuf((std::istreambuf_iterator<char>(kf)),
                               std::istreambuf_iterator<char>());
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
        // Secure channel: read entire stdin (binary-safe, until EOF) as key material.
        // Symmetric mode -> password; asymmetric decrypt -> age identity. GUI pipes via this
        // channel to avoid leaking through env vars / command line.
        std::vector<char> sbuf((std::istreambuf_iterator<char>(std::cin)),
                               std::istreambuf_iterator<char>());
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
                if(!password_meets_policy(std::string(password.cdata(),password.size()),preason)) {
                    std::cerr<<preason<<"\n";
                    return 1;
                }
            }
            return run_derive(output_dir,password,salt_spec,force_overwrite)?0:1;
        }
        if(action==ACTION_PUBKEY) return run_pubkey(password)?0:1;
        if(action==ACTION_VERIFY) {
            bool all=true;
            for(const auto& p: input_paths) if(!run_verify(p,password)) all=false;
            return all?0:1;
        }
        // ACTION_RECOVER：--rename 启用原地重命名（内容不变）
        {
            bool all=true;
            for(const auto& p: input_paths) if(!run_recover(p,password,recover_rename)) all=false;
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
                if(!password_meets_policy(std::string(pw1.data(),pw1.size()),preason)) {
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

    if(asym_mode) {
        all_ok=run_asym(input_paths,output_dir,is_encrypt,source_action,force_overwrite,recipient_spec,keyfile_path,password,obfuscate_name,lib_recipients);
    }
    else if(is_batch) {
        all_ok=process_files(input_paths,output_dir,password,mode,is_encrypt,source_action,force_overwrite,num_threads,restore_name,compress_level);
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
            std::string out_path;
            if(!output_dir.empty()) {
                if(!create_directory_recursive(output_dir)) {
                    std::cerr<<"Cannot create output directory: "<<output_dir<<"\n";
                    return false;
                }
                std::string base=in_path;
                size_t pos=base.find_last_of("/\\");
                std::string fname=(pos!=std::string::npos) ? base.substr(pos+1) : base;
                out_path=output_dir;
                if(!out_path.empty()&&out_path.back()!='/'&&out_path.back()!='\\')
                    out_path+='/';
                out_path+=fname;
            }
            else {
                out_path=in_path;
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
                    if(read_original_name(in_path,orig_name,password)&&!orig_name.empty()) {
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
            if(!force_overwrite && !has_resume_meta) {
                std::ifstream test;
                if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                    test.close();
                    std::cout<<"Output file exists: "<<out_path<<"\nOverwrite? (y/N): ";
                    char ch='n';
                    std::cin>>ch;
                    if(ch!='y'&&ch!='Y') {
                        std::cerr<<"Aborted.\n";
                        return false;
                    }
                }
            }

            bool ok;
            if(is_encrypt) {
                printf("Encrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
                // 防御性兜底：任何未预期异常（如编码转换失败）都以干净错误退出，
                // 而非未捕获导致 std::terminate/fastfail（GUI 侧表现为"进程崩溃"）。
                try {
                    ok=encrypt_file(in_path,out_path,password,mode,nullptr,true,compress_level);
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
            }
            else {
                printf("Decrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
                try {
                    ok=decrypt_file(in_path,out_path,password,nullptr,false,true);
                } catch(const std::exception& e) {
                    fprintf(stderr,"Error: decryption failed: %s\n",e.what());
                    ok=false;
                } catch(...) {
                    fprintf(stderr,"Error: decryption failed (unexpected exception)\n");
                    ok=false;
                }
                // 解密成功后同样按所选方式处理源文件（此处为 .ptd）：-de 删除、
                // --wipe-source 安全擦除、--recycle-source 移入回收站。
                if(ok && source_action!=0) {
                    if(!secure_handle_source(in_path, static_cast<SourceDisposition>(source_action))) {
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
            }
            return ok;
        }();
    }

    return all_ok ? 0 : 1;
}