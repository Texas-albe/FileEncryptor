#include "FileEncryptor.hpp"
#include "config.hpp"
#include "asym_crypto.hpp"
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
#else
#include <termios.h>
#include <unistd.h>
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
        <<"  -Y                Export public key from a private key file (-k)\n\n"
        <<"  -h, --help, -?    Show this help\n\n"
        <<"Options:\n"
        <<"  -o <dir>          Output directory (optional, default: source file's directory)\n"
        <<"  -de               Delete source file after successful encryption (encryption only)\n"
        <<"  -m <mode>         Encryption mode: xchacha20 (default) | aegis256 | rage\n"
        <<"                      rage = asymmetric hybrid encryption: a random file key\n"
  <<"                             is wrapped to X25519 recipients (rage/age format)\n"
        <<"  -y, --force       Overwrite existing output files without asking\n"
        <<"  -k <keyfile>      Read key material from file (non-interactive; alt: ENCRYPTOR_KEY env / --key-stdin)\n"
        <<"                      -m rage decrypt: this is the private key file (AGE-SECRET-KEY-...)\n"
        <<"  -r <pub|file>     Public key for -m rage encrypt: an \"age1...\" string, or a file\n"
        <<"                      holding one public key per line ('#' comments and publickey: ok)\n"
        <<"  --key-stdin       Read the password from stdin until EOF (symmetric modes only)\n"
        <<"  --salt <hex|file> Salt for -G: 32 hex chars, or a file holding them (default: random 16B)\n\n"
        <<"Config (YAML): log file/level, worker threads, path length/whitelist, progress\n"
        <<"  rotation, rate limit (max_speed), etc. are configured in fileencryptor.yaml (see README).\n\n"
        <<"Input:\n"
        <<"  For single mode: provide the file path as positional argument\n"
        <<"  For batch mode:  provide directory paths via -i (multiple allowed)\n"
        <<"                   All files under directories will be processed recursively.\n\n"
        <<"Usage:\n"
        <<"  File encryption / decryption:\n"
        <<"    FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\n"
        <<"    FileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\n"
        <<"    FileEncryptor -e/-d -m rage -r <pub>|-k <priv> <File> [-o <Path>] [-y]\n"
        <<"  Key management (rage/age):\n"
        <<"    FileEncryptor -g [-o <dir>]\n"
        <<"    FileEncryptor -G [-o <dir>] [--salt <hex|file>]\n"
        <<"    FileEncryptor -Y -k <private key file>\n";
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
static bool run_asym(const std::vector<std::string>& input_paths,
                     const std::string& output_dir,
                     bool is_encrypt,
                     bool delete_source,
                     bool force_overwrite,
                     const std::string& recipient_spec,
                     const std::string& identity_file,
                     const SecureBuffer& key_material) {
    std::vector<std::string> recipients;
    if(is_encrypt) {
        // -r takes the public key itself ("age1...") or a file of public keys.
        if(recipient_spec.empty()) {
            std::cerr<<"Asymmetric encryption requires -r <public key or public key file>.\n";
            return false;
        }
        std::string err;
        if(!collect_recipients(recipient_spec,recipients,err)) {
            std::cerr<<err<<"\n";
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
            if(out_path==in_path) {
                std::cerr<<"Error: output path would overwrite input file.\n";
                all_ok=false; continue;
            }
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

        AsymOutcome o;
        if(is_encrypt) {
            printf("Asymmetric encrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            o=fe_asym_encrypt(recipients,in_path,out_path);
        } else {
            printf("Asymmetric decrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            std::string identity(key_material.cdata(), key_material.size());
            {   // the private key file may carry a trailing newline / spaces
                size_t a=0,b=identity.size();
                while(a<b && (unsigned char)identity[a]<=0x20) ++a;
                while(b>a && (unsigned char)identity[b-1]<=0x20) --b;
                if(a!=0||b!=identity.size()) identity=identity.substr(a,b-a);
            }
            o=fe_asym_decrypt(identity,in_path,out_path);
            sodium_memzero(identity.data(),identity.size());
        }
        if(!o.ok) {
            std::cerr<<"Failed: "<<o.error<<"\n";
            all_ok=false; continue;
        }
        if(is_encrypt && delete_source) {
            if(!remove_file_utf8(in_path)) {
                std::cerr<<"Error: could not delete source file: "<<in_path<<"\n";
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
static bool run_keygen(const std::string& output_dir) {
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

    if(!write_line(priv_path,priv)) {
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

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
        std::ifstream t;
        if(!open_stream(t,p,std::ios::in)) return false;
        t.close();
        return true;
    };
    auto write_line=[](const std::string& path,const std::string& content)->bool{
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

    sodium_memzero(salt_hex,sizeof(salt_hex));
    sodium_memzero(salt.data(),salt.size());
    if(!ok) {
        sodium_memzero(priv.data(),priv.size());
        return false;
    }

    // stdout: 只有公钥本身，便于重定向
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
        ACTION_DERIVE,ACTION_PUBKEY
    } action=ACTION_NONE;

    std::vector<std::string> input_paths;
    std::string output_dir;
    CryptoMode mode=CryptoMode::XCHACHA20;
    bool delete_source=false;
    bool force_overwrite=false;
    int num_threads=0;
    std::string keyfile_path;   // 一.1：密钥文件输入（-k）
    bool asym_mode=false;       // -m age：非对称混合加密（rage/age，X25519 + ChaCha20-Poly1305）
    std::string recipient_spec; // -r <pub|file>: public key (age1...) or a file of them (encrypt)
    bool key_from_stdin=false;  // --key-stdin：从 stdin 读取密钥材料（密码或 age 身份私钥）
    std::string salt_spec;      // --salt <hex|file>：-G 派生的盐（空 = 生成随机盐）

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
            delete_source=true;
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
        return run_keygen(output_dir) ? 0 : 1;
    }

    // -G（口令派生）/ -Y（公钥导出）只需要密钥材料，不需要输入文件
    if(input_paths.empty()&&action!=ACTION_DERIVE&&action!=ACTION_PUBKEY) {
        std::cerr<<"No input paths specified.\n";
        print_usage();
        return 1;
    }

    if(!is_batch&&input_paths.size()>1) {
        std::cerr<<"Single mode accepts only one input path.\n";
        return 1;
    }

    if(delete_source&&!is_encrypt) {
        std::cerr<<"-de option is only valid for encryption.\n";
        return 1;
    }

    // 单文件加密 AEGIS-256 可用性回退：缺 AES-NI 时自动切换到 XChaCha20
    if(is_encrypt&&!is_batch&&mode==CryptoMode::AEGIS256&&!aegis256_supported()) {
        std::cout<<"Warning: AEGIS-256 is not available on this CPU (AES-NI required).\n"
            <<"Do you want to switch to XChaCha20 (secure)? (y/N): ";
        char ch='n';
        std::cin>>ch;
        if(ch=='y'||ch=='Y') {
            mode=CryptoMode::XCHACHA20;
            fprintf(stderr,"Switched to XChaCha20 mode.\n");
        }
        else {
            fprintf(stderr,"Continuing with AEGIS-256 (may fail on this CPU).\n");
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

    // 口令派生 / 公钥导出：只消费密钥材料，不读写任何输入文件，
    // 因此必须在下面的“对称密码交互输入”之前拦截。
    if(action==ACTION_DERIVE||action==ACTION_PUBKEY) {
        if(!used_key_source) {
            std::cout<<(action==ACTION_DERIVE
                ? "Enter derivation password (min 6 characters): "
                : "Enter private key (AGE-SECRET-KEY-...): ");
            std::vector<char> p=get_password();
            if(p.empty()) { std::cerr<<"No key material provided.\n"; return 1; }
            password=SecureBuffer(p.data(),p.size());
            sodium_memzero(p.data(),p.size()); p.clear();
        }
        if(action==ACTION_DERIVE) {
            if(password.size()<6) {
                std::cerr<<"Derivation password too short (min 6 characters).\n";
                return 1;
            }
            return run_derive(output_dir,password,salt_spec,force_overwrite)?0:1;
        }
        return run_pubkey(password)?0:1;
    }

    if(is_encrypt && !asym_mode) {
        if(used_key_source) {
            // 非交互密钥源：不二次确认、不做强度提示
            if(password.size()<6) {
                std::cerr<<"Key too short (min 6 characters)\n";
                return 1;
            }
        }
        else {
            std::cout<<"Enter password (min 6 characters, strong recommended): ";
            std::vector<char> pw1=get_password();
            if(pw1.size()<6) {
                std::cerr<<"Password too short.\n";
                sodium_memzero(pw1.data(),pw1.size()); pw1.clear();
                return 1;
            }

            bool has_upper=false,has_lower=false,has_digit=false,has_special=false;
            bool has_non_ascii=false;
            for(char c : pw1) {
                unsigned char u=(unsigned char)c;
                if(u <= 127) {
                    // 仅对 ASCII 字符做字符类检测；非 ASCII（如 UTF-8 中文）字节在 C locale
                    // 下 is* 行为未定义/不可靠，且多字节字符本身熵很高，不应误判为弱口令。
                    if(isupper(u)) has_upper=true;
                    else if(islower(u)) has_lower=true;
                    else if(isdigit(u)) has_digit=true;
                    else if(ispunct(u)) has_special=true;
                } else {
                    has_non_ascii=true;
                }
            }
            // 非 ASCII 口令（如纯中文长口令）熵足够，跳过字符类提醒，避免误判为弱密码；
            // 仅对“纯 ASCII 且缺少某字符类”的口令给出弱密码建议。
            if(!has_non_ascii && !(has_upper&&has_lower&&has_digit&&has_special)) {
                std::cerr<<"Warning: Password lacks some character classes (upper/lower/digit/symbol).\n"
                    <<"Consider using a stronger password.\n";
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

    if(asym_mode) {
        all_ok=run_asym(input_paths,output_dir,is_encrypt,delete_source,force_overwrite,recipient_spec,keyfile_path,password);
    }
    else if(is_batch) {
        all_ok=process_files(input_paths,output_dir,password,mode,is_encrypt,delete_source,force_overwrite,num_threads);
    }
    else {
        // 单文件处理放入 lambda：用 early-return 替代 goto cleanup_password，
        // 避免跨过带非平凡析构的 std::ifstream 声明（严格 C++ 下 ill-formed，MSVC -W4 报 C4533）。
        all_ok = [&]() -> bool {
            const std::string& in_path=input_paths[0];
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

            if(action==ACTION_DECRYPT) {
                std::string lower=in_path;
                // 仅对 ASCII 字节转小写（UTF-8 多字节字节值为负，直接传 ::tolower 是 UB）
                std::transform(lower.begin(),lower.end(),lower.begin(),
                    [](unsigned char c){ return (char)std::tolower(c); });
                if(lower.size()<4||lower.substr(lower.size()-4)!=".ptd") {
                    std::cerr<<"Error: Decryption input must have .ptd extension.\n";
                    return false;
                }
                // 先剥离 .ptd 得到明文输出路径
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

            // 续传无缝衔接：若检测到续传元数据（加密看 .progress；解密需 .progress + .part），
            // 跳过覆盖确认，直接交给 encrypt/decrypt_file 续传，避免大文件中断后重跑被“覆盖？”打断。
            bool has_resume_meta=false;
            {
                std::ifstream pf;
                if(open_stream(pf,out_path+".progress",std::ios::in|std::ios::binary)&&pf.good()) {
                    pf.close();
                    if(is_encrypt) has_resume_meta=true;
                    else {
                        std::ifstream part;
                        if(open_stream(part,out_path+".part",std::ios::in|std::ios::binary)&&part.good()) {
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
                ok=encrypt_file(in_path,out_path,password,mode,nullptr,true);
                if(ok&&delete_source) {
                    if(!remove_file_utf8(in_path)) {
                        std::cerr<<"Error: could not delete source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
            }
            else {
                printf("Decrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
                ok=decrypt_file(in_path,out_path,password,nullptr,false,true);
            }
            return ok;
        }();
    }

    return all_ok ? 0 : 1;
}