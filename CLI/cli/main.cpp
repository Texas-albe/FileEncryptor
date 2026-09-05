#include "FileEncryptor.hpp"
#include "config.hpp"
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
        <<"Modes:\n"
        <<"  -e                Encrypt single file\n"
        <<"  -d                Decrypt single file\n"
        <<"  -be               Batch encrypt directories/files\n"
        <<"  -bd               Batch decrypt directories/files\n"
        <<"  -h, --help, -?    Show this help\n\n"
        <<"Options:\n"
        <<"  -o <dir>          Output directory (optional, default: source file's directory)\n"
        <<"  -de               Delete source file after successful encryption (encryption only)\n"
        <<"  -m <mode>         Encryption mode: xchacha20 (default) or aegis256\n"
        <<"  -y, --force       Overwrite existing output files without asking\n"
        <<"  -k <keyfile>      Read key material from file (non-interactive; alt: ENCRYPTOR_KEY env)\n\n"
        <<"Config (YAML): log file/level, worker threads, path length/whitelist, progress\n"
        <<"  rotation, rate limit (max_speed), etc. are configured in fileencryptor.yaml (see README).\n\n"
        <<"Input:\n"
        <<"  For single mode: provide the file path as positional argument\n"
        <<"  For batch mode:  provide directory paths via -i (multiple allowed)\n"
        <<"                   All files under directories will be processed recursively.\n\n"
        <<"Usage:\n"
        <<"  FileEncryptor -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\n"
        <<"  FileEncryptor -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y]\n";
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
        ACTION_BATCH_ENCRYPT,ACTION_BATCH_DECRYPT
    } action=ACTION_NONE;

    std::vector<std::string> input_paths;
    std::string output_dir;
    CryptoMode mode=CryptoMode::XCHACHA20;
    bool delete_source=false;
    bool force_overwrite=false;
    int num_threads=0;
    std::string keyfile_path;   // 一.1：密钥文件输入（-k）

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

    if(input_paths.empty()) {
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
    else {
        const char* ek=std::getenv("ENCRYPTOR_KEY");
        if(ek&&*ek) {
            password = SecureBuffer(ek, std::strlen(ek));
            used_key_source=true;
            log_event(LOG_INFO,"key_source",{{"type","env"}});
        }
    }

    if(is_encrypt) {
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
    else {
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

    if(is_batch) {
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