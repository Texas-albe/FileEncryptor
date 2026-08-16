#include "FileEncryptor.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <fstream>
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
static std::vector<char> get_password_win() {
    std::vector<char> pwd;
    char ch;
    while((ch=_getch())!='\r'&&ch!='\n') {
        if(ch==0||ch==0xE0) { _getch(); continue; }
        if(ch=='\b') {
            if(!pwd.empty()) { pwd.pop_back(); std::cout<<"\b \b"; }
            continue;
        }
        pwd.push_back(ch);
        std::cout<<'*';
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
        <<"  -j <num>          Number of parallel threads (default: CPU cores)\n\n"
        <<"Input:\n"
        <<"  For single mode: provide the file path as positional argument\n"
        <<"  For batch mode:  provide directory paths via -i (multiple allowed)\n"
        <<"                   All files under directories will be processed recursively.\n\n"
        <<"Usage:\n"
        <<"  FileEncryptor.exe -e/-d <FileName> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y] [-j Num]\n"
        <<"  FileEncryptor.exe -be/-bd <Path> [-o <Path>] [-de] [-m xchacha20|aegis256] [-y] [-j Num]\n";
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
        else if(arg=="-j"&&i+1<argc) {
            try {
                int t=std::stoi(argv[++i]);
                num_threads=(t<1) ? 1 : t;
            }
            catch(const std::exception&) {
                std::cerr<<"Error: invalid value for -j (expected an integer >= 1). Ignoring -j, using default thread count.\n";
                num_threads=0;
            }
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
        char ch;
        std::cin>>ch;
        if(ch=='y'||ch=='Y') {
            mode=CryptoMode::XCHACHA20;
            fprintf(stderr,"Switched to XChaCha20 mode.\n");
        }
        else {
            fprintf(stderr,"Continuing with AEGIS-256 (may fail on this CPU).\n");
        }
    }

    // ---------- 密码输入 ----------
    std::vector<char> password;
    if(is_encrypt) {
        std::cout<<"Enter password (min 6 characters, strong recommended): ";
        auto pw1=get_password();
        if(pw1.size()<6) {
            std::cerr<<"Password too short.\n";
            sodium_memzero(pw1.data(),pw1.size());
            return 1;
        }

        bool has_upper=false,has_lower=false,has_digit=false,has_special=false;
        for(char c : pw1) {
            if(isupper((unsigned char)c)) has_upper=true;
            else if(islower((unsigned char)c)) has_lower=true;
            else if(isdigit((unsigned char)c)) has_digit=true;
            else if(ispunct((unsigned char)c)) has_special=true;
        }
        if(!(has_upper&&has_lower&&has_digit&&has_special)) {
            std::cerr<<"Warning: Password lacks some character classes (upper/lower/digit/symbol).\n"
                <<"Consider using a stronger password.\n";
        }

        std::cout<<"Re-enter password: ";
        auto pw2=get_password();
        if(pw1!=pw2) {
            std::cerr<<"Passwords do not match.\n";
            sodium_memzero(pw1.data(),pw1.size());
            sodium_memzero(pw2.data(),pw2.size());
            return 1;
        }
        password=std::move(pw1);
        sodium_memzero(pw2.data(),pw2.size());
    }
    else {
        std::cout<<"Enter password (min 6 characters): ";
        password=get_password();
        if(password.size()<6) {
            std::cerr<<"Password too short.\n";
            sodium_memzero(password.data(),password.size());
            return 1;
        }
    }

    if(sodium_mlock(password.data(),password.size())!=0) {
        std::cerr<<"Warning: could not lock password memory (maybe insufficient privileges).\n";
    }

    bool all_ok=true;

    if(is_batch) {
        all_ok=process_files(input_paths,output_dir,password,mode,is_encrypt,delete_source,force_overwrite,num_threads);
    }
    else {
        const std::string& in_path=input_paths[0];
        std::string out_path;
        if(!output_dir.empty()) {
            if(!create_directory_recursive(output_dir)) {
                std::cerr<<"Cannot create output directory: "<<output_dir<<"\n";
                all_ok=false;
                goto cleanup_password;
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
            std::transform(lower.begin(),lower.end(),lower.begin(),::tolower);
            if(lower.size()<4||lower.substr(lower.size()-4)!=".ptd") {
                std::cerr<<"Error: Decryption input must have .ptd extension.\n";
                all_ok=false;
                goto cleanup_password;
            }
            // 先剥离 .ptd 得到明文输出路径
            if(out_path.size()>=4&&
                (out_path.substr(out_path.size()-4)==".ptd"||
                    out_path.substr(out_path.size()-4)==".PTD")) {
                out_path=out_path.substr(0,out_path.size()-4);
            }
            if(out_path==in_path) {
                std::cerr<<"Error: Output path would overwrite input file.\n";
                all_ok=false;
                goto cleanup_password;
            }
        }
        else {
            out_path+=".ptd";
        }

        // 覆盖提示：基于最终输出路径（加密问 .ptd、解密问明文文件）
        if(!force_overwrite) {
            std::ifstream test;
            if(open_stream(test,out_path,std::ios::in)&&test.good()) {
                test.close();
                std::cout<<"Output file exists: "<<out_path<<"\nOverwrite? (y/N): ";
                char ch;
                std::cin>>ch;
                if(ch!='y'&&ch!='Y') {
                    std::cerr<<"Aborted.\n";
                    all_ok=false;
                    goto cleanup_password;
                }
            }
        }

        if(is_encrypt) {
            printf("Encrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            all_ok=encrypt_file(in_path,out_path,password,mode,nullptr,false);
            if(all_ok&&delete_source) {
                if(!remove_file_utf8(in_path)) {
                    std::cerr<<"Error: could not delete source file: "<<in_path<<"\n";
                    all_ok=false;
                }
            }
        }
        else {
            printf("Decrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            all_ok=decrypt_file(in_path,out_path,password,nullptr,false,false);
        }
    }

cleanup_password:
    sodium_munlock(password.data(),password.size());
    sodium_memzero(password.data(),password.size());

    return all_ok ? 0 : 1;
}