#include "FileEncryptor.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <sodium.h>

#ifdef _WIN32
#include <conio.h>
static std::string get_password_win() {
    std::string pwd;
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
#else
#include <termios.h>
#include <unistd.h>
static std::string get_password_posix() {
    std::string pwd;
    struct termios oldt,newt;
    tcgetattr(STDIN_FILENO,&oldt);
    newt=oldt;
    newt.c_lflag&=~ECHO;
    tcsetattr(STDIN_FILENO,TCSANOW,&newt);
    std::getline(std::cin,pwd);
    tcsetattr(STDIN_FILENO,TCSANOW,&oldt);
    std::cout<<std::endl;
    return pwd;
}
#endif

static std::string get_password() {
#ifdef _WIN32
    return get_password_win();
#else
    return get_password_posix();
#endif
}

static void print_usage(const char* prog) {
    std::cout<<"FileEncryptor v1.0.0\n\n"
        <<"Modes\n"
        <<"  -e           Encrypt single file\n"
        <<"  -d           Decrypt single file\n"
        <<"  -be          Batch encrypt directories/files\n"
        <<"  -bd          Batch decrypt directories/files\n"
        <<"Options:\n"
        <<"  -o <dir>     Output directory (optional, default: source file's directory)\n"
        <<"  -de          Delete source file after successful encryption (encryption only)\n"
        <<"  -m <mode>    Encryption mode: aes (default) or xchacha20\n"
        <<"Input:\n"
        <<"  For single mode: provide the file path as positional argument\n"
        <<"  For batch mode:  provide directory paths via -i (multiple allowed)\n"
        <<"                    All files under directories will be processed recursively.\n";
}

int main(int argc,char* argv[]) {
    anti_debug_check();

    if(sodium_init()<0) {
        std::cerr<<"Libsodium initialization failed.\n";
        return 1;
    }

    enum {
        ACTION_NONE,ACTION_ENCRYPT,ACTION_DECRYPT,
        ACTION_BATCH_ENCRYPT,ACTION_BATCH_DECRYPT
    } action=ACTION_NONE;

    std::vector<std::string> input_paths;
    std::string output_dir;
    CryptoMode mode=CryptoMode::AES_GCM;
    bool delete_source=false;

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
            if(m=="aes") mode=CryptoMode::AES_GCM;
            else if(m=="xchacha20") mode=CryptoMode::XCHACHA20;
            else { std::cerr<<"Unknown mode: "<<m<<"\n"; return 1; }
        }
        else if(arg=="-i"&&i+1<argc) {
            input_paths.push_back(argv[++i]);
        }
        else if(arg[0]!='-') {
            input_paths.push_back(arg);
        }
        else {
            std::cerr<<"Unknown option: "<<arg<<"\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    bool is_batch=(action==ACTION_BATCH_ENCRYPT||action==ACTION_BATCH_DECRYPT);
    bool is_encrypt=(action==ACTION_ENCRYPT||action==ACTION_BATCH_ENCRYPT);

    if(action==ACTION_NONE) {
        std::cerr<<"No mode specified.\n";
        print_usage(argv[0]);
        return 1;
    }

    if(input_paths.empty()) {
        std::cerr<<"No input paths specified.\n";
        print_usage(argv[0]);
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

    // ---------- 密码输入 ----------
    std::string password;
    if(is_encrypt) {
        // 加密：输入两次
        std::cout<<"Enter password (min 6 characters, strong recommended): ";
        std::string pw1=get_password();
        if(pw1.size()<6) {
            std::cerr<<"Password too short.\n";
            volatile char* p=&pw1[0];
            for(size_t i=0; i<pw1.size(); ++i) p[i]=0;
            return 1;
        }

        // 复杂度检查并输出警告
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
        std::string pw2=get_password();
        if(pw1!=pw2) {
            std::cerr<<"Passwords do not match.\n";
            volatile char* p1=&pw1[0];
            volatile char* p2=&pw2[0];
            for(size_t i=0; i<pw1.size(); ++i) p1[i]=0;
            for(size_t i=0; i<pw2.size(); ++i) p2[i]=0;
            return 1;
        }
        password=pw1;
        volatile char* p2_clear=&pw2[0];
        for(size_t i=0; i<pw2.size(); ++i) p2_clear[i]=0;
    }
    else {
        // 解密：只输入一次
        std::cout<<"Enter password (min 6 characters): ";
        password=get_password();
        if(password.size()<6) {
            std::cerr<<"Password is too short.\n";
            volatile char* p=&password[0];
            for(size_t i=0; i<password.size(); ++i) p[i]=0;
            return 1;
        }
    }

    bool all_ok=true;

    if(is_batch) {
        all_ok=process_files(input_paths,output_dir,password,mode,is_encrypt,delete_source);
    }
    else {
        const std::string& in_path=input_paths[0];
        std::string out_path;
        if(!output_dir.empty()) {
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

        bool ok=false;
        if(is_encrypt) {
            out_path+=".ptd";
            printf("Encrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            ok=encrypt_file(in_path,out_path,password,mode,nullptr);
            if(ok&&delete_source) {
                if(std::remove(in_path.c_str())!=0) {
                    std::cerr<<"Warning: could not delete "<<in_path<<"\n";
                }
            }
        }
        else {
            if(out_path.size()>=4&&out_path.substr(out_path.size()-4)==".ptd") {
                out_path=out_path.substr(0,out_path.size()-4);
            }
            printf("Decrypting: %s -> %s\n",in_path.c_str(),out_path.c_str());
            ok=decrypt_file(in_path,out_path,password,nullptr);
        }
        all_ok=ok;
    }

    volatile char* p=&password[0];
    for(size_t i=0; i<password.size(); ++i) p[i]=0;

    return all_ok ? 0 : 1;
}