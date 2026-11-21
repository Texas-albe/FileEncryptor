// 批量处理模块
// 从 FileEncryptor.cpp 拆分
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <windows.h>    // 必须早于 C++ 头
#include <winioctl.h>   // FSCTL_GET_REPARSE_POINT
#endif
#include "FileEncryptor.hpp"
#ifdef FE_WITH_ZSTD
#include "zstd.h"   // 仅当构建集成
#endif
#include <cstdio>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <memory>
#include <array>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <string>
#include <chrono>
#include <iostream>
#include <functional>
#include <cctype>
#include <sys/stat.h>
#include <sodium.h>
#include "config.hpp"
#include "cipher.hpp"
#include "progress_frame.hpp"
#include "ptd_format.hpp"
#include "asym_crypto.hpp"
#include "machine_id.hpp"
#include "watermark.hpp"
#include "split_volumes.hpp"
#include "kdf.hpp"
#include "util/byte_io.hpp"
#include "util/hex.hpp"
#include "secure_zero.hpp"
#include "buffer_pool.hpp"
#include <atomic>
#ifdef FE_WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#endif
#include <thread>
#include <mutex>
#include <condition_variable>
#include <filesystem>
#include <ctime>

#ifdef _WIN32
#include <io.h>      // _isatty / _fileno
#else
#include <unistd.h> // isatty
#endif

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>    // _aligned_malloc / _aligned_free
#include <debugapi.h>
#include <shlobj.h>
#include <aclapi.h>       // SetEntriesInAclW / SetNamedSecurityInfoW
#include <direct.h>
#include <io.h>
#include <process.h>
#pragma comment(lib, "shell32.lib")   // SHFileOperationW
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>     // chmod
#include <pwd.h>
#include <dirent.h>
#include <fcntl.h>
#include <cerrno>
#include <signal.h>
#endif

namespace fs = std::filesystem;

#ifdef __linux__
#include <signal.h>
#include <unistd.h>
#endif

// 目录遍历
#ifdef _WIN32
#include <io.h>
#else
#include <dirent.h>
#endif

// Batch filter state, set from CLI options
static std::vector<std::string> g_exclude_patterns;
static bool g_skip_hidden = false;
static bool g_preserve_times = true;

void batch_set_exclude_patterns(const std::vector<std::string>& patterns) {
    g_exclude_patterns = patterns;
}
void batch_set_skip_hidden(bool b) { g_skip_hidden = b; }
void batch_set_preserve_times(bool b) { g_preserve_times = b; }

// Wildcard match: '*' and '?', case-insensitive
static bool fe_wild_match_ci(const std::string& text, const std::string& pat) {
    size_t t = 0, p = 0, star = std::string::npos, mark = 0;
    auto eq = [](unsigned char a, unsigned char b) {
        return std::tolower(a) == std::tolower(b);
    };
    while (t < text.size()) {
        if (p < pat.size() && (pat[p] == '?' || eq((unsigned char)pat[p], (unsigned char)text[t]))) {
            ++t; ++p;
        } else if (p < pat.size() && pat[p] == '*') {
            star = p++; mark = t;
        } else if (star != std::string::npos) {
            p = star + 1; t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

static bool fe_name_excluded(const std::string& name) {
    for (const auto& p : g_exclude_patterns)
        if (fe_wild_match_ci(name, p)) return true;
    return false;
}

static bool fe_name_hidden(const std::string& name) {
    return !name.empty() && name[0] == '.';
}

// Full-path filter for dry-run enumeration and callers without dir recursion
bool fe_batch_filter_path(const std::string& full_path) {
    if (full_path.empty()) return true;
    size_t pos = full_path.find_last_of("/\\");
    std::string name = (pos != std::string::npos) ? full_path.substr(pos + 1) : full_path;
    if (g_skip_hidden && fe_name_hidden(name)) return false;
    if (fe_name_excluded(name)) return false;
    // Any excluded parent dir name prunes the whole subtree
    size_t start = 0;
    while (pos != std::string::npos) {
        size_t sep = full_path.find_first_of("/\\", start);
        if (sep == std::string::npos || sep >= pos) break;
        std::string seg = full_path.substr(start, sep - start);
        if (!seg.empty() && seg != "." && seg != ".." && seg.find(':') == std::string::npos &&
            fe_name_excluded(seg)) {
            return false;
        }
        start = sep + 1;
    }
    return true;
}

// Copy source mtime to output file (filesystem level, no format change)
static void fe_preserve_mtime(const std::string& src, const std::string& dst) {
    if (!g_preserve_times) return;
    std::error_code ec;
    auto t = fs::last_write_time(src, ec);
    if (ec) return;
    fs::last_write_time(dst, t, ec);
}

static bool is_directory(const std::string& path) {
#ifdef _WIN32
    struct _stat64 st;
    if(_wstat64(utf8_to_wstring(path).c_str(),&st)!=0) return false;
    return (st.st_mode&S_IFDIR)!=0;
#else
    struct stat st;
    if(stat(path.c_str(),&st)!=0) return false;
    return (st.st_mode&S_IFDIR)!=0;
#endif
}

bool fe_path_is_directory(const std::string& path) { return is_directory(path); }

static void collect_files_from_dir(const std::string& dir,std::vector<std::string>& out_files,int depth=0) {
    // 防御
    // 超过深度上限
    if(depth>1024) {
        std::cerr<<"Warning: directory nesting too deep, skipping: "<<dir<<"\n";
        return;
    }
#ifdef _WIN32
    std::wstring wpattern=utf8_to_wstring(dir+"\\*");
    struct _wfinddata_t fd;
    intptr_t handle=_wfindfirst(wpattern.c_str(),&fd);
    if(handle==-1) return;
    do {
        if(wcscmp(fd.name,L".")==0||wcscmp(fd.name,L"..")==0) continue;
        std::string name=wstring_to_utf8(fd.name);
        // filter: hidden and excluded names prune dirs too
        if(g_skip_hidden&&((fd.attrib&_A_HIDDEN)||fe_name_hidden(name))) continue;
        if(fe_name_excluded(name)) continue;
        std::string full=dir+"\\"+name;
        // 跳过重解析点
        if((fd.attrib&_A_SUBDIR)&&!(fd.attrib&0x0400)) {
            collect_files_from_dir(full,out_files,depth+1);
        }
        else {
            out_files.push_back(full);
        }
    } while(_wfindnext(handle,&fd)==0);
    _findclose(handle);
#else
    DIR* dp=opendir(dir.c_str());
    if(!dp) return;
    struct dirent* entry;
    while((entry=readdir(dp))!=nullptr) {
        if(strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0) continue;
        // filter: hidden and excluded names prune dirs too
        std::string ename=entry->d_name;
        if(g_skip_hidden&&fe_name_hidden(ename)) continue;
        if(fe_name_excluded(ename)) continue;
        std::string full=dir+"/"+ename;
        struct stat st;
        if(lstat(full.c_str(),&st)==0) {
            if(S_ISLNK(st.st_mode)) {
                continue; // 跳过符号链接
            }
            if(S_ISDIR(st.st_mode)) {
                collect_files_from_dir(full,out_files,depth+1);
            }
            else {
                out_files.push_back(full);
            }
        }
    }
    closedir(dp);
#endif
}

// 批量处理
static std::string build_batch_out_path(const std::string& in_path,
    const std::string& out_dir_clean,
    const std::vector<std::string>& input_paths, bool include_root_name) {
    std::string out_path=out_dir_clean+"/";
    std::string best_root;
    for(const auto& root:input_paths) {
        // 前缀匹配需带边
        // "D
        if(is_directory(root)&&in_path.length()>=root.length()&&
           in_path.compare(0,root.length(),root)==0&&
           (in_path.length()==root.length()||
            in_path[root.length()]=='/'||in_path[root.length()]=='\\')) {
            if(root.length()>best_root.length()) best_root=root;
        }
    }
    if(!best_root.empty()) {
        std::string suffix=in_path.substr(best_root.length());
        if(!suffix.empty()&&(suffix[0]=='/'||suffix[0]=='\\')) suffix.erase(0,1);
        // 加密保留输入根
        // 多 -i 同名冲突
        bool need_root_name=include_root_name||input_paths.size()>1;
        if(need_root_name) {
            size_t root_pos=best_root.find_last_of("/\\");
            std::string root_name=(root_pos!=std::string::npos) ? best_root.substr(root_pos+1) : best_root;
            if(!root_name.empty()) out_path+=root_name+"/";
        }
        out_path+=suffix;
    }
    else {
        size_t pos=in_path.find_last_of("/\\");
        std::string fname=(pos!=std::string::npos) ? in_path.substr(pos+1) : in_path;
        out_path+=fname;
    }
    // 路径穿越防御
    if(path_has_traversal(out_path)) return "";
    return out_path;
}

// 批量预派生用
// 与 read_original_name 同源
static bool read_header_kdf_params(const std::string& ptd_path,
    unsigned char salt[ARGON2_SALT_LEN], unsigned int& ops, uint32_t& mem_kb) {
    std::ifstream f;
    if(!open_stream(f,ptd_path,std::ios::binary)) return false;
    unsigned char hdr[HEADER_SIZE_V6];
    if(!f.read(reinterpret_cast<char*>(hdr),5)) return false;
    if(memcmp(hdr,MAGIC,4)!=0) return false;
    unsigned char ver=hdr[4];
    if(ver!=1&&ver!=2&&ver!=3&&ver!=VERSION&&ver!=5&&ver!=6) return false;
    uint64_t need=header_size_for_version(ver);
    if(need<5||need>sizeof(hdr)) return false;
    if(!f.read(reinterpret_cast<char*>(hdr+5),(std::streamoff)(need-5))) return false;
    ops=ARGON2_OPS_LEGACY; mem_kb=ARGON2_MEM_LEGACY_KB;
    if(ver==1)      { FileHeaderV1 h=load_header<FileHeaderV1>(hdr); memcpy(salt,h.salt,ARGON2_SALT_LEN); }
    else if(ver==2) { FileHeaderV2 h=load_header<FileHeaderV2>(hdr); memcpy(salt,h.salt,ARGON2_SALT_LEN); ops=h.opslimit; mem_kb=h.memlimit_kb; }
    else if(ver==3) { FileHeaderV3 h=load_header<FileHeaderV3>(hdr); memcpy(salt,h.salt,ARGON2_SALT_LEN); ops=h.opslimit; mem_kb=h.memlimit_kb; }
    else if(ver==5) { FileHeaderV5 h=load_header<FileHeaderV5>(hdr); memcpy(salt,h.salt,ARGON2_SALT_LEN); ops=h.opslimit; mem_kb=h.memlimit_kb; }
    else if(ver==6) { FileHeaderV6 h=load_header<FileHeaderV6>(hdr); memcpy(salt,h.salt,ARGON2_SALT_LEN); ops=h.opslimit; mem_kb=h.memlimit_kb; }
    else            { FileHeaderV4 h=load_header<FileHeaderV4>(hdr); memcpy(salt,h.salt,ARGON2_SALT_LEN); ops=h.opslimit; mem_kb=h.memlimit_kb; }
    return true;
}

// 分卷输入
static bool kdf_params_for_batch_input(const std::string& in_path,
    unsigned char salt[ARGON2_SALT_LEN], unsigned int& ops, uint32_t& mem_kb) {
    if(read_header_kdf_params(in_path,salt,ops,mem_kb)) return true;
    if(fe_file_exists(in_path)) return false;
    for(const auto& v:find_volumes(in_path))
        if(read_header_kdf_params(v,salt,ops,mem_kb)) return true;
    return false;
}

bool process_files(const std::vector<std::string>& input_paths,
    const std::string& out_dir,
    const SecureBuffer& password,
    CryptoMode mode,    bool encrypt,
    int source_action,
    bool force_overwrite,
    int num_threads,
    bool restore_name,
    int compress_level,
    const WatermarkSpec* wm,
    uint64_t split_bytes) {
    // 批量入口兜底
    // 不自动降级
    if(encrypt&&mode==CryptoMode::AEGIS256&&!aegis256_supported()) {
        fprintf(stderr,"Warning: AEGIS-256 unavailable on this CPU (AES-NI required); "
                       "proceeding as requested (will be very slow / side-channel weak). "
                       "Consider -m xchacha20.\n");
    }

    std::string out_dir_clean=out_dir;
    while(!out_dir_clean.empty()&&(out_dir_clean.back()=='/'||out_dir_clean.back()=='\\')) {
        out_dir_clean.pop_back();
    }
    // 非 ASCII
    // 负 char 传入 C 字符分类
    if(out_dir_clean.size()==2&&isalpha((unsigned char)out_dir_clean[0])&&out_dir_clean[1]==':') {
        out_dir_clean+='\\';
    }
    if(!out_dir_clean.empty()&&!create_directory_recursive(out_dir_clean)) {
        fprintf(stderr,"Cannot create output directory: %s\n",out_dir_clean.c_str());
        return false;
    }

    std::vector<std::string> all_files;
    for(const auto& path:input_paths) {
        if(is_directory(path)) {
            collect_files_from_dir(path,all_files);
        }
        else {
            all_files.push_back(path);
        }
    }

    size_t non_ptd_skipped=0;   // 批量解密
    // restore_name 批量解密：预扫描
    std::unordered_map<std::string, std::vector<unsigned char>> kek_cache;
    if(!encrypt) {
        // 批量解密只处理
        std::vector<std::string> filtered;
        size_t skipped=0;
        for(const auto& f:all_files) {
            std::string lower=f;
            // 仅对 ASCII 字节转小写
            // 传给
            std::transform(lower.begin(),lower.end(),lower.begin(),
                [](unsigned char c){ return (char)std::tolower(c); });
            if(lower.size()>=4&&lower.compare(lower.size()-4,4,".ptd")==0) {
                filtered.push_back(f);
            } else {
                ++skipped;
            }
        }
        // 分卷归组
        // 不折
        {
            std::vector<std::string> kept;
            std::vector<std::string> groups;
            for(const auto& f:filtered) {
                std::string base=base_ptd_of(f);
                if(base.empty()) { kept.push_back(f); continue; }
                if(std::find(groups.begin(),groups.end(),base)==groups.end())
                    groups.push_back(base);
            }
            for(const auto& base:groups) {
                // 完整件
                // worker 侧合并
                if(fe_file_exists(base)) kept.push_back(base);
                else if(!find_volumes(base).empty()) kept.push_back(base);
            }
            // 保持原有顺序
            std::vector<std::string> ordered;
            for(const auto& f:filtered) {
                std::string base=base_ptd_of(f);
                if(base.empty()) { ordered.push_back(f); continue; }
                if(std::find(kept.begin(),kept.end(),base)==kept.end()) continue;
                if(std::find(ordered.begin(),ordered.end(),base)==ordered.end())
                    ordered.push_back(base);
            }
            all_files=std::move(ordered);
        }
        non_ptd_skipped=skipped;
        if(skipped>0) {
            fprintf(stderr,"Skipped %zu non-.ptd file(s) in batch decrypt.\n",skipped);
            log_event(LOG_WARN,"batch_skipped_non_ptd",{{"count",std::to_string(skipped)}});
        }
    }

    if(all_files.empty()) {
        fprintf(stderr,"No files found to process.\n");
        return false;
    }

    size_t total_bytes=0;
    // 预扫描尺寸缓存
    std::unordered_map<std::string,int64_t> size_cache;
    size_cache.reserve(all_files.size());
    for(const auto& f:all_files) {
        int64_t s=fe_file_size(f);
        if(s>=0) { total_bytes+=(size_t)s; size_cache.emplace(f,s); }
    }

    printf("Total files: %zu, Total size: %s\n",all_files.size(),format_size((uint64_t)total_bytes).c_str());

    // 并发线程数优先
    int cfg_threads=global_config().worker_threads;
    if(cfg_threads>0) num_threads=cfg_threads;
    if(num_threads<=0) {
        num_threads=std::thread::hardware_concurrency();
        if(num_threads<=0) num_threads=4;
    }
    // 资源耗尽防御
    // 故并发线程数
    if(global_config().max_open_files>0) {
        int cap=(int)(global_config().max_open_files/3);
        if(cap<1) cap=1;
        if(num_threads>cap) num_threads=cap;
    }
    printf("Using %d thread(s)\n",num_threads);
    log_event(LOG_INFO,"batch_start",
        {{"mode",encrypt?"encrypt":"decrypt"},
         {"files",std::to_string(all_files.size())},
         {"threads",std::to_string(num_threads)},
         {"total_bytes",std::to_string(total_bytes)}});

    std::vector<std::string> files_to_process;
    bool pre_scan_ok=true;   // 预扫描阶段
    // 预扫描优化
    // 数万文件逐个递
    std::string last_mkdir;
    size_t scan_idx=0;
    for(const auto& in_path:all_files) {
        if((++scan_idx%2000)==0) {
            fprintf(stderr,"Pre-scanning: %zu/%zu files\n",scan_idx,all_files.size());
        }
        std::string out_path;
        if(!out_dir_clean.empty()) {
            out_path=build_batch_out_path(in_path,out_dir_clean,input_paths,encrypt);
            if(out_path.empty()) {
                fprintf(stderr,"Skipping %s: output path escapes output directory.\n",in_path.c_str());
                continue;
            }
        }
        else {
            out_path=in_path;
        }

        if(encrypt) {
            if(global_config().obfuscate_names) {
                out_path=replace_basename(out_path,
                    make_obfuscated_basename(in_path,password));
            }
            out_path+=".ptd";
        }
        else {
            if(out_path.size()>=4&&
                (out_path.substr(out_path.size()-4)==".ptd"||
                    out_path.substr(out_path.size()-4)==".PTD")) {
                out_path=out_path.substr(0,out_path.size()-4);
            }
            // 文件名
            if(restore_name) {
                std::vector<unsigned char> kek(ARGON2_OUTPUT_LEN);
                std::string orig_name;
                if(read_original_name(in_path,orig_name,password,nullptr,0,&kek)) {
                    kek_cache[in_path]=kek;   // 缓存 KEK
                    if(!orig_name.empty()) out_path=replace_basename(out_path,orig_name);
                }
            }
        }

        size_t dirpos=out_path.find_last_of("/\\");
        if(dirpos!=std::string::npos) {
            std::string out_subdir=out_path.substr(0,dirpos);
            if(out_subdir!=last_mkdir) {
                create_directory_recursive(out_subdir);
                last_mkdir=std::move(out_subdir);
            }
        }

        bool skip=false;
        if(!force_overwrite && fe_file_exists(out_path)) {
            // 先 stat 判存
            // 也会经过过滤驱
            // 加密侧
            // 头坏
            int64_t sz_hint=-1;
            { auto _sc=size_cache.find(in_path); if(_sc!=size_cache.end()) sz_hint=_sc->second; }
            bool hdr_ok=false, complete=false;
            if(encrypt) {
                complete=fe_is_complete_output(out_path,encrypt,in_path,sz_hint,&hdr_ok);
            }
            else {
                hdr_ok=fe_is_file_valid(out_path);
                if(hdr_ok) complete=fe_is_complete_output(out_path,encrypt,in_path,sz_hint);
            }
            if(!hdr_ok) {
                fprintf(stderr,"Existing file %s is corrupted, will overwrite.\n",out_path.c_str());
            }
            else if(fe_file_exists(out_path+".prs")) {
                fprintf(stderr,"Existing file %s has unfinished progress, will resume.\n",out_path.c_str());
            }
            else if(complete) {
                // 头部有效、无 .prs、尺寸
                // 但解密若带源处
                skip=true;
                printf("Skipped: %s (already done)\n",in_path.c_str());
                if(!encrypt && source_action!=0) {
                    if(!secure_handle_source(in_path,static_cast<SourceDisposition>(source_action))) {
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        pre_scan_ok=false;
                    }
                }
            }
            else {
                // 头部有效但尺寸
                // 残留下“
                fprintf(stderr,"Existing file %s is incomplete (no progress), will re-encrypt.\n",out_path.c_str());
            }
        }
        if(!skip) {
            files_to_process.push_back(in_path);
        }
    }

    if(files_to_process.empty()) {
        printf("No files to process (all already exist and valid, -y not specified).\n");
        return true;
    }

    printf("Processing %zu files (skipped %zu valid existing).\n",
        files_to_process.size(),all_files.size()-files_to_process.size());

    // 帧式进度显示
    // use_frame=false 时回退旧
    feui::BatchProgress progress_ui;
    const bool use_frame=progress_ui.begin(num_threads,total_bytes);

    std::atomic<size_t> file_index{0};
    std::atomic<size_t> global_processed{0};
    // 文件级计数
    std::atomic<size_t> files_done{0};
    std::atomic<size_t> files_failed{0};
    std::atomic<size_t> skipped_not_ptd{0};   // worker 魔数预检发现
    const size_t files_skipped=(all_files.size()-files_to_process.size())+non_ptd_skipped;
    std::mutex error_mutex;
    std::vector<std::string> error_files;
    std::chrono::steady_clock::time_point start_time=std::chrono::steady_clock::now();
    std::atomic<bool> all_ok{pre_scan_ok};
    std::atomic<bool> display_stop{false};

    // 显示线程
    std::thread display_thread;
    if(use_frame) {
        display_thread=std::thread([&]{
            while(!display_stop.load(std::memory_order_relaxed)) {
                progress_ui.setProcessed(global_processed.load(std::memory_order_relaxed));
                progress_ui.setFileStats(files_done.load(std::memory_order_relaxed),
                                         files_failed.load(std::memory_order_relaxed),
                                         files_skipped+skipped_not_ptd.load(std::memory_order_relaxed),
                                         files_to_process.size());
                progress_ui.render(false);
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
            }
        });
    }

    // KDF 与数据阶段分离
    // 独占全部 worker
    // 阶段里
    std::unordered_map<std::string, std::array<unsigned char,ARGON2_SALT_LEN>> salt_cache;
    if(encrypt) {
        // 盐先于派生随机
        salt_cache.reserve(files_to_process.size());
        for(const auto& f:files_to_process) {
            std::array<unsigned char,ARGON2_SALT_LEN> s;
            randombytes_buf(s.data(),s.size());
            salt_cache.emplace(f,s);
        }
    }
    {
        int kdf_n=kdf_max_concurrency();
        if(kdf_n>num_threads) kdf_n=num_threads;
        if(kdf_n<1) kdf_n=1;
        unsigned int kdf_ops=ARGON2_OPS_DEFAULT, kdf_memkb=ARGON2_MEM_DEFAULT_KB;
        kdf_preset_params(global_config().kdf_preset,kdf_ops,kdf_memkb);
        if(files_to_process.size()>=(size_t)(kdf_n*4)) {
            fprintf(stderr,"Pre-deriving keys for %zu file(s) on %d thread(s)...\n",
                files_to_process.size(),kdf_n);
        }
        std::atomic<size_t> kdf_idx{0};
        std::mutex kdf_mu;
        std::vector<std::thread> kdf_threads;
        for(int i=0;i<kdf_n;++i) {
            kdf_threads.emplace_back([&]{
                while(true) {
                    size_t ki=kdf_idx.fetch_add(1);
                    if(ki>=files_to_process.size()) break;
                    const auto& f=files_to_process[ki];
                    { std::lock_guard<std::mutex> lk(kdf_mu); if(kek_cache.count(f)) continue; }
                    std::vector<unsigned char> kek(ARGON2_OUTPUT_LEN);
                    bool got=false;
                    if(encrypt) {
                        auto sit=salt_cache.find(f);
                        if(sit!=salt_cache.end())
                            got=derive_key(password.data(),password.size(),sit->second.data(),
                                           kek.data(),kdf_ops,(size_t)kdf_memkb*1024);
                    }
                    else {
                        unsigned char salt[ARGON2_SALT_LEN];
                        unsigned int ops=0; uint32_t memkb=0;
                        if(kdf_params_for_batch_input(f,salt,ops,memkb))
                            got=derive_key(password.data(),password.size(),salt,kek.data(),
                                           ops,(size_t)memkb*1024);
                        sodium_memzero(salt,sizeof(salt));
                    }
                    // 读头失败或密码
                    if(!got) continue;
                    std::lock_guard<std::mutex> lk(kdf_mu);
                    kek_cache.emplace(f,std::move(kek));
                }
            });
        }
        for(auto& kt:kdf_threads) kt.join();
    }

    auto worker=[&](int slot) {
        // 线程结束时清空
        struct SlotGuard {
            feui::BatchProgress* ui;
            int slot;
            ~SlotGuard() { if(ui) ui->setSlot(slot,std::string(),0,0,false); }
        } guard{use_frame ? &progress_ui : nullptr,slot};

        while(true) {
            size_t idx=file_index.fetch_add(1);
            if(idx>=files_to_process.size()) break;
            const auto& in_path=files_to_process[idx];

            // 分卷输入
            SplitPlan plan;
            MergedTemp merged;
            std::string src_path=in_path;
            if(!encrypt) {
                std::string perr;
                if(!resolve_decrypt_input(in_path,plan,perr)) {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    std::cerr<<"Error: "<<perr<<"\n";
                    error_files.push_back(in_path);
                    ++files_failed;
                    all_ok=false;
                    continue;
                }
                if(plan.from_volumes) {
                    merged.path=plan.merged_path;
                    src_path=plan.merged_path;
                }
            }

            std::string out_path;
            if(!out_dir_clean.empty()) {
                out_path=build_batch_out_path(in_path,out_dir_clean,input_paths,encrypt);
                if(out_path.empty()) {
                    // 输出路径逃出目
                    std::lock_guard<std::mutex> lock(error_mutex);
                    error_files.push_back(in_path);
                    ++files_failed;
                    all_ok=false;
                    continue;
                }
            }
            else {
                out_path=in_path;
            }

            if(encrypt) {
                if(global_config().obfuscate_names) {
                    out_path=replace_basename(out_path,
                        make_obfuscated_basename(in_path,password));
                }
                out_path+=".ptd";
            }
            else {
                if(out_path.size()>=4&&
                    (out_path.substr(out_path.size()-4)==".ptd"||
                        out_path.substr(out_path.size()-4)==".PTD")) {
                    out_path=out_path.substr(0,out_path.size()-4);
                }
                // 还原文件名
                if(restore_name) {
                    std::string orig_name;
                    auto _kit=kek_cache.find(in_path);
                    const unsigned char* kek_ptr=(_kit!=kek_cache.end())?_kit->second.data():nullptr;
                    if(read_original_name(in_path,orig_name,password,kek_ptr,kek_ptr?ARGON2_OUTPUT_LEN:0)
                       &&!orig_name.empty()) {
                        out_path=replace_basename(out_path,orig_name);
                    }
                }
            }

            size_t last_file_processed=0;

            bool ok=false;
            // 原子落盘
            // 或崩溃
            // 临时名
            std::unique_ptr<AtomicOutput> atomic_out;
            if(encrypt) atomic_out.reset(new AtomicOutput(out_path));
            const unsigned char* enc_salt=nullptr;
            const unsigned char* enc_kek=nullptr;
            {
                auto _sit=salt_cache.find(in_path);
                if(_sit!=salt_cache.end()) enc_salt=_sit->second.data();
                auto _kit=kek_cache.find(in_path);
                if(_kit!=kek_cache.end()) enc_kek=_kit->second.data();
            }
            const std::string enc_target = encrypt ? atomic_out->path() : out_path;
            if(encrypt) {
                ok=encrypt_file(in_path,enc_target,password,mode,
                    [&](size_t processed,size_t total) {
                        size_t inc=processed-last_file_processed;
                        last_file_processed=processed;
                        global_processed+=inc;
                        if(use_frame) {
                            // 帧模式
                            progress_ui.setSlot(slot,in_path,processed,total,true);
                            progress_ui.setProcessed(global_processed.load());
                        }
                        else {
                            static std::mutex print_mutex;
                            std::lock_guard<std::mutex> lock(print_mutex);
                            print_progress(global_processed.load(),total_bytes,start_time,false);
                        }
                    },true,compress_level,false,nullptr,wm,enc_salt,enc_kek);
                // 自校验已过才提
                if(ok && !atomic_out->commit()) ok=false;
                if(ok && source_action!=0) {
                    if(!secure_handle_source(in_path, static_cast<SourceDisposition>(source_action))) {
                        std::lock_guard<std::mutex> lock(error_mutex);
                        std::cerr<<"Error: could not process source file: "<<in_path<<"\n";
                        ok=false;
                    }
                }
            }
            else {
                // 伪 .ptd 预检
                // 普通文件误冠 .ptd
                {
                    unsigned char m5[5];
                    std::ifstream mf;
                    if(open_stream(mf,src_path,std::ios::binary)
                       &&mf.read(reinterpret_cast<char*>(m5),5)&&mf.gcount()==5
                       &&memcmp(m5,MAGIC,4)!=0) {
                        ++skipped_not_ptd;
                        fprintf(stderr,"Skipped: %s (not a PTD encrypted file)\n",in_path.c_str());
                        continue;
                    }
                }
                const unsigned char* dec_kek=nullptr;
                { auto _kit=kek_cache.find(in_path); if(_kit!=kek_cache.end()) dec_kek=_kit->second.data(); }
                ok=decrypt_file(src_path,out_path,password,
                    [&](size_t processed,size_t total) {
                        size_t inc=processed-last_file_processed;
                        last_file_processed=processed;
                        global_processed+=inc;
                        if(use_frame) {
                            progress_ui.setSlot(slot,in_path,processed,total,true);
                            progress_ui.setProcessed(global_processed.load());
                        }
                        else {
                            static std::mutex print_mutex;
                            std::lock_guard<std::mutex> lock(print_mutex);
                            print_progress(global_processed.load(),total_bytes,start_time,false);
                        }
                    },true,true,nullptr,dec_kek);
                if(ok) fe_preserve_mtime(src_path, out_path);   // ptd mtime to plain
                // 解密成功后处理
                // 输入来自分卷
                if(ok && source_action!=0) {
                    // 输入来自分卷
                    // 归一阶段没认出
                    std::vector<std::string> victims=plan.from_volumes
                        ? plan.volumes : std::vector<std::string>{in_path};
                    if(victims.size()<=1 && !plan.from_volumes) {
                        std::vector<std::string> vols=find_volumes(in_path);
                        if(!vols.empty()) victims=vols;
                    }
                    for(const auto& v:victims) {
                        if(!secure_handle_source(v,static_cast<SourceDisposition>(source_action))) {
                            std::cerr<<"Error: could not process source file: "<<v<<"\n";
                            ok=false;
                        }
                    }
                }
            }

            bool file_ok = ok;
            if(ok) {
                // 仅真正成功处理
                if(file_ok) {
                    int64_t fsize=-1;
                    { auto _it=size_cache.find(in_path); if(_it!=size_cache.end()) fsize=_it->second; }
                    if(fsize<0) fsize=fe_file_size(in_path);
                    if(fsize>=0) {
                        size_t file_size=(size_t)fsize;
                        if(last_file_processed<file_size) {
                            global_processed+=(file_size-last_file_processed);
                            last_file_processed=file_size;
                        }
                    }
                }
                if(encrypt) {
                    fe_preserve_mtime(in_path, out_path);   // src mtime to cipher
                    if(write_sha256_enabled()) write_sha256_sidecar(out_path); // 功能10
                    if(split_bytes>0) {
                        std::string serr;
                        if(!finish_encrypt_split(out_path,split_bytes,
                                              write_sha256_enabled(),serr)) {
                            std::lock_guard<std::mutex> lock(error_mutex);
                            std::cerr<<"Error: split failed: "<<serr<<"\n";
                            all_ok=false;
                            file_ok=false;
                        }
                    }
                }
                if(file_ok) {
                    ++files_done;
                    log_event(LOG_DEBUG,"file_done",{{"path",in_path}});
                }
            }
            if(!file_ok) {
                ++files_failed;
                // 单文件失败
                all_ok=false;
                {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    error_files.push_back(in_path);
                }
                fprintf(stderr,"Failed: %s (skipped, continuing with remaining files)\n",in_path.c_str());
                log_event(LOG_ERROR,"file_failed",{{"path",in_path}});
            }
        }
        };

    std::vector<std::thread> threads;
    for(int i=0; i<num_threads; ++i) {
        threads.emplace_back(worker,i);   // 每个 worker 绑定一个显
    }
    for(auto& t:threads) {
        t.join();
    }
    // 停止显示线程
    display_stop.store(true);
    if(display_thread.joinable()) display_thread.join();

    if(error_files.empty()) {
        // 全部成功
        global_processed=total_bytes;
    }
    // 有失败文件
    if(use_frame) {
        progress_ui.setProcessed(global_processed.load());
        progress_ui.setFileStats(files_done.load(),files_failed.load(),
                                 files_skipped+skipped_not_ptd.load(),files_to_process.size());
        progress_ui.finish();            // 渲染
    }
    else {
        print_progress(global_processed.load(),total_bytes,start_time,true);
    }
    if(!error_files.empty()) {
        fprintf(stderr,
            "\nWarning: %zu file(s) failed; the final progress reflects processed bytes only.\n",
            error_files.size());
    }

    if(!encrypt&&!error_files.empty()) {
        fprintf(stderr,"\n--- Decryption errors (%zu files) ---\n",error_files.size());
        for(const auto& f:error_files) {
            fprintf(stderr,"  %s\n",f.c_str());
        }
        fprintf(stderr,"Total %zu files failed.\n",error_files.size());
    }
    if(encrypt&&!error_files.empty()) {
        fprintf(stderr,"\n--- Encryption errors (%zu files) ---\n",error_files.size());
        for(const auto& f:error_files) {
            fprintf(stderr,"  %s\n",f.c_str());
        }
        fprintf(stderr,"Total %zu files failed.\n",error_files.size());
    }

    // 清空中缓存
    for(auto& kv:kek_cache) sodium_memzero(kv.second.data(), kv.second.size());
    kek_cache.clear();

    // 宿主
    // 不用 fopen
    // 目标可能已存
    // 而非 O_EXCL后者
    if(const char* stats_path=std::getenv("FILEENCRYPTOR_STATS_FILE")) {
        FILE* sf=nullptr;
        bool blocked=path_is_symlink(stats_path);
        if(blocked) {
            fprintf(stderr,"Refusing to write stats through a symlink: %s\n",stats_path);
        }
#ifndef _WIN32
        // O_NOFOLLOW
        if(!blocked) {
            int sfd=::open(stats_path,O_CREAT|O_TRUNC|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
            if(sfd>=0) {
                sf=::fdopen(sfd,"wb");
                if(!sf) ::close(sfd);
            } else if(errno==ELOOP) {
                fprintf(stderr,"Refusing to write stats through a symlink: %s\n",stats_path);
            }
        }
#else
        // MSVC 无 O_NOFOLLOW；上面
        if(!blocked) sf=fopen(stats_path,"wb");
#endif
        if(sf) {
            fprintf(sf,"{\"total_bytes\":%llu,\"files_done\":%llu,\"files_failed\":%llu,"
                      "\"files_skipped\":%llu,\"total_files\":%llu}\n",
                (unsigned long long)total_bytes,
                (unsigned long long)files_done.load(),
                (unsigned long long)files_failed.load(),
                (unsigned long long)(files_skipped+skipped_not_ptd.load()),
                (unsigned long long)all_files.size());
            fclose(sf);
        }
    }

    return all_ok.load();
}