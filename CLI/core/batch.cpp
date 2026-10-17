// 批量处理模块：目录遍历 / 输出路径构造 / KDF 参数探测 / 批量入口。
// 从 FileEncryptor.cpp 拆分而来，保持 FileEncryptor.hpp 中 process_files / fe_path_is_directory 声明不变。
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <windows.h>    // 必须早于 C++ 头：CreateFileW / DeviceIoControl
#include <winioctl.h>   // FSCTL_GET_REPARSE_POINT
#endif
#include "FileEncryptor.hpp"
#ifdef FE_WITH_ZSTD
#include "zstd.h"   // 仅当构建集成了 zstd 预编译库时引入（third_party/zstd/include）
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
#include <malloc.h>    // _aligned_malloc / _aligned_free（输入侧页对齐大缓冲）
#include <debugapi.h>
#include <shlobj.h>
#include <aclapi.h>       // SetEntriesInAclW / SetNamedSecurityInfoW（密钥文件 DACL 收紧）
#include <direct.h>
#include <io.h>
#include <process.h>
#pragma comment(lib, "shell32.lib")   // SHFileOperationW（回收站）
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>     // chmod（密钥文件 0600）
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
    // 防御：极端深的目录嵌套（>1024 层）会耗尽调用栈导致崩溃（DoS）。
    // 超过深度上限时跳过该子树并发出告警，而非继续递归。
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
        std::string full=dir+"\\"+name;
        // 跳过重解析点（junction/符号链接目录，属性位 0x0400），避免目录循环导致死递归
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
        std::string full=dir+"/"+entry->d_name;
        struct stat st;
        if(lstat(full.c_str(),&st)==0) {
            if(S_ISLNK(st.st_mode)) {
                continue; // 跳过符号链接，避免目录循环
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
        // 前缀匹配需带边界：root 后须紧跟分隔符或与 in_path 相同，
        // 否则 "D:\data" 会误匹配 "D:\database\x"。
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
        // 加密保留输入根目录名作顶层；解密默认不附加（多输入根时即使解密也附加），
        // 避免多 -i 同名冲突。
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
    // 路径穿越防御：复用 path_has_traversal 的组件法（覆盖前缀 “..” 与中间 “/..”，
    if(path_has_traversal(out_path)) return "";
    return out_path;
}

// 批量预派生用：只读文件头的 KDF 三元组（盐 + ops + mem），不做任何密钥派生。
// 与 read_original_name 同源的版本分派，保证 v1 旧格式回落到历史固定参数。
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

// 分卷输入的 base 不在场时，各卷头部与完整件一致，取第一卷即可
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
    // 批量入口兜底：main.cpp 已处理 AEGIS-256 缺 AES-NI 的降级；若仍直达传入，
    // 不自动降级仅警告，交由调用方显式决定（避免自动化任务静默行为变更）。
    if(encrypt&&mode==CryptoMode::AEGIS256&&!aegis256_supported()) {
        fprintf(stderr,"Warning: AEGIS-256 unavailable on this CPU (AES-NI required); "
                       "proceeding as requested (will be very slow / side-channel weak). "
                       "Consider -m xchacha20.\n");
    }

    std::string out_dir_clean=out_dir;
    while(!out_dir_clean.empty()&&(out_dir_clean.back()=='/'||out_dir_clean.back()=='\\')) {
        out_dir_clean.pop_back();
    }
    // 非 ASCII（UTF-8 多字节）字节必须转成 unsigned char 再传给 isalpha，
    // 否则负 char 传入 C 字符分类函数是未定义行为（glibc 下可能越界查表）。
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

    size_t non_ptd_skipped=0;   // 批量解密中被过滤掉的非 .ptd 文件数（计入 SKIP）
    // restore_name 批量解密：预扫描派生 KEK 后缓存，worker 复用（避免每文件 3 次 Argon2id → 1 次）
    std::unordered_map<std::string, std::vector<unsigned char>> kek_cache;
    if(!encrypt) {
        // 批量解密只处理 .ptd 文件，与单文件 -d 强制 .ptd 保持一致
        std::vector<std::string> filtered;
        size_t skipped=0;
        for(const auto& f:all_files) {
            std::string lower=f;
            // 仅对 ASCII 字节转小写：中文等 UTF-8 多字节字节值为负，
            // 直接传给 ::tolower 是未定义行为（Windows/Linux 均可能越界查表）。
            std::transform(lower.begin(),lower.end(),lower.begin(),
                [](unsigned char c){ return (char)std::tolower(c); });
            if(lower.size()>=4&&lower.compare(lower.size()-4,4,".ptd")==0) {
                filtered.push_back(f);
            } else {
                ++skipped;
            }
        }
        // 分卷归组：foo.001.ptd / foo.002.ptd 折成一份 foo.ptd。
        // 不折的话每个卷都会被当成独立密文去解，必然失败。
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
                // 完整件在场就用它（分卷是残留副本）；不在场但分卷齐全则记 base，
                // worker 侧合并后再解
                if(fe_file_exists(base)) kept.push_back(base);
                else if(!find_volumes(base).empty()) kept.push_back(base);
            }
            // 保持原有顺序，避免进度与日志顺序突变
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
    // 预扫描尺寸缓存：worker 成功补进度时复用，免去每文件二次 stat（超大批量省 syscall）
    std::unordered_map<std::string,int64_t> size_cache;
    size_cache.reserve(all_files.size());
    for(const auto& f:all_files) {
        int64_t s=fe_file_size(f);
        if(s>=0) { total_bytes+=(size_t)s; size_cache.emplace(f,s); }
    }

    printf("Total files: %zu, Total size: %s\n",all_files.size(),format_size((uint64_t)total_bytes).c_str());

    // 并发线程数优先取自 YAML 配置（worker_threads），否则回退到 CLI/自动
    int cfg_threads=global_config().worker_threads;
    if(cfg_threads>0) num_threads=cfg_threads;
    if(num_threads<=0) {
        num_threads=std::thread::hardware_concurrency();
        if(num_threads<=0) num_threads=4;
    }
    // 资源耗尽防御：限制同时打开的文件数。每个线程约持有 2 个句柄（输入 + 输出），
    // 故并发线程数不超过 max_open_files/3，避免批量/高并发场景句柄耗尽导致 DoS。
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
    bool pre_scan_ok=true;   // 预扫描阶段的源处理失败，稍后并入 all_ok
    // 预扫描优化：单线程循环内可安全缓存"上次已确保存在的输出子目录"，
    // 避免数万文件逐个递归 stat 各级目录（此阶段在任何帧输出之前，曾表现为 GUI"进度停滞"）。
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
            // 文件名还原默认关闭：开启需每文件多跑一次 Argon2id KDF，性能较差
            if(restore_name) {
                std::vector<unsigned char> kek(ARGON2_OUTPUT_LEN);
                std::string orig_name;
                if(read_original_name(in_path,orig_name,password,nullptr,0,&kek)) {
                    kek_cache[in_path]=kek;   // 缓存 KEK，worker 复用（3× → 1× Argon2id）
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
            // 先 stat 判存在再打开：对不存在的输出逐文件做失败的 CreateFile
            // 也会经过过滤驱动（AV 实时扫描），大目录下是无谓的开销。
            // 加密侧把「头是否有效」并入完整性检查一次 open 完成；解密侧仍先判头，
            // 头坏就没必要再读全长。
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
                // 头部有效、无 .prs、尺寸完整即已完成，安全跳过；
                // 但解密若带源处置(-de/--wipe-source/--recycle-source)仍须移除源 .ptd。
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
                // 头部有效但尺寸不完整且无 .prs：多半是上一轮在首个 save_progress 前被强杀，
                // 残留下“仅头部”的半截 .ptd。当作未完成重新加密，避免解密字节不一致。
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

    // 帧式进度显示（v2.3.0）：1 行汇总 + 每线程 1 行，按帧原地刷新
    // use_frame=false 时（输出被重定向到文件/管道且宿主未显式开启）回退旧的单行 \r 进度条。
    feui::BatchProgress progress_ui;
    const bool use_frame=progress_ui.begin(num_threads,total_bytes);

    std::atomic<size_t> file_index{0};
    std::atomic<size_t> global_processed{0};
    // 文件级计数：帧末行 FILES ... 实时反映 完成/跳过/失败，供 GUI 等宿主解析
    std::atomic<size_t> files_done{0};
    std::atomic<size_t> files_failed{0};
    std::atomic<size_t> skipped_not_ptd{0};   // worker 魔数预检发现的伪 .ptd（非加密文件）
    const size_t files_skipped=(all_files.size()-files_to_process.size())+non_ptd_skipped;
    std::mutex error_mutex;
    std::vector<std::string> error_files;
    std::chrono::steady_clock::time_point start_time=std::chrono::steady_clock::now();
    std::atomic<bool> all_ok{pre_scan_ok};
    std::atomic<bool> display_stop{false};

    // 显示线程：每 40ms 推一帧，使空闲线程行稳定刷新，不依赖 worker 回调频率。
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

    // KDF 与数据阶段分离：先以 KDF 并发上限（默认 4）集中派生全部 KEK，再让数据阶段
    // 独占全部 worker。Argon2id 是内存带宽瓶颈型，并发再高墙钟也不降；若把派生混在数据
    // 阶段里，16 个 worker 会堵在 4 个信号量许可上，实际只有 4 路在干活。
    std::unordered_map<std::string, std::array<unsigned char,ARGON2_SALT_LEN>> salt_cache;
    if(encrypt) {
        // 盐先于派生随机生成：加密侧 KEK 只依赖 (密码, 盐, ops, mem)，可提前算好
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
                    // 读头失败或密码派生失败都不缓存：worker 会自行派生并给出原样报错
                    if(!got) continue;
                    std::lock_guard<std::mutex> lk(kdf_mu);
                    kek_cache.emplace(f,std::move(kek));
                }
            });
        }
        for(auto& kt:kdf_threads) kt.join();
    }

    auto worker=[&](int slot) {
        // 线程结束时清空自己的槽位（置空闲），避免最后一帧残留已完成文件的进度
        struct SlotGuard {
            feui::BatchProgress* ui;
            int slot;
            ~SlotGuard() { if(ui) ui->setSlot(slot,std::string(),0,0,false); }
        } guard{use_frame ? &progress_ui : nullptr,slot};

        while(true) {
            size_t idx=file_index.fetch_add(1);
            if(idx>=files_to_process.size()) break;
            const auto& in_path=files_to_process[idx];

            // 分卷输入（base 不存在、只有 foo.001.ptd）先合并成完整件
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
                    // 输出路径逃出目标目录（路径穿越）：跳过该文件，绝不回退到源路径，
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
                // 还原文件名（与预扫描一致）：默认关闭以省去每文件 KDF
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
            // 原子落盘：与单文件路径同一套守卫。进程被强杀（GUI 取消=杀进程树）
            // 或崩溃时，最终路径上不留半截密文，只留可辨识的 .fe_tmp_ 残留。
            // 临时名按最终路径确定性派生，worker 并发处理不同源文件时互不干扰。
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
                            // 帧模式：只更新槽位状态，实际绘制由显示线程按帧节流完成
                            progress_ui.setSlot(slot,in_path,processed,total,true);
                            progress_ui.setProcessed(global_processed.load());
                        }
                        else {
                            static std::mutex print_mutex;
                            std::lock_guard<std::mutex> lock(print_mutex);
                            print_progress(global_processed.load(),total_bytes,start_time,false);
                        }
                    },true,compress_level,false,nullptr,wm,enc_salt,enc_kek);
                // 自校验已过才提交：此刻最终路径上要么是完整密文，要么什么都没有
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
                // 伪 .ptd 预检：magic 不匹配直接按 SKIP 跳过，
                // 避免普通文件误冠 .ptd 后白跑一次 Argon2id 再误报 Failed。
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
                // 解密成功后处理源 .ptd（-de 删除 / 擦除 / 回收站）；
                // 输入来自分卷时，每一卷都要处置
                if(ok && source_action!=0) {
                    // 输入来自分卷时每一卷都要处置；plan.volumes 为空说明
                    // 归一阶段没认出分卷，退回按 base 名兜底枚举
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
                // 仅真正成功处理的文件才补齐进度并计入 files_done；分卷失败从 file_ok 摘掉
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
                    if(write_sha256_enabled()) write_sha256_sidecar(out_path); // 功能10：校验单
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
                // 单文件失败仅记录并继续（统一 Failed: 前缀供 GUI 统计），不中断整批
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
        threads.emplace_back(worker,i);   // 每个 worker 绑定一个显示槽位（帧的第 i+2 行）
    }
    for(auto& t:threads) {
        t.join();
    }
    // 停止显示线程后再收尾，避免最后一帧被后台线程覆盖
    display_stop.store(true);
    if(display_thread.joinable()) display_thread.join();

    if(error_files.empty()) {
        // 全部成功：安全地拉满到 100%（任务中途失败文件已不会拉满）
        global_processed=total_bytes;
    }
    // 有失败文件：按真实已处理字节收尾，不掩盖失败/跳过情况
    if(use_frame) {
        progress_ui.setProcessed(global_processed.load());
        progress_ui.setFileStats(files_done.load(),files_failed.load(),
                                 files_skipped+skipped_not_ptd.load(),files_to_process.size());
        progress_ui.finish();            // 渲染最终帧并换行收尾
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

    // 清空中缓存的派生密钥，避免明文残留于进程内存
    for(auto& kv:kek_cache) sodium_memzero(kv.second.data(), kv.second.size());
    kek_cache.clear();

    // 宿主（GUI）可通过环境变量指定统计文件，批量结束时写入 JSON 供宿主解析。
    // 不用 fopen(wb)：trunc 打开会跟随攻击者预置的符号链接，把统计内容写进别处。
    // 目标可能已存在（Qt 侧 QTemporaryFile 会先建好空文件），故用「拒绝跟随链接」
    // 而非 O_EXCL——后者会让宿主永远读不到统计。
    if(const char* stats_path=std::getenv("FILEENCRYPTOR_STATS_FILE")) {
        FILE* sf=nullptr;
        bool blocked=path_is_symlink(stats_path);
        if(blocked) {
            fprintf(stderr,"Refusing to write stats through a symlink: %s\n",stats_path);
        }
#ifndef _WIN32
        // O_NOFOLLOW：末分量是符号链接则 ELOOP，不顺着它写到别处
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
        // MSVC 无 O_NOFOLLOW；上面的句柄级重解析点判定已挡掉链接
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