#include "source_handling.hpp"
#include "FileEncryptor.hpp"
#include <sodium.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "shell32.lib")   // SHFileOperationW

// 公共 Windows SDK(winnt.h) 未声明 REPARSE_DATA_BUFFER，故本地定义以解析符号链接重解析点；
// 若日后引入 DDK 的 ntifs.h 可移除。
#ifndef REPARSE_DATA_BUFFER
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#endif
#else
#include <unistd.h>   // readlink（符号链接目标解析）
#endif

// 覆写缓冲大小：与加密块一致（1 MiB），仅影响擦写吞吐，不影响擦除效果
static const size_t FE_WIPE_CHUNK = 1024*1024;

static bool source_still_exists(const std::string& path) {
    std::ifstream f;
    return open_stream(f,path,std::ios::binary);
}

// 解析符号链接得到目标路径（相对目标按链接所在目录绝对化）；失败返回空串。
// M25：解析与后续打开之间无法做到原子（TOCTOU），换链竞态的残留风险
// 在此标注——本仓未实现按 inode/fd 的覆写，故只能以路径级复核缓解。
static std::string resolve_link_target(const std::string& path) {
#ifdef _WIN32
    const std::wstring w=utf8_to_wstring(path);
    HANDLE h=CreateFileW(w.c_str(),0,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE) return std::string();
    std::vector<char> buf(16384,0);
    DWORD ret=0;
    std::string out;
    if(DeviceIoControl(h,FSCTL_GET_REPARSE_POINT,nullptr,0,
            buf.data(),(DWORD)buf.size(),&ret,nullptr) && ret>0) {
        const auto* rp=reinterpret_cast<const REPARSE_DATA_BUFFER*>(buf.data());
        if(rp->ReparseTag==IO_REPARSE_TAG_SYMLINK) {
            const USHORT off=rp->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR);
            const USHORT len=rp->SymbolicLinkReparseBuffer.PrintNameLength/sizeof(WCHAR);
            const WCHAR* pn=rp->SymbolicLinkReparseBuffer.PathBuffer+off;
            std::wstring t(pn,len);
            if(t.find(L':')==std::wstring::npos && !t.empty() && t[0]!=L'\\') {
                // 相对符号链接：按链接所在目录拼成绝对路径
                const size_t slash=path.find_last_of("/\\");
                t=utf8_to_wstring(slash==std::string::npos
                    ? std::string() : path.substr(0,slash+1))+t;
            }
            out=wstring_to_utf8(t);
        }
    }
    CloseHandle(h);
    return out;
#else
    std::vector<char> buf(4096,0);
    const ssize_t n=::readlink(path.c_str(),buf.data(),buf.size()-1);
    if(n<=0) return std::string();
    buf[(size_t)n]=0;
    std::string t(buf.data());
    if(!t.empty() && t[0]!='/' && t.find(':')==std::string::npos) {
        // 相对符号链接：按链接所在目录拼成绝对路径
        const size_t slash=path.find_last_of("/\\");
        t=(slash==std::string::npos) ? t : path.substr(0,slash+1)+t;
    }
    return t;
#endif
}

bool secure_handle_source(const std::string& path, SourceDisposition disp) {
    if(disp==SourceDisposition::Keep) return true;
#ifdef __ANDROID__
    // SAF fd 模型无覆写能力（DocumentsContract 不提供随机写句柄），也无统一回收站语义，
    // Wipe/Recycle 一律降级为直接删除（与「擦除铁律仅限入盘模式」一致）；
    // 桌面路径模式保留完整三遍覆写 / 回收站语义。
    if(disp==SourceDisposition::Wipe || disp==SourceDisposition::Recycle)
        return remove_file_utf8(path);
#endif
    // M25：输入是符号链接时，明文在链接指向的目标里。Delete/Wipe/Recycle 都
    // 必须同时处置解析后的目标（删除 / 覆写），只删链接会把「删除源文件」的
    // 承诺落空、明文原样留在磁盘上。
    std::string link_target;
    const bool is_link=path_is_symlink(path);
    if(is_link) {
        link_target=resolve_link_target(path);
        if(link_target.empty()) {
            // 解析不出目标：只删链接本身，目标明文无法定位处置（降级并说明）
            return remove_file_utf8(path);
        }
    }
    const std::string& target = is_link ? link_target : path;

    if(disp==SourceDisposition::Delete) {
        // 符号链接只移除链接自身（remove 语义即如此），但解析出的目标文件
        // 是真正的明文源，一并删除
        if(!remove_file_utf8(target)) return false;
        if(is_link) remove_file_utf8(path);
        return true;
    }
    if(disp==SourceDisposition::Recycle) {
#ifdef _WIN32
        std::wstring wpath=utf8_to_wstring(target);   // 处置解析后的目标
        wpath.push_back(L'\0'); wpath.push_back(L'\0');   // SHFileOperation 要求双 NUL 结尾
        SHFILEOPSTRUCTW op{};
        op.wFunc = FO_DELETE;
        op.pFrom = wpath.c_str();
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        int r = SHFileOperationW(&op);
        if(r==0 && !op.fAnyOperationsAborted) {
            if(is_link) remove_file_utf8(path);
            return true;
        }
        // SHFileOperationW 存在"返回失败 / fAnyOperationsAborted 误置但文件确已移走"的情况，
        // 故以原路径是否仍存在为最终判据，避免把已成功的受控删除误报为失败。
        if(!source_still_exists(target)) {
            if(is_link) remove_file_utf8(path);
            return true;
        }
        // 回收站不可用（如网络路径）回退为直接删除，避免明文残留于原路径
        if(remove_file_utf8(target)) {
            if(is_link) remove_file_utf8(path);
            return true;
        }
        return false;
#else
        if(remove_file_utf8(target)) {   // 非 Windows：回收站语义不统一，回退直接删除
            if(is_link) remove_file_utf8(path);
            return true;
        }
        return false;
#endif
    }
    if(disp==SourceDisposition::Wipe) {
        // 多遍覆写（0x00 / 0xFF / 随机）后删除；任一遍写入失败即标记 wipe_failed， 但仍尝试删除文件避免明文残留，返回 false
        // 告知调用者擦除不完整。 注意：SSD 上软件覆写仅 NIST Clear 级，因磨损均衡无法保证物理块被覆写。
        // 符号链接：覆写解析出的目标（明文所在），完成后目标与链接一并删除。
        // TOCTOU：path_is_symlink 判定与打开之间链接可被换走，换链后覆写会作用到
        // 新目标；本仓未实现 fd 级（按 inode）覆写，残留风险在此标注。
        // 只读文件先放开写权限（Windows 是属性位，POSIX 是权限位），否则打不开写句柄就只能干删
        clear_readonly_attribute(target);
        std::fstream f;
        if(!open_stream(f,target,std::ios::in|std::ios::out|std::ios::binary)) {
            return remove_file_utf8(path);
        }
        f.seekp(0,std::ios::end);
        std::streamoff sz=f.tellp();
        if(!f||sz<0) {
            // 量不出长度就不该声称擦除过：保留文件并返回失败，交回用户处置
            f.close();
            fprintf(stderr,"Wipe aborted: cannot determine size of source file: %s\n",path.c_str());
            return false;
        }
        f.seekp(0,std::ios::beg);
        std::vector<unsigned char> buf(FE_WIPE_CHUNK);
        const unsigned char pat[2]={0x00,0xFF};
        bool wipe_failed=false;
        for(int pass=0; pass<3; ++pass) {
            f.seekp(0,std::ios::beg);
            f.clear();
            unsigned long long remaining=(unsigned long long)(sz>0?sz:0);
            while(remaining>0) {
                size_t n=(size_t)std::min<unsigned long long>(FE_WIPE_CHUNK, remaining);
                if(pass==2) randombytes_buf(buf.data(),n);
                else std::memset(buf.data(), pat[pass&1], n);
                f.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)n);
                if(!f) { wipe_failed=true; break; }
                remaining-=n;
            }
            f.flush();
            if(wipe_failed) break;
        }
        f.close();
        sodium_memzero(buf.data(), buf.size());
        bool deleted=remove_file_utf8(target);
        if(is_link) remove_file_utf8(path);   // 链接本身：目标已处置，顺手删掉
        return deleted && !wipe_failed;
    }
    return true;
}
