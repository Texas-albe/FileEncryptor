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

// 公共 Windows SDK
// 若日后引入 DDK
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
#include <unistd.h>   // readlink
#endif

// 覆写缓冲大小
static const size_t FE_WIPE_CHUNK = 1024*1024;

static bool source_still_exists(const std::string& path) {
    std::ifstream f;
    return open_stream(f,path,std::ios::binary);
}

// 解析符号链接
// M25
// 在此标注本仓未
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
                // 相对符号链接
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
        // 相对符号链接
        const size_t slash=path.find_last_of("/\\");
        t=(slash==std::string::npos) ? t : path.substr(0,slash+1)+t;
    }
    return t;
#endif
}

bool secure_handle_source(const std::string& path, SourceDisposition disp) {
    if(disp==SourceDisposition::Keep) return true;
#ifdef __ANDROID__
    // SAF fd 模型无覆写能力
    // Wipe/Recycle 一律降级
    // 桌面路径模式保
    if(disp==SourceDisposition::Wipe || disp==SourceDisposition::Recycle)
        return remove_file_utf8(path);
#endif
    // M25
    // 必须同时处置解
    // 承诺落空、明文原
    std::string link_target;
    const bool is_link=path_is_symlink(path);
    if(is_link) {
        link_target=resolve_link_target(path);
        if(link_target.empty()) {
            // 解析不出目标
            return remove_file_utf8(path);
        }
    }
    const std::string& target = is_link ? link_target : path;

    if(disp==SourceDisposition::Delete) {
        // 符号链接只移除
        // 是真正
        if(!remove_file_utf8(target)) return false;
        if(is_link) remove_file_utf8(path);
        return true;
    }
    if(disp==SourceDisposition::Recycle) {
#ifdef _WIN32
        std::wstring wpath=utf8_to_wstring(target);   // 处置解析
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
        // SHFileOperationW 存在"返回失败 /
        // 故以原路径是否
        if(!source_still_exists(target)) {
            if(is_link) remove_file_utf8(path);
            return true;
        }
        // 回收站不可用
        if(remove_file_utf8(target)) {
            if(is_link) remove_file_utf8(path);
            return true;
        }
        return false;
#else
        if(remove_file_utf8(target)) {   // 非 Windows
            if(is_link) remove_file_utf8(path);
            return true;
        }
        return false;
#endif
    }
    if(disp==SourceDisposition::Wipe) {
        // 多遍覆写
        // 告知调用者擦除
        // 符号链接
        // TOCTOU
        // 新目标
        // 只读文件先放开
        clear_readonly_attribute(target);
        std::fstream f;
        if(!open_stream(f,target,std::ios::in|std::ios::out|std::ios::binary)) {
            return remove_file_utf8(path);
        }
        f.seekp(0,std::ios::end);
        std::streamoff sz=f.tellp();
        if(!f||sz<0) {
            // 量不出长度
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
        if(is_link) remove_file_utf8(path);   // 链接本身
        return deleted && !wipe_failed;
    }
    return true;
}
