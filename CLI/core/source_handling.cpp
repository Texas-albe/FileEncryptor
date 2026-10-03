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
#endif

// 覆写缓冲大小：与加密块一致（1 MiB），仅影响擦写吞吐，不影响擦除效果
static const size_t FE_WIPE_CHUNK = 1024*1024;

static bool source_still_exists(const std::string& path) {
    std::ifstream f;
    return open_stream(f,path,std::ios::binary);
}

bool secure_handle_source(const std::string& path, SourceDisposition disp) {
    if(disp==SourceDisposition::Keep) return true;
    if(disp==SourceDisposition::Delete) {
        // 符号链接只移除链接自身（remove 语义即如此），不跟随到目标
        return remove_file_utf8(path);
    }
    if(disp==SourceDisposition::Recycle) {
#ifdef _WIN32
        std::wstring wpath=utf8_to_wstring(path);
        wpath.push_back(L'\0'); wpath.push_back(L'\0');   // SHFileOperation 要求双 NUL 结尾
        SHFILEOPSTRUCTW op{};
        op.wFunc = FO_DELETE;
        op.pFrom = wpath.c_str();
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
        int r = SHFileOperationW(&op);
        if(r==0 && !op.fAnyOperationsAborted) return true;
        // SHFileOperationW 存在"返回失败 / fAnyOperationsAborted 误置但文件确已移走"的情况，
        // 故以原路径是否仍存在为最终判据，避免把已成功的受控删除误报为失败。
        if(!source_still_exists(path)) return true;
        // 回收站不可用（如网络路径）回退为直接删除，避免明文残留于原路径
        return remove_file_utf8(path);
#else
        return remove_file_utf8(path);   // 非 Windows：回收站语义不统一，回退直接删除
#endif
    }
    if(disp==SourceDisposition::Wipe) {
        // 多遍覆写（0x00 / 0xFF / 随机）后删除；任一遍写入失败即标记 wipe_failed， 但仍尝试删除文件避免明文残留，返回 false
        // 告知调用者擦除不完整。 注意：SSD 上软件覆写仅 NIST Clear 级，因磨损均衡无法保证物理块被覆写。
        // 符号链接：明文不在链接里，覆写会写到链接指向的目标上（等于破坏无关文件），只删链接
        if(path_is_symlink(path)) return remove_file_utf8(path);
        // 只读文件先放开写权限（Windows 是属性位，POSIX 是权限位），否则打不开写句柄就只能干删
        clear_readonly_attribute(path);
        std::fstream f;
        if(!open_stream(f,path,std::ios::in|std::ios::out|std::ios::binary)) {
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
        bool deleted=remove_file_utf8(path);
        return deleted && !wipe_failed;
    }
    return true;
}
