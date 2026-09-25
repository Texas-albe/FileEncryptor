#include "source_handling.hpp"
#include "FileEncryptor.hpp"
#include <sodium.h>
#include <vector>
#include <fstream>
#include <algorithm>

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
        // 多遍覆写（0x00 / 0xFF / 随机）后删除，使残留磁介质无法恢复明文
#ifdef _WIN32
        clear_readonly_attribute(path);
#endif
        std::fstream f;
        if(!open_stream(f,path,std::ios::in|std::ios::out|std::ios::binary)) {
            return remove_file_utf8(path);   // 打不开则直接删除兜底
        }
        f.seekg(0,std::ios::end);
        std::streamoff sz=f.tellg();
        f.seekg(0,std::ios::beg);
        std::vector<unsigned char> buf(FE_WIPE_CHUNK);
        const unsigned char pat[2]={0x00,0xFF};
        for(int pass=0; pass<3; ++pass) {
            f.seekg(0,std::ios::beg);
            unsigned long long remaining=(unsigned long long)(sz>0?sz:0);
            while(remaining>0) {
                size_t n=(size_t)std::min<unsigned long long>(FE_WIPE_CHUNK, remaining);
                if(pass==2) randombytes_buf(buf.data(),n);
                else std::memset(buf.data(), pat[pass&1], n);
                f.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)n);
                if(!f) break;
                remaining-=n;
            }
            f.flush();
        }
        f.close();
        sodium_memzero(buf.data(), buf.size());
        return remove_file_utf8(path);
    }
    return true;
}
