#include "mapped_file.hpp"
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

MappedFile::~MappedFile() { close(); }

MappedFile::MappedFile(MappedFile&& o) noexcept
    : data_(o.data_), size_(o.size_), error_(std::move(o.error_))
#ifdef _WIN32
    , file_handle_(o.file_handle_), map_handle_(o.map_handle_)
#else
    , fd_(o.fd_)
#endif
{
    o.data_ = nullptr; o.size_ = 0;
#ifdef _WIN32
    o.file_handle_ = nullptr; o.map_handle_ = nullptr;
#else
    o.fd_ = -1;
#endif
}

MappedFile& MappedFile::operator=(MappedFile&& o) noexcept {
    if (this != &o) {
        close();
        data_ = o.data_; size_ = o.size_; error_ = std::move(o.error_);
#ifdef _WIN32
        file_handle_ = o.file_handle_; map_handle_ = o.map_handle_;
        o.file_handle_ = nullptr; o.map_handle_ = nullptr;
#else
        fd_ = o.fd_; o.fd_ = -1;
#endif
        o.data_ = nullptr; o.size_ = 0;
    }
    return *this;
}

bool MappedFile::open(const std::string& path) {
    close();
#ifdef _WIN32
    // UTF-8 转宽字符
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) { error_ = "path conversion failed"; return false; }
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wlen);

    file_handle_ = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        file_handle_ = nullptr; error_ = "cannot open file"; return false;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(file_handle_, &sz)) { error_ = "cannot get file size"; close(); return false; }
    size_ = (size_t)sz.QuadPart;
    if (size_ == 0) { error_ = "empty file"; close(); return false; }

    map_handle_ = CreateFileMappingW(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map_handle_) { error_ = "CreateFileMapping failed"; close(); return false; }
    data_ = (unsigned char*)MapViewOfFile(map_handle_, FILE_MAP_READ, 0, 0, 0);
    if (!data_) { error_ = "MapViewOfFile failed"; close(); return false; }
    return true;
#else
    fd_ = ::open(path.c_str(), O_RDONLY);
    if (fd_ < 0) { error_ = "cannot open file"; return false; }
    struct stat st;
    if (fstat(fd_, &st) != 0) { error_ = "cannot stat file"; close(); return false; }
    size_ = (size_t)st.st_size;
    if (size_ == 0) { error_ = "empty file"; close(); return false; }
    void* p = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (p == MAP_FAILED) { error_ = "mmap failed"; close(); return false; }
    data_ = (unsigned char*)p;
    return true;
#endif
}

void MappedFile::close() {
#ifdef _WIN32
    if (data_) { UnmapViewOfFile(data_); data_ = nullptr; }
    if (map_handle_) { CloseHandle(map_handle_); map_handle_ = nullptr; }
    if (file_handle_) { CloseHandle(file_handle_); file_handle_ = nullptr; }
#else
    if (data_) { munmap(data_, size_); data_ = nullptr; }
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
#endif
    size_ = 0;
}
