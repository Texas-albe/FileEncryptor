#pragma once
#include <cstddef>
#include <string>

// MappedFile：跨平台内存映射文件，替代大文件全量读入。 Windows 用 CreateFileMapping/MapViewOfFile，Linux 用
// mmap。 映射整个文件为只读，data() 返回首地址，size() 返回文件大小。
class MappedFile {
public:
    MappedFile() = default;
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& o) noexcept;
    MappedFile& operator=(MappedFile&& o) noexcept;

    // 映射整个文件为只读；失败返回 false，error() 含原因。
    bool open(const std::string& path);
    void close();

    const unsigned char* data() const { return data_; }
    size_t size() const { return size_; }
    bool is_open() const { return data_ != nullptr; }
    const std::string& error() const { return error_; }

private:
    unsigned char* data_ = nullptr;
    size_t size_ = 0;
    std::string error_;
#ifdef _WIN32
    void* file_handle_ = nullptr;
    void* map_handle_ = nullptr;
#else
    int fd_ = -1;
#endif
};
