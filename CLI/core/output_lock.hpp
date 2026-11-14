// 输出侧
// 这些是「写产物」
// 都应先取锁、用 no-follow
#pragma once
#include <string>

// 跨进程输出锁结
enum class LockResult { OK, LOCKED, CANNOT_CREATE };

// 取 <out_path>.lock。成功=取
// 持有进程已退出
LockResult fe_acquire_output_lock(const std::string& out_path, std::string& lock_path);

// 进程是否存活
bool fe_process_alive(int pid);

// 以「不跟随符号链
bool fe_create_output_no_follow(const std::string& path);

// AtomicOutput 的临时路径：续传
// 在构造 AtomicOutput
std::string atomic_output_tmp_path(const std::string& final_path);

// 清掉只读属性
void clear_readonly_attribute(const std::string& path);

// 收紧密钥文件权
void tighten_file_permissions(const std::string& path);

// 删除文件
bool remove_file_utf8(const std::string& path);

// RAII
struct OutputLockGuard {
    std::string path;
    bool owned;
    ~OutputLockGuard() {
        if(owned && !path.empty()) remove_file_utf8(path);
    }
};
