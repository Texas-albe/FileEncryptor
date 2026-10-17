// 输出侧的并发与落盘保障：跨进程输出锁、防符号链接写穿、原子替换、权限收紧。
//
// 这些是「写产物」的共同前置条件：任何可能覆盖同一输出的路径（加密/解密/密钥文件）
// 都应先取锁、用 no-follow 的方式创建、写完再原子替换。
#pragma once
#include <string>

// 跨进程输出锁结果
enum class LockResult { OK, LOCKED, CANNOT_CREATE };

// 取 <out_path>.lock。成功=取得锁；已锁定=被存活进程持有；无法创建=权限或路径问题。
// 持有进程已退出的失效锁会被回收后重试。
LockResult fe_acquire_output_lock(const std::string& out_path, std::string& lock_path);

// 进程是否存活（用于判定锁是否失效）
bool fe_process_alive(int pid);

// 以「不跟随符号链接」的方式创建/截断输出文件，杜绝被链接劫持写穿到无关路径。
bool fe_create_output_no_follow(const std::string& path);

// 清掉只读属性（Windows 属性位 / POSIX 属主写位），为覆写做准备
void clear_readonly_attribute(const std::string& path);

// 收紧密钥文件权限到 0600 语义（Windows 写真正 DACL：当前用户 + SYSTEM，阻断继承）
void tighten_file_permissions(const std::string& path);

// 删除文件（UTF-8 路径；定义在 output_lock.cpp，返回 bool）
bool remove_file_utf8(const std::string& path);

// RAII：析构时删除锁文件（持有且非空）
struct OutputLockGuard {
    std::string path;
    bool owned;
    ~OutputLockGuard() {
        if(owned && !path.empty()) remove_file_utf8(path);
    }
};
