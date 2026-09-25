#pragma once
#include <string>

// 加密后源文件处理方式
enum class SourceDisposition : int {
    Keep   = 0,  // 保留源文件（默认）
    Delete = 1,  // 直接删除（等价旧 -de）
    Wipe   = 2,  // 安全擦除：多遍覆写（0x00 / 0xFF / 随机）后删除
    Recycle= 3   // 受控删除：移入系统回收站（Windows: SHFileOperation FO_DELETE+FOF_ALLOWUNDO）
};

// 按 disposition 处理已成功加密的源文件；返回是否成功
// （Recycle/Wipe 失败时仍保证不残留明文于原路径——回退为直接删除）。
bool secure_handle_source(const std::string& path, SourceDisposition disp);
