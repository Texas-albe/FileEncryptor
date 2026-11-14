#pragma once
#include <string>

// 加密后源文件处
enum class SourceDisposition : int {
    Keep   = 0,  // 保留源文件
    Delete = 1,  // 删除
    Wipe   = 2,  // 安全擦除
    Recycle= 3   // 受控删除
};

// 按 disposition 处理已成功加
bool secure_handle_source(const std::string& path, SourceDisposition disp);
