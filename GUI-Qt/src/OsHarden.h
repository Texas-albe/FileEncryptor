// P0-1 进程对象 DACL 加固
// 收紧自身进程
// 使同机其他非特
// 失败静默
#pragma once

namespace OsHarden {

void hardenProcessDacl();

// P1-2 镜像加载策略
void hardenImageLoadPolicy();

// P1-3 把自身登记进 WER 排
void disableCrashDump();

// P2 调试器检测
bool isDebuggerAttached();

}
