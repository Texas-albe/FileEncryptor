// P0-1 进程对象 DACL 加固（仅 Windows 有意义）
//
// 收紧自身进程对象 DACL 为「当前用户 + SYSTEM + Administrators」并阻断继承，
// 使同机其他非特权用户无法 OpenProcess 读走口令/派生密钥/明文缓冲，也无法注入。
// 失败静默：加固属纵深防御，不应阻断 GUI 启动。
#pragma once

namespace OsHarden {

// 幂等，可在启动时调用一次；非 Windows 平台为空实现。
void hardenProcessDacl();

// P1-2 镜像加载策略：禁远程 / 低完整性镜像，系统 DLL 强制走 System32。
void hardenImageLoadPolicy();

// P1-3 把自身登记进 WER 排除列表，不再产生崩溃转储。
void disableCrashDump();

// P2 调试器检测（仅用于告警，不做阻断）
bool isDebuggerAttached();

}
