// FileEncryptorLocator - 定位 FileEncryptor CLI 可执行文件
// CLI/GUI 拆分为独立项目后的查找策略（三段）：
//   1) 环境变量 FILEENCRYPTOR_EXE（绝对路径，显式覆盖）
//   2) 外壳 exe 同目录（打包发布的常见布局）
//   3) PATH 查找（Linux/macOS 安装到 /usr/bin 后）
// 跨平台：Windows 加 .exe 后缀；其它平台不加。
#pragma once
#include <QString>
#include <QStringList>

class FileEncryptorLocator {
public:
    // 返回找到的完整路径；找不到返回空串。
    static QString locate();
    // 外壳 exe 所在目录（供 UI 显示当前查找上下文）
    static QString selfDir();
    // 获取当前程序版本号
    static QString version();
    // 生成带版本号的可执行文件名列表
    static QStringList getExpectedNames();
    // 检查是否存在符合命名规则的 CLI 程序（带版本号）
    static bool existsWithVersion(QString* foundPath=nullptr);
};