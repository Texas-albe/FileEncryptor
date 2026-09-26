// FileEncryptorLocator - 定位 FileEncryptor CLI 可执行文件
// 查找顺序：环境变量 FILEENCRYPTOR_EXE > 外壳 exe 同目录 > PATH；Windows 加 .exe 后缀，其它平台不加。
#pragma once
#include <QString>
#include <QStringList>

class FileEncryptorLocator {
public:
    // 返回找到的完整路径；找不到返回空串。
    static QString locate();
    // 外壳 exe 所在目录（供 UI 显示当前查找上下文）
    static QString selfDir();
    static QString version();
    // GUI 自身版本（单一来源；main/MainWindow/AboutDialogs 统一读取）
    static QString guiVersion();
    // CLI 下载页 URL
    static QString cliDownloadUrl();
    // 生成带版本号的可执行文件名列表
    static QStringList getExpectedNames();
    // 检查是否存在符合命名规则的 CLI 程序（带版本号）
    static bool existsWithVersion(QString* foundPath=nullptr);
};
