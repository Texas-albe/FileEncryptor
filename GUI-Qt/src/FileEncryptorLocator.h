// 定位 CLI 可执行文件
#pragma once
#include <QString>
#include <QStringList>

class FileEncryptorLocator {
public:
    static QString locate();
    // 外壳 exe 所在目录
    static QString selfDir();
    static QString version();
    // GUI 自身版本
    static QString guiVersion();
    // CLI 下载页 URL
    static QString cliDownloadUrl();
    // 生成带版本号的候选文件名
    static QStringList getExpectedNames();
    // 检查是否存在匹配的 CLI
    static bool existsWithVersion(QString* foundPath=nullptr);
};
