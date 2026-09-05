// FileEncryptorLocator 实现
// CLI/GUI 拆分为独立项目后的查找策略（三段）：
//   1) 环境变量 FILEENCRYPTOR_EXE（绝对路径，显式覆盖）
//   2) 外壳 exe 同目录（打包发布的常见布局）
//   3) PATH 查找（Linux/macOS 安装到 /usr/bin 后）
// 跨平台：Windows 加 .exe 后缀；其它平台不加。
#include "FileEncryptorLocator.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcessEnvironment>

#ifdef Q_OS_WIN
static const QString kExeName = QStringLiteral("FileEncryptorCLI.exe");
#else
static const QString kExeName = QStringLiteral("FileEncryptorCLI");
#endif

static bool isExecutable(const QString& path) {
    QFileInfo fi(path);
    return fi.exists() && fi.isFile() && fi.isExecutable();
}

QString FileEncryptorLocator::selfDir() {
    return QCoreApplication::applicationDirPath();
}

QString FileEncryptorLocator::locate() {
    // 1) 环境变量 FILEENCRYPTOR_EXE（绝对路径，显式覆盖）
    const QString envPath = qEnvironmentVariable("FILEENCRYPTOR_EXE");
    if (!envPath.isEmpty() && isExecutable(envPath)) {
        return envPath;
    }

    const QString dir = selfDir();
    QDir d(dir);

    // 2) 外壳 exe 同目录（CLI + GUI 同目录打包发布的常见布局）
    QString cand = d.absoluteFilePath(kExeName);
    if (isExecutable(cand)) return cand;

    // 3) PATH 查找（Linux/macOS 安装到 /usr/bin 后；Windows 偶有便携需求）
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    for (const QString& p : env.value("PATH").split(QDir::listSeparator(), Qt::SkipEmptyParts)) {
        cand = QDir(p).absoluteFilePath(kExeName);
        if (isExecutable(cand)) return cand;
    }

    return {};
}
