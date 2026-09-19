// FileEncryptorLocator 实现
#include "FileEncryptorLocator.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcessEnvironment>

// 缺陷18 修复：候选文件名不再各自硬编码版本号，统一由 getExpectedNames() 从
// version() 派生，保证「期望的 CLI 版本」只有一处定义（getExpectedNames 与
// locate 共用同一份列表）。

static bool isExecutable(const QString& path) {
    QFileInfo fi(path);
    return fi.exists()&&fi.isFile()&&fi.isExecutable();
}

QString FileEncryptorLocator::selfDir() {
    return QCoreApplication::applicationDirPath();
}

// 在指定目录中按候选名依次探测
static QString findInDir(const QString& dir) {
    QDir d(dir);
    if(!d.exists()) return {};
    const QStringList names=FileEncryptorLocator::getExpectedNames();
    for(const QString& name:names) {
        const QString cand=d.absoluteFilePath(name);
        if(isExecutable(cand)) return cand;
    }
    return {};
}

QString FileEncryptorLocator::locate() {
    // 1) 环境变量
    const QString envPath=qEnvironmentVariable("FILEENCRYPTOR_EXE");
    if(!envPath.isEmpty()&&isExecutable(envPath)) {
        return envPath;
    }

    // 2) 同目录
    QString found=findInDir(selfDir());
    if(!found.isEmpty()) return found;

    // 3) PATH
    const QProcessEnvironment env=QProcessEnvironment::systemEnvironment();
    for(const QString& p:env.value("PATH").split(QDir::listSeparator(),Qt::SkipEmptyParts)) {
        found=findInDir(p);
        if(!found.isEmpty()) return found;
    }

    return {};
}

// ====== 新增函数实现 ======

// 期望的配套 CLI 版本（发布包文件名随之变化）。升级 CLI 时只需改这一处。
QString FileEncryptorLocator::version() {
    return QStringLiteral("2.3.0");
}

// GUI 自身版本（与 GUI/CMakeLists.txt project VERSION 同步）。
// 缺陷18 修复：main.cpp / MainWindow / AboutDialogs 此前各自硬编码
// "1.2.1" / "1.0.1" 三处不一致的兜底值，现统一从本函数读取。
QString FileEncryptorLocator::guiVersion() {
    return QStringLiteral("1.3.0");
}

QStringList FileEncryptorLocator::getExpectedNames() {
    const QString ver=version();
#ifdef Q_OS_WIN
    return {
        QStringLiteral("FileEncryptorCLI-%1-Windows.exe").arg(ver),
        QStringLiteral("FileEncryptorCLI.exe"),
        QStringLiteral("FileEncryptor.exe"),
        QStringLiteral("file-encryptor-cli.exe"),
        QStringLiteral("fe.exe"),
    };
#else
    return {
        QStringLiteral("FileEncryptorCLI-%1-Linux").arg(ver),
        QStringLiteral("FileEncryptorCLI"),
        QStringLiteral("FileEncryptor"),
        QStringLiteral("file-encryptor-cli"),
        QStringLiteral("fe"),
    };
#endif
}

static QString findInDirWithNames(const QString& dir,const QStringList& names) {
    QDir d(dir);
    if(!d.exists()) return {};
    for(const QString& name:names) {
        const QString cand=d.absoluteFilePath(name);
        if(isExecutable(cand)) return cand;
    }
    return {};
}

bool FileEncryptorLocator::existsWithVersion(QString* foundPath) {
    const QStringList names=getExpectedNames();

    // 1) 环境变量
    const QString envPath=qEnvironmentVariable("FILEENCRYPTOR_EXE");
    if(!envPath.isEmpty()&&isExecutable(envPath)) {
        if(foundPath) *foundPath=envPath;
        return true;
    }

    // 2) 同目录
    QString found=findInDirWithNames(selfDir(),names);
    if(!found.isEmpty()) {
        if(foundPath) *foundPath=found;
        return true;
    }

    // 3) PATH
    const QProcessEnvironment env=QProcessEnvironment::systemEnvironment();
    for(const QString& p:env.value("PATH").split(QDir::listSeparator(),Qt::SkipEmptyParts)) {
        found=findInDirWithNames(p,names);
        if(!found.isEmpty()) {
            if(foundPath) *foundPath=found;
            return true;
        }
    }

    return false;
}