// FileEncryptorLocator 实现
#include "FileEncryptorLocator.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcessEnvironment>

#ifdef Q_OS_WIN
static const QStringList kExeNames={
    QStringLiteral("FileEncryptorCLI-2.1.1-Windows.exe"),
    QStringLiteral("FileEncryptorCLI.exe"),
    QStringLiteral("FileEncryptor.exe"),
    QStringLiteral("file-encryptor-cli.exe"),
    QStringLiteral("fe.exe"),
};
#else
static const QStringList kExeNames={
    QStringLiteral("FileEncryptorCLI-2.1.1-Linux"),
    QStringLiteral("FileEncryptorCLI"),
    QStringLiteral("FileEncryptor"),
    QStringLiteral("file-encryptor-cli"),
    QStringLiteral("fe"),
};
#endif

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
    for(const QString& name:kExeNames) {
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

QString FileEncryptorLocator::version() {
    return QStringLiteral("2.1.1");
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