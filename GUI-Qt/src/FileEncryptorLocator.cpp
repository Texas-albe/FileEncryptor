#include "FileEncryptorLocator.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcessEnvironment>


static bool isExecutable(const QString& path) {
    QFileInfo fi(path);
    return fi.exists()&&fi.isFile()&&fi.isExecutable();
}

QString FileEncryptorLocator::selfDir() {
    return QCoreApplication::applicationDirPath();
}

// 按候选名探测目录
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


// 配套 CLI 版本
QString FileEncryptorLocator::version() {
    return QStringLiteral("2.7.0");
}

// GUI 自身版本
QString FileEncryptorLocator::guiVersion() {
    return QStringLiteral("2.1.0");
}

QString FileEncryptorLocator::cliDownloadUrl() {
    return QStringLiteral("https://github.com/Texas-albe/FileEncryptor/releases/tag/GUI2.1.0_CLI2.7.0");
}

QStringList FileEncryptorLocator::getExpectedNames() {
    const QString ver=version();
#ifdef Q_OS_WIN
    return {
        QStringLiteral("FileEncryptorCLI-%1-cmd-Windows.exe").arg(ver),
        QStringLiteral("FileEncryptorCLI.exe"),
        QStringLiteral("FileEncryptor.exe"),
        QStringLiteral("file-encryptor-cli.exe"),
        QStringLiteral("fe.exe"),
    };
#else
    return {
        QStringLiteral("FileEncryptorCLI-%1-cmd-Linux").arg(ver),
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

    const QString envPath=qEnvironmentVariable("FILEENCRYPTOR_EXE");
    if(!envPath.isEmpty()&&isExecutable(envPath)) {
        if(foundPath) *foundPath=envPath;
        return true;
    }

    QString found=findInDirWithNames(selfDir(),names);
    if(!found.isEmpty()) {
        if(foundPath) *foundPath=found;
        return true;
    }

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
