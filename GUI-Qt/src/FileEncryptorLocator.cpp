#include "FileEncryptorLocator.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcessEnvironment>


static bool isExecutable(const QString& path) {
    QFileInfo fi(path);
    return fi.exists()&&fi.isFile()&&fi.isExecutable();
}

QString FileEncryptorLocator::selfDir() {
    return QCoreApplication::applicationDirPath();
}

// 按候选名探测目
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
    // 环境变量
    const QString envPath=qEnvironmentVariable("FILEENCRYPTOR_EXE");
    if(!envPath.isEmpty()&&isExecutable(envPath)) {
        return envPath;
    }

    // 同目录
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
    return QStringLiteral("3.1.1");
}

// GUI 自身版本
QString FileEncryptorLocator::guiVersion() {
    return QStringLiteral("3.1.1");
}

QString FileEncryptorLocator::cliDownloadUrl() {
    return QStringLiteral("https://github.com/Texas-albe/FileEncryptor/releases/tag/GUI3.1.1_CLI3.1.1");
}

QStringList FileEncryptorLocator::getExpectedNames() {
    const QString ver=version();
#ifdef Q_OS_WIN
    return {
        QStringLiteral("FileEncryptorCLI-%1-cmd-Windows.exe").arg(ver),
        // 预发布后缀
        // 但 CLI 自报版本带
        QStringLiteral("FileEncryptorCLI-3.1.1-cmd-Windows.exe"),
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

// 加密盘挂载持有
QStringList FileEncryptorLocator::getMounterExpectedNames() {
#ifdef Q_OS_WIN
    return { QStringLiteral("FE-Mounter.exe"), QStringLiteral("fe-mounter.exe") };
#else
    return { QStringLiteral("FE-Mounter"), QStringLiteral("fe-mounter") };
#endif
}

// 按指定候选名探
static QString findInDirWithNames(const QString& dir,const QStringList& names);

QString FileEncryptorLocator::locateMounter() {
    // 环境变量
    const QString envPath=qEnvironmentVariable("FE_MOUNTER_EXE");
    if(!envPath.isEmpty()&&isExecutable(envPath)) return envPath;
    // 同目录
    QString found=findInDirWithNames(selfDir(),getMounterExpectedNames());
    if(!found.isEmpty()) return found;
    // 3) PATH
    const QProcessEnvironment env=QProcessEnvironment::systemEnvironment();
    for(const QString& p:env.value("PATH").split(QDir::listSeparator(),Qt::SkipEmptyParts)) {
        found=findInDirWithNames(p,getMounterExpectedNames());
        if(!found.isEmpty()) return found;
    }
    return {};
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

// 把 "2.7.1" 解析成三元组
static bool parseVersion(const QString& s,int* maj,int* min,int* pat) {
    if(s.isEmpty()) return false;
    const QStringList parts=s.split(QLatin1Char('.'));
    if(parts.isEmpty()||parts.size()>3) return false;
    int v[3]={0,0,0};
    for(int i=0;i<parts.size();++i) {
        bool ok=false;
        v[i]=parts.at(i).toInt(&ok);
        if(!ok||v[i]<0) return false;
    }
    *maj=v[0]; *min=v[1]; *pat=v[2];
    return true;
}

// 三元组比较
static bool verLess(int amaj,int amin,int apat,int bmaj,int bmin,int bpat) {
    if(amaj!=bmaj) return amaj<bmaj;
    if(amin!=bmin) return amin<bmin;
    return apat<bpat;
}

// "FileEncryptorCLI
static bool cliVersionOfFile(const QString& fileName,int* maj,int* min,int* pat) {
    const QString prefix=QStringLiteral("FileEncryptorCLI-");
    if(!fileName.startsWith(prefix,Qt::CaseInsensitive)) return false;
    QString rest=fileName.mid(prefix.size());
    // 版本号后面必跟 '-cmd-'
    int end=rest.indexOf(QLatin1Char('-'));
    if(end<0) end=rest.indexOf(QLatin1Char('.'));
    if(end<=0) return false;
    return parseVersion(rest.left(end),maj,min,pat);
}

QStringList FileEncryptorLocator::cleanupOutdated(const QString& keepPath) {
    QStringList removed;
    int wantMaj=0,wantMin=0,wantPat=0;
    if(!parseVersion(version(),&wantMaj,&wantMin,&wantPat)) return removed;

    // 只看程序目录
    QDir dir(selfDir());
    if(!dir.exists()) return removed;

    const QString keepFull=keepPath.isEmpty()?QString():QFileInfo(keepPath).absoluteFilePath();
    const QStringList entries=dir.entryList(QDir::Files|QDir::NoDotAndDotDot,QDir::Name);
    for(const QString& name:entries) {
        int maj=0,min=0,pat=0;
        if(!cliVersionOfFile(name,&maj,&min,&pat)) continue;
        // 只删严格低于目
        // 免得用户手动放
        if(!verLess(maj,min,pat,wantMaj,wantMin,wantPat)) continue;
        if(!keepFull.isEmpty()&&QFileInfo(dir.absoluteFilePath(name)).absoluteFilePath()==keepFull) continue;
        if(QFile::remove(dir.absoluteFilePath(name))) removed<<name;
        // 删不掉
    }
    return removed;
}

bool FileEncryptorLocator::existsWithVersion(QString* foundPath) {
    const QStringList names=getExpectedNames();

    // 三条命中路径统
    // 探测
    auto finish=[foundPath](const QString& p)->bool {
        cleanupOutdated(p);
        if(foundPath) *foundPath=p;
        return true;
    };

    const QString envPath=qEnvironmentVariable("FILEENCRYPTOR_EXE");
    if(!envPath.isEmpty()&&isExecutable(envPath)) return finish(envPath);

    QString found=findInDirWithNames(selfDir(),names);
    if(!found.isEmpty()) return finish(found);

    const QProcessEnvironment env=QProcessEnvironment::systemEnvironment();
    for(const QString& p:env.value("PATH").split(QDir::listSeparator(),Qt::SkipEmptyParts)) {
        found=findInDirWithNames(p,names);
        if(!found.isEmpty()) return finish(found);
    }

    // 没找到
    cleanupOutdated(QString());
    return false;
}