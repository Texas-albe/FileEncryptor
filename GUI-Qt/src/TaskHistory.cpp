#include "TaskHistory.h"

#include <QCoreApplication>

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QUuid>
#include <QLibrary>
#include <QByteArray>
#include <algorithm>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace {
const char* kTimestampFormat="yyyy-MM-dd HH:mm:ss";

// 路径载荷加密：Windows DPAPI / Linux libsecret
static QJsonObject pathPayload(const TaskRecord& r) {
    QJsonObject p;
    p.insert(QStringLiteral("inputPaths"),QJsonArray::fromStringList(r.inputPaths));
    p.insert(QStringLiteral("outputDir"),r.outputDir);
    p.insert(QStringLiteral("intoVault"),r.intoVault);
    p.insert(QStringLiteral("keyfile"),r.keyfile);
    p.insert(QStringLiteral("identity"),r.identity);
    p.insert(QStringLiteral("wrapInput"),r.wrapInput);
    p.insert(QStringLiteral("wrapOutput"),r.wrapOutput);
    p.insert(QStringLiteral("watermarkKey"),r.watermarkKey);
    p.insert(QStringLiteral("recipient"),r.recipient);
    return p;
}

static void applyPayload(TaskRecord& r,const QJsonObject& p) {
    const QJsonArray ip=p.value(QStringLiteral("inputPaths")).toArray();
    r.inputPaths.clear();
    for(const QJsonValue& v:ip) r.inputPaths.append(v.toString());
    auto get=[&](const char* n){ return p.value(QString::fromLatin1(n)).toString(); };
    r.outputDir=get("outputDir");
    r.intoVault=get("intoVault");
    r.keyfile=get("keyfile");
    r.identity=get("identity");
    r.wrapInput=get("wrapInput");
    r.wrapOutput=get("wrapOutput");
    r.watermarkKey=get("watermarkKey");
    r.recipient=get("recipient");
}

#ifdef Q_OS_WIN
static QString encryptPaths(const TaskRecord& r) {
    const QByteArray json=QJsonDocument(pathPayload(r)).toJson(QJsonDocument::Compact);
    DATA_BLOB in;
    in.cbData=static_cast<DWORD>(json.size());
    in.pbData=reinterpret_cast<BYTE*>(const_cast<char*>(json.constData()));
    DATA_BLOB out={0,nullptr};
    if(!CryptProtectData(&in,nullptr,nullptr,nullptr,nullptr,0,&out)) return QString();
    QByteArray blob(reinterpret_cast<const char*>(out.pbData),static_cast<int>(out.cbData));
    if(out.pbData) LocalFree(out.pbData);
    return QStringLiteral("dpapi1:")+QString::fromLatin1(blob.toBase64());
}

static bool decryptPaths(const QString& ct,TaskRecord& r) {
    if(!ct.startsWith(QStringLiteral("dpapi1:"))) return false;
    const QByteArray blob=QByteArray::fromBase64(
        ct.mid(7).toLatin1());
    DATA_BLOB in;
    in.cbData=static_cast<DWORD>(blob.size());
    in.pbData=reinterpret_cast<BYTE*>(const_cast<char*>(blob.constData()));
    DATA_BLOB out={0,nullptr};
    if(!CryptUnprotectData(&in,nullptr,nullptr,nullptr,nullptr,0,&out)) return false;
    const QByteArray json(reinterpret_cast<const char*>(out.pbData),static_cast<int>(out.cbData));
    if(out.pbData) LocalFree(out.pbData);
    QJsonParseError pe;
    const QJsonDocument doc=QJsonDocument::fromJson(json,&pe);
    if(pe.error!=QJsonParseError::NoError||!doc.isObject()) return false;
    applyPayload(r,doc.object());
    return true;
}
#else
struct SecretSchema {
    const char* name;
    int flags;
    int count;
    const char** names;
    const int* types;
};
typedef int (*StoreFn)(const SecretSchema*,const char*,const char*,const char*,
                       void*,void**,...);
typedef char* (*LookupFn)(const SecretSchema*,void*,void**,...);
typedef int (*ClearFn)(const SecretSchema*,void*,void**,...);
typedef void (*FreeFn)(void*);

static bool secretCall(const QString& id,const QString* payload,TaskRecord* out) {
    QLibrary lib(QStringLiteral("libsecret-1.so.0"));
    if(!lib.load()) return false;
    auto store=reinterpret_cast<StoreFn>(lib.resolve("secret_password_store_sync"));
    auto lookup=reinterpret_cast<LookupFn>(lib.resolve("secret_password_lookup_sync"));
    auto clear=reinterpret_cast<ClearFn>(lib.resolve("secret_password_clear_sync"));
    auto gfree=reinterpret_cast<FreeFn>(lib.resolve("g_free"));
    if(payload) {
        if(!store) return false;
        static const char* names[]={"fe_task_id",nullptr};
        static const int types[]={0};
        SecretSchema schema={"com.yaoyingluo.fileencryptor.taskpath",0,1,names,types};
        const QByteArray idb=id.toUtf8(),pb=payload->toUtf8();
        int ok=store(&schema,"default","FileEncryptor task path",
                     pb.constData(),nullptr,nullptr,"fe_task_id",idb.constData(),nullptr);
        return ok!=0;
    }
    if(!lookup||!gfree||!clear) return false;
    static const char* names[]={"fe_task_id",nullptr};
    static const int types[]={0};
    SecretSchema schema={"com.yaoyingluo.fileencryptor.taskpath",0,1,names,types};
    const QByteArray idb=id.toUtf8();
    char* pw=lookup(&schema,nullptr,nullptr,"fe_task_id",idb.constData(),nullptr);
    if(!pw) return false;
    const QByteArray json(pw);
    gfree(pw);
    QJsonParseError pe;
    const QJsonDocument doc=QJsonDocument::fromJson(json,&pe);
    if(pe.error!=QJsonParseError::NoError||!doc.isObject()) return false;
    applyPayload(*out,doc.object());
    clear(&schema,nullptr,nullptr,"fe_task_id",idb.constData(),nullptr);
    return true;
}

static QString encryptPaths(const TaskRecord& r) {
    const QString id=QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString payload=QString::fromUtf8(
        QJsonDocument(pathPayload(r)).toJson(QJsonDocument::Compact));
    if(!secretCall(id,&payload,nullptr)) return QString();
    return QStringLiteral("keyring:")+id;
}

static bool decryptPaths(const QString& ct,TaskRecord& r) {
    if(!ct.startsWith(QStringLiteral("keyring:"))) return false;
    QString id=ct.mid(8);
    return secretCall(id,nullptr,&r);
}
#endif

static bool stripPaths(TaskRecord& r,QString& ct) {
    ct=encryptPaths(r);
    if(ct.isEmpty()) return false;
    r.inputPaths.clear();
    r.outputDir.clear();
    r.intoVault.clear();
    r.keyfile.clear();
    r.identity.clear();
    r.wrapInput.clear();
    r.wrapOutput.clear();
    r.watermarkKey.clear();
    r.recipient.clear();
    return true;
}

// 记录 → JSON 对象
QJsonObject toJson(const TaskRecord& r) {
    TaskRecord stored=r;
    QString ct;
    if(stripPaths(stored,ct)) stored.pathCt=ct;
    const TaskRecord& src=stored;
    QJsonObject o;
    o.insert(QStringLiteral("v"),2);
    if(!ct.isEmpty()) o.insert(QStringLiteral("pathCt"),ct);
    o.insert(QStringLiteral("id"),src.id);
    o.insert(QStringLiteral("startedAt"),src.startedAt);
    o.insert(QStringLiteral("finishedAt"),src.finishedAt);
    o.insert(QStringLiteral("durationMs"),src.durationMs);
    o.insert(QStringLiteral("action"),src.action);
    o.insert(QStringLiteral("actionLabel"),src.actionLabel);
    o.insert(QStringLiteral("mode"),src.mode);
    o.insert(QStringLiteral("inputCount"),src.inputCount);
    if(!src.inputPaths.isEmpty())
        o.insert(QStringLiteral("inputPaths"),QJsonArray::fromStringList(src.inputPaths));
    o.insert(QStringLiteral("totalBytes"),src.totalBytes);
    o.insert(QStringLiteral("filesDone"),src.filesDone);
    o.insert(QStringLiteral("outputDir"),src.outputDir);
    o.insert(QStringLiteral("exitCode"),src.exitCode);
    o.insert(QStringLiteral("cancelled"),src.cancelled);
    o.insert(QStringLiteral("error"),src.error);
    o.insert(QStringLiteral("status"),src.status);
    o.insert(QStringLiteral("filesSkip"),src.filesSkip);
    o.insert(QStringLiteral("filesFail"),src.filesFail);
    o.insert(QStringLiteral("sourceIndex"),src.sourceIndex);
    o.insert(QStringLiteral("force"),src.force);
    o.insert(QStringLiteral("sha256"),src.sha256);
    o.insert(QStringLiteral("compress"),src.compress);
    o.insert(QStringLiteral("compressionLevel"),src.compressionLevel);
    if(!src.fileCipher.isEmpty()) o.insert(QStringLiteral("fileCipher"),src.fileCipher);
    o.insert(QStringLiteral("pqc"),src.pqc);
    o.insert(QStringLiteral("watermark"),src.watermark);
    if(!src.watermarkKey.isEmpty()) o.insert(QStringLiteral("watermarkKey"),src.watermarkKey);
    if(!src.keyfile.isEmpty()) o.insert(QStringLiteral("keyfile"),src.keyfile);
    if(!src.recipient.isEmpty()) o.insert(QStringLiteral("recipient"),src.recipient);
    if(!src.identity.isEmpty()) o.insert(QStringLiteral("identity"),src.identity);
    if(!src.wrapInput.isEmpty()) o.insert(QStringLiteral("wrapInput"),src.wrapInput);
    if(!src.wrapOutput.isEmpty()) o.insert(QStringLiteral("wrapOutput"),src.wrapOutput);
    if(!src.wrapAlg.isEmpty()) o.insert(QStringLiteral("wrapAlg"),src.wrapAlg);
    o.insert(QStringLiteral("restoreName"),src.restoreName);
    o.insert(QStringLiteral("pack"),src.pack);
    if(!src.intoVault.isEmpty()) o.insert(QStringLiteral("intoVault"),src.intoVault);
    return o;
}

// JSON 对象 → 记录
TaskRecord fromJson(const QJsonObject& o) {
    TaskRecord r;
    r.id          =o.value(QStringLiteral("id")).toString();
    r.startedAt   =o.value(QStringLiteral("startedAt")).toString();
    r.finishedAt  =o.value(QStringLiteral("finishedAt")).toString();
    r.durationMs  =static_cast<qint64>(o.value(QStringLiteral("durationMs")).toDouble(0));
    r.action      =o.value(QStringLiteral("action")).toString();
    // 动作名一律
    r.actionLabel = TaskHistory::actionLabel(r.action);
    r.mode        =o.value(QStringLiteral("mode")).toString();
    r.inputCount  =o.value(QStringLiteral("inputCount")).toInt(0);
    const QJsonArray ip=o.value(QStringLiteral("inputPaths")).toArray();
    for(const QJsonValue& v:ip) r.inputPaths.append(v.toString());
    r.totalBytes  =static_cast<qint64>(o.value(QStringLiteral("totalBytes")).toDouble(0));
    r.filesDone   =o.value(QStringLiteral("filesDone")).toInt(0);
    r.outputDir   =o.value(QStringLiteral("outputDir")).toString();
    r.exitCode    =o.value(QStringLiteral("exitCode")).toInt(0);
    r.cancelled   =o.value(QStringLiteral("cancelled")).toBool(false);
    r.error       =o.value(QStringLiteral("error")).toString();
    r.status      =o.value(QStringLiteral("status")).toString();
    r.filesSkip   =o.value(QStringLiteral("filesSkip")).toInt(0);
    r.filesFail   =o.value(QStringLiteral("filesFail")).toInt(0);
    r.sourceIndex =o.value(QStringLiteral("sourceIndex")).toInt(0);
    r.force       =o.value(QStringLiteral("force")).toBool(false);
    r.sha256      =o.value(QStringLiteral("sha256")).toBool(false);
    r.compress    =o.value(QStringLiteral("compress")).toBool(false);
    r.compressionLevel=o.value(QStringLiteral("compressionLevel")).toInt(0);
    r.fileCipher     =o.value(QStringLiteral("fileCipher")).toString();
    r.pqc            =o.value(QStringLiteral("pqc")).toBool(true);
    r.watermark      =o.value(QStringLiteral("watermark")).toBool(false);
    r.watermarkKey   =o.value(QStringLiteral("watermarkKey")).toString();
    r.keyfile     =o.value(QStringLiteral("keyfile")).toString();
    r.recipient   =o.value(QStringLiteral("recipient")).toString();
    r.identity    =o.value(QStringLiteral("identity")).toString();
    r.wrapInput   =o.value(QStringLiteral("wrapInput")).toString();
    r.wrapOutput  =o.value(QStringLiteral("wrapOutput")).toString();
    r.wrapAlg     =o.value(QStringLiteral("wrapAlg")).toString();
    r.restoreName =o.value(QStringLiteral("restoreName")).toBool(false);
    r.pack        =o.value(QStringLiteral("pack")).toBool(false);
    r.intoVault   =o.value(QStringLiteral("intoVault")).toString();
    r.pathCt      =o.value(QStringLiteral("pathCt")).toString();
    if(!r.pathCt.isEmpty()) decryptPaths(r.pathCt,r);
    return r;
}
}

static QString userConfigDir() {
#ifdef Q_OS_WIN
    QString base = qEnvironmentVariable("APPDATA");
    if (base.isEmpty()) return QString();
    return QDir::toNativeSeparators(base + QStringLiteral("/FileEncryptor"));
#else
    QString base = qEnvironmentVariable("XDG_CONFIG_HOME");
    if (base.isEmpty()) {
        const QString home = QDir::homePath();
        if (home.isEmpty()) return QString();
        base = home + QStringLiteral("/.config");
    }
    return QDir::toNativeSeparators(base + QStringLiteral("/fileencryptor"));
#endif
}

QString TaskHistory::dir() {
    const QString base=userConfigDir();
    if(base.isEmpty()) return QString();
    return QDir::toNativeSeparators(base+QStringLiteral("/history"));
}

QString TaskHistory::filePath() {
    const QString d=dir();
    if(d.isEmpty()) return QString();
    const QString cur=QDir::toNativeSeparators(d+QStringLiteral("/tasks.log"));
    if(QFileInfo::exists(cur)) return cur;
    const QString legacy=QDir::toNativeSeparators(d+QStringLiteral("/tasks.jsonl"));
    if(QFileInfo::exists(legacy)) return legacy;
    return cur;
}

QString TaskHistory::newId() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

// 动作名面向用户
namespace {
QString th(const char* s) {
    return QCoreApplication::translate("TaskHistory", s);
}
}

QString TaskHistory::actionLabel(const QString& actionKey) {
    if(actionKey==QStringLiteral("encrypt"))        return th("加密 (-e)");
    if(actionKey==QStringLiteral("decrypt"))        return th("解密 (-d)");
    if(actionKey==QStringLiteral("batch-encrypt"))  return th("批量加密 (-be)");
    if(actionKey==QStringLiteral("batch-decrypt"))  return th("批量解密 (-bd)");
    if(actionKey==QStringLiteral("keygen"))         return th("生成密钥对 (-g)");
    if(actionKey==QStringLiteral("derive"))         return th("密码派生 (-G)");
    if(actionKey==QStringLiteral("pubkey"))         return th("导出公钥 (-Y)");
    if(actionKey==QStringLiteral("wrap"))           return th("包装密钥 (--wrap-key)");
    if(actionKey==QStringLiteral("unwrap"))         return th("解包密钥 (--unwrap-key)");
    return actionKey;
}

bool TaskHistory::append(const TaskRecord& r,QString& err) {
    const QString path=filePath();
    if(path.isEmpty()) { err=th("无法确定用户配置目录"); return false; }
    QDir d;
    if(!d.mkpath(dir())) { err=th("无法创建历史目录"); return false; }
    // 目录收紧
    // 注意
    // 文件实际继承
    QFile::setPermissions(dir(),QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner);

    QFile f(path);
    if(!f.open(QIODevice::Append|QIODevice::Text)) {
        err=f.errorString();
        return false;
    }
    // 历史文件收紧
    f.setPermissions(QFile::ReadOwner|QFile::WriteOwner);
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    ts << QJsonDocument(toJson(r)).toJson(QJsonDocument::Compact) << '\n';
    ts.flush();
    if(ts.status()!=QTextStream::Ok) { err=th("写入历史失败"); return false; }
    // 裁剪到
    QString perr;
    prune(1000, perr);
    return true;
}

bool TaskHistory::load(QVector<TaskRecord>& out,QString& err) {
    out.clear();
    const QString path=filePath();
    if(path.isEmpty()) { err=th("无法确定用户配置目录"); return false; }
    QFile f(path);
    if(!f.exists()) return true;
    if(!f.open(QIODevice::ReadOnly|QIODevice::Text)) { err=f.errorString(); return false; }

    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    while(!ts.atEnd()) {
        const QString line=ts.readLine().trimmed();
        if(line.isEmpty()) continue;
        QJsonParseError pe;
        const QJsonDocument doc=QJsonDocument::fromJson(line.toUtf8(),&pe);
        if(pe.error!=QJsonParseError::NoError||!doc.isObject()) continue;
        out.push_back(fromJson(doc.object()));
    }
    // 最新
    std::reverse(out.begin(),out.end());
    return true;
}

bool TaskHistory::clear(QString& err) {
    const QString path=filePath();
    if(path.isEmpty()) { err=th("无法确定用户配置目录"); return false; }
    QFile f(path);
    if(!f.exists()) return true;
    if(f.remove()) return true;
    // Windows 占用时降级截断
    if(f.open(QIODevice::WriteOnly|QIODevice::Truncate)) {
        f.close();
        return true;
    }
    err=f.errorString();
    return false;
}


bool TaskHistory::save(const QVector<TaskRecord>& records,QString& err) {
    const QString path=filePath();
    if(path.isEmpty()) { err=th("无法确定用户配置目录"); return false; }
    QDir d;
    if(!d.mkpath(dir())) { err=th("无法创建历史目录"); return false; }
    // 0700
    QFile::setPermissions(dir(),QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner);
    QFile f(path);
    if(!f.open(QIODevice::WriteOnly|QIODevice::Text|QIODevice::Truncate)) {
        err=f.errorString();
        return false;
    }
    // 0600
    f.setPermissions(QFile::ReadOwner|QFile::WriteOwner);
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    // 按时间正序写回
    for(int i=records.size()-1;i>=0;--i)
        ts << QJsonDocument(toJson(records[i])).toJson(QJsonDocument::Compact) << '\n';
    return true;
}

bool TaskHistory::prune(int keepLatest,QString& err) {
    QVector<TaskRecord> all;
    if(!load(all,err)) return false;
    if(all.size()<=keepLatest) return true;

    const QString path=filePath();
    QFile f(path);
    if(!f.open(QIODevice::WriteOnly|QIODevice::Text|QIODevice::Truncate)) {
        err=f.errorString();
        return false;
    }
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    for(int i=keepLatest-1;i>=0;--i)
        ts << QJsonDocument(toJson(all[i])).toJson(QJsonDocument::Compact) << '\n';
    return true;
}
