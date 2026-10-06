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
#include <algorithm>

namespace {
const char* kTimestampFormat="yyyy-MM-dd HH:mm:ss";

// 记录 → JSON 对象
QJsonObject toJson(const TaskRecord& r) {
    QJsonObject o;
    o.insert(QStringLiteral("v"),1);
    o.insert(QStringLiteral("id"),r.id);
    o.insert(QStringLiteral("startedAt"),r.startedAt);
    o.insert(QStringLiteral("finishedAt"),r.finishedAt);
    o.insert(QStringLiteral("durationMs"),r.durationMs);
    o.insert(QStringLiteral("action"),r.action);
    o.insert(QStringLiteral("actionLabel"),r.actionLabel);
    o.insert(QStringLiteral("mode"),r.mode);
    o.insert(QStringLiteral("inputCount"),r.inputCount);
    if(!r.inputPaths.isEmpty())
        o.insert(QStringLiteral("inputPaths"),QJsonArray::fromStringList(r.inputPaths));
    o.insert(QStringLiteral("totalBytes"),r.totalBytes);
    o.insert(QStringLiteral("filesDone"),r.filesDone);
    o.insert(QStringLiteral("outputDir"),r.outputDir);
    o.insert(QStringLiteral("exitCode"),r.exitCode);
    o.insert(QStringLiteral("cancelled"),r.cancelled);
    o.insert(QStringLiteral("error"),r.error);
    o.insert(QStringLiteral("status"),r.status);
    o.insert(QStringLiteral("filesSkip"),r.filesSkip);
    o.insert(QStringLiteral("filesFail"),r.filesFail);
    o.insert(QStringLiteral("sourceIndex"),r.sourceIndex);
    o.insert(QStringLiteral("force"),r.force);
    o.insert(QStringLiteral("sha256"),r.sha256);
    o.insert(QStringLiteral("compress"),r.compress);
    o.insert(QStringLiteral("compressionLevel"),r.compressionLevel);
    if(!r.fileCipher.isEmpty()) o.insert(QStringLiteral("fileCipher"),r.fileCipher);
    o.insert(QStringLiteral("pqc"),r.pqc);
    o.insert(QStringLiteral("watermark"),r.watermark);
    if(!r.watermarkKey.isEmpty()) o.insert(QStringLiteral("watermarkKey"),r.watermarkKey);
    if(!r.keyfile.isEmpty()) o.insert(QStringLiteral("keyfile"),r.keyfile);
    if(!r.recipient.isEmpty()) o.insert(QStringLiteral("recipient"),r.recipient);
    if(!r.identity.isEmpty()) o.insert(QStringLiteral("identity"),r.identity);
    if(!r.wrapInput.isEmpty()) o.insert(QStringLiteral("wrapInput"),r.wrapInput);
    if(!r.wrapOutput.isEmpty()) o.insert(QStringLiteral("wrapOutput"),r.wrapOutput);
    if(!r.wrapAlg.isEmpty()) o.insert(QStringLiteral("wrapAlg"),r.wrapAlg);
    o.insert(QStringLiteral("restoreName"),r.restoreName);
    o.insert(QStringLiteral("pack"),r.pack);
    if(!r.intoVault.isEmpty()) o.insert(QStringLiteral("intoVault"),r.intoVault);
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
    // 动作名一律按当前语言重新生成：文件里存的是写入时的语言，直接用会中英混杂
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

// 动作名面向用户展示，随界面语言翻译（英文不附 CLI 参数）
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
    if(actionKey==QStringLiteral("unwrap"))         return th("解开密钥 (--unwrap-key)");
    return actionKey;
}

bool TaskHistory::append(const TaskRecord& r,QString& err) {
    const QString path=filePath();
    if(path.isEmpty()) { err=th("无法确定用户配置目录"); return false; }
    QDir d;
    if(!d.mkpath(dir())) { err=th("无法创建历史目录"); return false; }
    // 历史目录收紧为 0700
    QFile::setPermissions(dir(),QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner);

    QFile f(path);
    if(!f.open(QIODevice::Append|QIODevice::Text)) {
        err=f.errorString();
        return false;
    }
    // 历史文件收紧为 0600
    f.setPermissions(QFile::ReadOwner|QFile::WriteOwner);
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    ts << QJsonDocument(toJson(r)).toJson(QJsonDocument::Compact) << '\n';
    ts.flush();
    if(ts.status()!=QTextStream::Ok) { err=th("写入历史失败"); return false; }
    // 裁剪到最近 1000 条
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
    // 最新在前
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
    QFile::setPermissions(dir(),QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner);
    QFile f(path);
    if(!f.open(QIODevice::WriteOnly|QIODevice::Text|QIODevice::Truncate)) {
        err=f.errorString();
        return false;
    }
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
