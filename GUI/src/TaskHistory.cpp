// TaskHistory 实现（功能5）
#include "TaskHistory.h"

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
    return o;
}

// JSON 对象 → 记录（缺字段用默认值，避免旧版本数据读不出来）
TaskRecord fromJson(const QJsonObject& o) {
    TaskRecord r;
    r.id          =o.value(QStringLiteral("id")).toString();
    r.startedAt   =o.value(QStringLiteral("startedAt")).toString();
    r.finishedAt  =o.value(QStringLiteral("finishedAt")).toString();
    r.durationMs  =static_cast<qint64>(o.value(QStringLiteral("durationMs")).toDouble(0));
    r.action      =o.value(QStringLiteral("action")).toString();
    r.actionLabel =o.value(QStringLiteral("actionLabel")).toString();
    if(r.actionLabel.isEmpty()) r.actionLabel=TaskHistory::actionLabel(r.action);
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
    return r;
}
} // namespace

// 用户配置目录（与 CLI user_config_dir() 同源：Windows %APPDATA%/FileEncryptor、
// Linux $XDG_CONFIG_HOME/fileencryptor 或 ~/.config/fileencryptor）。
// 注意：不能用 QDir::cdUp()——目录尚不存在时它会返回 false；QFileInfo::dir() 纯字符串
// 取父路径，不检查存在性，故首次使用也能正确解析历史目录。
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
    // v1.3.0：扩展名统一为 3 个字符（.log，JSONL 内容不变）；旧文件 tasks.jsonl 仍会读取。
    const QString cur=QDir::toNativeSeparators(d+QStringLiteral("/tasks.log"));
    if(QFileInfo::exists(cur)) return cur;
    const QString legacy=QDir::toNativeSeparators(d+QStringLiteral("/tasks.jsonl"));
    if(QFileInfo::exists(legacy)) return legacy;
    return cur;
}

QString TaskHistory::newId() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

QString TaskHistory::actionLabel(const QString& actionKey) {
    if(actionKey==QStringLiteral("encrypt"))        return QStringLiteral("加密 (-e)");
    if(actionKey==QStringLiteral("decrypt"))        return QStringLiteral("解密 (-d)");
    if(actionKey==QStringLiteral("batch-encrypt"))  return QStringLiteral("批量加密 (-be)");
    if(actionKey==QStringLiteral("batch-decrypt"))  return QStringLiteral("批量解密 (-bd)");
    if(actionKey==QStringLiteral("keygen"))         return QStringLiteral("生成密钥对 (-g)");
    if(actionKey==QStringLiteral("derive"))         return QStringLiteral("口令派生 (-G)");
    if(actionKey==QStringLiteral("pubkey"))         return QStringLiteral("导出公钥 (-Y)");
    return actionKey;
}

bool TaskHistory::append(const TaskRecord& r,QString& err) {
    const QString path=filePath();
    if(path.isEmpty()) { err=QStringLiteral("无法确定用户配置目录"); return false; }
    QDir d;
    if(!d.mkpath(dir())) { err=QStringLiteral("无法创建历史目录"); return false; }

    QFile f(path);
    if(!f.open(QIODevice::Append|QIODevice::Text)) {
        err=f.errorString();
        return false;
    }
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    ts << QJsonDocument(toJson(r)).toJson(QJsonDocument::Compact) << '\n';
    ts.flush();
    if(ts.status()!=QTextStream::Ok) { err=QStringLiteral("写入历史失败"); return false; }
    // 控制历史体积：每次追加后自动裁剪到最近 1000 条（裁剪失败不影响本次追加结果）。
    QString perr;
    prune(1000, perr);
    return true;
}

bool TaskHistory::load(QVector<TaskRecord>& out,QString& err) {
    out.clear();
    const QString path=filePath();
    if(path.isEmpty()) { err=QStringLiteral("无法确定用户配置目录"); return false; }
    QFile f(path);
    if(!f.exists()) return true;    // 无历史 = 空列表
    if(!f.open(QIODevice::ReadOnly|QIODevice::Text)) { err=f.errorString(); return false; }

    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    while(!ts.atEnd()) {
        const QString line=ts.readLine().trimmed();
        if(line.isEmpty()) continue;
        QJsonParseError pe;
        const QJsonDocument doc=QJsonDocument::fromJson(line.toUtf8(),&pe);
        if(pe.error!=QJsonParseError::NoError||!doc.isObject()) continue;  // 跳过损坏行
        out.push_back(fromJson(doc.object()));
    }
    // 最新在前
    std::reverse(out.begin(),out.end());
    return true;
}

bool TaskHistory::clear(QString& err) {
    const QString path=filePath();
    if(path.isEmpty()) { err=QStringLiteral("无法确定用户配置目录"); return false; }
    QFile f(path);
    if(!f.exists()) return true;
    if(f.remove()) return true;
    // Windows：刚写入的文件可能被索引/杀软短暂占用，remove 会失败。
    // 降级为截断清空——对用户而言效果等价（历史为空），不把偶发锁当成真错误。
    if(f.open(QIODevice::WriteOnly|QIODevice::Truncate)) {
        f.close();
        return true;
    }
    err=f.errorString();
    return false;
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
    // all 已是最新在前，需按时间正序写回
    for(int i=all.size()-1;i>=all.size()-keepLatest;--i)
        ts << QJsonDocument(toJson(all[i])).toJson(QJsonDocument::Compact) << '\n';
    return true;
}
