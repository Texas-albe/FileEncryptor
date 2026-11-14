// 任务历史持久化
#pragma once
#include <QString>
#include <QStringList>
#include <QVector>

struct TaskRecord {
    QString id;
    QString startedAt;
    QString finishedAt;
    qint64  durationMs=0;
    QString action;
    QString actionLabel;
    QString mode;
    // 非对称模式
    QString fileCipher;
    int     inputCount=0;
    QStringList inputPaths;
    qint64  totalBytes=0;
    int     filesDone=0;
    int     filesSkip=0;
    int     filesFail=0;
    QString outputDir;
    int     exitCode=0;
    bool    cancelled=false;
    QString error;
    QString status;
    int     sourceIndex=0;
    bool    force=false;
    bool    sha256=false;
    bool    compress=false;
    int     compressionLevel=0;
    bool    pqc=true;
    bool    watermark=false;
    QString watermarkKey;
    QString keyfile;
    QString recipient;
    QString identity;
    // 密钥包装
    QString wrapInput;
    QString wrapOutput;
    QString wrapAlg;
    bool    restoreName=false;
    // 打包
    bool    pack=false;
    QString intoVault;
};

class TaskHistory {
public:
    static QString dir();
    static QString filePath();

    // 追加一条记录
    static bool append(const TaskRecord& r,QString& err);
    // 读取全部记录
    static bool load(QVector<TaskRecord>& out,QString& err);
    static bool clear(QString& err);
    // 保存列表
    static bool save(const QVector<TaskRecord>& records,QString& err);
    // 裁剪到
    static bool prune(int keepLatest,QString& err);

    static QString newId();
    static QString actionLabel(const QString& actionKey);
};
