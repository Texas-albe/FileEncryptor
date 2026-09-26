// TaskHistory - 任务历史持久化（功能5）
// 存储布局（与 CLI/GUI 其余用户数据同根，路径统一经 QDir::toNativeSeparators 归一化）：
//   <用户配置目录>/history/tasks.log
// 每行一条 JSON 记录（JSONL：追加写、顺序读，单条损坏不影响其余条目）。
// 记录一次运行的动作/模式/输入规模/耗时/结果，供历史面板回放，并为功能6（批量 ETA）
// 提供速率样本。
#pragma once
#include <QString>
#include <QStringList>
#include <QVector>

struct TaskRecord {
    QString id;              // 唯一标识（UUID 无花括号）
    QString startedAt;       // "yyyy-MM-dd HH:mm:ss"（本地时间）
    QString finishedAt;      // 同上；未完成为空
    qint64  durationMs=0;    // 实际耗时
    QString action;          // 机器键：encrypt/decrypt/batch-encrypt/batch-decrypt/keygen/derive/pubkey
    QString actionLabel;     // 显示名（中文）
    QString mode;            // 机器键：xchacha20/aegis256/asymmetric
    int     inputCount=0;    // 输入路径数
    QStringList inputPaths;  // 输入路径原列表（回放时恢复到输入列表原位；旧记录无此字段）
    qint64  totalBytes=0;    // 输入数据总量（目录递归统计）
    int     filesDone=0;     // CLI 已开始处理的文件数（取消时用于估算保留数）
    QString outputDir;       // -o（空=源目录）
    int     exitCode=0;
    bool    cancelled=false;
    QString error;
    QString status;          // success / failed / cancelled
};

class TaskHistory {
public:
    static QString dir();
    static QString filePath();

    // 追加一条记录；目录不存在时自动创建
    static bool append(const TaskRecord& r,QString& err);
    // 读取全部记录（最新在前）；文件不存在视为空历史（返回 true）
    static bool load(QVector<TaskRecord>& out,QString& err);
    static bool clear(QString& err);
    // 仅保留最近 keepLatest 条（超出部分丢弃）
    static bool prune(int keepLatest,QString& err);

    static QString newId();
    static QString actionLabel(const QString& actionKey);
};
