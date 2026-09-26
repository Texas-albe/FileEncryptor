// EtaEstimator - 批量任务剩余时间预估（功能6）
// 历史速率取 TaskHistory 完整成功记录吞吐中位数（按 action+mode 分层取样）；运行中按完成比例实时外推，有实时进度时以实时值为准，否则退回历史速率。
#pragma once
#include <QString>
#include <QVector>
#include "TaskHistory.h"

class EtaEstimator {
public:
    struct Estimate {
        bool    valid=false;        // 是否给出有效预估
        qint64  totalMs=0;          // 预估总耗时
        qint64  remainingMs=0;      // 预估剩余（= totalMs - elapsedMs）
        double  bytesPerSec=0.0;    // 采用的吞吐（字节/秒）
        int     sampleCount=0;      // 历史样本数（0 = 纯实时外推）
        bool    fromProgress=false; // true=实时外推；false=历史速率
    };

    // 基于历史样本预估处理 bytes 字节所需时间
    static Estimate estimate(qint64 bytes,const QString& action,const QString& mode,
                             const QVector<TaskRecord>& history);

    // 运行中：按已完成/总数比例外推剩余时间；done<=0 时退回历史预估
    static Estimate fromProgress(int done,int total,qint64 elapsedMs,const Estimate& hist);

    static QString formatDuration(qint64 ms);
    static QString formatRate(double bytesPerSec);
    static QString formatBytes(qint64 bytes);
};
