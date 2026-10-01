// 批量任务剩余时间预估
#pragma once
#include <QString>
#include <QVector>
#include "TaskHistory.h"

class EtaEstimator {
public:
    struct Estimate {
        bool    valid=false;
        qint64  totalMs=0;
        qint64  remainingMs=0;
        double  bytesPerSec=0.0;
        int     sampleCount=0;
        bool    fromProgress=false;
    };

    // 按历史样本预估耗时
    static Estimate estimate(qint64 bytes,const QString& action,const QString& mode,
                             const QVector<TaskRecord>& history);

    // 运行中外推剩余时间
    static Estimate fromProgress(int done,int total,qint64 elapsedMs,const Estimate& hist);

    static QString formatDuration(qint64 ms);
    static QString formatRate(double bytesPerSec);
    static QString formatBytes(qint64 bytes);
};
