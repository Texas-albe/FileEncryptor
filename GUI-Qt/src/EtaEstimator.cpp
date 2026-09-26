// EtaEstimator 实现（功能6）
#include "EtaEstimator.h"

#include <QObject>
#include <algorithm>
#include <cmath>

namespace {
// 最近样本上限：越多越平滑，但过旧样本可能来自完全不同的硬件/场景
const int kMaxSamples=10;

// 一条记录是否可作为速率样本：必须完整成功、有字节量与耗时
bool usableSample(const TaskRecord& r) {
    return r.status==QStringLiteral("success") && !r.cancelled
           && r.totalBytes>0 && r.durationMs>0;
}

// 取吞吐中位数（比均值抗离群：一次异常慢的任务不会拖垮后续所有预估）
double medianRate(const QVector<TaskRecord>& recs,int limit) {
    QVector<double> rates;
    rates.reserve(limit);
    for(int i=0;i<recs.size()&&rates.size()<limit;++i) {
        if(!usableSample(recs[i])) continue;
        rates.push_back(static_cast<double>(recs[i].totalBytes)
                        /(static_cast<double>(recs[i].durationMs)/1000.0));
    }
    if(rates.isEmpty()) return 0.0;
    std::sort(rates.begin(),rates.end());
    const int n=rates.size();
    return (n%2) ? rates[n/2] : (rates[n/2-1]+rates[n/2])/2.0;
}

// 分层取样：先 action+mode，再 action，最后全体
double pickRate(const QString& action,const QString& mode,
                const QVector<TaskRecord>& history,int* sampleCount) {
    QVector<TaskRecord> exact,byAction;
    for(const TaskRecord& r : history) {
        if(!usableSample(r)) continue;
        if(r.action==action) {
            byAction.push_back(r);
            if(r.mode==mode) exact.push_back(r);
        }
    }
    double rate=medianRate(exact,kMaxSamples);
    int used=std::min<int>(static_cast<int>(exact.size()),kMaxSamples);
    if(rate<=0.0) {
        rate=medianRate(byAction,kMaxSamples);
        used=std::min<int>(static_cast<int>(byAction.size()),kMaxSamples);
    }
    if(rate<=0.0) {
        int total=0;
        for(const TaskRecord& r : history) if(usableSample(r)) ++total;
        rate=medianRate(history,kMaxSamples);
        used=std::min(total,kMaxSamples);
    }
    if(sampleCount) *sampleCount=used;
    return rate;
}
} // namespace

EtaEstimator::Estimate EtaEstimator::estimate(qint64 bytes,const QString& action,
                                              const QString& mode,
                                              const QVector<TaskRecord>& history) {
    Estimate e;
    if(bytes<=0) return e;
    const double rate=pickRate(action,mode,history,&e.sampleCount);
    if(rate<=0.0) return e;      // 无样本 → 无法预估
    e.bytesPerSec=rate;
    e.totalMs=static_cast<qint64>(std::llround(static_cast<double>(bytes)/rate*1000.0));
    e.remainingMs=e.totalMs;
    e.valid=true;
    return e;
}

EtaEstimator::Estimate EtaEstimator::fromProgress(int done,int total,qint64 elapsedMs,
                                                  const Estimate& hist) {
    Estimate e=hist;
    if(done<=0||total<=0||elapsedMs<=0) return e;   // 尚无进度 → 沿用历史预估
    if(done>=total) { e.remainingMs=0; e.totalMs=elapsedMs; e.valid=true; e.fromProgress=true; return e; }

    // 按完成比例外推总耗时；再与历史预估做加权（进度越多越信任实时值）
    const double frac=static_cast<double>(done)/static_cast<double>(total);
    const qint64 liveTotal=static_cast<qint64>(std::llround(static_cast<double>(elapsedMs)/frac));
    if(hist.valid) {
        const double w=frac;    // 进度权重
        e.totalMs=static_cast<qint64>(std::llround(liveTotal*w+hist.totalMs*(1.0-w)));
    } else {
        e.totalMs=liveTotal;
    }
    e.remainingMs=std::max<qint64>(0,e.totalMs-elapsedMs);
    e.valid=true;
    e.fromProgress=true;
    return e;
}

QString EtaEstimator::formatDuration(qint64 ms) {
    if(ms<0) return QStringLiteral("--");
    if(ms<1000) return QObject::tr("%1 毫秒").arg(ms);
    const qint64 totalSec=ms/1000;
    if(totalSec<60) return QObject::tr("%1 秒").arg(totalSec);
    const qint64 h=totalSec/3600;
    const qint64 m=(totalSec%3600)/60;
    const qint64 s=totalSec%60;
    if(h>0)
        return QStringLiteral("%1:%2:%3").arg(h).arg(m,2,10,QChar('0')).arg(s,2,10,QChar('0'));
    return QStringLiteral("%1:%2").arg(m,2,10,QChar('0')).arg(s,2,10,QChar('0'));
}

QString EtaEstimator::formatRate(double bytesPerSec) {
    if(bytesPerSec<=0.0) return QStringLiteral("--");
    const double mb=bytesPerSec/(1024.0*1024.0);
    if(mb>=1.0) return QObject::tr("%1 MB/s").arg(QString::number(mb,'f',1));
    const double kb=bytesPerSec/1024.0;
    if(kb>=1.0) return QObject::tr("%1 KB/s").arg(QString::number(kb,'f',1));
    return QObject::tr("%1 B/s").arg(QString::number(bytesPerSec,'f',0));
}

QString EtaEstimator::formatBytes(qint64 bytes) {
    if(bytes<0) return QStringLiteral("--");
    const double gb=static_cast<double>(bytes)/(1024.0*1024.0*1024.0);
    if(gb>=1.0) return QObject::tr("%1 GB").arg(QString::number(gb,'f',2));
    const double mb=static_cast<double>(bytes)/(1024.0*1024.0);
    if(mb>=1.0) return QObject::tr("%1 MB").arg(QString::number(mb,'f',1));
    const double kb=static_cast<double>(bytes)/1024.0;
    if(kb>=1.0) return QObject::tr("%1 KB").arg(QString::number(kb,'f',1));
    return QObject::tr("%1 B").arg(bytes);
}
