// 成就核心服务 Minecraft 进度格式
#pragma once
#include <QString>
#include <QStringList>
#include <QVector>
#include <QMap>
#include <QMutex>
#include <functional>

// 文本组件 三语
struct AdvText {
    QString text;
    QString textEn;
    QString textRu;

    QString of(const QString& lang) const;
};

// 准则定义
struct CriterionDef {
    QString trigger;
    // 计数下限 hasMin=false 触发即达成
    bool hasMin=false;
    qint64 min=0;
    // 计数上限
    bool hasMax=false;
    qint64 max=0;
};

// 显示信息
struct AdvDisplay {
    QString icon;
    AdvText title;
    AdvText desc;
    // task goal challenge
    QString frame=QStringLiteral("task");
    // 仅根进度有效
    QString background;
    bool showToast=true;
    // 未完成时隐藏自身与子树
    bool hidden=false;
};

// 进度定义
struct AdvDef {
    QString id;
    bool hasParent=false;
    QString parent;
    bool hasDisplay=false;
    AdvDisplay display;
    // 准则名 -> 定义
    QMap<QString, CriterionDef> criteria;
    // 子列表间 AND 内部 OR
    QList<QStringList> requirements;
    bool hasReqs=false;
    int experience=0;
};

// 进度状态 对齐 MC 玩家文件
struct AdvState {
    // 准则名 -> 达成时刻
    QMap<QString, QString> criteria;
    // 准则名 -> 累计计数
    QMap<QString, qint64> progress;
    bool done=false;
};

class AchievementService {
public:
    // 列表面板条目
    struct Entry {
        AdvDef def;
        AdvState state;
        bool visible=false;
    };

    static AchievementService& instance();

    // 解锁回调 toast
    std::function<void(const AdvDef&)> onUnlocked;

    // 读定义与状态
    bool load();
    // 事件计数判解锁
    // 返回本次新完成
    QVector<AdvDef> observe(const QString& ev, qint64 n=1);
    // 列表面板用 仅可见项
    QVector<Entry> entries() const;
    // 完成度概览
    QPair<int,int> progress() const;

private:
    AchievementService()=default;
    AdvState& stateOf(const QString& id);
    static bool isDone(const AdvDef& d, const AdvState& st);
    bool visible(const AdvDef& d, QMap<QString,bool>& cache) const;
    void pruneTree();
    static QString now();
    void save() const;

    QVector<AdvDef> defs_;
    // id -> 定义
    QMap<QString, AdvDef> index_;
    // id -> 状态
    QMap<QString, AdvState> state_;
    mutable QMutex mutex_;
};
