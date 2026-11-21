// 成就解锁 Toast 无边框置顶窗
#pragma once
#include <QWidget>
#include <QPointer>
#include <QVector>

class QPaintEvent;
class QLabel;
class QPropertyAnimation;
struct AdvDef;

// 单条通知卡 自绘圆角半透明
class AchievementToast : public QWidget {
    Q_OBJECT
public:
    // def 定义 lang 语言码 cardW 卡宽 slot 槽位
    AchievementToast(const AdvDef& def, const QString& lang, int cardW, int slot,
                     QWidget* parent = nullptr);
    ~AchievementToast() override;

    // 槽位改变 平滑下移
    void setSlot(int slot);
    // 播滑入 停留 滑出
    void play();

signals:
    // 退场完毕 请求回收
    void expired(AchievementToast* self);

protected:
    void paintEvent(QPaintEvent* e) override;

private:
    QPoint targetPos() const;
    void animateIn();
    void animateOut();

    QLabel* m_icon = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_desc = nullptr;
    QPropertyAnimation* m_posAnim = nullptr;
    int m_slot = 0;
    int m_cardW = 312;
    QString m_lang;
    QString m_frame;
    QString m_iconName;
    bool m_inDone = false;
    bool m_out = false;
};

// 队列管理器 维护堆叠与回收
class AchievementToastManager : public QObject {
    Q_OBJECT
public:
    static AchievementToastManager& instance();

    // 弹一条 def 定义 lang 语言码
    void show(const AdvDef& def, const QString& lang);
    // 退出清场
    void clear();

private:
    AchievementToastManager() = default;
    void reflow();
    void onExpired(AchievementToast* t);

    QVector<QPointer<AchievementToast>> m_items;
};
