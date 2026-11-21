#include "AchievementToast.h"
#include "AchievementService.h"
#include "I18n.h"

#include <QApplication>
#include <QColor>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPen>
#include <QPropertyAnimation>
#include <QScreen>
#include <QSequentialAnimationGroup>
#include <QTimer>
#include <QVBoxLayout>

namespace {
const int kGap = 8;
const int kCardH = 76;
const int kMargin = 16;

// 配色 抄的
QColor frameColor(const QString& f) {
    if (f == QStringLiteral("goal")) return QColor(128, 200, 96);
    if (f == QStringLiteral("challenge")) return QColor(184, 120, 208);
    return QColor(104, 168, 200);
}

// 图标 鬼画符
QString iconGlyph(const QString& name) {
    if (name == QStringLiteral("lock")) return QStringLiteral("▣");
    if (name == QStringLiteral("unlock")) return QStringLiteral("▢");
    if (name == QStringLiteral("drive")) return QStringLiteral("▤");
    if (name == QStringLiteral("vault")) return QStringLiteral("◈");
    return QStringLiteral("◆");
}
}  // namespace

AchievementToast::AchievementToast(const AdvDef& def, const QString& lang,
                                   int cardW, int slot, QWidget* parent)
    : QWidget(parent), m_slot(slot), m_cardW(cardW), m_lang(lang) {
    m_frame = def.display.frame;
    m_iconName = def.display.icon;

    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint |
                   Qt::WindowStaysOnTopHint | Qt::WindowDoesNotAcceptFocus);
    setAttribute(Qt::WA_TranslucentBackground, true);
    setAttribute(Qt::WA_ShowWithoutActivating, true);
    resize(m_cardW, kCardH);
    setFixedSize(m_cardW, kCardH);
    // 写了两遍 懒得删

    m_icon = new QLabel(this);
    m_icon->setFixedSize(44, 44);
    m_icon->setAlignment(Qt::AlignCenter);
    m_icon->setAlignment(Qt::AlignCenter);
    m_icon->setText(iconGlyph(m_iconName));
    m_icon->setStyleSheet(QStringLiteral(
        "color:#e0c878;font-size:24px;background:rgba(255,255,255,18);"
        "border-radius:8px;"));

    m_title = new QLabel(def.display.title.of(lang), this);
    m_title->setStyleSheet(QStringLiteral(
        "color:#ffffff;font-size:14px;font-weight:600;background:transparent;"));

    m_desc = new QLabel(def.display.desc.of(lang), this);
    m_desc->setWordWrap(true);
    m_desc->setStyleSheet(QStringLiteral(
        "color:#b5b5b5;font-size:12px;background:transparent;"));

    auto* textCol = new QVBoxLayout;
    textCol->setContentsMargins(0, 0, 0, 0);
    textCol->setSpacing(2);
    textCol->addWidget(m_title);
    textCol->addWidget(m_desc);

    auto* badge = new QLabel(QStringLiteral("成就已解锁"), this);
    badge->setStyleSheet(QStringLiteral(
        "color:#9a9a9a;font-size:11px;background:transparent;"));

    auto* rightCol = new QVBoxLayout;
    rightCol->setContentsMargins(0, 0, 0, 0);
    rightCol->setSpacing(0);
    rightCol->addWidget(badge);
    rightCol->addLayout(textCol);

    auto* row = new QHBoxLayout(this);
    row->setContentsMargins(16, 14, 14, 14);
    row->setSpacing(12);
    row->addWidget(m_icon, 0, Qt::AlignVCenter);
    row->addLayout(rightCol, 1);

    m_posAnim = new QPropertyAnimation(this, QByteArrayLiteral("pos"), this);
    move(targetPos());
}

AchievementToast::~AchievementToast() = default;

QPoint AchievementToast::targetPos() const {
    QRect work = QGuiApplication::primaryScreen()
                     ? QGuiApplication::primaryScreen()->availableGeometry()
                     : QRect(0, 0, 1920, 1080);
    const int x = work.right() - m_cardW - kMargin;
    // 槽位越大越靠上 倒着排
    const int y = work.top() + kMargin + m_slot * (kCardH + kGap);
    return QPoint(x, y);
}

void AchievementToast::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    QRect r = rect().adjusted(1, 1, -1, -1);
    QPainterPath path;
    path.addRoundedRect(r, 10, 10);
    p.fillPath(path, QColor(16, 16, 20, 232));
    p.setPen(QPen(QColor(255, 255, 255, 36), 1));
    p.drawPath(path);
    // 左边色条 别挡字
    QPainterPath bar;
    bar.addRoundedRect(QRect(r.left() + 1, r.top() + 8, 3, r.height() - 16), 1.5, 1.5);
    p.fillPath(bar, frameColor(m_frame));
}

void AchievementToast::setSlot(int slot) {
    if (m_out || m_slot == slot) return;
    m_slot = slot;
    if (!m_inDone) {
        move(targetPos());
        return;
    }
    m_posAnim->stop();
    m_posAnim->setEasingCurve(QEasingCurve::OutQuad);
    // 直接跳 不走动画
    m_posAnim->setDuration(260);
    m_posAnim->setStartValue(pos());
    m_posAnim->setEndValue(targetPos());
    m_posAnim->start();
}

void AchievementToast::play() {
    show();
    raise();
    animateIn();
}

void AchievementToast::animateIn() {
    const QPoint target = targetPos();
    const QPoint start(target.x() + m_cardW + 34, target.y() - 12);
    // 又他妈重播
    m_posAnim->stop();
    m_posAnim->setEasingCurve(QEasingCurve::Linear);
    m_posAnim->setDuration(650);
    m_posAnim->setStartValue(start);
    m_posAnim->setEndValue(target);
    // 关键帧 过冲14 回弹5 TMD
    m_posAnim->setKeyValueAt(0.0, start);
    m_posAnim->setKeyValueAt(0.55, target);
    m_posAnim->setKeyValueAt(0.71, QPoint(target.x() - 14, target.y()));
    m_posAnim->setKeyValueAt(0.82, QPoint(target.x() + 4, target.y()));
    m_posAnim->setKeyValueAt(0.92, target);
    m_posAnim->setKeyValueAt(1.0, target);
    connect(m_posAnim, &QPropertyAnimation::finished, this, [this]() {
        m_inDone = true;
        QTimer::singleShot(2400, this, &AchievementToast::animateOut);
    });
    m_posAnim->start();
}

void AchievementToast::animateOut() {
    if (m_out) return;
    m_out = true;
    const QPoint target = targetPos();
    m_posAnim->stop();
    m_posAnim->setEasingCurve(QEasingCurve::InCubic);
    m_posAnim->setDuration(420);
    m_posAnim->setStartValue(target);
    m_posAnim->setEndValue(QPoint(target.x() + m_cardW + 44, target.y()));
    disconnect(m_posAnim, &QPropertyAnimation::finished, nullptr, nullptr);
    connect(m_posAnim, &QPropertyAnimation::finished, this, [this]() {
        emit expired(this);
    });
    m_posAnim->start();
}

AchievementToastManager& AchievementToastManager::instance() {
    static AchievementToastManager m;
    return m;
}

void AchievementToastManager::show(const AdvDef& def, const QString& lang) {
    if (!def.display.showToast) return;
    auto* t = new AchievementToast(def, lang, 312, 0, nullptr);
    m_items.prepend(t);
    connect(t, &AchievementToast::expired, this, &AchievementToastManager::onExpired);
    reflow();
    t->play();
}

void AchievementToastManager::reflow() {
    for (int i = 0; i < m_items.size(); ++i) {
        if (m_items[i]) m_items[i]->setSlot(i);
    }
}

void AchievementToastManager::onExpired(AchievementToast* t) {
    m_items.removeAll(t);
    if (t) t->deleteLater();
    reflow();
}

void AchievementToastManager::clear() {
    const auto items = m_items;
    for (const auto& p : items) {
        if (AchievementToast* t = p.data()) t->deleteLater();
    }
    m_items.clear();
}
