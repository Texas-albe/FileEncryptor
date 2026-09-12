// PasswordDialog 实现
#include "PasswordDialog.h"
#include "PasswordStrength.h"
#include "MsgBox.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QToolButton>
#include <QFont>
#include <QPainter>
#include <QPixmap>
#include <QPainterPath>
#include <QPalette>
#include <QColor>
#include <QStyle>
#include <QStyleOption>

// 自定义密码框：掩码态以 * 显示（QLineEdit 默认用圆点，且未提供 setPasswordCharacter 接口）。
class EyeLineEdit : public QLineEdit {
public:
    using QLineEdit::QLineEdit;
protected:
    void paintEvent(QPaintEvent* e) override;
};

void EyeLineEdit::paintEvent(QPaintEvent*) {
    QPainter p(this);
    QStyleOptionFrame opt;
    initStyleOption(&opt);
    style()->drawPrimitive(QStyle::PE_PanelLineEdit, &opt, &p, this);

    const QRect content = style()->subElementRect(QStyle::SE_LineEditContents, &opt, this);
    const int textH = p.fontMetrics().height();
    const QString real = text();

    p.setFont(font());
    p.setRenderHint(QPainter::TextAntialiasing);

    if (real.isEmpty()) {
        if (!hasFocus()) {
            p.setPen(palette().color(QPalette::PlaceholderText));
            p.drawText(content, Qt::AlignLeft | Qt::AlignVCenter, placeholderText());
        } else if (!isReadOnly()) {
            const int top = (height() - textH) / 2;
            p.fillRect(content.left(), top, 1, textH, palette().color(QPalette::WindowText));
        }
        return;
    }

    // 掩码态用 * 代表每个字符；明文态显示真实内容
    const QString disp = (echoMode() == QLineEdit::Password)
                         ? QString(real.length(), QLatin1Char('*'))
                         : real;
    p.setPen(palette().color(QPalette::WindowText));
    p.drawText(content, Qt::AlignLeft | Qt::AlignVCenter, disp);

    // 光标（获得焦点时显示，非只读）
    if (hasFocus() && !isReadOnly()) {
        const int cp = cursorPosition();
        const int x = content.left() + p.fontMetrics().horizontalAdvance(disp.left(cp));
        const int top = (height() - textH) / 2;
        p.fillRect(x, top, 1, textH, palette().color(QPalette::WindowText));
    }
}

// 小眼睛图标：visible=true 睁眼，false 闭眼（叠加斜杠）。颜色与文本框文字一致。
static QIcon makeEyeIcon(bool visible, const QColor& color) {
    const int S = 22;
    QPixmap pm(S, S);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(QPen(color, 1.6));
    p.setBrush(Qt::NoBrush);

    // 眼眶（上下眼睑构成的水滴形眼睛）
    QPainterPath eye;
    eye.moveTo(4, S / 2.0);
    eye.quadTo(S / 2.0, S / 2.0 - 8, S - 4, S / 2.0);
    eye.quadTo(S / 2.0, S / 2.0 + 8, 4, S / 2.0);
    p.drawPath(eye);

    // 瞳孔
    p.setBrush(color);
    p.drawEllipse(QPointF(S / 2.0, S / 2.0), 2.6, 2.6);

    if (!visible) {
        // 闭眼斜杠
        p.drawLine(QLineF(5, 5, S - 5, S - 5));
    }
    return QIcon(pm);
}

PasswordDialog::PasswordDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("输入口令"));
    setMinimumWidth(380);

    auto* lay = new QVBoxLayout(this);
    lay->setSpacing(8);

    auto* purpose = new QLabel(tr("请输入口令："));
    m_purposeLabel = purpose;
    lay->addWidget(purpose);

    m_pw = new EyeLineEdit;
    m_pw->setEchoMode(QLineEdit::Password);
    m_pw->setPlaceholderText(tr("口令（经 stdin 注入子进程，不留盘）"));
    setupEye(m_pw);
    lay->addWidget(m_pw);

    // 强度提示（实时）
    auto* strengthRow = new QHBoxLayout;
    auto* lblStrength = new QLabel(tr("强度："));
    m_strength = new QLabel(tr("未输入"));
    m_strength->setAlignment(Qt::AlignCenter);
    QFont f = m_strength->font();
    f.setBold(true);
    f.setPointSize(f.pointSize() + 2);
    m_strength->setFont(f);
    strengthRow->addWidget(lblStrength);
    strengthRow->addWidget(m_strength);
    strengthRow->addStretch();
    lay->addLayout(strengthRow);

    // 二次确认（默认隐藏，setRequireConfirm 开启）
    m_confirm = new EyeLineEdit;
    m_confirm->setEchoMode(QLineEdit::Password);
    m_confirm->setPlaceholderText(tr("再次输入以确认"));
    setupEye(m_confirm);
    m_confirm->setVisible(false);
    lay->addWidget(m_confirm);

    // 按钮行
    auto* btnRow = new QHBoxLayout;
    m_ok = new QPushButton(tr("确定"));
    auto* cancel = new QPushButton(tr("取消"));
    btnRow->addStretch();
    btnRow->addWidget(m_ok);
    btnRow->addWidget(cancel);
    lay->addLayout(btnRow);

    connect(m_ok, &QPushButton::clicked, this, &PasswordDialog::onAccept);
    connect(cancel, &QPushButton::clicked, this, &PasswordDialog::reject);
    connect(m_pw, &QLineEdit::textChanged, this, &PasswordDialog::onTextChanged);

    onTextChanged();
}

// 在密码框右侧（框内）放置小眼睛按钮：透明背景与文本框一致；
// 按住显示明文，松开恢复掩码（以 * 表示），图标在睁眼/闭眼间切换。
void PasswordDialog::setupEye(QLineEdit* le) {
    const QColor c = le->palette().color(QPalette::WindowText);

    auto* btn = new QToolButton(le);
    btn->setCursor(Qt::ArrowCursor);
    btn->setIcon(makeEyeIcon(/*visible=*/false, c));   // 默认闭眼（掩码态）
    btn->setToolTip(tr("按住显示密码，松开隐藏"));
    btn->setStyleSheet(QStringLiteral("QToolButton{border:none;background:transparent;}"));
    btn->setFixedSize(22, 22);

    // 把眼睛按钮放到密码框右侧内部（透明背景，与文本框一致）
    auto* lay = new QHBoxLayout(le);
    lay->setContentsMargins(0, 0, 2, 0);
    lay->setSpacing(0);
    lay->addStretch();
    lay->addWidget(btn);

    // 右侧预留空间，避免输入文字被按钮遮挡
    le->setTextMargins(0, 0, 24, 0);

    // 按住小眼睛显示明文，松开恢复掩码
    connect(btn, &QToolButton::pressed, this, [le, btn, c]() {
        le->setEchoMode(QLineEdit::Normal);
        btn->setIcon(makeEyeIcon(/*visible=*/true, c));
    });
    connect(btn, &QToolButton::released, this, [le, btn, c]() {
        le->setEchoMode(QLineEdit::Password);
        btn->setIcon(makeEyeIcon(/*visible=*/false, c));
    });
}

PasswordDialog::~PasswordDialog() {
    if (!m_secret.empty()) {
        std::memset(m_secret.data(), 0, m_secret.size());
        m_secret.clear();
    }
}

void PasswordDialog::setPurpose(const QString& purpose) {
    m_purposeLabel->setText(purpose);
}

void PasswordDialog::setRequireConfirm(bool on) {
    m_requireConfirm = on;
    m_confirm->setVisible(on);
}

void PasswordDialog::onTextChanged() {
    const StrengthResult r = PasswordStrength::evaluate(m_pw->text());
    m_strength->setText(r.label);
    m_strength->setStyleSheet(QStringLiteral("color:%1;").arg(r.colorHex));
    m_strength->setToolTip(r.detail);
}

bool PasswordDialog::validate(QString& reason) {
    const QString pw = m_pw->text();
    if (pw.isEmpty()) {
        reason = tr("口令不能为空。");
        return false;
    }
    if (!PasswordStrength::meetsPolicy(pw, reason)) {
        return false;
    }
    if (m_requireConfirm && m_confirm->text() != pw) {
        reason = tr("两次输入的口令不一致。");
        return false;
    }
    return true;
}

void PasswordDialog::onAccept() {
    QString reason;
    if (!validate(reason)) {
        MsgBox::error(this, tr("口令无效"), reason);
        return;
    }
    // 取出口令（UTF-8 字节），随后清掉输入框明文
    const QByteArray b = m_pw->text().toUtf8();
    m_secret.assign(b.begin(), b.end());
    m_pw->clear();
    m_confirm->clear();
    accept();
}

std::vector<unsigned char> PasswordDialog::takePassword() {
    std::vector<unsigned char> out;
    out.swap(m_secret);   // 移动，原缓冲置空
    return out;
}
