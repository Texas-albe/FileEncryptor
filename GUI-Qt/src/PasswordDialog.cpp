// PasswordDialog 实现
#include "PasswordDialog.h"
#include "PasswordStrength.h"
#include "MsgBox.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QAction>
#include <QFont>
#include <QPainter>
#include <QPixmap>
#include <QPainterPath>
#include <QPalette>
#include <QColor>

// 安全擦除：见 secure_zero.h（MainWindow 与 PasswordDialog 共用）。
#include "secure_zero.h"

// 不再使用自绘的 EyeLineEdit。
//   缺陷9（自绘）：完全接管 paintEvent 会绕开 QLineEdit 内置的输入法预编辑（IME）、
//   选区高亮、长文本滚动与 RTL 布局，深色主题下还需自配文字颜色，极易与平台行为漂移；
//  掩码字符随系统用标准圆点显示（QLineEdit 未公开 setPasswordCharacter，自绘仅为换 *），
//   权衡后放弃 * 掩码，回归标准回显。
//   缺陷8（布局）：此前把 QHBoxLayout 直接塞进 QLineEdit 并手工 setTextMargins 预留
//   眼睛按钮位置，与 QLineEdit 内部几何管理相互干扰，主题/字体变化时文字可能被按钮
//   遮挡。改用 QLineEdit 自带的 addAction(TrailingPosition)，由控件自行排布尾部动作并
//   自动处理文本避让。

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

    m_pw = new QLineEdit;
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
    m_confirm = new QLineEdit;
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

// 在密码框右侧放置小眼睛动作（QLineEdit::TrailingPosition，控件自行管理布局）：
// 点击在掩码/明文间切换，图标随之切换。颜色取当前调色板文字色，主题切换后仍可读。
void PasswordDialog::setupEye(QLineEdit* le) {
    const QColor c = le->palette().color(QPalette::WindowText);
    QAction* act = le->addAction(makeEyeIcon(/*visible=*/false, c), QLineEdit::TrailingPosition);
    act->setToolTip(tr("点击显示/隐藏密码"));
    connect(act, &QAction::triggered, le, [le, act](bool) {
        const bool showing = (le->echoMode() == QLineEdit::Normal);
        le->setEchoMode(showing ? QLineEdit::Password : QLineEdit::Normal);
        act->setIcon(makeEyeIcon(!showing, le->palette().color(QPalette::WindowText)));
    });
}

PasswordDialog::~PasswordDialog() {
    // std::memset + clear 会被优化成 dead store；用 volatile 逐字节写零确保真擦除。
    secure_zero(m_secret.data(), m_secret.size());
    m_secret.clear();
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
