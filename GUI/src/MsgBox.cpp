// MsgBox 实现
#include "MsgBox.h"

static QMessageBox::Icon toQtIcon(MsgBox::Icon icon) {
    switch (icon) {
    case MsgBox::Icon::Warning:  return QMessageBox::Warning;
    case MsgBox::Icon::Error:    return QMessageBox::Critical;
    case MsgBox::Icon::Question: return QMessageBox::Question;
    case MsgBox::Icon::Info:
    default:                     return QMessageBox::Information;
    }
}

QMessageBox::StandardButton MsgBox::show(QWidget* parent, Icon icon,
    const QString& title, const QString& text, QMessageBox::StandardButtons buttons) {
    QMessageBox box(parent);
    box.setIcon(toQtIcon(icon));
    box.setWindowTitle(title);
    box.setText(text);
    box.setStandardButtons(buttons);
    box.setMinimumWidth(360);
    if (parent) box.setWindowModality(Qt::WindowModal);
    return static_cast<QMessageBox::StandardButton>(box.exec());
}

void MsgBox::showAsync(QWidget* parent, Icon icon, const QString& title,
    const QString& text, QMessageBox::StandardButtons buttons,
    std::function<void(QMessageBox::StandardButton)> cb) {
    auto* box = new QMessageBox(parent);
    box->setIcon(toQtIcon(icon));
    box->setWindowTitle(title);
    box->setText(text);
    box->setStandardButtons(buttons);
    box->setMinimumWidth(360);
    if (parent) box->setWindowModality(Qt::WindowModal);
    // 用 Qt5+ 的 finished(int) 信号：用户关闭后回调并自动销毁
    QObject::connect(box, QOverload<int>::of(&QMessageBox::finished),
        box, [box, cb](int result) {
            if (cb) cb(static_cast<QMessageBox::StandardButton>(result));
            box->deleteLater();
        });
    box->open();
}

void MsgBox::info(QWidget* parent, const QString& title, const QString& text,
    std::function<void()> cb) {
    if (cb) showAsync(parent, Icon::Info, title, text, QMessageBox::Ok,
        [cb](QMessageBox::StandardButton) { cb(); });
    else show(parent, Icon::Info, title, text, QMessageBox::Ok);
}

void MsgBox::warn(QWidget* parent, const QString& title, const QString& text,
    std::function<void()> cb) {
    if (cb) showAsync(parent, Icon::Warning, title, text, QMessageBox::Ok,
        [cb](QMessageBox::StandardButton) { cb(); });
    else show(parent, Icon::Warning, title, text, QMessageBox::Ok);
}

void MsgBox::error(QWidget* parent, const QString& title, const QString& text,
    std::function<void()> cb) {
    if (cb) showAsync(parent, Icon::Error, title, text, QMessageBox::Ok,
        [cb](QMessageBox::StandardButton) { cb(); });
    else show(parent, Icon::Error, title, text, QMessageBox::Ok);
}

bool MsgBox::confirm(QWidget* parent, const QString& title, const QString& text,
    QMessageBox::StandardButtons buttons) {
    const QMessageBox::StandardButton r = show(parent, Icon::Question, title, text, buttons);
    return r == QMessageBox::Yes || r == QMessageBox::Ok;
}
