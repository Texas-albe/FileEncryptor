// 统一弹窗模块
#pragma once
#include <QMessageBox>
#include <QString>
#include <functional>

class QWidget;

class MsgBox {
public:
    enum class Icon { Info, Warning, Error, Question };

    // 同步弹窗
    static QMessageBox::StandardButton show(QWidget* parent, Icon icon,
        const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok);

    // 异步弹窗（关闭后回调）
    static void showAsync(QWidget* parent, Icon icon,
        const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons,
        std::function<void(QMessageBox::StandardButton)> cb);

    // 便捷封装（标题 + 内容 + 回调）
    static void info(QWidget* parent, const QString& title, const QString& text,
        std::function<void()> cb = nullptr);
    static void warn(QWidget* parent, const QString& title, const QString& text,
        std::function<void()> cb = nullptr);
    static void error(QWidget* parent, const QString& title, const QString& text,
        std::function<void()> cb = nullptr);

    // 确认框返回是否确认
    static bool confirm(QWidget* parent, const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons = QMessageBox::Yes | QMessageBox::No);
};
