// MsgBox - 统一弹窗模块（警告 / 提示 / 错误 / 确认）
//
// 设计目标：
//   1) 项目内所有交互弹窗统一经由本模块，避免散落 QMessageBox::warning/...
//      导致标题/风格/调用方式不一致。
//   2) 提供 title + content + 可选回调（callback）的可复用调用方法：
//      - 同步：show() / confirm() 直接返回用户选择（会阻塞，适合校验失败后的拦截）。
//      - 异步：info()/warn()/error() 的 cb 在用户关闭后回调（不阻塞调用方）。
//   3) 视觉风格与 ThemeManager 一致：QMessageBox 继承 QApplication 调色板
//      （ThemeManager 已按浅色/深色统一设置），此处仅统一最小宽度与窗口模态。
#pragma once
#include <QMessageBox>
#include <QString>
#include <functional>

class QWidget;

class MsgBox {
public:
    enum class Icon { Info, Warning, Error, Question };

    // 同步弹窗：返回用户点击的标准按钮（适合 confirm / 拦截性校验）
    static QMessageBox::StandardButton show(QWidget* parent, Icon icon,
        const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok);

    // 异步弹窗：用户关闭后以回调返回所点按钮（不阻塞调用方）
    static void showAsync(QWidget* parent, Icon icon,
        const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons,
        std::function<void(QMessageBox::StandardButton)> cb);

    // 便捷封装（标题 + 内容 + 可选关闭回调）
    static void info(QWidget* parent, const QString& title, const QString& text,
        std::function<void()> cb = nullptr);
    static void warn(QWidget* parent, const QString& title, const QString& text,
        std::function<void()> cb = nullptr);
    static void error(QWidget* parent, const QString& title, const QString& text,
        std::function<void()> cb = nullptr);

    // 确认框：Yes / Ok → true；No / Cancel / 关闭 → false
    static bool confirm(QWidget* parent, const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons = QMessageBox::Yes | QMessageBox::No);
};
