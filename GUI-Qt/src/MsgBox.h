// MsgBox - 统一弹窗模块（警告/提示/错误/确认）：项目内弹窗统一走本模块以保证标题/风格/调用方式一致。
// 提供同步 show()/confirm()（阻塞返回用户选择）与异步 info/warn/error（关闭后回调）；视觉随 ThemeManager 调色板，仅统一最小宽度与窗口模态。
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
