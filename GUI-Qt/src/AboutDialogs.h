// 关于菜单
#pragma once
#include <QDialog>

class QTextBrowser;

// 鸣谢对话框
class CreditsDialog : public QDialog {
    Q_OBJECT
public:
    explicit CreditsDialog(QWidget* parent = nullptr);
};

// README 摘要对话框
class ReadmeDialog : public QDialog {
    Q_OBJECT
public:
    explicit ReadmeDialog(QWidget* parent = nullptr);
};
