// AboutDialogs - "关于"菜单的两个子项对话框
// ①鸣谢对话框：列出贡献者信息（代码开发、测试）+ 个人主页链接
// ②README 摘要对话框：展示项目简介
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
