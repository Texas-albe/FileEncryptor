// CliNotFoundDialog.h - CLI 程序未找到时的错误提示对话框
#pragma once
#include <QDialog>

class QLabel;
class QPushButton;

class CliNotFoundDialog: public QDialog {
    Q_OBJECT
public:
    explicit CliNotFoundDialog(const QString& detailMessage=QString(),
        QWidget* parent=nullptr);

    // 显示错误对话框并返回用户选择（重试/取消）
    static bool showAndAsk(QWidget* parent=nullptr);

private slots:
    void onRetry();
    void onCancel();

private:
    bool m_retry=false;
};