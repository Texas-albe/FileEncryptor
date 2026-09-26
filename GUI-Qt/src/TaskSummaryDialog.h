// TaskSummaryDialog - 任务完成汇总弹窗
#pragma once
#include <QDialog>

class QLabel;

class TaskSummaryDialog : public QDialog {
    Q_OBJECT
public:
    TaskSummaryDialog(const QString& title, const QString& duration,
                      const QString& avgSpeed, const QString& encryptedSize,
                      int done, int skip, int fail, QWidget* parent=nullptr);
};