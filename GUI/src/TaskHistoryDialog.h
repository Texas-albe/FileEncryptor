// TaskHistoryDialog - 任务历史面板（功能5）
// 列出每次运行的动作/模式/规模/耗时/结果，支持清空与「回放」（回填参数到主窗口）。
// v1.3.0：批量 ETA 已从本面板剥离 —— 它现在固定显示在拟命令行上部的批量进度面板
// （仅批量模式可见），本面板只负责历史记录本身。
#pragma once
#include <QDialog>
#include <QVector>
#include "TaskHistory.h"

class QLabel;
class QTableWidget;
class QPushButton;

class TaskHistoryDialog : public QDialog {
    Q_OBJECT
public:
    explicit TaskHistoryDialog(QWidget* parent=nullptr);

    // 双击（或选中后确定）返回的记录，用于回放；无效时 id 为空
    TaskRecord selectedRecord() const;

private slots:
    void onRefresh();
    void onClear();

private:
    void reload();
    void populateTable();
    void updateStats();
    QString modeLabel(const QString& mode) const;
    QString statusLabel(const QString& status) const;

    QLabel*       m_stats=nullptr;
    QTableWidget* m_table=nullptr;
    QPushButton*  m_btnRefresh=nullptr;
    QPushButton*  m_btnClear=nullptr;
    QPushButton*  m_btnClose=nullptr;

    QVector<TaskRecord> m_records;
};
