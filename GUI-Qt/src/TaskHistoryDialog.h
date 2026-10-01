// 任务历史面板
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

    // 回放返回的记录
    TaskRecord selectedRecord() const;

private slots:
    void onRefresh();
    void onClear();
    void onDeleteSelected();
    void onTableContextMenu(const QPoint& pos);

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
    QPushButton*  m_btnDelete=nullptr;

    QVector<TaskRecord> m_records;
};
