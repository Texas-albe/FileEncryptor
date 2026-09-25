// TaskHistoryDialog 实现（功能5 + 功能6 面板）
#include "TaskHistoryDialog.h"
#include "EtaEstimator.h"
#include "MsgBox.h"

#include <QAbstractItemView>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {
const int kColTime=0,kColAction=1,kColMode=2,kColInputs=3,kColBytes=4,
          kColDone=5,kColDuration=6,kColRate=7,kColStatus=8,kColOutDir=9;
}

TaskHistoryDialog::TaskHistoryDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("任务历史"));
    resize(860,520);

    auto* lay=new QVBoxLayout(this);

    m_stats=new QLabel;
    m_stats->setWordWrap(true);
    lay->addWidget(m_stats);

    // ---- 历史表 ----
    m_table=new QTableWidget;
    m_table->setColumnCount(10);
    m_table->setHorizontalHeaderLabels({
        tr("开始时间"),tr("动作"),tr("模式"),tr("输入"),tr("数据量"),
        tr("完成文件"),tr("耗时"),tr("吞吐"),tr("结果"),tr("输出目录")});
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setStretchLastSection(true);
    lay->addWidget(m_table,1);

    auto* hint=new QLabel(tr("双击一行可将该次任务的参数回填到主窗口（回放）。"));
    hint->setWordWrap(true);
    lay->addWidget(hint);

    auto* btnRow=new QHBoxLayout;
    btnRow->addStretch();
    m_btnRefresh=new QPushButton(tr("刷新"));
    m_btnClear=new QPushButton(tr("清空历史"));
    m_btnClose=new QPushButton(tr("关闭"));
    btnRow->addWidget(m_btnRefresh);
    btnRow->addWidget(m_btnClear);
    btnRow->addWidget(m_btnClose);
    lay->addLayout(btnRow);

    connect(m_btnRefresh,&QPushButton::clicked,this,&TaskHistoryDialog::onRefresh);
    connect(m_btnClear,&QPushButton::clicked,this,&TaskHistoryDialog::onClear);
    connect(m_btnClose,&QPushButton::clicked,this,&QDialog::reject);
    connect(m_table,&QTableWidget::cellDoubleClicked,this,[this]{ accept(); });

    reload();
}

QString TaskHistoryDialog::modeLabel(const QString& mode) const {
    if(mode==QStringLiteral("xchacha20"))  return tr("XChaCha20");
    if(mode==QStringLiteral("aegis256"))   return tr("AEGIS-256");
    if(mode==QStringLiteral("asymmetric")) return tr("非对称");
    return mode.isEmpty() ? tr("-") : mode;
}

QString TaskHistoryDialog::statusLabel(const QString& status) const {
    if(status==QStringLiteral("success"))   return tr("成功");
    if(status==QStringLiteral("failed"))    return tr("失败");
    if(status==QStringLiteral("cancelled")) return tr("已取消");
    return status.isEmpty() ? tr("-") : status;
}

void TaskHistoryDialog::reload() {
    QString err;
    if(!TaskHistory::load(m_records,err)) {
        MsgBox::warn(this,tr("读取失败"),tr("无法读取任务历史：%1").arg(err));
        m_records.clear();
    }
    populateTable();
    updateStats();
}

void TaskHistoryDialog::populateTable() {
    m_table->setRowCount(m_records.size());
    for(int i=0;i<m_records.size();++i) {
        const TaskRecord& r=m_records[i];
        const auto set=[&](int col,const QString& text){
            auto* it=new QTableWidgetItem(text);
            m_table->setItem(i,col,it);
        };
        set(kColTime,r.startedAt);
        set(kColAction,r.actionLabel.isEmpty()?TaskHistory::actionLabel(r.action):r.actionLabel);
        set(kColMode,modeLabel(r.mode));
        set(kColInputs,r.inputCount>0?QString::number(r.inputCount):tr("-"));
        set(kColBytes,r.totalBytes>0?EtaEstimator::formatBytes(r.totalBytes):tr("-"));
        set(kColDone,r.filesDone>0?QString::number(r.filesDone):tr("-"));
        set(kColDuration,r.durationMs>0?EtaEstimator::formatDuration(r.durationMs):tr("-"));
        const double rate=(r.durationMs>0&&r.totalBytes>0)
            ? static_cast<double>(r.totalBytes)/(static_cast<double>(r.durationMs)/1000.0) : 0.0;
        set(kColRate,EtaEstimator::formatRate(rate));
        set(kColStatus,statusLabel(r.status));
        set(kColOutDir,r.outputDir.isEmpty()?tr("（源目录）"):r.outputDir);
    }
}

void TaskHistoryDialog::updateStats() {
    int ok=0,failed=0,cancelled=0;
    for(const TaskRecord& r : m_records) {
        if(r.status==QStringLiteral("success"))   ++ok;
        else if(r.status==QStringLiteral("failed"))    ++failed;
        else if(r.status==QStringLiteral("cancelled")) ++cancelled;
    }
    m_stats->setText(tr("<b>共 %1 条记录</b> — 成功 %2 · 失败 %3 · 已取消 %4")
                         .arg(m_records.size()).arg(ok).arg(failed).arg(cancelled));
}

TaskRecord TaskHistoryDialog::selectedRecord() const {
    const int row=m_table->currentRow();
    if(row<0||row>=m_records.size()) return TaskRecord();
    return m_records[row];
}

void TaskHistoryDialog::onRefresh() { reload(); }

void TaskHistoryDialog::onClear() {
    if(m_records.isEmpty()) {
        MsgBox::info(this,tr("任务历史"),tr("当前没有历史记录。"));
        return;
    }
    if(!MsgBox::confirm(this,tr("清空历史"),
        tr("将删除全部 %1 条任务历史记录（仅影响本面板，不影响任何加密文件与密钥库）。\n\n确定继续？")
            .arg(m_records.size()))) return;
    QString err;
    if(!TaskHistory::clear(err)) {
        MsgBox::warn(this,tr("清空失败"),tr("无法清空任务历史：%1").arg(err));
        return;
    }
    reload();
}
