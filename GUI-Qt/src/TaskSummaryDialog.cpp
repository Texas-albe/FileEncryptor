#include "TaskSummaryDialog.h"
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QLabel>
#include <QVBoxLayout>

TaskSummaryDialog::TaskSummaryDialog(const QString& title, const QString& duration,
                                     const QString& avgSpeed, const QString& encryptedSize,
                                     int done, int skip, int fail, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("任务完成"));
    resize(360, 220);

    auto* lay=new QVBoxLayout(this);

    auto* titleLabel=new QLabel(title);
    titleLabel->setStyleSheet("font-size:16px;font-weight:bold;");
    lay->addWidget(titleLabel);

    auto* grid=new QGridLayout;
    grid->setHorizontalSpacing(16);
    grid->setVerticalSpacing(8);

    auto addItem=[&](int row,int col,const QString& label,const QString& value,bool warn=false){
        auto* l=new QLabel(label);
        l->setStyleSheet("color:#888;font-size:11px;");
        auto* v=new QLabel(value);
        v->setStyleSheet(warn?"color:#ff6b6b;font-size:14px;font-weight:bold;":"font-size:14px;font-weight:bold;");
        grid->addWidget(l,row,col*2);
        grid->addWidget(v,row,col*2+1);
    };

    addItem(0,0,tr("用时"),duration);
    addItem(0,1,tr("平均速度"),avgSpeed);
    addItem(1,0,tr("加密后大小"),encryptedSize);
    addItem(1,1,tr("完成"),QString::number(done));
    addItem(2,0,tr("跳过"),QString::number(skip));
    addItem(2,1,tr("失败"),QString::number(fail),fail>0);

    lay->addLayout(grid);
    lay->addStretch();

    auto* btnBox=new QDialogButtonBox(QDialogButtonBox::Ok);
    connect(btnBox,&QDialogButtonBox::accepted,this,&QDialog::accept);
    lay->addWidget(btnBox);
}