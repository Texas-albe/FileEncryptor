// CliNotFoundDialog.cpp
#include "CliNotFoundDialog.h"
#include "FileEncryptorLocator.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QStyle>
#include <QApplication>

CliNotFoundDialog::CliNotFoundDialog(const QString& detailMessage,QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("FileEncryptor CLI 未找到"));
    setMinimumWidth(500);
    setModal(true);

    auto* root=new QVBoxLayout(this);

    // 错误图标
    auto* iconRow=new QHBoxLayout;
    QLabel* iconLabel=new QLabel;
    iconLabel->setPixmap(QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical)
        .pixmap(48,48));
    iconRow->addWidget(iconLabel);
    iconRow->addStretch();
    root->addLayout(iconRow);

    // 主错误信息
    auto* mainLabel=new QLabel(tr(
        "<b>无法找到 FileEncryptor CLI 可执行文件</b><br/><br/>"
        "程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。"
    ));
    mainLabel->setWordWrap(true);
    root->addWidget(mainLabel);

    // 详细信息
    const QStringList expected=FileEncryptorLocator::getExpectedNames();
    QString detail=tr(
        "请确保以下任一文件存在于本程序同目录或 PATH 环境变量中：<br/><br/>"
        "<b>预期文件名：</b><br/>"
    );
    for(const QString& name:expected) {
        detail+=QStringLiteral("&nbsp;&nbsp;• %1<br/>").arg(name);
    }
    detail+=tr("<br/><b>当前程序目录：</b>%1<br/>")
        .arg(FileEncryptorLocator::selfDir());

    if(!detailMessage.isEmpty()) {
        detail+=tr("<br/><b>详细信息：</b>%1").arg(detailMessage);
    }

    auto* detailLabel=new QLabel(detail);
    detailLabel->setWordWrap(true);
    detailLabel->setStyleSheet("QLabel { font-size: 10pt; color: #666; }");
    root->addWidget(detailLabel);

    // 提示：设置环境变量
    auto* envTip=new QLabel(tr(
        "<i>提示：也可设置环境变量 FILEENCRYPTOR_EXE 指向 CLI 程序的完整路径。</i>"
    ));
    envTip->setWordWrap(true);
    envTip->setStyleSheet("QLabel { font-size: 9pt; color: #888; }");
    root->addWidget(envTip);

    // 按钮
    auto* buttons=new QDialogButtonBox;
    auto* retryBtn=buttons->addButton(tr("重试"),QDialogButtonBox::AcceptRole);
    auto* cancelBtn=buttons->addButton(tr("关闭"),QDialogButtonBox::RejectRole);
    retryBtn->setDefault(true);

    connect(retryBtn,&QPushButton::clicked,this,&CliNotFoundDialog::onRetry);
    connect(cancelBtn,&QPushButton::clicked,this,&CliNotFoundDialog::onCancel);
    root->addWidget(buttons);
}

void CliNotFoundDialog::onRetry() {
    m_retry=true;
    accept();
}

void CliNotFoundDialog::onCancel() {
    m_retry=false;
    reject();
}

bool CliNotFoundDialog::showAndAsk(QWidget* parent) {
    CliNotFoundDialog dlg(QString(),parent);
    return dlg.exec()==QDialog::Accepted&&dlg.m_retry;
}