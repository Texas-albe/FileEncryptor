// CliNotFoundDialog.cpp - CLI 未找到对话框（含 GitHub 自动检索下载）
#include "CliNotFoundDialog.h"
#include "FileEncryptorLocator.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QProgressBar>
#include <QStyle>
#include <QApplication>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QRegularExpression>
#include <QVersionNumber>

static const char* kGithubApi = "https://api.github.com/repos/Texas-albe/FileEncryptor";

CliNotFoundDialog::CliNotFoundDialog(const QString& detailMessage, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("FileEncryptor CLI 未找到"));
    setMinimumWidth(520);
    setModal(true);
    m_net = new QNetworkAccessManager(this);
    auto* root = new QVBoxLayout(this);
    auto* iconRow = new QHBoxLayout;
    QLabel* iconLabel = new QLabel;
    iconLabel->setPixmap(QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical).pixmap(48, 48));
    iconRow->addWidget(iconLabel);
    iconRow->addStretch();
    root->addLayout(iconRow);
    auto* mainLabel = new QLabel(tr("<b>无法找到 FileEncryptor CLI 可执行文件</b><br/><br/>程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。"));
    mainLabel->setWordWrap(true);
    root->addWidget(mainLabel);
    const QStringList expected = FileEncryptorLocator::getExpectedNames();
    QString detail = tr("预期文件名：") + "<br/>";
    for (const QString& name : expected)
        detail += QStringLiteral("&nbsp;&nbsp;• %1<br/>").arg(name);
    detail += tr("<br/>当前程序目录：%1").arg(FileEncryptorLocator::selfDir());
    if (!detailMessage.isEmpty()) detail += tr("<br/>详细信息：%1").arg(detailMessage);
    auto* detailLabel = new QLabel(detail);
    detailLabel->setWordWrap(true);
    detailLabel->setStyleSheet("QLabel{font-size:10pt;color:#888;}");
    root->addWidget(detailLabel);
    m_statusLabel = new QLabel;
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet("QLabel{font-size:9pt;color:#aaa;}");
    root->addWidget(m_statusLabel);
    m_progress = new QProgressBar;
    m_progress->setVisible(false);
    m_progress->setRange(0, 100);
    root->addWidget(m_progress);
    root->addStretch();
    auto* buttons = new QDialogButtonBox;
    m_downloadBtn = buttons->addButton(tr("下载 CLI"), QDialogButtonBox::ActionRole);
    m_retryBtn = buttons->addButton(tr("重试"), QDialogButtonBox::AcceptRole);
    auto* cancelBtn = buttons->addButton(tr("关闭"), QDialogButtonBox::RejectRole);
    m_retryBtn->setDefault(true);
    connect(m_downloadBtn, &QPushButton::clicked, this, &CliNotFoundDialog::onDownload);
    connect(m_retryBtn, &QPushButton::clicked, this, &CliNotFoundDialog::onRetry);
    connect(cancelBtn, &QPushButton::clicked, this, &CliNotFoundDialog::onCancel);
    root->addWidget(buttons);
}

CliNotFoundDialog::~CliNotFoundDialog() { if (m_currentReply) m_currentReply->abort(); }
void CliNotFoundDialog::onRetry() { m_retry = true; accept(); }
void CliNotFoundDialog::onCancel() { m_retry = false; reject(); }

void CliNotFoundDialog::onDownload() {
    m_downloadBtn->setEnabled(false);
    m_retryBtn->setEnabled(false);
    m_statusLabel->setText(tr("正在从 GitHub 检索可用版本…"));
    QUrl tagsUrl(QStringLiteral("%1/tags").arg(kGithubApi)); QNetworkRequest req(tagsUrl);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onTagsFinished);
}

void CliNotFoundDialog::onTagsFinished() {
    if (!m_currentReply) return;
    QNetworkReply::NetworkError err = m_currentReply->error();
    QByteArray data = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;
    if (err != QNetworkReply::NoError) { m_statusLabel->setText(tr("网络错误")); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    QJsonParseError pe;
    QJsonDocument doc = QJsonDocument::fromJson(data, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray()) { m_statusLabel->setText(tr("解析失败")); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    const QString guiVer = FileEncryptorLocator::guiVersion();
    QString bestTag; QVersionNumber bestCliVer;
    QRegularExpression re(QStringLiteral("^GUI%1_CLI([\\d.]+)$").arg(QRegularExpression::escape(guiVer)));
    for (const QJsonValue& v : doc.array()) {
        QString tag = v.toObject().value("name").toString();
        QRegularExpressionMatch m = re.match(tag);
        if (m.hasMatch()) {
            QVersionNumber cliVer = QVersionNumber::fromString(m.captured(1));
            if (bestTag.isEmpty() || cliVer > bestCliVer) { bestTag = tag; bestCliVer = cliVer; }
        }
    }
    if (bestTag.isEmpty()) { m_statusLabel->setText(tr("未找到匹配 GUI %1 的 release").arg(guiVer)); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    m_statusLabel->setText(tr("找到 %1，正在获取下载链接…").arg(bestTag));
    QUrl relUrl(QStringLiteral("%1/releases/tags/%2").arg(kGithubApi, bestTag)); QNetworkRequest req(relUrl);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onReleaseFinished);
}

void CliNotFoundDialog::onReleaseFinished() {
    if (!m_currentReply) return;
    QByteArray data = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) { m_statusLabel->setText(tr("获取 release 失败")); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    QJsonArray assets = doc.object().value("assets").toArray();
    QString downloadUrl = pickCliAsset(assets);
    if (downloadUrl.isEmpty()) { m_statusLabel->setText(tr("未找到当前平台的 CLI 包")); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    QFileInfo fi(downloadUrl);
    m_savePath = QDir(FileEncryptorLocator::selfDir()).filePath(fi.fileName());
    m_statusLabel->setText(tr("下载中：%1").arg(fi.fileName()));
    m_progress->setVisible(true);
    startDownload(downloadUrl, m_savePath);
}

QString CliNotFoundDialog::pickCliAsset(const QJsonArray& assets) const {
#ifdef Q_OS_WIN
    const QString suffix = ".exe";
#else
    const QString suffix = "";
#endif
    for (const QJsonValue& v : assets) {
        QJsonObject a = v.toObject();
        QString name = a.value("name").toString();
        if (name.startsWith("FileEncryptorCLI-") && (suffix.isEmpty() || name.endsWith(suffix)))
            return a.value("browser_download_url").toString();
    }
    return QString();
}

void CliNotFoundDialog::startDownload(const QString& url, const QString& savePath) {
    QUrl dlUrl(url); QNetworkRequest req(dlUrl);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::downloadProgress, this, &CliNotFoundDialog::onDownloadProgress);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onDownloadFinished);
}

void CliNotFoundDialog::onDownloadProgress(qint64 received, qint64 total) { if (total > 0) m_progress->setValue(static_cast<int>(received * 100 / total)); }

void CliNotFoundDialog::onDownloadFinished() {
    if (!m_currentReply) return;
    QByteArray data = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;
    QFile f(m_savePath);
    if (f.open(QIODevice::WriteOnly)) {
        f.write(data); f.close();
        m_statusLabel->setText(tr("下载完成：%1").arg(QFileInfo(m_savePath).fileName()));
        m_progress->setValue(100);
        m_retryBtn->setEnabled(true);
    } else { m_statusLabel->setText(tr("保存失败")); m_downloadBtn->setEnabled(true); }
}

bool CliNotFoundDialog::showAndAsk(QWidget* parent) {
    CliNotFoundDialog dlg(QString(), parent);
    return dlg.exec() == QDialog::Accepted && dlg.m_retry;
}