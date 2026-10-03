// CLI 未找到对话框实现
#include "CliNotFoundDialog.h"
#include "FileEncryptorLocator.h"
#include "ThemeManager.h"
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
#include <QCryptographicHash>
#include <QTemporaryFile>
#include <QUrl>

static const char* kGithubApi = "https://api.github.com/repos/Texas-albe/FileEncryptor";

// 更新源白名单，与 Updater/src/updater.cpp 的 kGitHubHosts 保持一致
static const char* const kAllowedHosts[] = {
    "github.com", "api.github.com",
    "objects.githubusercontent.com", "codeload.github.com"
};

CliNotFoundDialog::CliNotFoundDialog(const QString& detailMessage, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("FileEncryptor CLI 未找到"));
    setMinimumWidth(520);
    setModal(true);
    m_net = new QNetworkAccessManager(this);
    auto* root = new QVBoxLayout(this);

    // 图标与「无法找到… / 程序需要…」两行文案放同一行
    auto* headRow = new QHBoxLayout;
    QLabel* iconLabel = new QLabel;
    iconLabel->setPixmap(QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical).pixmap(48, 48));
    headRow->addWidget(iconLabel);
    auto* headText = new QVBoxLayout;
    headText->setSpacing(2);
    auto* titleLabel = new QLabel(tr("<b>无法找到 FileEncryptor CLI 可执行文件</b>"));
    auto* subLabel = new QLabel(tr("程序需要 FileEncryptorCLI 命令行工具来执行加密/解密操作。"));
    for (QLabel* t : { titleLabel, subLabel }) {
        t->setWordWrap(true);
        headText->addWidget(t);
    }
    headRow->addLayout(headText, 1);
    headRow->addStretch();
    root->addLayout(headRow);

    // 不再单独设「详细信息」段：预置文件名、当前程序目录、可设置环境变量三项平铺
    const QStringList expected = FileEncryptorLocator::getExpectedNames();
    QString info = tr("预期文件名：") + QStringLiteral("<br/>");
    for (const QString& name : expected)
        info += QStringLiteral("&nbsp;&nbsp;• %1<br/>").arg(name);
    info += tr("<br/>当前程序目录：%1<br/>").arg(FileEncryptorLocator::selfDir());
    info += tr("也可设置环境变量 FILEENCRYPTOR_EXE 指向 CLI 程序路径。");
    (void)detailMessage;
    const QString muted=QLatin1String(ThemeManager::mutedTextHex());
    auto* infoLabel = new QLabel(info);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel{font-size:10pt;color:%1;}").arg(muted));
    root->addWidget(infoLabel);
    m_statusLabel = new QLabel;
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("QLabel{font-size:9pt;color:%1;}").arg(muted));
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

CliNotFoundDialog::~CliNotFoundDialog() {
    if (m_currentReply) m_currentReply->abort();
    if (!m_tempPath.isEmpty()) QFile::remove(m_tempPath);
}
void CliNotFoundDialog::onRetry() { m_retry = true; accept(); }
void CliNotFoundDialog::onCancel() {
    // 先把 reply 摘掉再 abort，否则 abort 同步触发的 finished 会走进网络错误分支
    QNetworkReply* r=m_currentReply;
    m_currentReply=nullptr;
    if(r) { r->abort(); r->deleteLater(); }
    m_retry=false;
    reject();
}

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
    const QString cliVer = FileEncryptorLocator::version();
    // 只接受精确配套的 tag
    const QString want = QStringLiteral("GUI%1_CLI%2").arg(guiVer, cliVer);
    const QJsonArray arr = doc.array();
    int idx = -1;
    for (int i = 0; i < arr.size(); ++i) {
        if (arr.at(i).toObject().value(QStringLiteral("name")).toString() == want) { idx = i; break; }
    }
    if (idx < 0) { m_statusLabel->setText(tr("未找到预期的 CLI %1（要求 tag GUI%2_CLI%1），已中止下载").arg(cliVer, guiVer)); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    m_statusLabel->setText(tr("找到 %1，正在获取下载链接…").arg(want));
    QUrl relUrl(QStringLiteral("%1/releases/tags/%2").arg(kGithubApi, want)); QNetworkRequest req(relUrl);
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
    // 仅允许 GitHub 官方域名
    if (!isAllowedDownloadHost(QUrl(downloadUrl))) {
        m_statusLabel->setText(tr("下载地址不在允许的域名白名单内"));
        m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return;
    }
    m_assetUrl = downloadUrl;
    m_shaWarned = false;
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

bool CliNotFoundDialog::isAllowedDownloadHost(const QUrl& url) const {
    const QString host = url.host().toLower();
    for (const char* h : kAllowedHosts)
        if (host == QLatin1String(h)) return true;
    return false;
}

void CliNotFoundDialog::startDownload(const QString& url, const QString& savePath) {
    QUrl dlUrl(url);
    if (!isAllowedDownloadHost(dlUrl)) { failDownload(tr("下载地址不在允许的域名白名单内")); return; }
    QNetworkRequest req(dlUrl);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::downloadProgress, this, &CliNotFoundDialog::onDownloadProgress);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onDownloadFinished);
}

void CliNotFoundDialog::onDownloadProgress(qint64 received, qint64 total) { if (total > 0) m_progress->setValue(static_cast<int>(received * 100 / total)); }

void CliNotFoundDialog::onDownloadFinished() {
    if (!m_currentReply) return;
    QNetworkReply::NetworkError err = m_currentReply->error();
    QByteArray data = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;
    if (err != QNetworkReply::NoError) { failDownload(tr("下载失败")); return; }
    m_assetData = data;
    // 先写临时文件再原子改名
    QTemporaryFile tmp(QDir(FileEncryptorLocator::selfDir())
        .filePath(QStringLiteral(".fileencryptor_dl_XXXXXX")));
    tmp.setAutoRemove(false);
    if (!tmp.open()) { failDownload(tr("无法创建临时下载文件")); m_assetData.clear(); return; }
    tmp.write(m_assetData);
    tmp.close();
    m_tempPath = tmp.fileName();
    startShaCheck();
}

void CliNotFoundDialog::startShaCheck() {
    // 拉取 .sha256 做完整性比对
    QUrl shaUrl(m_assetUrl + QStringLiteral(".sha256"));
    if (!isAllowedDownloadHost(shaUrl)) { failDownload(tr("校验文件地址不在白名单内")); return; }
    m_statusLabel->setText(tr("正在校验文件完整性…"));
    QNetworkRequest req(shaUrl);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onShaDownloaded);
}

void CliNotFoundDialog::onShaDownloaded() {
    if (!m_currentReply) return;
    const QNetworkReply::NetworkError err = m_currentReply->error();
    const QByteArray shaBody = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;

    // 无校验文件则跳过校验
    if (err != QNetworkReply::NoError) {
        m_shaWarned = true;
        installFromTemp();
        return;
    }
    // 解析 64 位十六进制摘要
    const QRegularExpression re(QStringLiteral("([0-9a-fA-F]{64})"));
    const QRegularExpressionMatch m = re.match(QString::fromLatin1(shaBody));
    if (!m.hasMatch()) {
        m_shaWarned = true;
        installFromTemp();
        return;
    }
    const QString expected = m.captured(1).toLower();
    const QString actual = QString::fromLatin1(
        QCryptographicHash::hash(m_assetData, QCryptographicHash::Sha256).toHex()).toLower();
    if (actual != expected) {
        QFile::remove(m_tempPath);
        m_tempPath.clear();
        m_assetData.clear();
        m_statusLabel->setText(tr("完整性校验失败：SHA256 不匹配，已拒绝安装"));
        m_downloadBtn->setEnabled(true);
        return;
    }
    installFromTemp();
}

void CliNotFoundDialog::installFromTemp() {
    QFile::remove(m_savePath);
    if (!QFile::rename(m_tempPath, m_savePath)) {
        // rename 失败退化为复制
        if (!QFile::copy(m_tempPath, m_savePath)) {
            QFile::remove(m_tempPath);
            m_tempPath.clear(); m_assetData.clear();
            m_statusLabel->setText(tr("安装到目标路径失败"));
            m_downloadBtn->setEnabled(true);
            return;
        }
        QFile::remove(m_tempPath);
    }
    m_tempPath.clear();
    m_assetData.clear();
    m_downloaded=true;
#ifndef Q_OS_WIN
    // POSIX：rename/copy 保留的是临时文件权限，需显式给执行位，否则 CLI 跑不起来
    QFile::setPermissions(m_savePath,
        QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner|
        QFileDevice::ReadGroup|QFileDevice::ExeGroup|
        QFileDevice::ReadOther|QFileDevice::ExeOther);
#endif
    QString msg = tr("下载完成：%1").arg(QFileInfo(m_savePath).fileName());
    if (m_shaWarned) msg += tr("（未提供 SHA256 校验文件，已跳过完整性校验）");
    m_statusLabel->setText(msg);
    m_progress->setValue(100);
    m_retryBtn->setEnabled(true);
}

void CliNotFoundDialog::failDownload(const QString& msg) {
    if (!m_tempPath.isEmpty()) { QFile::remove(m_tempPath); m_tempPath.clear(); }
    m_assetData.clear();
    m_statusLabel->setText(msg);
    m_downloadBtn->setEnabled(true);
}

