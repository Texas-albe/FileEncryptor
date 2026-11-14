// CLI 未找到对话框实
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

// 更新源白名单
static const char* const kAllowedHosts[] = {
    "github.com", "api.github.com",
    "objects.githubusercontent.com", "codeload.github.com"
};

// 禁止 QNAM 自动跟随重
// Qt 无 setRedirectPolicy 方法，只
// RedirectPolicyAttribute 属性；ManualRedirectPolicy
static void reqNoRedirect(QNetworkRequest& req)
{
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::ManualRedirectPolicy);
}

CliNotFoundDialog::CliNotFoundDialog(const QString& detailMessage, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("FileEncryptor CLI 未找到"));
    setMinimumWidth(520);
    setModal(true);
    m_net = new QNetworkAccessManager(this);
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(16,14,16,12);
    root->setSpacing(8);

    // 图标
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

    // 单独设「详细信息」
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
    m_downloadBtn->setProperty("uiRole", "primary");
    m_retryBtn->setProperty("uiRole", "secondary");
    cancelBtn->setProperty("uiRole", "quiet");
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
    // 先把 reply 摘掉
    QNetworkReply* r=m_currentReply;
    m_currentReply=nullptr;
    if(r) { r->abort(); r->deleteLater(); }
    m_retry=false;
    reject();
}

void CliNotFoundDialog::onDownload() {
    m_downloadBtn->setEnabled(false);
    m_retryBtn->setEnabled(false);
    m_redirects = 0;   // 用户主动下载重
    m_statusLabel->setText(tr("正在从 GitHub 检索可用版本…"));
    startTagsRequest(QUrl(QStringLiteral("%1/tags").arg(kGithubApi)));
}

// M47
void CliNotFoundDialog::startTagsRequest(const QUrl& url) {
    if (!isAllowedDownloadHost(url)) { failDownload(tr("下载地址不在允许的域名白名单内")); return; }
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    reqNoRedirect(req);
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onTagsFinished);
}

void CliNotFoundDialog::onTagsFinished() {
    if (!m_currentReply) return;
    if (followRedirect(m_currentReply, &CliNotFoundDialog::startTagsRequest)) return;
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
    // 只接受精确配套
    const QString want = QStringLiteral("GUI%1_CLI%2").arg(guiVer, cliVer);
    const QJsonArray arr = doc.array();
    int idx = -1;
    for (int i = 0; i < arr.size(); ++i) {
        if (arr.at(i).toObject().value(QStringLiteral("name")).toString() == want) { idx = i; break; }
    }
    if (idx < 0) { m_statusLabel->setText(tr("未找到预期的 CLI %1（要求 tag GUI%2_CLI%1），已中止下载").arg(cliVer, guiVer)); m_downloadBtn->setEnabled(true); m_retryBtn->setEnabled(true); return; }
    m_statusLabel->setText(tr("找到 %1，正在获取下载链接…").arg(want));
    startReleaseRequest(QUrl(QStringLiteral("%1/releases/tags/%2").arg(kGithubApi, want)));
}

void CliNotFoundDialog::startReleaseRequest(const QUrl& url) {
    if (!isAllowedDownloadHost(url)) { failDownload(tr("下载地址不在允许的域名白名单内")); return; }
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    reqNoRedirect(req);
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onReleaseFinished);
}

void CliNotFoundDialog::onReleaseFinished() {
    if (!m_currentReply) return;
    if (followRedirect(m_currentReply, &CliNotFoundDialog::startReleaseRequest)) return;
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

// M47
bool CliNotFoundDialog::followRedirect(QNetworkReply* reply,
                                       void (CliNotFoundDialog::*restart)(const QUrl&)) {
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status < 301 || status > 308) return false;
    QUrl target = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
    const QUrl baseUrl = reply->url();   // 先取
    reply->deleteLater();
    m_currentReply = nullptr;
    // 循环上限
    if (++m_redirects > 20) {
        m_redirects = 0;
        failDownload(tr("重定向次数过多，已中止下载"));
        return true;
    }
    // 相对 Location
    if (!target.isEmpty() && target.isRelative()) target = baseUrl.resolved(target);
    if (target.isEmpty() || !isAllowedDownloadHost(target)) {
        failDownload(tr("重定向地址不在允许的域名白名单内"));
        return true;
    }
    (this->*restart)(target);
    return true;
}

void CliNotFoundDialog::startDownload(const QString& url, const QString& savePath) {
    QUrl dlUrl(url);
    if (!isAllowedDownloadHost(dlUrl)) { failDownload(tr("下载地址不在允许的域名白名单内")); return; }
    QNetworkRequest req(dlUrl);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    reqNoRedirect(req);
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::downloadProgress, this, &CliNotFoundDialog::onDownloadProgress);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onDownloadFinished);
}

void CliNotFoundDialog::startAssetRequest(const QUrl& url) {
    startDownload(url.toString(), m_savePath);
}

void CliNotFoundDialog::onDownloadProgress(qint64 received, qint64 total) { if (total > 0) m_progress->setValue(static_cast<int>(received * 100 / total)); }

void CliNotFoundDialog::onDownloadFinished() {
    if (!m_currentReply) return;
    if (followRedirect(m_currentReply, &CliNotFoundDialog::startAssetRequest)) return;
    QNetworkReply::NetworkError err = m_currentReply->error();
    QByteArray data = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;
    if (err != QNetworkReply::NoError) { failDownload(tr("下载失败")); return; }
    m_assetData = data;
    // 先写临时文件
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
    // 拉取 .sha256 做完整性比
    startShaRequest(QUrl(m_assetUrl + QStringLiteral(".sha256")));
}

void CliNotFoundDialog::startShaRequest(const QUrl& url) {
    if (!isAllowedDownloadHost(url)) { failDownload(tr("校验文件地址不在白名单内")); return; }
    m_statusLabel->setText(tr("正在校验文件完整性…"));
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileEncryptorGUI");
    reqNoRedirect(req);
    m_currentReply = m_net->get(req);
    connect(m_currentReply, &QNetworkReply::finished, this, &CliNotFoundDialog::onShaDownloaded);
}

void CliNotFoundDialog::onShaDownloaded() {
    if (!m_currentReply) return;
    if (followRedirect(m_currentReply, &CliNotFoundDialog::startShaRequest)) return;
    const QNetworkReply::NetworkError err = m_currentReply->error();
    const QByteArray shaBody = m_currentReply->readAll();
    m_currentReply->deleteLater();
    m_currentReply = nullptr;

    // M47
    if (err != QNetworkReply::NoError) {
        QFile::remove(m_tempPath);
        m_tempPath.clear();
        m_assetData.clear();
        failDownload(tr("获取 SHA256 校验文件失败，已中止下载"));
        return;
    }
    // 解析 64 位十六进制
    const QRegularExpression re(QStringLiteral("([0-9a-fA-F]{64})"));
    const QRegularExpressionMatch m = re.match(QString::fromLatin1(shaBody));
    // M47
    if (!m.hasMatch()) {
        QFile::remove(m_tempPath);
        m_tempPath.clear();
        m_assetData.clear();
        failDownload(tr("SHA256 校验文件格式不符，已中止下载"));
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
        // rename 失败退化
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
    // POSIX
    QFile::setPermissions(m_savePath,
        QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner|
        QFileDevice::ReadGroup|QFileDevice::ExeGroup|
        QFileDevice::ReadOther|QFileDevice::ExeOther);
#endif
    m_statusLabel->setText(tr("下载完成：%1").arg(QFileInfo(m_savePath).fileName()));
    m_progress->setValue(100);
    m_retryBtn->setEnabled(true);
}

void CliNotFoundDialog::failDownload(const QString& msg) {
    if (!m_tempPath.isEmpty()) { QFile::remove(m_tempPath); m_tempPath.clear(); }
    m_assetData.clear();
    m_statusLabel->setText(msg);
    m_downloadBtn->setEnabled(true);
}

