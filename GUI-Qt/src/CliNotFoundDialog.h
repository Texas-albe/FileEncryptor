// CLI 未找到对话框（含自动下载）
#pragma once
#include <QDialog>

class QLabel;
class QPushButton;
class QProgressBar;
class QNetworkAccessManager;
class QNetworkReply;
class QUrl;

class CliNotFoundDialog: public QDialog {
    Q_OBJECT
public:
    explicit CliNotFoundDialog(const QString& detailMessage=QString(),
        QWidget* parent=nullptr);
    ~CliNotFoundDialog();

    // 调用方用 exec() 弹出后，靠这两个 getter 判断后续动作
    bool retryPressed() const { return m_retry; }
    bool downloaded() const { return m_downloaded; }

private slots:
    void onRetry();
    void onCancel();
    void onDownload();
    void onTagsFinished();
    void onReleaseFinished();
    void onDownloadProgress(qint64 received, qint64 total);
    void onDownloadFinished();
    void onShaDownloaded();

private:
    void startDownload(const QString& url, const QString& savePath);
    void startShaCheck();
    void installFromTemp();
    void failDownload(const QString& msg);
    QString pickCliAsset(const QJsonArray& assets) const;
    bool isAllowedDownloadHost(const QUrl& url) const;
    // M47：QNetworkAccessManager 的自动重定向不过白名单，改为手动跟随，
    // 每跳都对新 url 复检主机白名单；返回 true 表示已发起新请求
    bool followRedirect(QNetworkReply* reply,
                        void (CliNotFoundDialog::*restart)(const QUrl&));
    void startTagsRequest(const QUrl& url);
    void startReleaseRequest(const QUrl& url);
    void startAssetRequest(const QUrl& url);
    void startShaRequest(const QUrl& url);

    bool m_retry=false;
    bool m_downloaded=false;
    QNetworkAccessManager* m_net=nullptr;
    QNetworkReply* m_currentReply=nullptr;
    QPushButton* m_downloadBtn=nullptr;
    QPushButton* m_retryBtn=nullptr;
    QProgressBar* m_progress=nullptr;
    QLabel* m_statusLabel=nullptr;
    QString m_savePath;
    QString m_assetUrl;
    QString m_tempPath;
    QByteArray m_assetData;
    // M47：手动跟随重定向的计数（防重定向环）
    int m_redirects = 0;
};
