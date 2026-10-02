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
    bool m_shaWarned=false;
};
