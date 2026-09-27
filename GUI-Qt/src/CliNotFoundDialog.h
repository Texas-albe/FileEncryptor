// CliNotFoundDialog.h - CLI 程序未找到时的错误提示对话框（含自动下载）
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

    static bool showAndAsk(QWidget* parent=nullptr);

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
    QNetworkAccessManager* m_net=nullptr;
    QNetworkReply* m_currentReply=nullptr;
    QPushButton* m_downloadBtn=nullptr;
    QPushButton* m_retryBtn=nullptr;
    QProgressBar* m_progress=nullptr;
    QLabel* m_statusLabel=nullptr;
    QString m_savePath;
    QString m_assetUrl;        // 待校验的 CLI 资产下载地址
    QString m_tempPath;         // 资产先写入与目标同目录的临时文件，校验通过后原子改名
    QByteArray m_assetData;     // 已下载资产字节（用于 SHA256 校验）
    bool m_shaWarned=false;     // .sha256 缺失时跳过校验并在结果中提示
};
