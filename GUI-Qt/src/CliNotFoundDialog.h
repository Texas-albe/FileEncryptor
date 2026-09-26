// CliNotFoundDialog.h - CLI 程序未找到时的错误提示对话框（含自动下载）
#pragma once
#include <QDialog>

class QLabel;
class QPushButton;
class QProgressBar;
class QNetworkAccessManager;
class QNetworkReply;

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

private:
    void startDownload(const QString& url, const QString& savePath);
    QString pickCliAsset(const QJsonArray& assets) const;

    bool m_retry=false;
    QNetworkAccessManager* m_net=nullptr;
    QNetworkReply* m_currentReply=nullptr;
    QPushButton* m_downloadBtn=nullptr;
    QPushButton* m_retryBtn=nullptr;
    QProgressBar* m_progress=nullptr;
    QLabel* m_statusLabel=nullptr;
    QString m_savePath;
};
