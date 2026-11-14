// 预览解密窗口
#pragma once
#include <QDialog>
// 槽参数类型要完
// 只前置声明 class OutputLine
#include "ICommandExecutor.h"

class QLabel;
class QPlainTextEdit;
class QSpinBox;
class QPushButton;

// 预览请求
struct PreviewRequest {
    QString programPath;
    QString filePath;
    // 为空表示非对称/
    QByteArray password;
    // 预览字节数
    int maxBytes = 4096;
};

class PreviewDialog : public QDialog {
    Q_OBJECT
public:
    explicit PreviewDialog(QWidget* parent = nullptr);
    ~PreviewDialog() override;

    void setFileName(const QString& name);
    // 启动预览
    void start(const PreviewRequest& req);

signals:
    // 请求下一个文件
    void nextRequested();

private slots:
    void onOutput(const OutputLine& line);
    void onFinished(const CommandResult& result);
    void onNextClicked();
    void onCloseClicked();

private:
    void appendChunk(const QString& text);
    void setBusy(bool busy);
    // 子进程 stdout 是二进制
    // 预览到
    void flushPending();

    QLabel*    m_fileLabel = nullptr;
    QPlainTextEdit* m_view = nullptr;
    QSpinBox*  m_bytes = nullptr;
    QPushButton* m_nextBtn = nullptr;
    QPushButton* m_closeBtn = nullptr;
    QLabel*    m_status = nullptr;

    QByteArray m_pending;
    class ProcessCommandExecutor* m_exec = nullptr;
    PreviewRequest m_req;
    bool m_done = false;
    int  m_exitCode = -1;
    QString m_errText;
};
