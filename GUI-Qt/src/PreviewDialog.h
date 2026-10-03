// 预览解密窗口：调 CLI --preview 把明文前缀取回来显示，不落盘
#pragma once
#include <QDialog>
// 槽参数类型要完整定义：moc 生成元数据时按声明处的名字配对，
// 只前置声明 class OutputLine 会解析不出真实签名，LNK2019。
#include "ICommandExecutor.h"

class QLabel;
class QPlainTextEdit;
class QSpinBox;
class QPushButton;

// 预览请求：外部负责填好 programPath / filePath / 口令
struct PreviewRequest {
    QString programPath;
    QString filePath;
    // 为空表示非对称/无需口令
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
    // 启动预览；由 dialog 内部管理 executor 生命周期
    void start(const PreviewRequest& req);

signals:
    // 请求下一个文件（用户点「下一个」）
    void nextRequested();

private slots:
    void onOutput(const OutputLine& line);
    void onFinished(const CommandResult& result);
    void onNextClicked();
    void onCloseClicked();

private:
    void appendChunk(const QString& text);
    void setBusy(bool busy);
    // 子进程 stdout 是二进制流，Qt 的 QString::fromUtf8 会按 \0 截断：
    // 预览到的字节先缓存成 QByteArray，收齐再一次性解码
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
