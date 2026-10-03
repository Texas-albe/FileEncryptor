// QProcess 异步执行 CLI
#pragma once
#include "ICommandExecutor.h"
#include <QProcess>

class ProcessCommandExecutor : public ICommandExecutor {
    Q_OBJECT
public:
    explicit ProcessCommandExecutor(QObject* parent = nullptr);
    ~ProcessCommandExecutor() override;

    // raw 模式：stdout 原样字节流交给 rawStdout，不做行解析。
    // 预览解密要的就是二进制明文前缀，走行解析会被 \r / \0 切坏。
    void execute(const CommandRequest& request) override;
    void setRawMode(bool on);
    void cancel() override;
    bool isRunning() const override;
    void answerConfirm(bool yes) override;

private slots:
    void onReadyReadStandardOutput();
    void onReadyReadStandardError();
    void onFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onErrorOccurred(QProcess::ProcessError error);

private:
    QProcess* m_process = nullptr;
    QString m_outBuffer;
    QString m_errBuffer;
    bool m_cancelled = false;
    bool m_finishedEmitted = false;

    void flushLines(QString& buffer, bool isError);
    void handleLine(const QString& line, bool isError);
    void emitFinished(const CommandResult& r);
    void cleanup();

    bool m_raw = false;

    QStringList m_frameLines;
    bool m_inFrame = false;

    QString m_confirmFile;
    // 已弹窗等回答 / 已写答案但 CLI 未取走，两态都禁止再次弹窗
    bool m_confirmPending = false;
    bool m_confirmAnswered = false;
    class QTimer* m_confirmTimer = nullptr;
    void pollConfirmFile();
};
