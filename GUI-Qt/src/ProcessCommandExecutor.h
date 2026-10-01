// QProcess 异步执行 CLI
#pragma once
#include "ICommandExecutor.h"
#include <QProcess>

class ProcessCommandExecutor : public ICommandExecutor {
    Q_OBJECT
public:
    explicit ProcessCommandExecutor(QObject* parent = nullptr);
    ~ProcessCommandExecutor() override;

    void execute(const CommandRequest& request) override;
    void cancel() override;
    bool isRunning() const override;

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

    QStringList m_frameLines;
    bool m_inFrame = false;
};
