// ProcessCommandExecutor - 用 QProcess 异步执行 FileEncryptor CLI：按行推送 stdout/stderr，cancel() kill 进程树。
// 密钥/身份私钥经请求内 stdinData 写入子进程 stdin 后关闭写通道，不经环境变量；QProcess 跨平台行为一致。
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
    QString m_outBuffer;   // stdout 行缓冲（按 \n 切分）
    QString m_errBuffer;   // stderr 行缓冲
    bool m_cancelled = false;
    bool m_finishedEmitted = false;  // finished 每次执行至多发一次

    void flushLines(QString& buffer, bool isError);
    void handleLine(const QString& line, bool isError);   // 帧哨兵 / 普通行分流
    void emitFinished(const CommandResult& r);
    void cleanup();

    QStringList m_frameLines;   // 当前帧累计的行（哨兵 BEGIN/END 之间）
    bool m_inFrame = false;
};
