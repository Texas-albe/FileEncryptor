// ProcessCommandExecutor - 用 QProcess 异步执行 FileEncryptor 命令行程序
// 实现：异步捕获 stdout/stderr 按行推送；CancellationToken 取消（kill 进程树）；
//       密钥/身份私钥经请求内的 stdinData 写入子进程 stdin（安全管道），随后关闭写通道，
//       不通过环境变量注入，避免密钥在进程列表/环境中泄露。
// 跨平台：QProcess 在 Win/Linux/macOS 行为一致。
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

    void flushLines(QString& buffer, bool isError);
    void emitFinished(const CommandResult& r);
    void cleanup();
};
