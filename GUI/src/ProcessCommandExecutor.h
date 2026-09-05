// ProcessCommandExecutor - 用 QProcess 异步执行 FileEncryptor 命令行程序
// 实现：异步捕获 stdout/stderr 按行推送；CancellationToken 取消（kill 进程树）；
//       stdin 立即关闭（让子进程任何 cin 读取得 EOF，安全避开交互式提示）。
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
