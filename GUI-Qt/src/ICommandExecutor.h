// 命令执行抽象接
#pragma once
#include <QObject>
#include <QStringList>
#include <QString>
#include <QProcess>

struct OutputLine {
    QString text;
    bool isError = false;
    bool isProgress = false;
    // 批量进度帧整帧
    bool isFrame = false;
};

inline const char* feFrameBeginMarker() { return "\x1b[FEPRG+"; }
inline const char* feFrameEndMarker()   { return "\x1b[FEPRG-"; }

// CLI 询问确认
// 走文件
inline const char* feConfirmFileEnv() { return "FILEENCRYPTOR_CONFIRM_FILE"; }

// 命令请求
struct CommandRequest {
    QString programPath;
    QStringList arguments;
    QString workingDirectory;
    // 写入子进程 stdin
    QByteArray stdinData;
    QProcessEnvironment extraEnv;
    // CLI 询问确认
    QString confirmFile;
};

// 命令结果
struct CommandResult {
    int exitCode = -1;
    bool wasCancelled = false;
    QString errorString;
};

// 命令执行器接口
class ICommandExecutor : public QObject {
    Q_OBJECT
public:
    explicit ICommandExecutor(QObject* parent = nullptr) : QObject(parent) {}
    ~ICommandExecutor() override = default;

    // 启动命令
    virtual void execute(const CommandRequest& request) = 0;

    // 取消并 kill 进程树
    virtual void cancel() = 0;

    virtual bool isRunning() const = 0;

    // 回答 CLI
    virtual void answerConfirm(bool yes) = 0;

signals:
    void outputLine(const OutputLine& line);
    // raw 模式
    void rawStdout(const QByteArray& chunk);
    // CLI 请求确认
    void confirmPrompt(const QString& text);
    void finished(const CommandResult& result);
};
