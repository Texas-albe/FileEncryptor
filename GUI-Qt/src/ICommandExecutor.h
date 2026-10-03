// 命令执行抽象接口
#pragma once
#include <QObject>
#include <QStringList>
#include <QString>
#include <QProcess>

struct OutputLine {
    QString text;
    bool isError = false;
    bool isProgress = false;
    // 批量进度帧整帧输出
    bool isFrame = false;
};

inline const char* feFrameBeginMarker() { return "\x1b[FEPRG+"; }
inline const char* feFrameEndMarker()   { return "\x1b[FEPRG-"; }

// CLI 询问确认的握手文件环境变量：CLI 往里写问题，宿主写回 y/n。
// 走文件而非 stdin —— stdin 已被 --key-stdin 读到 EOF 占满，宿主无法再应答。
inline const char* feConfirmFileEnv() { return "FILEENCRYPTOR_CONFIRM_FILE"; }

// 命令请求
struct CommandRequest {
    QString programPath;
    QStringList arguments;
    QString workingDirectory;
    // 写入子进程 stdin 的数据
    QByteArray stdinData;
    QProcessEnvironment extraEnv;
    // CLI 询问确认时的握手文件路径（空 = 不启用）
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

    // 启动命令（异步）
    virtual void execute(const CommandRequest& request) = 0;

    // 取消并 kill 进程树
    virtual void cancel() = 0;

    virtual bool isRunning() const = 0;

    // 回答 CLI 的 y/n 询问
    virtual void answerConfirm(bool yes) = 0;

signals:
    void outputLine(const OutputLine& line);
    // raw 模式下的 stdout 原始字节（不经行解析），供预览解密显示二进制明文前缀
    void rawStdout(const QByteArray& chunk);
    // CLI 请求确认，text 为完整问题（已含 y/N 提示）
    void confirmPrompt(const QString& text);
    void finished(const CommandResult& result);
};
