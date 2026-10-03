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

// 命令请求
struct CommandRequest {
    QString programPath;
    QStringList arguments;
    QString workingDirectory;
    // 写入子进程 stdin 的数据
    QByteArray stdinData;
    QProcessEnvironment extraEnv;
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

signals:
    void outputLine(const OutputLine& line);
    // raw 模式下的 stdout 原始字节（不经行解析），供预览解密显示二进制明文前缀
    void rawStdout(const QByteArray& chunk);
    void finished(const CommandResult& result);
};
