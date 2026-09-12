// ICommandExecutor - 命令执行抽象接口
// 外壳层通过此接口调用 FileEncryptor 命令行程序，壳层与业务代码低耦合。
// 具体实现（ProcessCommandExecutor）用 QProcess 启动子进程；测试时可注入 Mock。
#pragma once
#include <QObject>
#include <QStringList>
#include <QString>
#include <QProcess>

// 单行输出（stdout 或 stderr）
struct OutputLine {
    QString text;
    bool isError;   // true=stderr, false=stdout
};

// 命令请求：argv + 可选 stdin 数据（安全通道，替代环境变量注入密钥）+ 工作目录
struct CommandRequest {
    QString programPath;        // FileEncryptor.exe 可执行文件路径
    QStringList arguments;      // argv（不含程序名）
    QString workingDirectory;   // 工作目录（空=继承父进程）
    // 写入子进程 stdin 的数据（密钥/身份私钥经此安全管道喂入，不进环境变量、不进命令行）。
    // 非空时执行器会写入并关闭写通道；为空时仅关闭 stdin 写通道。
    QByteArray stdinData;
    // 额外环境变量（一般无需注入密钥；保留供未来扩展）。
    QProcessEnvironment extraEnv;
};

// 命令结果
struct CommandResult {
    int exitCode = -1;
    bool wasCancelled = false;  // 是否被用户取消（kill）
    QString errorString;        // 启动失败等错误信息
};

// 命令执行器接口。实现类负责异步执行、实时回显、支持取消。
// 信号驱动：每读到一行 stdout/stderr 即 emit outputLine；结束时 emit finished。
class ICommandExecutor : public QObject {
    Q_OBJECT
public:
    explicit ICommandExecutor(QObject* parent = nullptr) : QObject(parent) {}
    ~ICommandExecutor() override = default;

    // 启动命令（异步）。request.arguments 不含程序名；programPath 为可执行文件完整路径。
    virtual void execute(const CommandRequest& request) = 0;

    // 取消正在运行的命令（kill 进程树）。幂等：未运行时调用无副作用。
    virtual void cancel() = 0;

    // 是否正在运行
    virtual bool isRunning() const = 0;

signals:
    // 每读到一行输出（stdout/stderr 分流）即发射
    void outputLine(const OutputLine& line);
    // 命令结束（正常退出、被取消、或启动失败）时发射
    void finished(const CommandResult& result);
};
