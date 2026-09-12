// ProcessCommandExecutor 实现
#include "ProcessCommandExecutor.h"
#include <QTextStream>
#include <QByteArray>

ProcessCommandExecutor::ProcessCommandExecutor(QObject* parent)
    : ICommandExecutor(parent) {}

ProcessCommandExecutor::~ProcessCommandExecutor() {
    cleanup();
}

void ProcessCommandExecutor::execute(const CommandRequest& request) {
    // 若已有进程在跑，先清理（不应发生，防御性）
    if (m_process) {
        cleanup();
    }

    m_cancelled = false;
    m_outBuffer.clear();
    m_errBuffer.clear();

    m_process = new QProcess(this);

    // 合并环境变量：继承父进程环境 + 注入 extraEnv（GUI 已不再经环境变量传递密钥）
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QStringList keys = request.extraEnv.keys();
    for (const QString& k : keys) {
        env.insert(k, request.extraEnv.value(k));
    }
    m_process->setProcessEnvironment(env);
    m_process->setProgram(request.programPath);
    m_process->setArguments(request.arguments);
    if (!request.workingDirectory.isEmpty()) {
        m_process->setWorkingDirectory(request.workingDirectory);
    }

    // 异步读取 stdout/stderr（分开处理：stdout 默认色，stderr 红色）
    m_process->setProcessChannelMode(QProcess::SeparateChannels);

    connect(m_process, &QProcess::readyReadStandardOutput,
            this, &ProcessCommandExecutor::onReadyReadStandardOutput);
    connect(m_process, &QProcess::readyReadStandardError,
            this, &ProcessCommandExecutor::onReadyReadStandardError);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &ProcessCommandExecutor::onFinished);
    connect(m_process, &QProcess::errorOccurred,
            this, &ProcessCommandExecutor::onErrorOccurred);

    // 启动子进程。
    m_process->start();
    // 安全通道：若请求携带 stdin 数据（密钥 / 身份私钥），写入子进程后关闭写通道，
    // 子进程据此从 stdin 读取密钥材料（CLI 侧 --key-stdin）。密钥不进环境变量、不进命令行，
    // 避免被进程列表 / 环境窥探泄露。即使无数据也关闭写通道，保持“stdin 已关闭”语义，
    // 防止子进程在交互式读取上阻塞。
    if (!request.stdinData.isEmpty()) {
        m_process->write(request.stdinData);
    }
    m_process->closeWriteChannel();
    // 启动是异步的；路径错误等失败经 errorOccurred -> Finished 处理
}

void ProcessCommandExecutor::cancel() {
    if (!m_process || !isRunning()) {
        return;
    }
    m_cancelled = true;
    // kill 进程树（跨平台：Linux kill 子进程，Windows taskkill /T 或 TerminateProcess）
    m_process->kill();
}

bool ProcessCommandExecutor::isRunning() const {
    return m_process && m_process->state() != QProcess::NotRunning;
}

void ProcessCommandExecutor::onReadyReadStandardOutput() {
    if (!m_process) return;
    // CLI 全程以 UTF-8 输出（Windows 侧已 SetConsoleOutputCP(CP_UTF8)）。
    // 这里必须用 fromUtf8 而非 fromLocal8Bit：后者在 Windows 按系统代码页（GBK）
    // 解析、在 Linux 按 locale 解析，会把 UTF-8 中文解成乱码。
    m_outBuffer.append(QString::fromUtf8(m_process->readAllStandardOutput()));
    flushLines(m_outBuffer, false);
}

void ProcessCommandExecutor::onReadyReadStandardError() {
    if (!m_process) return;
    m_errBuffer.append(QString::fromUtf8(m_process->readAllStandardError()));
    flushLines(m_errBuffer, true);
}

void ProcessCommandExecutor::flushLines(QString& buffer, bool isError) {
    // 按 \n 切分；保留最后未结束的半行（继续缓冲）
    int idx = 0;
    while ((idx = buffer.indexOf(QLatin1Char('\n'))) != -1) {
        QString line = buffer.left(idx);
        // 处理 \r（Windows CRLF）：UTF-8 解码不会自动剥 \r，这里统一处理
        if (line.endsWith(QLatin1Char('\r'))) {
            line.chop(1);
        }
        buffer.remove(0, idx + 1);
        // 空行也推送，保持输出行数一致
        emit outputLine(OutputLine{line, isError});
    }
}

void ProcessCommandExecutor::onFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitStatus);
    // 刷出残余半行
    if (!m_outBuffer.isEmpty()) {
        QString line = m_outBuffer;
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
        emit outputLine(OutputLine{line, false});
        m_outBuffer.clear();
    }
    if (!m_errBuffer.isEmpty()) {
        QString line = m_errBuffer;
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
        emit outputLine(OutputLine{line, true});
        m_errBuffer.clear();
    }

    CommandResult r;
    r.exitCode = exitCode;
    r.wasCancelled = m_cancelled;
    emitFinished(r);
}

void ProcessCommandExecutor::onErrorOccurred(QProcess::ProcessError error) {
    // 启动失败 / 崩溃等。被取消时 kill 会触发 Crashed，但 m_cancelled 已置位，按取消处理。
    if (m_cancelled) {
        return;
    }
    CommandResult r;
    r.wasCancelled = false;
    QString msg;
    switch (error) {
    case QProcess::FailedToStart: msg = tr("无法启动程序（路径错误或无执行权限）"); break;
    case QProcess::Crashed: msg = tr("进程崩溃"); break;
    case QProcess::Timedout: msg = tr("等待超时"); break;
    case QProcess::ReadError: msg = tr("读取输出失败"); break;
    case QProcess::WriteError: msg = tr("写入失败"); break;
    case QProcess::UnknownError: msg = tr("未知错误"); break;
    }
    r.errorString = msg;
    r.exitCode = -1;
    emit outputLine(OutputLine{tr("[错误] %1").arg(msg), true});
    emitFinished(r);
}

void ProcessCommandExecutor::emitFinished(const CommandResult& r) {
    emit finished(r);
    cleanup();
}

void ProcessCommandExecutor::cleanup() {
    if (m_process) {
        // 断开信号，防止 cleanup 过程中触发
        m_process->disconnect(this);
        if (m_process->state() != QProcess::NotRunning) {
            m_process->kill();
            m_process->waitForFinished(1000);
        }
        m_process->deleteLater();
        m_process = nullptr;
    }
    m_cancelled = false;
    m_outBuffer.clear();
    m_errBuffer.clear();
}
