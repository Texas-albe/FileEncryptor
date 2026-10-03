#include "ProcessCommandExecutor.h"
#include <QTextStream>
#include <QByteArray>

ProcessCommandExecutor::ProcessCommandExecutor(QObject* parent)
    : ICommandExecutor(parent) {}

ProcessCommandExecutor::~ProcessCommandExecutor() {
    cleanup();
}

void ProcessCommandExecutor::execute(const CommandRequest& request) {
    if (m_process) {
        cleanup();
    }

    m_cancelled = false;
    m_outBuffer.clear();
    m_errBuffer.clear();
    m_frameLines.clear();
    m_inFrame = false;
    m_finishedEmitted = false;

    m_process = new QProcess(this);

    // 合并环境变量
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

    // 异步读取 stdout/stderr
    m_process->setProcessChannelMode(QProcess::SeparateChannels);

    connect(m_process, &QProcess::readyReadStandardOutput,
            this, &ProcessCommandExecutor::onReadyReadStandardOutput);
    connect(m_process, &QProcess::readyReadStandardError,
            this, &ProcessCommandExecutor::onReadyReadStandardError);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &ProcessCommandExecutor::onFinished);
    connect(m_process, &QProcess::errorOccurred,
            this, &ProcessCommandExecutor::onErrorOccurred);

    m_process->start();
    // 写入 stdin 后关闭写通道
    if (!request.stdinData.isEmpty()) {
        m_process->write(request.stdinData);
    }
    m_process->closeWriteChannel();
}

void ProcessCommandExecutor::setRawMode(bool on) {
    m_raw = on;
}

void ProcessCommandExecutor::cancel() {
    if (!m_process || !isRunning()) {
        return;
    }
    m_cancelled = true;
    // kill 进程树
    m_process->kill();
}

bool ProcessCommandExecutor::isRunning() const {
    return m_process && m_process->state() != QProcess::NotRunning;
}

void ProcessCommandExecutor::onReadyReadStandardOutput() {
    if (!m_process) return;
    const QByteArray chunk = m_process->readAllStandardOutput();
    if (chunk.isEmpty()) return;
    // raw 模式：原样转交，不做行解析（预览解密的明文前缀可能是二进制）
    if (m_raw) { emit rawStdout(chunk); return; }
    // CLI 输出按 UTF-8 解码
    m_outBuffer.append(QString::fromUtf8(chunk));
    flushLines(m_outBuffer, false);
}

void ProcessCommandExecutor::onReadyReadStandardError() {
    if (!m_process) return;
    m_errBuffer.append(QString::fromUtf8(m_process->readAllStandardError()));
    flushLines(m_errBuffer, true);
}

void ProcessCommandExecutor::flushLines(QString& buffer, bool isError) {
    // 按行切分进度帧
    int nl;
    while ((nl = buffer.indexOf(QLatin1Char('\n'))) != -1) {
        QString line = buffer.left(nl);
        buffer.remove(0, nl + 1);
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
        handleLine(line, isError);
    }
    const int lastCr = buffer.lastIndexOf(QLatin1Char('\r'));
    if (lastCr != -1) {
        QString part = buffer.left(lastCr);
        buffer.remove(0, lastCr + 1);
        int start = 0;
        int cr;
        while ((cr = part.indexOf(QLatin1Char('\r'), start)) != -1) {
            const QString seg = part.mid(start, cr - start);
            start = cr + 1;
            if (!seg.isEmpty()) emit outputLine(OutputLine{seg, isError, true, false});
        }
        const QString seg = part.mid(start);
        if (!seg.isEmpty()) emit outputLine(OutputLine{seg, isError, true, false});
    }
}

void ProcessCommandExecutor::handleLine(const QString& line, bool isError) {
    // 收集帧内行
    if (line == QLatin1String(feFrameBeginMarker())) {
        m_frameLines.clear();
        m_inFrame = true;
        return;
    }
    if (line == QLatin1String(feFrameEndMarker())) {
        m_inFrame = false;
        if (!m_frameLines.isEmpty())
            emit outputLine(OutputLine{m_frameLines.join(QLatin1Char('\n')), isError, false, true});
        m_frameLines.clear();
        return;
    }
    if (m_inFrame) {
        m_frameLines << line;
        return;
    }
    // 普通行按 \r 刷新
    int start = 0;
    int cr;
    while ((cr = line.indexOf(QLatin1Char('\r'), start)) != -1) {
        const QString seg = line.mid(start, cr - start);
        start = cr + 1;
        if (!seg.isEmpty()) emit outputLine(OutputLine{seg, isError, true, false});
    }
    const QString tail = line.mid(start);
    if (!tail.isEmpty()) emit outputLine(OutputLine{tail, isError, false, false});
}

void ProcessCommandExecutor::onFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitStatus);
    // 刷出残余半行
    if (!m_outBuffer.isEmpty()) {
        flushLines(m_outBuffer, false);
        if (!m_outBuffer.isEmpty()) {
            QString line = m_outBuffer;
            if (line.startsWith(QLatin1Char('\r'))) line.remove(0, 1);
            handleLine(line, false);
            m_outBuffer.clear();
        }
    }
    // 补发未闭合的半帧
    if (m_inFrame && !m_frameLines.isEmpty()) {
        m_inFrame = false;
        emit outputLine(OutputLine{m_frameLines.join(QLatin1Char('\n')), false, false, true});
        m_frameLines.clear();
    }
    if (!m_errBuffer.isEmpty()) {
        flushLines(m_errBuffer, true);
        if (!m_errBuffer.isEmpty()) {
            QString line = m_errBuffer;
            if (line.startsWith(QLatin1Char('\r'))) line.remove(0, 1);
            handleLine(line, true);
            m_errBuffer.clear();
        }
    }

    CommandResult r;
    r.exitCode = exitCode;
    r.wasCancelled = m_cancelled;
    emitFinished(r);
}

void ProcessCommandExecutor::onErrorOccurred(QProcess::ProcessError error) {
    // 启动失败处理
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
    // finished 至多发一次
    if (m_finishedEmitted) {
        return;
    }
    m_finishedEmitted = true;
    emit finished(r);
    cleanup();
}

void ProcessCommandExecutor::cleanup() {
    if (m_process) {
        m_process->disconnect(this);
        if (m_process->state() != QProcess::NotRunning) {
            m_process->kill();
            // 短暂等待后兜底回收
            m_process->waitForFinished(200);
        }
        m_process->deleteLater();
        m_process = nullptr;
    }
    m_cancelled = false;
    m_outBuffer.clear();
    m_errBuffer.clear();
    m_frameLines.clear();
    m_inFrame = false;
}
