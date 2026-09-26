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
    m_frameLines.clear();
    m_inFrame = false;
    m_finishedEmitted = false;

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
    // 切分策略（顺序重要）：
    //   1) 先按 \n 切出完整行交给 handleLine —— 帧哨兵是整行，必须按行识别；
    //   2) 再处理缓冲区里"最后一个 \r 之前"的残留：CLI 的单行进度条以 \r 原地刷新
    //      且不带换行，若等到 \n 才处理，进度就会在结束时才一次性刷出。
    int nl;
    while ((nl = buffer.indexOf(QLatin1Char('\n'))) != -1) {
        QString line = buffer.left(nl);
        buffer.remove(0, nl + 1);
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);   // 兼容 CRLF
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
    // 帧哨兵：BEGIN 与 END 之间的行即一帧（汇总行 + 每线程行），整帧一次性发出
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
    // 普通行：行内的 \r 段按旧语义处理（原地刷新单行进度条）
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
    // 刷出残余半行（同样按 \r / \n 切分，保证末尾进度行正确刷新而非重复堆积）
    if (!m_outBuffer.isEmpty()) {
        flushLines(m_outBuffer, false);
        if (!m_outBuffer.isEmpty()) {
            QString line = m_outBuffer;
            if (line.startsWith(QLatin1Char('\r'))) line.remove(0, 1);
            handleLine(line, false);
            m_outBuffer.clear();
        }
    }
    // 进程被中断（取消/崩溃）时可能有未闭合的帧：把已收到的半帧补发出去
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
    // finished 保证每次 execute() 至多发一次。崩溃等场景下
    // errorOccurred 与 finished 可能先后到达（或 errorOccurred 自身多次触发），
    // 此前两条路径都会走 emitFinished，导致上层把一次任务当成两次结束
    // （进度条提前归零、取消按钮状态错乱、输出窗口被重置两次）。
    if (m_finishedEmitted) {
        return;
    }
    m_finishedEmitted = true;
    emit finished(r);
    cleanup();
}

void ProcessCommandExecutor::cleanup() {
    if (m_process) {
        // 断开信号，防止 cleanup 过程中触发
        m_process->disconnect(this);
        if (m_process->state() != QProcess::NotRunning) {
            m_process->kill();
            // 仅短暂等待子进程退出，避免阻塞调用线程（取消/析构路径）过久。
            // 200ms 足够正常终止；超时则由后续 deleteLater 兜底回收。
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
