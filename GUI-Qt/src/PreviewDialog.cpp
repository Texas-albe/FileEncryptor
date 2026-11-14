#include "PreviewDialog.h"
#include "ICommandExecutor.h"
#include "ProcessCommandExecutor.h"
#include "MsgBox.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QFileInfo>
#include <QFontDatabase>
#include <QScrollBar>

namespace {
// 二进制内容不适
// 统一转成「·」占位 + 转
QString toDisplayText(const QByteArray& raw)
{
    QString out;
    out.reserve(raw.size());
    for (int i = 0; i < raw.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(raw.at(i));
        if (c == '\n')            out += QLatin1Char('\n');
        else if (c == '\r')       out += QStringLiteral("\\r");
        else if (c == '\t')       out += QStringLiteral("\\t");
        else if (c < 0x20 || c == 0x7f) out += QLatin1Char('·');
        else out += QChar::fromLatin1(static_cast<char>(c));
    }
    return out;
}
}

PreviewDialog::PreviewDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("预览解密"));
    resize(760, 520);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 12, 14, 12);
    root->setSpacing(8);

    auto* topRow = new QHBoxLayout;
    m_fileLabel = new QLabel(this);
    m_fileLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    topRow->addWidget(m_fileLabel, 1);
    topRow->addWidget(new QLabel(tr("预览字节数："), this));
    m_bytes = new QSpinBox(this);
    m_bytes->setRange(64, 1 << 20);
    m_bytes->setSingleStep(256);
    m_bytes->setValue(4096);
    m_bytes->setSuffix(tr(" 字节"));
    topRow->addWidget(m_bytes);
    root->addLayout(topRow);

    m_view = new QPlainTextEdit(this);
    m_view->setReadOnly(true);
    m_view->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_view->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    m_view->setPlaceholderText(tr("正在向 CLI 请求明文前缀…"));
    root->addWidget(m_view, 1);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    root->addWidget(m_status);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch(1);
    m_nextBtn = new QPushButton(tr("下一个文件(&N)"), this);
    m_nextBtn->setProperty("uiRole", "primary");
    m_nextBtn->setVisible(false);
    btnRow->addWidget(m_nextBtn);
    m_closeBtn = new QPushButton(tr("关闭(&C)"), this);
    m_closeBtn->setProperty("uiRole", "secondary");
    btnRow->addWidget(m_closeBtn);
    root->addLayout(btnRow);

    connect(m_closeBtn, &QPushButton::clicked, this, &PreviewDialog::onCloseClicked);
    connect(m_nextBtn, &QPushButton::clicked, this, &PreviewDialog::onNextClicked);
    connect(m_bytes, &QSpinBox::valueChanged, this, [this](int) {
        if (m_done) emit nextRequested();   // 改字节数即
    });
}

PreviewDialog::~PreviewDialog()
{
    if (m_exec) m_exec->cancel();
}

void PreviewDialog::setFileName(const QString& name)
{
    m_fileLabel->setText(tr("文件：%1").arg(name));
}

void PreviewDialog::setBusy(bool busy)
{
    m_nextBtn->setEnabled(!busy);
    m_bytes->setEnabled(!busy);
    m_status->setText(busy ? tr("正在解密…") : m_status->text());
}

void PreviewDialog::start(const PreviewRequest& req)
{
    m_req = req;
    m_pending.clear();
    m_done = false;
    m_exitCode = -1;
    m_errText.clear();
    m_view->clear();
    m_nextBtn->setVisible(false);
    setBusy(true);

    CommandRequest cr;
    cr.programPath = req.programPath;
    // -preview 只落 stdout 明文前缀
    cr.arguments << QStringLiteral("-d")
                 << QStringLiteral("--preview")
                 << QStringLiteral("--max-bytes") << QString::number(req.maxBytes)
                 << QStringLiteral("--")
                 << req.filePath;
    cr.stdinData = req.password;

    if (!m_exec) {
        m_exec = new ProcessCommandExecutor(this);
        m_exec->setRawMode(true);   // 明文前缀
        connect(m_exec, &ICommandExecutor::rawStdout,
                this, [this](const QByteArray& c) { m_pending.append(c); });
        connect(m_exec, &ICommandExecutor::outputLine,
                this, &PreviewDialog::onOutput);
        connect(m_exec, &ICommandExecutor::finished,
                this, &PreviewDialog::onFinished);
    }
    m_exec->execute(cr);
}

void PreviewDialog::flushPending()
{
    if (m_pending.isEmpty()) return;
    const QByteArray take = m_pending;
    m_pending.clear();
    m_view->appendPlainText(toDisplayText(take));
    m_view->verticalScrollBar()->setValue(m_view->verticalScrollBar()->maximum());
}

void PreviewDialog::onOutput(const OutputLine& line)
{
    // raw 模式下 CLI
    if (!line.isError) return;
    const QString t = line.text.trimmed();
    if (t.isEmpty()) return;
    if (t.startsWith(QLatin1String("Previewing first"))) return;
    if (!m_errText.contains(t)) m_errText += t + QLatin1Char('\n');
}

void PreviewDialog::onFinished(const CommandResult& r)
{
    flushPending();
    m_done = true;
    m_exitCode = r.exitCode;
    setBusy(false);
    m_nextBtn->setVisible(true);

    if (r.exitCode == 0) {
        m_status->setText(tr("预览完成，未写出任何解密文件。"));
    } else if (r.wasCancelled) {
        m_status->setText(tr("已取消。"));
    } else {
        // 密码错 / 文件损坏 /
        m_status->setText(tr("预览失败：%1").arg(m_errText.isEmpty()
            ? tr("CLI 返回码 %1").arg(r.exitCode) : m_errText.trimmed()));
    }
}

void PreviewDialog::onNextClicked()
{
    emit nextRequested();
}

void PreviewDialog::onCloseClicked()
{
    if (m_exec) m_exec->cancel();
    accept();
}
