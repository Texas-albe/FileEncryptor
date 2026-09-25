// BatchProgressPanel 实现（GUI 1.3.0）
// 格式化与列宽算法与 CLI core/progress_frame.cpp 一一对应，改一处必须同步另一处。
#include "BatchProgressPanel.h"
#include "FontBootstrap.h"

#include <QFont>
#include <QFontMetrics>
#include <QLabel>
#include <QVBoxLayout>

// 与 CLI progress_frame.cpp 中的常量保持一致
namespace {
constexpr int kRateW = 12;
constexpr int kEtaW  = 11;
constexpr int kSepW  = 3;
constexpr int kMinColumns = 60;
constexpr int kMaxColumns = 200;
}

BatchProgressPanel::BatchProgressPanel(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(2, 2, 2, 4);
    lay->setSpacing(0);

    m_summary = new QLabel(this);
    QFont f = FontBootstrap::monoFont();
    f.setBold(true);
    m_summary->setFont(f);
    m_summary->setWordWrap(false);
    m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_summary->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    lay->addWidget(m_summary);

    m_rowsLayout = new QVBoxLayout;
    m_rowsLayout->setContentsMargins(0, 0, 0, 0);
    m_rowsLayout->setSpacing(0);
    lay->addLayout(m_rowsLayout);

    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

// ---------- 格式化（镜像 CLI fmt_bytes / fmt_rate / fmt_eta）----------
static QString fmtValue(double v, const QString& unit) {
    if (v < 10.0)       return QString::number(v, 'f', 2) + QStringLiteral(" ") + unit;
    else if (v < 100.0) return QString::number(v, 'f', 1) + QStringLiteral(" ") + unit;
    return QString::number(v, 'f', 0) + QStringLiteral(" ") + unit;
}

QString BatchProgressPanel::fmtBytes(qint64 bytes) {
    const double KB = 1024.0, MB = 1024.0 * 1024.0, GB = 1024.0 * 1024.0 * 1024.0;
    const double TB = GB * 1024.0;
    double v = (double)bytes;
    if (v >= TB)      return fmtValue(v / TB, QStringLiteral("TB"));
    else if (v >= GB) return fmtValue(v / GB, QStringLiteral("GB"));
    else if (v >= MB) return fmtValue(v / MB, QStringLiteral("MB"));
    else if (v >= KB) return fmtValue(v / KB, QStringLiteral("KB"));
    return QString::number(bytes) + QStringLiteral(" B");
}

QString BatchProgressPanel::fmtRate(double bytesPerSec) {
    if (!(bytesPerSec > 0.0)) return QStringLiteral("-");
    const double KB = 1024.0, MB = 1024.0 * 1024.0, GB = 1024.0 * 1024.0 * 1024.0;
    double v = bytesPerSec;
    if (v >= GB)      return fmtValue(v / GB, QStringLiteral("GB/s"));
    else if (v >= MB) return fmtValue(v / MB, QStringLiteral("MB/s"));
    else if (v >= KB) return fmtValue(v / KB, QStringLiteral("KB/s"));
    return fmtValue(v, QStringLiteral("B/s"));
}

QString BatchProgressPanel::fmtEta(double seconds) {
    if (!(seconds >= 0.0)) return QStringLiteral("--:--");
    qint64 total = (qint64)(seconds + 0.5);
    qint64 h = total / 3600;
    qint64 m = (total % 3600) / 60;
    qint64 s = total % 60;
    if (h > 0) return QString::asprintf("%lld:%02lld:%02lld", h, m, s);
    return QString::asprintf("%02lld:%02lld", m, s);
}

// ---------- 列宽（镜像 CLI build_lines 的分配规则）----------
BatchProgressPanel::Layout BatchProgressPanel::layoutFor(int columns) {
    Layout L;
    int avail = columns - kRateW - kEtaW - 3 * kSepW;
    if (avail < 30) avail = 30;
    int barW = avail * 40 / 100;
    if (barW < 16) barW = 16;
    if (barW > 42) barW = 42;
    int pathW = avail - barW;
    if (pathW < 12) pathW = 12;
    int inner = barW - 2 - 1 - 4;
    if (inner < 6) inner = 6;
    L.pathW = pathW;
    L.barW = barW;
    L.inner = inner;
    return L;
}

static QString padRight(const QString& s, int w) {
    return s.length() >= w ? s : s + QString(w - s.length(), QLatin1Char(' '));
}
static QString padLeft(const QString& s, int w) {
    return s.length() >= w ? s : QString(w - s.length(), QLatin1Char(' ')) + s;
}

QString BatchProgressPanel::summaryLine(int columns, qint64 totalBytes, qint64 doneBytes,
                                        double rateBytesPerSec, double etaSeconds) {
    const Layout L = layoutFor(columns);
    int pct = 0;
    if (totalBytes > 0) pct = (int)((double)doneBytes * 100.0 / (double)totalBytes);
    if (pct > 100) pct = 100;
    const QString totalCol = QStringLiteral("TOTAL ") + fmtBytes(totalBytes);
    const QString doneCol  = QStringLiteral("DONE ") + fmtBytes(doneBytes)
                           + QStringLiteral(" ") + QString::asprintf("%3d%%", pct);
    return padRight(totalCol, L.pathW) + QStringLiteral(" | ")
         + padRight(doneCol, L.barW) + QStringLiteral(" | ")
         + padLeft(fmtRate(rateBytesPerSec), kRateW) + QStringLiteral(" | ")
         + padLeft(QStringLiteral("ETA ") + fmtEta(etaSeconds), kEtaW);
}

QString BatchProgressPanel::idleLine(int columns) {
    const Layout L = layoutFor(columns);
    return padRight(QStringLiteral("-"), L.pathW) + QStringLiteral(" | ")
         + padRight(QStringLiteral("[") + QString(L.inner, QLatin1Char(' ')) + QStringLiteral("]  --%"), L.barW)
         + QStringLiteral(" | ")
         + padLeft(QStringLiteral("-"), kRateW) + QStringLiteral(" | ")
         + padLeft(QStringLiteral("ETA --:--"), kEtaW);
}

// ---------- 行管理 ----------
void BatchProgressPanel::ensureRows(int n) {
    while (m_rows.size() > n) {
        QLabel* l = m_rows.takeLast();
        m_rowsLayout->removeWidget(l);
        l->deleteLater();
    }
    while (m_rows.size() < n) {
        auto* l = new QLabel(this);
        l->setFont(FontBootstrap::monoFont());
        l->setWordWrap(false);
        l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        l->setText(idleLine(m_columns));
        m_rowsLayout->addWidget(l);
        m_rows.append(l);
    }
}

void BatchProgressPanel::setThreadCount(int n) {
    ensureRows(n > 0 ? n : 0);
}

void BatchProgressPanel::applyFrame(const QStringList& lines) {
    if (lines.isEmpty()) return;
    m_summary->setText(lines.first());
    ensureRows(lines.size() - 1);
    for (int i = 1; i < lines.size(); ++i) m_rows[i - 1]->setText(lines.at(i));
}

void BatchProgressPanel::showIdle(const QString& summary, int threads) {
    m_summary->setText(summary);
    ensureRows(threads > 0 ? threads : 0);
    const QString idle = idleLine(m_columns);
    for (QLabel* l : m_rows) l->setText(idle);
}

void BatchProgressPanel::clearAll() {
    m_summary->setText(QString());
    for (QLabel* l : m_rows) l->setText(idleLine(m_columns));
}

void BatchProgressPanel::setColumns(int columns) {
    if (columns < kMinColumns) columns = kMinColumns;
    if (columns > kMaxColumns) columns = kMaxColumns;
    m_columns = columns;
    // 已存在的空闲行按新列宽重排，避免运行中改宽度时列错位
    const QString idle = idleLine(m_columns);
    for (QLabel* l : m_rows) l->setText(idle);
}

int BatchProgressPanel::recommendedColumns() const {
    const QFontMetrics fm(FontBootstrap::monoFont());
    const int cw = fm.horizontalAdvance(QLatin1Char('M'));
    int cols = cw > 0 ? (width() - 8) / cw : 100;
    if (cols < kMinColumns) cols = kMinColumns;
    if (cols > kMaxColumns) cols = kMaxColumns;
    return cols;
}
