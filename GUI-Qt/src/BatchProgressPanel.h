// 批量任务帧式进
#pragma once
#include <QWidget>

class QLabel;
class QVBoxLayout;

class BatchProgressPanel : public QWidget {
    Q_OBJECT
public:
    explicit BatchProgressPanel(QWidget* parent = nullptr);

    // 重建行
    void setThreadCount(int n);
    // 渲染 CLI 帧
    void applyFrame(const QStringList& lines);
    // 空闲态
    void showIdle(const QString& summary, int threads);
    // 运行前清空
    void clearAll();

    // 推算传给 CLI
    int recommendedColumns() const;
    // 显式设定列宽并
    void setColumns(int columns);

    // 与 CLI 一致
    static QString fmtBytes(qint64 bytes);
    static QString fmtRate(double bytesPerSec);
    static QString fmtEta(double seconds);
    static QString summaryLine(int columns, qint64 totalBytes, qint64 doneBytes,
                               double rateBytesPerSec, double etaSeconds);
    // 空闲线程行
    static QString idleLine(int columns);

private:
    void ensureRows(int n);
    struct Layout { int pathW, barW, inner; };
    static Layout layoutFor(int columns);

    QLabel*      m_summary = nullptr;
    QVBoxLayout* m_rowsLayout = nullptr;
    QList<QLabel*> m_rows;
    int          m_columns = 100;
};
