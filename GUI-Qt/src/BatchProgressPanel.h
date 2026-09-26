// BatchProgressPanel - 批量任务的帧式进度面板（GUI 1.3.0）
// 直接呈现 CLI core/progress_frame.cpp 生成的帧文本（字段/分隔符/单位与 CLI 一致，不重排）；空闲态按同布局生成汇总行+空线程行，ETA 取自历史样本，保证布局不跳动。
#pragma once
#include <QWidget>

class QLabel;
class QVBoxLayout;

class BatchProgressPanel : public QWidget {
    Q_OBJECT
public:
    explicit BatchProgressPanel(QWidget* parent = nullptr);

    // 重建行：1 行汇总 + n 行线程（n<=0 时只留汇总行）
    void setThreadCount(int n);
    // 渲染 CLI 帧（整帧覆盖上一次帧；行数随帧内容自适应）
    void applyFrame(const QStringList& lines);
    // 空闲态：汇总行 + n 行占位（汇总行文本由调用方按 summaryLine() 生成）
    void showIdle(const QString& summary, int threads);
    // 运行前清空（保留行结构，文本置占位）
    void clearAll();

    // 依据面板宽度与等宽字体推算应传给 CLI 的 COLUMNS（保证帧宽刚好铺满面板）
    int recommendedColumns() const;
    // 显式设定列宽（运行开始时按面板实际宽度设定，并同步给 CLI 的 COLUMNS）
    void setColumns(int columns);

    // ---- 与 CLI core/progress_frame.cpp 严格一致的格式化/布局 ----
    static QString fmtBytes(qint64 bytes);
    static QString fmtRate(double bytesPerSec);
    static QString fmtEta(double seconds);
    // 按 CLI 的列宽规则生成汇总行（总大小 | 已处理大小 | 总速率 | ETA）
    static QString summaryLine(int columns, qint64 totalBytes, qint64 doneBytes,
                               double rateBytesPerSec, double etaSeconds);
    // 空闲线程行（与 CLI 空闲槽位同格式、同列宽）
    static QString idleLine(int columns);

private:
    void ensureRows(int n);
    struct Layout { int pathW, barW, inner; };
    static Layout layoutFor(int columns);          // 与 CLI build_lines() 同一套列宽算法

    QLabel*      m_summary = nullptr;
    QVBoxLayout* m_rowsLayout = nullptr;
    QList<QLabel*> m_rows;
    int          m_columns = 100;                  // 最近一次使用的列宽（空闲态渲染用）
};
