// ViewSettingsDialog - "视图设置"对话框：自定义主窗口背景图（预览/清除），结果经 selectedImagePath() 在 Accepted 后返回，由 MainWindow 应用并持久化。
#pragma once
#include <QDialog>

class QLabel;
class QPushButton;

class ViewSettingsDialog : public QDialog {
    Q_OBJECT
public:
    // currentPath：当前已生效的背景图路径（用于对话框初始化预览），可为空。
    explicit ViewSettingsDialog(const QString& currentPath, QWidget* parent = nullptr);

    // exec() 返回 QDialog::Accepted 时调用，返回用户最终选定的图片路径
    // （空串表示用户选择“清除背景”）。
    QString selectedImagePath() const { return m_result; }

private slots:
    void onChoose();
    void onClear();

private:
    void updatePreview(const QString& path);

    QLabel*     m_preview = nullptr;
    QPushButton* m_btnChoose = nullptr;
    QPushButton* m_btnClear = nullptr;
    QString     m_current;   // 对话框内的当前选择（未点时沿用外部传入值）
    QString     m_result;    // 最终确认结果
};
