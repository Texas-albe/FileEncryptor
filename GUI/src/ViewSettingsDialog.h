// ViewSettingsDialog - “视图设置”对话框
// 提供“自定义背景图”功能：用户选择一张图片作为主窗口背景，支持预览与清除。
// 选择结果（图片绝对路径，空串表示清除）由 selectedImagePath() 在 exec()==Accepted 后返回，
// 由 MainWindow 负责应用、按图片比例调整窗口大小并持久化。
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
