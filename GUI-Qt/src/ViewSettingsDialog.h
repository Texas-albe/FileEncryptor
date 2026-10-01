// 视图设置对话框（背景图）
#pragma once
#include <QDialog>

class QLabel;
class QPushButton;

class ViewSettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit ViewSettingsDialog(const QString& currentPath, QWidget* parent = nullptr);

    // 返回最终选定路径
    QString selectedImagePath() const { return m_result; }

private slots:
    void onChoose();
    void onClear();

private:
    void updatePreview(const QString& path);

    QLabel*     m_preview = nullptr;
    QPushButton* m_btnChoose = nullptr;
    QPushButton* m_btnClear = nullptr;
    QString     m_current;
    QString     m_result;
};
