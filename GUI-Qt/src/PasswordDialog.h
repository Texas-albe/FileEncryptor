// 口令输入弹窗
#pragma once
#include <QDialog>
#include <vector>

class QLineEdit;
class QLabel;
class QPushButton;

class PasswordDialog : public QDialog {
    Q_OBJECT
public:
    explicit PasswordDialog(QWidget* parent = nullptr);
    ~PasswordDialog() override;

    // 用途文案
    void setPurpose(const QString& purpose);
    // 是否二次确认
    void setRequireConfirm(bool on);

    // 取出口令并清空内部
    std::vector<unsigned char> takePassword();

private slots:
    void onAccept();
    void onTextChanged();

private:
    bool validate(QString& reason);
    // 放置显隐眼睛按钮
    void setupEye(QLineEdit* le);

    QLineEdit*  m_pw = nullptr;
    QLineEdit*  m_confirm = nullptr;
    QLabel*     m_purposeLabel = nullptr;
    QLabel*     m_strength = nullptr;
    QPushButton* m_ok = nullptr;
    bool m_requireConfirm = false;
    std::vector<unsigned char> m_secret;
};
