// PasswordDialog - 口令输入弹窗
//
// 交互：
//   - 标准密码掩码（QLineEdit::Password，掩码字符随系统主题）；
//   - 密码框右侧「小眼睛」动作（QLineEdit::TrailingPosition），点击在显示/隐藏间切换。
// 其它安全/策略：
//   - 可选「确认密码」二次输入（加密 / 口令派生场景开启），两次不一致则拒绝；
//   - 前端按 PasswordStrength::meetsPolicy 校验口令策略，不合规拒绝运行；
//   - 口令不长期驻留 QString：accept 时取出 UTF-8 字节进 m_secret（std::vector），
//     立即清空输入框明文；takePassword() 移动出缓冲，调用方用完即擦除（见 MainWindow）。
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

    // 用途文案（加密口令 / 解密口令 / 口令派生）
    void setPurpose(const QString& purpose);
    // 是否显示「确认密码」二次输入（加密 / 派生建议开启）
    void setRequireConfirm(bool on);

    // 取出口令（移动出内部缓冲，调用后内部清空）。返回后调用方应尽快用完并擦除。
    std::vector<unsigned char> takePassword();

private slots:
    void onAccept();
    void onTextChanged();

private:
    bool validate(QString& reason);
    // 在密码框右侧（框内）放置显示/隐藏眼睛按钮，点击切换掩码
    void setupEye(QLineEdit* le);

    QLineEdit*  m_pw = nullptr;
    QLineEdit*  m_confirm = nullptr;
    QLabel*     m_purposeLabel = nullptr;
    QLabel*     m_strength = nullptr;
    QPushButton* m_ok = nullptr;
    bool m_requireConfirm = false;
    std::vector<unsigned char> m_secret;   // 临时持有，析构/accept 后擦除
};
