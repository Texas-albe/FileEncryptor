// KeyLibraryDialog - 密钥库管理界面（功能1）
// 列出本机密钥库中的 age 身份与收件人，支持导入 / 移除 / 导出 / 复制公钥，
// 并可把选中条目应用为加密收件人（公钥串）或解密身份（私钥文件路径）。
// 存储与 CLI 共用（<用户配置目录>/keys/），见 KeyLibrary。
#pragma once
#include <QDialog>
#include <QVector>

#include "KeyLibrary.h"

class QTableWidget;
class QPushButton;
class QString;

class KeyLibraryDialog : public QDialog {
    Q_OBJECT
public:
    // cliPath：CLI 可执行文件路径，用于从私钥派生公钥（-Y）；为空时跳过派生。
    explicit KeyLibraryDialog(const QString& cliPath, QWidget* parent = nullptr);

    // 应用结果（对话框 accept 后读取）：
    // recipientPublicKeys：选中身份/收件人条目的公钥（age1...），逗号分隔；空 = 未选择。
    // identityKeyPath：选中身份条目的私钥文件完整路径；空 = 未选择。
    QString recipientPublicKeys() const { return m_resultPublicKeys; }
    QString identityKeyPath() const { return m_resultIdentityPath; }

private slots:
    void refresh();
    void onImport();
    void onRemove();
    void onExport();
    void onCopyPublicKey();
    void onApplyRecipients();
    void onApplyIdentity();

private:
    QVector<KeyLibEntry> selectedEntries() const;
    void updateButtonState();

    QString m_cliPath;
    QTableWidget* m_table = nullptr;
    QPushButton* m_btnImport = nullptr;
    QPushButton* m_btnRemove = nullptr;
    QPushButton* m_btnExport = nullptr;
    QPushButton* m_btnCopyPub = nullptr;
    QPushButton* m_btnApplyRecipient = nullptr;
    QPushButton* m_btnApplyIdentity = nullptr;
    QPushButton* m_btnClose = nullptr;

    QString m_resultPublicKeys;
    QString m_resultIdentityPath;
};
