// MainWindow - Qt GUI 主窗口，五区域布局
//   顶栏：QMenuBar "关于"菜单（鸣谢 + README摘要）
//   左侧：文件选择面板（QFileDialog 触发 + QListWidget 展示选中文件）
//   中部：主要功能区（模式 -e/-d/-be/-bd 单选 + 加密模式下拉 + -de/-y/-v 复选 + 运行/取消按钮）
//   右侧：密码输入框（EchoMode Password + 实时强度标签）
//   下部：只读 QPlainTextEdit（命令预览 + 执行输出回显，stdout/stderr 分色）
// 跨平台自适应：用 QSplitter + QGridLayout，窗口可缩放各区域比例。
#pragma once
#include <QMainWindow>
#include "ICommandExecutor.h"
#include "CliArgBuilder.h"
#include "ThemeManager.h"

// 前置声明
class QListWidget;
class QPlainTextEdit;
class QLineEdit;
class QLabel;
class QComboBox;
class QRadioButton;
class QCheckBox;
class QPushButton;
class QButtonGroup;
class QActionGroup;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* e) override;

private slots:
    // 文件选择
    void onAddFiles();
    void onAddDir();
    void onClearFiles();
    // 运行/取消
    void onRunClicked();
    void onCancelClicked();
    // 执行回显
    void onOutputLine(const OutputLine& line);
    void onCommandFinished(const CommandResult& r);
    // 密码强度实时
    void onPasswordChanged(const QString& text);
    // 选项变化 → 刷新命令预览
    void refreshCommandPreview();
    // 主题切换
    void onThemeSwitched();

private:
    // 构建各区域
    void buildMenu();
    QWidget* buildLeftPanel();
    QWidget* buildCenterPanel();
    QWidget* buildRightPanel();
    QWidget* buildBottomPanel();
    void connectSignals();
    void applyButtonStyles();  // 运行/取消按钮样式（主题感知）

    // 业务
    ShellOptions collectOptions() const;
    void appendOutput(const QString& text, bool isError);
    void setStatus(const QString& msg);

    // 顶栏菜单
    QMenuBar*   m_menuBar = nullptr;
    QActionGroup* m_themeGroup = nullptr;
    QAction*     m_actThemeSystem = nullptr;
    QAction*     m_actThemeLight = nullptr;
    QAction*     m_actThemeDark = nullptr;

    // 左侧文件面板
    QListWidget* m_fileList = nullptr;
    QPushButton* m_btnAddFiles = nullptr;
    QPushButton* m_btnAddDir = nullptr;
    QPushButton* m_btnClearFiles = nullptr;

    // 中部功能区
    QButtonGroup* m_actionGroup = nullptr;
    QRadioButton* m_rbEncrypt = nullptr;
    QRadioButton* m_rbDecrypt = nullptr;
    QRadioButton* m_rbBatchEncrypt = nullptr;
    QRadioButton* m_rbBatchDecrypt = nullptr;
    QComboBox* m_modeCombo = nullptr;        // xchacha20 / aegis256
    QCheckBox*  m_chkDeleteSource = nullptr; // -de
    QCheckBox*  m_chkForce = nullptr;         // -y（默认勾选）
    QCheckBox*  m_chkVerbose = nullptr;      // -v
    QLineEdit*  m_outDirEdit = nullptr;      // -o
    QPushButton* m_btnOutDirBrowse = nullptr;
    QLineEdit*  m_keyfileEdit = nullptr;     // -k
    QPushButton* m_btnKeyfileBrowse = nullptr;
    QPushButton* m_btnRun = nullptr;
    QPushButton* m_btnCancel = nullptr;
    QLabel*     m_statusLabel = nullptr;

    // 右侧密码框
    QLineEdit* m_passwordEdit = nullptr;
    QLabel*    m_strengthLabel = nullptr;

    // 下部只读文本框
    QPlainTextEdit* m_outputView = nullptr;

    // 命令执行器
    ICommandExecutor* m_executor = nullptr;
    QString m_fileEncryptorPath;   // 定位到的 FileEncryptor 可执行文件
};
