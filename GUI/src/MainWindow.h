// MainWindow - Qt GUI 主窗口，五区布局

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
class QGroupBox;
class QToolBar;
class QSplitter;
class QPixmap;
class ViewSettingsDialog;

class MainWindow: public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent=nullptr);
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
    // 选项变化 → 刷新命令预览
    void refreshCommandPreview();
    // 非对称模式下显示/隐藏收件人/身份输入与密码面板
    void updateAsymVisibility();
    // 主题切换（菜单栏下拉框）
    void onThemeComboChanged(int idx);
    // 视图设置（背景图）
    void onViewSettings();
    // 编辑 FileEncryptorCLI 的 yaml 配置（系统默认编辑器）
    void onEditConfig();
    // 主题实际生效变化（来自 ThemeManager 信号，切换主题后）
    void onThemeDarkChanged(bool dark);
    // 窗口几何变化 → 重绘背景图
    void resizeEvent(QResizeEvent* e) override;
    // 手动重试 CLI 检测
    void onRetryCliDetection();

private:
    // 构建各区域
    void buildMenu();
    void buildNavControls();
    QWidget* buildLeftPanel();
    QWidget* buildCenterPanel();
    QWidget* buildBottomPanel();
    void connectSignals();
    void applyButtonStyles();
    void applyPanelTransparency();
    QString locateConfigFile() const;
    void applyBackground(const QString& path,bool resizeToRatio=false);
    void resizeBgLabel();

    // CLI 检测相关
    bool checkCliExists(bool showDialog=true);
    void showCliNotFoundError(const QString& context=QString());

    // 业务
    ShellOptions collectOptions() const;
    void appendOutput(const QString& text,bool isError);
    void setStatus(const QString& msg);

    // 菜单栏
    QMenuBar* m_menuBar=nullptr;

    // 导航栏（菜单栏右上角控件）
    QWidget* m_navWidget=nullptr;
    QComboBox* m_themeCombo=nullptr;
    QPushButton* m_btnViewSettings=nullptr;

    // 面板容器（用于半透明叠加背景图）
    QWidget* m_leftPanel=nullptr;
    QWidget* m_centerPanel=nullptr;
    QWidget* m_bottomPanel=nullptr;
    QSplitter* m_outerSplitter=nullptr;

    // 背景图
    QLabel* m_bgLabel=nullptr;
    QPixmap  m_bgSource;
    QString  m_bgPath;

    // 左侧文件面板
    QListWidget* m_fileList=nullptr;
    QPushButton* m_btnAddFiles=nullptr;
    QPushButton* m_btnAddDir=nullptr;
    QPushButton* m_btnClearFiles=nullptr;

    // 中部功能区
    QButtonGroup* m_actionGroup=nullptr;
    QRadioButton* m_rbEncrypt=nullptr;
    QRadioButton* m_rbDecrypt=nullptr;
    QRadioButton* m_rbBatchEncrypt=nullptr;
    QRadioButton* m_rbBatchDecrypt=nullptr;
    QRadioButton* m_rbKeyGen=nullptr;
    QRadioButton* m_rbDerive=nullptr;    // -G：口令派生密钥对
    QRadioButton* m_rbPubKey=nullptr;    // -Y：由私钥导出公钥
    QComboBox* m_modeCombo=nullptr;
    QCheckBox* m_chkDeleteSource=nullptr;
    QCheckBox* m_chkForce=nullptr;
    QCheckBox* m_chkVerbose=nullptr;
    QLineEdit* m_outDirEdit=nullptr;
    QPushButton* m_btnOutDirBrowse=nullptr;
    QLineEdit* m_keyfileEdit=nullptr;
    QPushButton* m_btnKeyfileBrowse=nullptr;

    // Asymmetric (rage / X25519) input area
    QGroupBox* m_asymWidget=nullptr;     // recipients / identity rows
    QGroupBox* m_keygenWidget=nullptr;   // -g / -G / -Y 的说明区（标题与正文随动作切换）
    QLabel* m_keygenIntro=nullptr;
    QWidget* m_recipientRow=nullptr;   // public key input (-r, asymmetric encrypt)
    QWidget* m_identityRow=nullptr;    // private key file (-k, asymmetric decrypt)
    QLineEdit* m_recipientEdit=nullptr;
    QPushButton* m_btnRecipientBrowse=nullptr;
    QLineEdit* m_identityEdit=nullptr;
    QPushButton* m_btnIdentityBrowse=nullptr;

    QPushButton* m_btnRun=nullptr;
    QPushButton* m_btnCancel=nullptr;
    QLabel* m_statusLabel=nullptr;

    // 右侧密码框（已移除：口令改为运行时经 PasswordDialog 弹窗输入，主页面不留密码控件）
    bool m_lastProgressLine = false;   // 上一条输出是否为进度行（用于原地刷新而非重复追加）

    // 下部只读文本框
    QPlainTextEdit* m_outputView=nullptr;

    // 命令执行器
    ICommandExecutor* m_executor=nullptr;
    QString m_fileEncryptorPath;
};
