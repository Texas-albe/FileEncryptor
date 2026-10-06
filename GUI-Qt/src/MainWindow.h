// 主窗口：五区布局

#pragma once
#include <QMainWindow>
#include <QElapsedTimer>
#include <QTimer>
#include <QShowEvent>
#include <QProcess>
#include <QTextCursor>
#include <QTextBlock>
#include <QHash>
#include <QString>
#include <QStringList>
#include <atomic>
#include <memory>
#include <QFutureWatcher>
#include <QSystemTrayIcon>
#include "ICommandExecutor.h"
#include "CliArgBuilder.h"
#include "ThemeManager.h"
#include "TaskHistory.h"

struct DirStat {
    qint64 bytes=0;
    int    files=0;
};
struct ScanResult {
    qint64 bytes=0;
    int    files=0;
    bool   complete=true;
    QHash<QString,DirStat> entries;
};

// 前置声明
class QListWidget;
class QPlainTextEdit;
class QLineEdit;
class QLabel;
class QComboBox;
class QSpinBox;
class QDoubleSpinBox;
class QRadioButton;
class QCheckBox;
class QPushButton;
class QButtonGroup;
class QActionGroup;
class QGroupBox;
class QToolBar;
class QSplitter;
class QPixmap;
class QBoxLayout;
class ViewSettingsDialog;

class MainWindow: public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent=nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* e) override;
    void dragEnterEvent(QDragEnterEvent* e) override;
    void dropEvent(QDropEvent* e) override;

private slots:
    void onAddFiles();
    void onAddDir();
    void onClearFiles();
    void onRunClicked();
    void onCancelClicked();
    void onRewrapClicked();
    void onOutputLine(const OutputLine& line);
    void onCommandFinished(const CommandResult& r);
    // CLI 请求 y/n 确认：弹窗询问后把答案写回握手文件
    void onConfirmPrompt(const QString& text);
    void refreshCommandPreview();
    void updateAsymVisibility();
    // SM4 需 OpenSSL 支持：不可用时禁用模式下拉里的对应项
    void updateSm4Visibility();
    void updatePackVisibility();
    void updateWrapKeyVisibility();
    void onThemeActionTriggered();
    void onViewSettings();
    void onPreviewClicked();
    void openPreviewFor(const QString& path);
    void onEditConfig();
    void onThemeDarkChanged(bool dark);
    void resizeEvent(QResizeEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void onRetryCliDetection();
    void onOpenTaskHistory();
    void onCheckForUpdate();
    // 加密盘库管理（M4）：每个菜单项拼一组 --vault-* 参数后统一走 m_executor
    void onVaultInit();
    void onVaultList();
    void onVaultRecoveryCreate();
    void onVaultRecoveryOpen();
    void onVaultRekey();
    // 加密盘控制端（M3/M4 未完项）：挂载/锁定/解锁走 FE-Mounter，不由 CLI 持有
    void onVaultMount();
    void onVaultLock();
    void onVaultUnlock();
    void startPendingScan();
    void onPendingScanFinished();
    void flushPendingFrame();

private:
    // 构建各区域
    void buildMenu();
    QWidget* buildLeftPanel();
    QWidget* buildCenterPanel();
    QWidget* buildBottomPanel();
    void connectSignals();
    void applyButtonStyles();
    void applyPanelTransparency();
    // 选项行横排还是竖排：中文恒定横排，英/俄文按实测总宽决定，宽度够仍横排
    void reflowOptionRows();
    // 国庆节主题（节日窗口生效）
    void applyFlagRedTheme();
    QString locateConfigFile() const;
    // 自动更新流程
    QString locateUpdater() const;
    void handleCheckResult(const QByteArray& out, const QString& updater);
    void doUpdaterUpdate(const QString& updater, const QString& url, const QString& sha, const QString& sigUrl, long long size);
    void applyBackground(const QString& path,bool resizeToRatio=false);
    void resizeBgLabel();

    // CLI 检测相关
    bool checkCliExists(bool showDialog=true);
    void showCliNotFoundError(const QString& context=QString());
    void rescanCli();
    void probeZstdSupport();
    void onProbeFinished(int exitCode, QProcess::ExitStatus status);
    // 加密盘：目录插在 head 与 tail 之间（--vault-recovery <dir> --recovery-arg X 的顺序不能乱）；
    // needPw 时弹密码框走 --key-stdin
    void runVaultAction(const QString& title,const QStringList& head,
                        const QStringList& tail,bool needPw,bool requireVault=true);
    // 选加密盘目录：默认从上次用的目录开始；requireVault 为真时校验 vault.meta（不是盘则拒绝）
    QString pickVaultDir(const QString& title,bool requireVault);
    // 上次用的盘符/目录（QSettings 记忆）：盘符空则回落 Z:，目录空则不预设起点
    QString lastMountPoint() const;
    QString lastVaultDir() const;
    void rememberVault(const QString& dir,const QString& point);
    // 定位 FE-Mounter（缓存到 m_mounterPath）
    bool locateMounter();
    // detached 启动 FE-Mounter：pass 非空时落临时密码文件走 --pass-file，启动后延时删除
    void launchMounterDetached(const QStringList& args,const QByteArray& pass);
    // 挂载点对话框：盘符/目录（默认填上次用的）+ （可写时）可写勾选；返回是否确认且盘符非空
    bool promptMountPoint(QString& point,bool& rw);

    ShellOptions collectOptions() const;
    // 包装算法下拉的当前值；控件未建时回落到默认 KWP
    WrapAlg currentWrapAlg() const;
    void appendOutput(const QString& text,bool isError);
    void setStatus(const QString& msg);
    void addInputPaths(const QStringList& paths);
    QString resolveRecipients(const QString& raw) const;

    // 任务记录与 ETA
    void beginTaskRecord(const ShellOptions& o);
    void finishTaskRecord(const CommandResult& r);
    void applyTaskRecord(const TaskRecord& rec);
    void recomputePending();
    void resetPendingCache();
    void updateProgressLabel();
    void renderFrameLine(const OutputLine& line);
    static QString actionKey(CryptoAction a);
    static QString modeKey(CryptoMode m);

    // 菜单栏
    QMenuBar* m_menuBar=nullptr;

    // 「视图」菜单里的主题子菜单（浅色/深色/跟随系统）
    QActionGroup* m_themeGroup=nullptr;
    QAction* m_actThemeLight=nullptr;
    QAction* m_actThemeDark=nullptr;
    QAction* m_actThemeSystem=nullptr;

    QWidget* m_leftPanel=nullptr;
    QWidget* m_centerPanel=nullptr;
    QWidget* m_bottomPanel=nullptr;
    QSplitter* m_outerSplitter=nullptr;

    QLabel* m_bgLabel=nullptr;
    QPixmap  m_bgSource;
    QString  m_bgPath;

    QListWidget* m_fileList=nullptr;
    QPushButton* m_btnAddFiles=nullptr;
    QPushButton* m_btnAddDir=nullptr;
    QPushButton* m_btnClearFiles=nullptr;

    QButtonGroup* m_actionGroup=nullptr;
    QRadioButton* m_rbEncrypt=nullptr;
    QRadioButton* m_rbDecrypt=nullptr;
    QRadioButton* m_rbBatchEncrypt=nullptr;
    QRadioButton* m_rbBatchDecrypt=nullptr;
    QRadioButton* m_rbKeyGen=nullptr;
    QRadioButton* m_rbDerive=nullptr;
    QRadioButton* m_rbPubKey=nullptr;
    QRadioButton* m_rbWrapKey=nullptr;
    QRadioButton* m_rbUnwrapKey=nullptr;
    QWidget* m_modeRow=nullptr;   // 模式 + 文件算法同行，密钥管理下整行隐藏
    QComboBox* m_modeCombo=nullptr;
    QLabel* m_modeTitle=nullptr;
    // 非对称模式下的文件载荷加密算法（非对称只包裹该算法生成的会话密钥）
    QComboBox* m_fileCipherCombo=nullptr;
    QLabel* m_fileCipherLabel=nullptr;
    QComboBox* m_sourceCombo=nullptr;
    QCheckBox* m_chkForce=nullptr;
    QCheckBox* m_chkPack=nullptr;
    QCheckBox* m_chkSha256=nullptr;
    QCheckBox* m_chkSplit=nullptr;
    QWidget* m_splitRow=nullptr;
    QDoubleSpinBox* m_splitSize=nullptr;
    QComboBox* m_splitUnit=nullptr;
    QCheckBox* m_chkCompress=nullptr;
    QWidget* m_compressRow=nullptr;
    QCheckBox* m_chkX448=nullptr;
    QSpinBox* m_compressLevel=nullptr;
    QString   m_compressTipTemplate;
    QLabel*   m_compressLabel=nullptr;
    QLabel*   m_compressTitle=nullptr;
    QCheckBox* m_chkPqc=nullptr;
    QCheckBox* m_chkWatermark=nullptr;
    // 加密盘（M1/M4）：入盘勾选 + 库目录；能力位来自 CLI --features 的 vault=1
    QCheckBox* m_chkIntoVault=nullptr;
    QLineEdit* m_vaultDirEdit=nullptr;
    QPushButton* m_btnVaultBrowse=nullptr;
    QWidget*   m_wmKeyRow=nullptr;
    QLineEdit* m_wmKeyEdit=nullptr;
    QPushButton* m_btnWmKeyBrowse=nullptr;
    bool      m_zstdAvailable=false;
    bool      m_aegisAvailable=true;
    bool      m_aesGcmAvailable=true;
    bool      m_sm4Available=true;
    // 默认 false：旧 CLI 的 --features 无 pqc 字段时按「不支持」，仅观测到 pqc=1 才启用
    bool      m_pqcAvailable=false;
    // 同理：--pack 是 2.8.0 才有的开关，旧 CLI 不认 -p，下发后整个任务被拒
    bool      m_packAvailable=false;
    // 加密盘能力（--features 的 vault=1）：不支持时隐藏入盘控件
    bool      m_vaultAvailable=false;
    // 可写挂载能力（--features 的 vault_rw=1）：挂载对话框里才出现「可写挂载」
    bool      m_vaultRwAvailable=false;
    // FE-Mounter 挂载持有进程路径（detached 常驻挂载 / IPC 锁定解锁）
    QString   m_mounterPath;
    // 密钥包装层要 OpenSSL：--features 里 keywrap 字段缺失即视为不支持
    bool      m_keywrapAvailable=false;
    // 输出目录行：标签单独留指针，包装动作整行隐藏时不留孤零零的「输出目录」
    QLabel* m_outDirLabel=nullptr;
    QLineEdit* m_outDirEdit=nullptr;
    QPushButton* m_btnOutDirBrowse=nullptr;
    QLineEdit* m_keyfileEdit=nullptr;
    QPushButton* m_btnKeyfileBrowse=nullptr;

    QGroupBox* m_asymWidget=nullptr;
    // 非对称组的原始标题：包装动作下临时换成「收件人公钥」，切回时按原文恢复
    QString m_asymTitle;
    QGroupBox* m_keygenWidget=nullptr;
    QLabel* m_keygenIntro=nullptr;

    // 密钥包装区块（WrapKey / UnwrapKey 动作）
    QGroupBox* m_wrapWidget=nullptr;
    QWidget* m_wrapFileRow=nullptr;
    QLabel* m_wrapFileLabel=nullptr;
    // 选项行的四个横排布局，reflowOptionRows 按实测宽度统一切换方向
    QList<QBoxLayout*> m_optionRows;
    QLineEdit* m_wrapFileEdit=nullptr;
    QPushButton* m_btnWrapFileBrowse=nullptr;
    QWidget* m_wrapOutRow=nullptr;
    QLabel* m_wrapOutTitle=nullptr;
    QLineEdit* m_wrapOutEdit=nullptr;
    QPushButton* m_btnWrapOutBrowse=nullptr;
    QWidget* m_wrapAlgRow=nullptr;
    QComboBox* m_wrapAlgCombo=nullptr;
    QLabel* m_wrapAlgTitle=nullptr;
    QLabel* m_wrapIntro=nullptr;
    QWidget* m_recipientRow=nullptr;
    QWidget* m_identityRow=nullptr;
    QLineEdit* m_recipientEdit=nullptr;
    QPushButton* m_btnRecipientBrowse=nullptr;
    QLineEdit* m_identityEdit=nullptr;
    QPushButton* m_btnIdentityBrowse=nullptr;

    QPushButton* m_btnRun=nullptr;
    QPushButton* m_btnCancel=nullptr;
    QPushButton* m_btnRewrap=nullptr;
    QMenu* m_vaultMenu=nullptr;         // 加密盘库管理菜单；CLI 不支持时整体禁用
    QString m_rewrapTempKey;
    QLabel* m_statusLabel=nullptr;

    bool m_lastProgressLine = false;
    int m_runFileStarts = 0;
    mutable QString m_recipientTempFile;

    QTextBlock m_frameBlock;
    int m_frameLen=0;

    TaskRecord m_currentTask;
    QString m_statsFile;
    QString m_confirmFile;
    QElapsedTimer m_runTimer;
    int m_runFileTotal=0;
    QPushButton* m_btnTaskHistory=nullptr;
    QPushButton* m_btnPreview=nullptr;
    class PreviewDialog* m_previewDlg=nullptr;
    qint64 m_pendingBytes=0;
    int m_pendingFiles=0;

    QTimer* m_pendingTimer=nullptr;
    QFutureWatcher<ScanResult>* m_scanWatcher=nullptr;
    std::shared_ptr<std::atomic<bool>> m_scanCancel;
    QHash<QString,DirStat> m_dirCache;
    bool m_scanRestartPending=false;

    int m_doneFiles=0;
    int m_skipFiles=0;
    int m_failFiles=0;
    int m_totalFiles=0;
    QString m_currentFile;
    QLabel* m_progressLabel=nullptr;

    QTimer* m_frameTimer=nullptr;
    bool m_framePending=false;
    OutputLine m_pendingFrame;

    QPlainTextEdit* m_outputView=nullptr;

    // 国庆祝福语（功能区底部，常驻不被裁）
    QLabel* m_birthdayLabel=nullptr;
    void applyBirthdayStyle();

    // 命令执行器
    ICommandExecutor* m_executor=nullptr;
    QSystemTrayIcon* m_trayIcon=nullptr;
    QString m_fileEncryptorPath;

    QProcess* m_probeProcess=nullptr;
    QTimer*   m_probeTimer=nullptr;
};
