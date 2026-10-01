// 主窗口：五区布局

#pragma once
#include <QMainWindow>
#include <QElapsedTimer>
#include <QTimer>
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
    void refreshCommandPreview();
    void updateAsymVisibility();
    void onThemeComboChanged(int idx);
    void onViewSettings();
    void onEditConfig();
    void onThemeDarkChanged(bool dark);
    void resizeEvent(QResizeEvent* e) override;
    void onRetryCliDetection();
    void onOpenTaskHistory();
    void onCheckForUpdate();
    void startPendingScan();
    void onPendingScanFinished();
    void flushPendingFrame();

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
    // 国庆节主题（节日窗口生效）
    void applyFlagRedTheme();
    QString locateConfigFile() const;
    // 自动更新流程
    QString locateUpdater() const;
    void handleCheckResult(const QByteArray& out, const QString& updater);
    void doUpdaterUpdate(const QString& updater, const QString& url, const QString& sha, const QString& sigUrl);
    void applyBackground(const QString& path,bool resizeToRatio=false);
    void resizeBgLabel();

    // CLI 检测相关
    bool checkCliExists(bool showDialog=true);
    void showCliNotFoundError(const QString& context=QString());
    void probeZstdSupport();
    void onProbeFinished(int exitCode, QProcess::ExitStatus status);

    ShellOptions collectOptions() const;
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

    QWidget* m_navWidget=nullptr;
    QComboBox* m_themeCombo=nullptr;
    QPushButton* m_btnViewSettings=nullptr;

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
    QComboBox* m_modeCombo=nullptr;
    QComboBox* m_sourceCombo=nullptr;
    QCheckBox* m_chkForce=nullptr;
    QCheckBox* m_chkSha256=nullptr;
    QCheckBox* m_chkCompress=nullptr;
    QSpinBox* m_compressLevel=nullptr;
    QLabel*   m_compressLabel=nullptr;
    QLabel*   m_compressTitle=nullptr;
    bool      m_zstdAvailable=false;
    bool      m_aegisAvailable=true;
    QLineEdit* m_outDirEdit=nullptr;
    QPushButton* m_btnOutDirBrowse=nullptr;
    QLineEdit* m_keyfileEdit=nullptr;
    QPushButton* m_btnKeyfileBrowse=nullptr;

    QGroupBox* m_asymWidget=nullptr;
    QGroupBox* m_keygenWidget=nullptr;
    QLabel* m_keygenIntro=nullptr;
    QWidget* m_recipientRow=nullptr;
    QWidget* m_identityRow=nullptr;
    QLineEdit* m_recipientEdit=nullptr;
    QPushButton* m_btnRecipientBrowse=nullptr;
    QLineEdit* m_identityEdit=nullptr;
    QPushButton* m_btnIdentityBrowse=nullptr;

    QPushButton* m_btnRun=nullptr;
    QPushButton* m_btnCancel=nullptr;
    QPushButton* m_btnRewrap=nullptr;
    QString m_rewrapTempKey;
    QLabel* m_statusLabel=nullptr;

    bool m_lastProgressLine = false;
    int m_runFileStarts = 0;
    mutable QString m_recipientTempFile;

    QTextBlock m_frameBlock;
    int m_frameLen=0;

    TaskRecord m_currentTask;
    QString m_statsFile;
    QElapsedTimer m_runTimer;
    int m_runFileTotal=0;
    QPushButton* m_btnTaskHistory=nullptr;
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

    // 命令执行器
    ICommandExecutor* m_executor=nullptr;
    QSystemTrayIcon* m_trayIcon=nullptr;
    QString m_fileEncryptorPath;

    QProcess* m_probeProcess=nullptr;
    QTimer*   m_probeTimer=nullptr;
};
