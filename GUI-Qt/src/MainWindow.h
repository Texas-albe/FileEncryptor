// MainWindow - Qt GUI 主窗口，五区布局

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

// 目录扫描统计：供 QtConcurrent 异步扫描与结果缓存复用（按输入路径为 key）
struct DirStat {
    qint64 bytes=0;
    int    files=0;
};
struct ScanResult {
    qint64 bytes=0;
    int    files=0;
    bool   complete=true;                 // false = 被取消/中断，结果不完整（不入库）
    QHash<QString,DirStat> entries;       // key = 本次扫描的输入路径
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
    void dragEnterEvent(QDragEnterEvent* e) override;   // 功能4：拖放文件/目录
    void dropEvent(QDropEvent* e) override;

private slots:
    // 文件选择
    void onAddFiles();
    void onAddDir();
    void onClearFiles();
    // 运行/取消
    void onRunClicked();
    void onCancelClicked();
    // 密钥轮换（v6 容器 rewrap）
    void onRewrapClicked();
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
    // 功能5：打开任务历史面板
    void onOpenTaskHistory();
    // 目录扫描（异步）：防抖到期 → 发起扫描 / 扫描完成 → 入库
    void startPendingScan();
    void onPendingScanFinished();
    // 帧节流：合并高频进度帧后统一渲染，避免整帧替换把界面拖慢
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
    QString locateConfigFile() const;
    void applyBackground(const QString& path,bool resizeToRatio=false);
    void resizeBgLabel();

    // CLI 检测相关
    bool checkCliExists(bool showDialog=true);
    void showCliNotFoundError(const QString& context=QString());
    // CLI zstd 能力探测（--features 输出 zstd=1/0 → m_zstdAvailable）
    void probeZstdSupport();
    void onProbeFinished(int exitCode, QProcess::ExitStatus status);  // 异步探测完成

    // 业务
    ShellOptions collectOptions() const;
    void appendOutput(const QString& text,bool isError);
    void setStatus(const QString& msg);
    void addInputPaths(const QStringList& paths);         // 功能4：去重追加到文件列表
    QString resolveRecipients(const QString& raw) const;  // 功能8：多收件人归一化

    // 功能5/6：任务记录与 ETA
    void beginTaskRecord(const ShellOptions& o);          // 运行前登记任务
    void finishTaskRecord(const CommandResult& r);        // 运行结束落盘历史
    void applyTaskRecord(const TaskRecord& rec);          // 回放：回填参数
    void recomputePending();                              // 重算待处理字节/文件数（异步，防抖 + 缓存）
    void resetPendingCache();                             // 输入集合变化 → 作废扫描缓存
    void updateProgressLabel();                           // 状态栏实时计数（当前文件/完成/跳过/失败）
    void renderFrameLine(const OutputLine& line);         // 进度帧渲染（含计数解析）
    static QString actionKey(CryptoAction a);
    static QString modeKey(CryptoMode m);

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
    QComboBox* m_sourceCombo=nullptr;        // 加密后源文件处理：保留/删除/回收站/安全擦除
    QCheckBox* m_chkForce=nullptr;
    QCheckBox* m_chkSha256=nullptr;          // --sha256：加密成功后生成 <out>.ptd.sha256 校验单
    QCheckBox* m_chkCompress=nullptr;        // zstd 压缩开关（仅对称加密有效）
    QSpinBox* m_compressLevel=nullptr;       // zstd 级别（-5..22；默认 1）
    QLabel*   m_compressLabel=nullptr;
    QLabel*   m_compressTitle=nullptr;       // 行首标题「压缩 (zstd)」，随压缩行整体显隐
    bool      m_zstdAvailable=false;         // 由 CLI --features 探测
    bool      m_aegisAvailable=true;          // 由 CLI --features 探测（aegis=1/0）；默认 true 以免误拦
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
    QPushButton* m_btnRewrap=nullptr;        // 密钥轮换入口（v6 容器 rewrap）
    QString m_rewrapTempKey;                 // rewrap 新口令临时密钥文件（运行结束后删除）
    QLabel* m_statusLabel=nullptr;

    // 右侧密码框（已移除：口令改为运行时经 PasswordDialog 弹窗输入，主页面不留密码控件）
    bool m_lastProgressLine = false;   // 上一条输出是否为进度行（用于原地刷新而非重复追加）
    int m_runFileStarts = 0;           // 功能11：本次运行 CLI 已开始处理的文件数（取消时据此汇总）
    mutable QString m_recipientTempFile; // 功能8：多收件人临时公钥文件（仅含公钥，非机密）

    // 批量进度帧在拟 cmd 输出区内原地整帧刷新：用 QTextBlock 句柄锚定帧首块（position 随文档裁剪自动前移），新帧整体替换；块被裁剪则回退追加自愈。m_frameLen 记录上一帧长度用于构造替换区间。
    QTextBlock m_frameBlock;
    int m_frameLen=0;

    // 功能5：本次运行的任务记录（结束后写入历史）
    TaskRecord m_currentTask;
    QString m_statsFile;  // CLI 统计文件路径（FILEENCRYPTOR_STATS_FILE）
    QElapsedTimer m_runTimer;
    int m_runFileTotal=0;          // 本次运行待处理文件数快照（目录已展开）
    // 功能6：批量进度 / ETA 面板（已下线——进度帧改在拟 cmd 输出区内原地刷新）
    QPushButton* m_btnTaskHistory=nullptr;
    qint64 m_pendingBytes=0;
    int m_pendingFiles=0;

    // 目录扫描异步化（界面解耦）：防抖定时器 + QtConcurrent 工作线程 + 结果缓存。
    // 输入清单不变时（如反复勾选/取消条目）直接复用缓存，避免重复递归遍历同一目录。
    QTimer* m_pendingTimer=nullptr;
    QFutureWatcher<ScanResult>* m_scanWatcher=nullptr;
    std::shared_ptr<std::atomic<bool>> m_scanCancel;   // 跨线程取消标志（按值捕获，窗口析构后仍安全）
    QHash<QString,DirStat> m_dirCache;
    bool m_scanRestartPending=false;                   // 扫描进行中又有新请求 → 结束后补扫一次

    // 实时计数（解析 CLI 输出）：当前文件 / 已完成 / 跳过 / 失败
    int m_doneFiles=0;
    int m_skipFiles=0;
    int m_failFiles=0;
    int m_totalFiles=0;
    QString m_currentFile;
    QLabel* m_progressLabel=nullptr;

    // 进度帧节流：CLI 每 40ms 一帧，GUI 合并到 ~120ms 渲染一次
    QTimer* m_frameTimer=nullptr;
    bool m_framePending=false;
    OutputLine m_pendingFrame;

    // 下部只读文本框
    QPlainTextEdit* m_outputView=nullptr;

    // 命令执行器
    ICommandExecutor* m_executor=nullptr;
    QSystemTrayIcon* m_trayIcon=nullptr;
    QString m_fileEncryptorPath;

    // 异步能力探测（probeZstdSupport）：避免主线程同步等待阻塞 UI
    QProcess* m_probeProcess=nullptr;
    QTimer*   m_probeTimer=nullptr;
};
