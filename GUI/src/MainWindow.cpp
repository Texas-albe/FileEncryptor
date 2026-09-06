// MainWindow 实现

#include "MainWindow.h"
#include "AboutDialogs.h"
#include "FileEncryptorLocator.h"
#include "FontBootstrap.h"
#include "PasswordStrength.h"
#include "ProcessCommandExecutor.h"
#include "ViewSettingsDialog.h"
#include "CliNotFoundDialog.h"

#include <QMenuBar>
#include <QApplication>
#include <QStatusBar>
#include <QMenu>
#include <QAction>
#include <QActionGroup>
#include <QFileDialog>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QComboBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QPushButton>
#include <QButtonGroup>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QMessageBox>
#include <QCloseEvent>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QScrollBar>
#include <QFontDatabase>
#include <QColor>
#include <QToolBar>
#include <QPixmap>
#include <QScreen>
#include <QResizeEvent>
#include <QSettings>
#include <QDesktopServices>
#include <QUrl>
#include <QFile>
#include <QTimer>

MainWindow::MainWindow(QWidget* parent): QMainWindow(parent) {
    // 标题含版本号（与 CMake project VERSION 同步为 1.0.1）
    setWindowTitle(QStringLiteral("FileEncryptorGUI %1").arg(
        qApp->applicationVersion().isEmpty() ? QStringLiteral("1.0.1")
        : qApp->applicationVersion()));
    resize(1200,760);

    // 命令执行器（手写极简构造注入，不引 DI 容器）
    m_executor=new ProcessCommandExecutor(this);

    // 启动时检测 CLI 是否存在
    if(!FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        // 延迟显示错误对话框，避免阻塞主窗口初始化
        QTimer::singleShot(500,this,[this]() {
            showCliNotFoundError(tr("启动时检测"));
            });
    }

    buildMenu();
    buildNavControls();

    // 中央布局：左 | (中+右 纵向) | 下
    auto* centralSplitter=new QSplitter(Qt::Horizontal);

    auto* left=buildLeftPanel();
    auto* center=buildCenterPanel();
    auto* right=buildRightPanel();

    // 中 + 右 横向
    auto* midRight=new QSplitter(Qt::Horizontal);
    midRight->addWidget(center);
    midRight->addWidget(right);
    midRight->setStretchFactor(0,3);
    midRight->setStretchFactor(1,1);
    midRight->setSizes({700, 220});

    centralSplitter->addWidget(left);
    centralSplitter->addWidget(midRight);
    centralSplitter->setStretchFactor(0,1);
    centralSplitter->setStretchFactor(1,3);
    centralSplitter->setSizes({300, 900});

    auto* bottom=buildBottomPanel();
    auto* outerSplitter=new QSplitter(Qt::Vertical);
    outerSplitter->addWidget(centralSplitter);
    outerSplitter->addWidget(bottom);
    outerSplitter->setStretchFactor(0,6);
    outerSplitter->setStretchFactor(1,1);
    outerSplitter->setSizes({610, 150});

    setCentralWidget(outerSplitter);
    m_outerSplitter=outerSplitter;
    m_midRightSplitter=midRight;

    // 背景图：面板透明，透出主窗口底图
    applyPanelTransparency();
    // 启动期恢复已保存的背景图（不强制按比例缩放窗口，几何由下方 restoreGeometry 决定）
    QSettings s(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"));
    m_bgPath=s.value(QStringLiteral("backgroundImage")).toString();
    applyBackground(m_bgPath, /*resizeToRatio=*/false);
    // 恢复窗口几何（含背景图设置后的窗口大小，重启后保持生效）
    if(s.contains(QStringLiteral("geometry")))
        restoreGeometry(s.value(QStringLiteral("geometry")).toByteArray());

    // 状态栏
    m_statusLabel=new QLabel(this);
    statusBar()->addWidget(m_statusLabel,1);
    setStatus(m_fileEncryptorPath.isEmpty()
        ? tr("未找到 FileEncryptor 可执行文件 — 请设置环境变量 FILEENCRYPTOR_EXE 或将其置于本程序同目录")
        : tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));

    connectSignals();
    refreshCommandPreview();
}

MainWindow::~MainWindow()=default;

void MainWindow::closeEvent(QCloseEvent* e) {
    // 运行中弹确认
    if(m_executor&&m_executor->isRunning()) {
        auto ret=QMessageBox::question(
            this,tr("确认退出"),
            tr("有命令正在运行，退出将终止它。确定退出？"),
            QMessageBox::Yes|QMessageBox::No,QMessageBox::No);
        if(ret!=QMessageBox::Yes) {
            e->ignore();
            return;
        }
        m_executor->cancel();
    }
    // 持久化窗口几何（含背景图设置后的窗口大小，重启后保持生效）
    QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
        .setValue(QStringLiteral("geometry"),saveGeometry());
    e->accept();
}

// ---------- 顶栏菜单（关于 + 编辑；主题/视图设置控件在菜单栏右上角，同一行）----------
void MainWindow::buildMenu() {
    m_menuBar=menuBar();

    // —— 关于菜单 ——
    auto* aboutMenu=m_menuBar->addMenu(tr("关于(&A)"));

    auto* actCredits=aboutMenu->addAction(tr("鸣谢..."));
    connect(actCredits,&QAction::triggered,this,[this]{
        CreditsDialog dlg(this);
        dlg.exec();
        });

    auto* actReadme=aboutMenu->addAction(tr("README 摘要..."));
    connect(actReadme,&QAction::triggered,this,[this]{
        ReadmeDialog dlg(this);
        dlg.exec();
        });

    aboutMenu->addSeparator();
    auto* actAboutQt=aboutMenu->addAction(tr("关于 Qt..."));
    connect(actAboutQt,&QAction::triggered,qApp,&QApplication::aboutQt);

    // —— 编辑菜单（顶层，与“关于”同处菜单栏一行）——
    auto* editMenu=m_menuBar->addMenu(tr("编辑(&E)"));
    auto* actEditConfig=editMenu->addAction(tr("编辑 YAML 配置..."));
    connect(actEditConfig,&QAction::triggered,this,&MainWindow::onEditConfig);

    // —— 工具菜单（可选，添加 CLI 重试检测）——
    auto* toolsMenu=m_menuBar->addMenu(tr("工具(&T)"));
    auto* actRetryCli=toolsMenu->addAction(tr("重新检测 CLI 程序"));
    connect(actRetryCli,&QAction::triggered,this,&MainWindow::onRetryCliDetection);
}

// ---------- 菜单栏右上角控件：颜色主题 + 视图设置（与“关于”同一行）----------
void MainWindow::buildNavControls() {
    m_navWidget=new QWidget(this);
    auto* lay=new QHBoxLayout(m_navWidget);
    lay->setContentsMargins(0,0,0,0);
    lay->setSpacing(6);

    // 主题：下拉框，提供 跟随系统 / 浅色 / 深色 三种模式
    lay->addWidget(new QLabel(tr("主题：")));
    m_themeCombo=new QComboBox;
    m_themeCombo->addItem(tr("跟随系统"),static_cast<int>(ThemeManager::Theme::System));
    m_themeCombo->addItem(tr("浅色"),static_cast<int>(ThemeManager::Theme::Light));
    m_themeCombo->addItem(tr("深色"),static_cast<int>(ThemeManager::Theme::Dark));
    // 反映当前持久化偏好
    const int idx=m_themeCombo->findData(static_cast<int>(ThemeManager::chosenTheme()));
    m_themeCombo->setCurrentIndex(idx>=0 ? idx : 0);
    connect(m_themeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,&MainWindow::onThemeComboChanged);
    lay->addWidget(m_themeCombo);

    // 视图设置（背景图）
    m_btnViewSettings=new QPushButton(tr("视图设置"));
    connect(m_btnViewSettings,&QPushButton::clicked,this,&MainWindow::onViewSettings);
    lay->addWidget(m_btnViewSettings);

    // 置于菜单栏右上角（与“关于”同一行）
    m_menuBar->setCornerWidget(m_navWidget,Qt::TopRightCorner);

    // 主题实际生效变化（如“跟随系统”随系统切换）→ 同步下拉框并刷新面板
    connect(&ThemeManager::instance(),&ThemeManager::themeChanged,
        this,&MainWindow::onThemeDarkChanged);
}

void MainWindow::onThemeComboChanged(int idx) {
    const auto t=static_cast<ThemeManager::Theme>(
        m_themeCombo->itemData(idx).toInt());
    ThemeManager::setTheme(t);   // 持久化 + 应用调色板
    applyButtonStyles();
    applyPanelTransparency();    // 面板样式随主题刷新
    refreshCommandPreview();     // 命令预览按当前主题对比色刷新
}

void MainWindow::onThemeDarkChanged(bool /*dark*/) {
    // 跟随系统模式：系统主题变化后保持下拉框与面板同步
    const int idx=m_themeCombo->findData(static_cast<int>(ThemeManager::chosenTheme()));
    if(idx>=0) {
        m_themeCombo->blockSignals(true);
        m_themeCombo->setCurrentIndex(idx);
        m_themeCombo->blockSignals(false);
    }
    applyButtonStyles();
    applyPanelTransparency();
}

// ---------- 视图设置（自定义背景图）----------
void MainWindow::onViewSettings() {
    ViewSettingsDialog dlg(m_bgPath,this);
    if(dlg.exec()!=QDialog::Accepted) return;

    const QString path=dlg.selectedImagePath();
    if(path.isEmpty()) {
        // 清除背景
        applyBackground(QString(), /*resizeToRatio=*/false);
        return;
    }
    // 先校验可加载，避免选了损坏文件还写进设置
    const QPixmap pm(path);
    if(pm.isNull()) {
        QMessageBox::warning(this,tr("背景图无效"),
            tr("无法加载该图片，请选择有效的 PNG/JPG 等图片文件。"));
        return;
    }
    applyBackground(path, /*resizeToRatio=*/true);
}

// ---------- 背景图应用 ----------
void MainWindow::applyBackground(const QString& path,bool resizeToRatio) {
    // 清除
    if(path.isEmpty()||!QFileInfo(path).isFile()) {
        m_bgPath.clear();
        m_bgSource=QPixmap();
        if(m_bgLabel) m_bgLabel->hide();
        QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
            .setValue(QStringLiteral("backgroundImage"),QString());
        return;
    }

    const QPixmap pm(path);
    if(pm.isNull()) return;   // 不应发生（onViewSettings 已校验）；保险起见不改状态

    m_bgPath=path;
    m_bgSource=pm;

    if(!m_bgLabel) {
        m_bgLabel=new QLabel(this);
        m_bgLabel->setScaledContents(false);
        m_bgLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
        m_bgLabel->lower();          // 置于所有内容之下
    }
    m_bgLabel->show();
    resizeBgLabel();

    // 持久化
    QSettings(QStringLiteral("FileEncryptor"),QStringLiteral("FileEncryptorGUI"))
        .setValue(QStringLiteral("backgroundImage"),path);

    // 按图片比例拉伸/缩小窗口
    if(resizeToRatio) {
        const qreal ar=static_cast<qreal>(pm.width())/static_cast<qreal>(pm.height());
        QScreen* scr=screen();
        const QRect avail=scr ? scr->availableGeometry() : QRect(0,0,1280,800);
        int h=qBound(480,pm.height(),900);
        int w=qRound(h*ar);
        const int maxW=qRound(avail.width()*0.9);
        const int maxH=qRound(avail.height()*0.9);
        if(w>maxW) { w=maxW; h=qRound(w/ar); }
        if(h>maxH) { h=maxH; w=qRound(h*ar); }
        resize(w,h);
    }
}

// 背景图 QLabel：铺满整个窗口，等比扩展（KeepAspectRatioByExpanding）铺满不变形
void MainWindow::resizeBgLabel() {
    if(!m_bgLabel) return;
    m_bgLabel->setGeometry(rect());
    if(!m_bgSource.isNull()) {
        m_bgLabel->setPixmap(m_bgSource.scaled(
            size(),Qt::KeepAspectRatioByExpanding,Qt::SmoothTransformation));
    }
}

// 面板透明：除输入框(QLineEdit)与按钮(QPushButton)保留自身样式外，
// 其余区域背景一律透明，与整体背景（主题底色或背景图）保持一致，避免颜色突兀的区块。
void MainWindow::applyPanelTransparency() {
    const QString transparent=QStringLiteral("background:transparent;");
    const bool dk=ThemeManager::isDarkActive();

    // 四个功能面板透明（其内部的标签/单选/复选本就无填充，自然融入整体背景）
    for(QWidget* p:{m_leftPanel, m_centerPanel, m_rightPanel, m_bottomPanel}) {
        if(!p) continue;
        p->setAttribute(Qt::WA_TranslucentBackground);
        p->setAutoFillBackground(false);
        p->setStyleSheet(transparent);
    }

    // 通用配色：亮色用浅灰底+深字，暗色用深底+浅字
    const QString fieldBg=dk ? QStringLiteral("#1E1E1E") : QStringLiteral("#F0F0EC");
    const QString fieldFg=dk ? QStringLiteral("#E6E6E6") : QStringLiteral("#333333");
    const QString fieldBor=dk ? QStringLiteral("#3C3C3C") : QStringLiteral("#C8C8C4");
    const QString fieldSel=dk ? QStringLiteral("#3D6B99") : QStringLiteral("#4A7C50");
    const QString altBg=dk ? QStringLiteral("#252525") : QStringLiteral("#E8E8E4");
    const QString hoverBg=dk ? QStringLiteral("#333333") : QStringLiteral("#E0E0DC");
    const QString indBg=dk ? QStringLiteral("#2A2A2A") : QStringLiteral("#FFFFFF");
    const QString indBor=dk ? QStringLiteral("#5A5A5A") : QStringLiteral("#999999");

    // 文件列表：随主题——亮色浅灰底+深字，暗色深底+浅字
    if(m_fileList) {
        m_fileList->setStyleSheet(QStringLiteral(
            "QListWidget{background:%1;color:%2;border:1px solid %3;"
            "border-radius:3px;outline:0;}"
            "QListWidget::item{background:%1;color:%2;padding:2px 4px;}"
            "QListWidget::item:alternate{background:%4;}"
            "QListWidget::item:selected{background:%5;color:#FFFFFF;}"
            "QListWidget::item:hover{background:%6;}"
            "QListWidget::indicator{width:14px;height:14px;border:1px solid %7;"
            "border-radius:2px;background:%8;}"
            "QListWidget::indicator:checked{background:%5;border:1px solid %7;}"
        ).arg(fieldBg,fieldFg,fieldBor,altBg,fieldSel,hoverBg,indBor,indBg));
    }

    // 文本输入框(QLineEdit)与命令预览/输出框：随主题，亮色浅灰底+深字
    const QString fieldStyle=QStringLiteral(
        "background:%1;color:%2;border:1px solid %3;"
        "border-radius:3px;padding:2px 4px;"
        "selection-background-color:%4;selection-color:#FFFFFF;"
    ).arg(fieldBg,fieldFg,fieldBor,fieldSel);
    for(QLineEdit* e:{m_outDirEdit, m_keyfileEdit, m_passwordEdit}) {
        if(e) e->setStyleSheet(fieldStyle);
    }
    if(m_outputView) m_outputView->setStyleSheet(fieldStyle);

    // 勾选框(QCheckBox)/单选框(QRadioButton)：随主题，亮色浅灰底+深字
    const QString optionStyle=QStringLiteral(
        "QCheckBox,QRadioButton{background:%1;color:%2;"
        "border:1px solid %3;border-radius:3px;padding:4px 6px;spacing:6px;}"
        "QCheckBox::indicator,QRadioButton::indicator{width:14px;height:14px;"
        "border:1px solid %4;background:%5;}"
        "QCheckBox::indicator{border-radius:2px;}"
        "QRadioButton::indicator{border-radius:7px;}"
        "QCheckBox::indicator:hover,QRadioButton::indicator:hover{border:1px solid #7AA7D9;}"
        "QCheckBox::indicator:checked{background:%6;border:1px solid %4;}"
        "QRadioButton::indicator:checked{background:%6;border:1px solid %4;}"
    ).arg(fieldBg,fieldFg,fieldBor,indBor,indBg,fieldSel);
    for(QWidget* c:{static_cast<QWidget*>(m_chkDeleteSource), static_cast<QWidget*>(m_chkForce),
                       static_cast<QWidget*>(m_chkVerbose),
                       static_cast<QWidget*>(m_rbEncrypt), static_cast<QWidget*>(m_rbDecrypt),
                       static_cast<QWidget*>(m_rbBatchEncrypt), static_cast<QWidget*>(m_rbBatchDecrypt)}) {
        if(c) c->setStyleSheet(optionStyle);
    }

    // 下拉框(QComboBox：主题/模式) 与其余按钮：随主题显式配色，
    // 亮色浅灰底+深字（避免依赖调色板在某些环境下仍渲染深色）
    const QString ctrlBg=dk ? QStringLiteral("#3D3D40") : QStringLiteral("#ECECEA");
    const QString ctrlFg=dk ? QStringLiteral("#E6E6E6") : QStringLiteral("#333333");
    const QString ctrlBor=dk ? QStringLiteral("#4A4A4D") : QStringLiteral("#C8C8C4");
    const QString ctrlHover=dk ? QStringLiteral("#4A4A4D") : QStringLiteral("#DCDCD8");
    const QString comboStyle=QStringLiteral(
        "QComboBox{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:2px 6px;min-width:60px;}"
        "QComboBox::drop-down{border:none;width:18px;}"
        "QComboBox::down-arrow{image:none;width:0;height:0;border-left:4px solid transparent;"
        "border-right:4px solid transparent;border-top:5px solid %2;}"
        "QComboBox QAbstractItemView{background:%1;color:%2;border:1px solid %3;"
        "selection-background-color:%4;selection-color:#FFFFFF;outline:0;}"
    ).arg(ctrlBg,ctrlFg,ctrlBor,fieldSel);
    for(QComboBox* cb:{m_themeCombo, m_modeCombo}) {
        if(cb) cb->setStyleSheet(comboStyle);
    }
    const QString btnStyle=QStringLiteral(
        "QPushButton{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:4px 10px;}"
        "QPushButton:hover{background:%4;}"
        "QPushButton:disabled{background:%1;color:#999999;}"
    ).arg(ctrlBg,ctrlFg,ctrlBor,ctrlHover);
    for(QPushButton* b:{m_btnAddFiles, m_btnAddDir, m_btnClearFiles,
                           m_btnOutDirBrowse, m_btnKeyfileBrowse, m_btnViewSettings}) {
        if(b) b->setStyleSheet(btnStyle);
    }

    // 外层 splitter 与中右 splitter 透明，让背景在面板间隙也可见
    for(QWidget* s:{m_outerSplitter, m_midRightSplitter}) {
        if(!s) continue;
        s->setAttribute(Qt::WA_TranslucentBackground);
        s->setAutoFillBackground(false);
        s->setStyleSheet(transparent);
    }
}

void MainWindow::resizeEvent(QResizeEvent* e) {
    QMainWindow::resizeEvent(e);
    resizeBgLabel();
}

// ---------- 编辑 YAML 配置（调用系统默认编辑器）----------

static const char* kDefaultConfigYaml=
"# 运维参数仅由此文件提供，CLI 不可覆盖；删除即恢复默认。\n"
"log_file: \"\"              # 留空 = 仅控制台进度\n"
"log_level: INFO           # ERROR / WARN / INFO / DEBUG\n"
"worker_threads: 0         # 0 = 自动（CPU 核数）\n"
"max_open_files: 256       # 并发线程上限 = 此值 / 3（防句柄耗尽）\n"
"max_memory_bytes: 0       # 0 = 不限（可写 512MB / 1GB 等）\n"
"io_buffer_size: 1MB       # 内部流式缓冲（可写 512KB / 2MB 等）\n"
"max_speed: 0              # 0 = 不限速；可写 10MB/s、1.5GB/s、512KB/s（总吞吐上限）\n"
"max_path_length: 0        # 0 = 不限\n"
"path_whitelist_enabled: false\n"
"# path_whitelist:\n"
"#   - C:/Data/In\n"
"progress_rotation: true   # 覆盖 .progress 前先备份 .progress.bak\n"
"obfuscate_names: true     # 混淆输出文件名\n";

// 定位 CLI 的 yaml 配置（与 CLI core/config.cpp::find_config_file 搜索顺序一致）
QString MainWindow::locateConfigFile() const {
    const QString name=QStringLiteral("fileencryptor.yaml");
    // 1) FILEENCRYPTOR_CONFIG 环境变量（显式，最高优先）
    const QString env=qEnvironmentVariable("FILEENCRYPTOR_CONFIG");
    if(!env.isEmpty()&&QFileInfo(env).isFile()) return env;
    // 2) CWD：用户在哪个目录启动，配置就在哪里
    QString p=QDir::current().absoluteFilePath(name);
    if(QFileInfo(p).isFile()) return p;
    // 3) CLI 可执行文件目录
    if(!m_fileEncryptorPath.isEmpty()) {
        p=QFileInfo(m_fileEncryptorPath).absolutePath()+QLatin1Char('/')+name;
        if(QFileInfo(p).isFile()) return p;
    }
    // 4) 用户配置目录
    QString ucd;
#ifdef Q_OS_WIN
    ucd=qEnvironmentVariable("APPDATA");
    if(!ucd.isEmpty()) ucd+=QLatin1String("/FileEncryptor");
#else
    const QString xdg=qEnvironmentVariable("XDG_CONFIG_HOME");
    if(!xdg.isEmpty()) ucd=xdg+QLatin1String("/fileencryptor");
    else {
        const QString home=qEnvironmentVariable("HOME");
        if(!home.isEmpty()) ucd=home+QLatin1String("/.config/fileencryptor");
    }
#endif
    if(!ucd.isEmpty()) {
        p=ucd+QLatin1Char('/')+name;
        if(QFileInfo(p).isFile()) return p;
    }
    return {};
}

void MainWindow::onEditConfig() {
    QString target=locateConfigFile();
    // 未找到 → 按 CLI 行为在 CWD 生成默认配置（便于用户直接编辑）
    if(target.isEmpty()) {
        target=QDir::current().absoluteFilePath(QStringLiteral("fileencryptor.yaml"));
        QFile f(target);
        if(!f.exists()) {
            if(!f.open(QIODevice::WriteOnly|QIODevice::Truncate)) {
                QMessageBox::warning(this,tr("无法创建配置文件"),
                    tr("无法在以下位置创建默认配置文件：\n%1").arg(target));
                return;
            }
            f.write(kDefaultConfigYaml);
            f.close();
        }
    }
    // 调用系统默认编辑器打开（按文件关联；无关联时提示路径）
    if(!QDesktopServices::openUrl(QUrl::fromLocalFile(target))) {
        QMessageBox::information(this,tr("请手动打开"),
            tr("系统未关联 YAML 文件的默认编辑器，请手动打开：\n%1").arg(target));
    }
}

// ---------- CLI 检测相关 ----------
bool MainWindow::checkCliExists(bool showDialog) {
    QString foundPath;
    if(FileEncryptorLocator::existsWithVersion(&foundPath)) {
        m_fileEncryptorPath=foundPath;
        return true;
    }

    if(showDialog) {
        showCliNotFoundError(tr("执行操作时"));
    }
    return false;
}

void MainWindow::showCliNotFoundError(const QString& context) {
    const QStringList expected=FileEncryptorLocator::getExpectedNames();
    QString detail=tr("在 %1 未找到 CLI 程序。\n\n").arg(context);
    detail+=tr("预期文件名：\n");
    for(const QString& name:expected) {
        detail+=QStringLiteral("  - %1\n").arg(name);
    }
    detail+=tr("\n当前程序目录：\n  %1\n").arg(FileEncryptorLocator::selfDir());
    detail+=tr("\n也可设置环境变量 FILEENCRYPTOR_EXE 指向 CLI 程序路径。");

    QMessageBox::critical(this,tr("FileEncryptor CLI 未找到"),detail);
}

void MainWindow::onRetryCliDetection() {
    if(FileEncryptorLocator::existsWithVersion(&m_fileEncryptorPath)) {
        setStatus(tr("就绪 | FileEncryptor: %1").arg(m_fileEncryptorPath));
        QMessageBox::information(this,tr("检测成功"),
            tr("已找到 CLI 程序：\n%1").arg(m_fileEncryptorPath));
    }
    else {
        showCliNotFoundError(tr("手动重试"));
    }
}

// ---------- 运行/取消按钮样式（主题感知，保证深色下文字清晰）----------
void MainWindow::applyButtonStyles() {
    const bool dark=ThemeManager::isDarkActive();
    // 运行按钮：浅色下用柔化绿（#4A7C50）+ 白字，降低饱和度；深色下亮绿
    m_btnRun->setStyleSheet(
        dark
        ? "QPushButton{background:#43A047;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#66BB6A;}"
        : "QPushButton{background:#4A7C50;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#3D6B4A;}");
    m_btnCancel->setStyleSheet(
        dark
        ? "QPushButton{background:#E53935;color:#FFFFFF;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#EF5350;}"
        "QPushButton:disabled{background:#555;color:#ccc;}"
        : "QPushButton{background:#C0392B;color:white;padding:6px 18px;font-weight:bold;border-radius:4px;}"
        "QPushButton:hover{background:#A93226;}"
        "QPushButton:disabled{background:#999;color:#eee;}");
}

// ---------- 左侧文件选择面板 ----------
QWidget* MainWindow::buildLeftPanel() {
    auto* w=new QWidget;
    m_leftPanel=w;
    auto* lay=new QVBoxLayout(w);

    auto* title=new QLabel(tr("<b>文件选择</b>"));
    title->setAlignment(Qt::AlignCenter);
    lay->addWidget(title);

    m_fileList=new QListWidget;
    m_fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_fileList->setAlternatingRowColors(true);
    lay->addWidget(m_fileList,1);

    auto* btnRow1=new QHBoxLayout;
    m_btnAddFiles=new QPushButton(tr("添加文件..."));
    m_btnAddDir=new QPushButton(tr("添加目录..."));
    btnRow1->addWidget(m_btnAddFiles);
    btnRow1->addWidget(m_btnAddDir);
    lay->addLayout(btnRow1);

    auto* btnRow2=new QHBoxLayout;
    m_btnClearFiles=new QPushButton(tr("清空"));
    btnRow2->addStretch();
    btnRow2->addWidget(m_btnClearFiles);
    lay->addLayout(btnRow2);

    return w;
}

// ---------- 中部主要功能区 ----------
QWidget* MainWindow::buildCenterPanel() {
    auto* w=new QWidget;
    m_centerPanel=w;
    auto* lay=new QGridLayout(w);
    lay->setColumnStretch(1,1);

    int row=0;

    // 动作模式
    auto* lblAction=new QLabel(tr("<b>操作</b>"));
    lay->addWidget(lblAction,row,0);
    m_rbEncrypt=new QRadioButton(tr("加密 (-e)"));
    m_rbDecrypt=new QRadioButton(tr("解密 (-d)"));
    m_rbBatchEncrypt=new QRadioButton(tr("批量加密 (-be)"));
    m_rbBatchDecrypt=new QRadioButton(tr("批量解密 (-bd)"));
    m_actionGroup=new QButtonGroup(this);
    m_actionGroup->addButton(m_rbEncrypt,static_cast<int>(CryptoAction::Encrypt));
    m_actionGroup->addButton(m_rbDecrypt,static_cast<int>(CryptoAction::Decrypt));
    m_actionGroup->addButton(m_rbBatchEncrypt,static_cast<int>(CryptoAction::BatchEncrypt));
    m_actionGroup->addButton(m_rbBatchDecrypt,static_cast<int>(CryptoAction::BatchDecrypt));
    m_rbEncrypt->setChecked(true);

    auto* actionRow=new QHBoxLayout;
    actionRow->addWidget(m_rbEncrypt);
    actionRow->addWidget(m_rbDecrypt);
    actionRow->addWidget(m_rbBatchEncrypt);
    actionRow->addWidget(m_rbBatchDecrypt);
    actionRow->addStretch();
    lay->addLayout(actionRow,row,1);
    row++;

    // 加密模式
    auto* lblMode=new QLabel(tr("加密模式"));
    lay->addWidget(lblMode,row,0);
    m_modeCombo=new QComboBox;
    m_modeCombo->addItem(tr("XChaCha20-Poly1305（默认，兼容性最好）"),static_cast<int>(CryptoMode::XChaCha20));
    m_modeCombo->addItem(tr("AEGIS-256（需 AES-NI 指令）"),static_cast<int>(CryptoMode::Aegis256));
    lay->addWidget(m_modeCombo,row,1);
    row++;

    // 输出目录
    auto* lblOut=new QLabel(tr("输出目录 (-o)"));
    lay->addWidget(lblOut,row,0);
    auto* outRow=new QHBoxLayout;
    m_outDirEdit=new QLineEdit;
    m_outDirEdit->setPlaceholderText(tr("留空 = 输出到源文件目录"));
    m_btnOutDirBrowse=new QPushButton(tr("浏览..."));
    outRow->addWidget(m_outDirEdit);
    outRow->addWidget(m_btnOutDirBrowse);
    lay->addLayout(outRow,row,1);
    row++;

    // 密钥文件
    auto* lblKey=new QLabel(tr("密钥文件 (-k)"));
    lay->addWidget(lblKey,row,0);
    auto* keyRow=new QHBoxLayout;
    m_keyfileEdit=new QLineEdit;
    m_keyfileEdit->setPlaceholderText(tr("留空 = 用右侧密码经 ENCRYPTOR_KEY"));
    m_btnKeyfileBrowse=new QPushButton(tr("浏览..."));
    keyRow->addWidget(m_keyfileEdit);
    keyRow->addWidget(m_btnKeyfileBrowse);
    lay->addLayout(keyRow,row,1);
    row++;

    // 选项
    auto* lblOpts=new QLabel(tr("选项"));
    lay->addWidget(lblOpts,row,0);
    auto* optsRow=new QHBoxLayout;
    m_chkDeleteSource=new QCheckBox(tr("完成后删除源文件 (-de)"));
    m_chkForce=new QCheckBox(tr("覆盖已存在文件 (-y)"));
    m_chkForce->setChecked(true);
    m_chkVerbose=new QCheckBox(tr("详细输出 (-v)"));
    optsRow->addWidget(m_chkDeleteSource);
    optsRow->addWidget(m_chkForce);
    optsRow->addWidget(m_chkVerbose);
    optsRow->addStretch();
    lay->addLayout(optsRow,row,1);
    row++;

    // 运行/取消按钮
    auto* runRow=new QHBoxLayout;
    m_btnRun=new QPushButton(tr("▶ 运行"));
    m_btnCancel=new QPushButton(tr("■ 取消"));
    m_btnCancel->setEnabled(false);
    runRow->addStretch();
    runRow->addWidget(m_btnRun);
    runRow->addWidget(m_btnCancel);
    lay->addLayout(runRow,row,1);
    row++;
    // 按钮样式按当前主题应用（构造期 + 主题切换期都会调用）
    applyButtonStyles();

    lay->setRowStretch(row,1);
    return w;
}

// ---------- 右侧密码输入框 ----------
QWidget* MainWindow::buildRightPanel() {
    auto* w=new QWidget;
    m_rightPanel=w;
    auto* lay=new QVBoxLayout(w);

    auto* title=new QLabel(tr("<b>密码</b>"));
    title->setAlignment(Qt::AlignCenter);
    lay->addWidget(title);

    auto* lbl=new QLabel(tr("加密口令："));
    lay->addWidget(lbl);

    m_passwordEdit=new QLineEdit;
    m_passwordEdit->setEchoMode(QLineEdit::Password);   // 星号隐藏
    m_passwordEdit->setPlaceholderText(tr("输入密码（经环境变量注入，不留盘）"));
    lay->addWidget(m_passwordEdit);

    // 强度提示
    auto* lblStrength=new QLabel(tr("强度："));
    lay->addWidget(lblStrength);
    m_strengthLabel=new QLabel(tr("未输入"));
    m_strengthLabel->setAlignment(Qt::AlignCenter);
    QFont f=m_strengthLabel->font();
    f.setBold(true);
    f.setPointSize(f.pointSize()+2);
    m_strengthLabel->setFont(f);
    lay->addWidget(m_strengthLabel);

    lay->addStretch();

    // 提示文字
    auto* tip=new QLabel(tr(
        "<small><i>提示：密码经 ENCRYPTOR_KEY 环境变量\n"
        "注入子进程，不写入命令行/磁盘。\n"
        "提供密钥文件 (-k) 时优先用密钥文件。</i></small>"));
    tip->setWordWrap(true);
    lay->addWidget(tip);

    return w;
}

// ---------- 下部只读文本框 ----------
QWidget* MainWindow::buildBottomPanel() {
    auto* w=new QWidget;
    m_bottomPanel=w;
    auto* lay=new QVBoxLayout(w);
    lay->setContentsMargins(0,0,0,0);

    auto* header=new QLabel(tr("<b>命令浏览与执行输出</b>"));
    lay->addWidget(header);

    m_outputView=new QPlainTextEdit;
    m_outputView->setReadOnly(true);
    m_outputView->setPlaceholderText(tr("此处显示命令预览与执行输出。stdout 默认色，stderr 红色。"));
    // 等宽字体便于对齐
    m_outputView->setFont(FontBootstrap::monoFont());
    lay->addWidget(m_outputView);

    return w;
}

// ---------- 信号连接 ----------
void MainWindow::connectSignals() {
    connect(m_btnAddFiles,&QPushButton::clicked,this,&MainWindow::onAddFiles);
    connect(m_btnAddDir,&QPushButton::clicked,this,&MainWindow::onAddDir);
    connect(m_btnClearFiles,&QPushButton::clicked,this,&MainWindow::onClearFiles);

    connect(m_btnRun,&QPushButton::clicked,this,&MainWindow::onRunClicked);
    connect(m_btnCancel,&QPushButton::clicked,this,&MainWindow::onCancelClicked);

    connect(m_executor,&ICommandExecutor::outputLine,this,&MainWindow::onOutputLine);
    connect(m_executor,&ICommandExecutor::finished,this,&MainWindow::onCommandFinished);

    connect(m_passwordEdit,&QLineEdit::textChanged,this,&MainWindow::onPasswordChanged);

    // 选项变化刷新命令预览
    auto refresh=[this]{ refreshCommandPreview(); };
    connect(m_actionGroup,&QButtonGroup::idClicked,this,refresh);
    connect(m_modeCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,refresh);
    connect(m_outDirEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_keyfileEdit,&QLineEdit::textChanged,this,refresh);
    connect(m_chkDeleteSource,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkForce,&QCheckBox::stateChanged,this,refresh);
    connect(m_chkVerbose,&QCheckBox::stateChanged,this,refresh);
    // 文件列表勾选框切换 → 刷新命令预览（仅勾选项进入命令）
    connect(m_fileList,&QListWidget::itemChanged,this,refresh);

    // 浏览按钮
    connect(m_btnOutDirBrowse,&QPushButton::clicked,this,[this]{
        QString d=QFileDialog::getExistingDirectory(this,tr("选择输出目录"),
            m_outDirEdit->text().isEmpty() ? QDir::homePath() : m_outDirEdit->text());
        if(!d.isEmpty()) m_outDirEdit->setText(d);
        });
    connect(m_btnKeyfileBrowse,&QPushButton::clicked,this,[this]{
        QString f=QFileDialog::getOpenFileName(this,tr("选择密钥文件"),
            QDir::homePath(),tr("所有文件 (*)"));
        if(!f.isEmpty()) m_keyfileEdit->setText(f);
        });
}

// ---------- 文件选择 ----------
void MainWindow::onAddFiles() {
    const QStringList files=QFileDialog::getOpenFileNames(
        this,tr("选择文件"),QDir::homePath(),tr("所有文件 (*)"));
    for(const QString& f:files) {
        auto* item=new QListWidgetItem(f,m_fileList);
        item->setFlags(item->flags()|Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Checked);
    }
    refreshCommandPreview();
}

void MainWindow::onAddDir() {
    const QString d=QFileDialog::getExistingDirectory(
        this,tr("选择目录"),QDir::homePath());
    if(!d.isEmpty()) {
        auto* item=new QListWidgetItem(d,m_fileList);
        item->setFlags(item->flags()|Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Checked);
        refreshCommandPreview();
    }
}

void MainWindow::onClearFiles() {
    m_fileList->clear();
    refreshCommandPreview();
}

// ---------- 密码强度 ----------
void MainWindow::onPasswordChanged(const QString& text) {
    const StrengthResult r=PasswordStrength::evaluate(text);
    m_strengthLabel->setText(r.label);
    m_strengthLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(r.colorHex));
    m_strengthLabel->setToolTip(r.detail);
    refreshCommandPreview();
}

// ---------- 收集选项 ----------
ShellOptions MainWindow::collectOptions() const {
    ShellOptions o;
    o.action=static_cast<CryptoAction>(m_actionGroup->checkedId());
    o.mode=static_cast<CryptoMode>(m_modeCombo->currentData().toInt());

    for(int i=0; i<m_fileList->count(); ++i) {
        auto* it=m_fileList->item(i);
        if(it->checkState()==Qt::Checked) o.inputPaths<<it->text();
    }

    o.outputDir=m_outDirEdit->text().trimmed();
    o.deleteSource=m_chkDeleteSource->isChecked();
    o.forceOverwrite=m_chkForce->isChecked();
    o.verbose=m_chkVerbose->isChecked();
    o.keyfilePath=m_keyfileEdit->text().trimmed();
    o.password=m_passwordEdit->text();

    return o;
}

// ---------- 运行 ----------
void MainWindow::onRunClicked() {
    // 检测 CLI 是否存在
    if(!checkCliExists(true)) {
        return;  // 用户取消或重试失败，阻止继续
    }

    // 检查是否已经存在（双重保险）
    if(m_fileEncryptorPath.isEmpty()) {
        // 再次尝试定位
        m_fileEncryptorPath=FileEncryptorLocator::locate();
        if(m_fileEncryptorPath.isEmpty()) {
            showCliNotFoundError(tr("运行前检测"));
            return;
        }
    }

    const ShellOptions o=collectOptions();

    // 校验
    if(o.inputPaths.isEmpty()) {
        QMessageBox::warning(this,tr("缺少输入"),tr("请先添加文件或目录。"));
        return;
    }
    bool isBatch=(o.action==CryptoAction::BatchEncrypt||
        o.action==CryptoAction::BatchDecrypt);
    if(!isBatch&&o.inputPaths.size()>1) {
        QMessageBox::warning(this,tr("输入过多"),
            tr("单文件模式只接受一个输入路径，请清空后只选一个，或改用批量模式。"));
        return;
    }
    // 密钥校验：未提供密钥文件时，密码必须 >=6（main.cpp L338-341）
    if(o.keyfilePath.isEmpty()&&o.password.length()<6) {
        QMessageBox::warning(this,tr("密码过短"),
            tr("密码至少 6 个字符（或提供密钥文件 -k）。"));
        m_passwordEdit->setFocus();
        return;
    }

    // 构建命令
    CommandRequest req;
    req.programPath=m_fileEncryptorPath;
    req.arguments=CliArgBuilder::buildArguments(o);
    req.extraEnv=CliArgBuilder::buildEnvironment(o);

    // 输出区清空并显示命令预览
    m_outputView->clear();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    appendOutput(QStringLiteral(">>> %1\n").arg(preview),false);
    appendOutput(QStringLiteral("--- 执行开始 ---\n"),false);

    // UI 状态切换
    m_btnRun->setEnabled(false);
    m_btnCancel->setEnabled(true);
    setStatus(tr("运行中..."));

    m_executor->execute(req);
}

void MainWindow::onCancelClicked() {
    if(m_executor->isRunning()) {
        appendOutput(tr("\n--- 用户取消，正在终止子进程... ---\n"),true);
        m_executor->cancel();
    }
}

// ---------- 执行回显 ----------
void MainWindow::onOutputLine(const OutputLine& line) {
    appendOutput(line.text+QStringLiteral("\n"),line.isError);
}

void MainWindow::onCommandFinished(const CommandResult& r) {
    m_btnRun->setEnabled(true);
    m_btnCancel->setEnabled(false);

    QString summary;
    if(r.wasCancelled) {
        summary=tr("--- 已取消（退出码 %1） ---").arg(r.exitCode);
        setStatus(tr("已取消"));
    }
    else if(!r.errorString.isEmpty()) {
        summary=tr("--- 执行失败：%1 ---").arg(r.errorString);
        setStatus(tr("失败：%1").arg(r.errorString));
    }
    else if(r.exitCode==0) {
        summary=tr("--- 执行成功（退出码 0） ---");
        setStatus(tr("完成"));
    }
    else {
        summary=tr("--- 执行结束（退出码 %1） ---").arg(r.exitCode);
        setStatus(tr("结束（退出码 %1）").arg(r.exitCode));
    }
    appendOutput(QStringLiteral("\n%1\n").arg(summary),r.exitCode!=0);
}

// ---------- 输出追加 + 自动滚动 ----------
void MainWindow::appendOutput(const QString& text,bool isError) {
    // 输出框背景随主题：亮色浅灰底→深字，暗色深底→浅字
    const unsigned int rgb=isError ? ThemeManager::stderrColorRGB()
        : ThemeManager::stdoutColorRGB();
    QTextCharFormat fmt;
    fmt.setForeground(QColor((rgb>>16)&0xFF,(rgb>>8)&0xFF,rgb&0xFF));
    QTextCursor cur=m_outputView->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(text,fmt);
    // 自动滚到底
    QScrollBar* bar=m_outputView->verticalScrollBar();
    bar->setValue(bar->maximum());
}

// ---------- 命令预览刷新 ----------
void MainWindow::refreshCommandPreview() {
    // 不运行时刷新顶部命令预览（运行中不打断输出）
    if(m_executor&&m_executor->isRunning()) return;
    const ShellOptions o=collectOptions();
    const QString preview=CliArgBuilder::buildPreview(m_fileEncryptorPath,o);
    // 仅当输出区为空或上一次是预览时刷新（避免覆盖执行结果）
    if(m_outputView->toPlainText().isEmpty()||
        m_outputView->toPlainText().startsWith(QStringLiteral(">>>"))) {
        m_outputView->clear();
        appendOutput(QStringLiteral(">>> 命令预览: %1\n").arg(preview),false);
    }
}

void MainWindow::setStatus(const QString& msg) {
    if(m_statusLabel) {
        if(m_fileEncryptorPath.isEmpty()) {
            m_statusLabel->setText(tr("未找到 CLI 程序 — 请将 FileEncryptorCLI 置于同目录或设置 FILEENCRYPTOR_EXE"));
        }
        else {
            m_statusLabel->setText(msg);
        }
    }
}