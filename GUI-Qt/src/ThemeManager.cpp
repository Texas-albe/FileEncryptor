#include "ThemeManager.h"
#include "I18n.h"
#include <QApplication>
#include <QGuiApplication>
#include <QPalette>
#include <QSettings>
#include <QStyleHints>
#include <QWidget>
#include <QColor>
#include <string>

static const char* kOrg = "FileEncryptor";
static const char* kApp = "FileEncryptorGUI";
static const char* kKey = "theme";
static ThemeManager::Theme g_chosen = ThemeManager::Theme::Light;
static bool g_darkActive = false;

// 国庆节主题
bool ThemeManager::isNationalDay(const QDate& d) {
    return d.month() == 10 && d.day() >= 1 && d.day() <= 7;
}

int ThemeManager::nationalDayAge(const QDate& d) {
    return d.year() - 1949;
}

const char* ThemeManager::chinaRedHex() {
    return "#DE2910";
}

const char* ThemeManager::lightRedBgHex() {
    return "#F6C9C4";
}

// 界面配色
namespace {

// 国庆配色：底子保持中性，红只落在强调处。
// 早先把大面积底色也铺成红系，国旗红被衬底稀释成粉红，反而看不出节日感。
const ThemeManager::Ui kRedLight = {
    "#F7F5F4",                  // window
    "rgba(240,238,237,0.55)",   // panelRgba（半透明，透出背景图）
    "#FFFFFF",                  // field
    "#F0EEED",                  // ctrl
    "#E6E3E2",                  // ctrlHover
    "#F1EFEE",                  // alt
    "#C4BDBB",                  // border
    "#1C1817",                  // text
    "#FFFFFF",                  // indicator
    "#8A8180",                  // indicatorBorder
    "#8A8180",                  // placeholder
    "#DE2910",                  // highlight（国旗红原色）
    "#B8B1AF",                  // scrollHandle
    "#DE2910",                  // scrollHover
    "#DE2910",                  // accent
    "#F04A30",                  // accentHover
    "#A81F0A",                  // accentPressed
    "#FFFFFF",                  // onAccent
    "#8E2214",                  // danger（比主色更暗，避免和节日红混淆）
    "#F3DED9",                  // dangerHover
    "#8A8180",                  // disabledText
    "#9A6B00",                  // warning
    "#2E7D32",                  // success
};

// 深色下层级只能靠明度差，红落在暗背景上会发闷，故控件底比卡片底亮一档
const ThemeManager::Ui kRedDark = {
    "#121111",
    "rgba(30,28,28,0.55)",
    "#171616",
    "#2C2929",
    "#3A3636",
    "#1E1C1C",
    "#403C3C",
    "#F5F2F1",
    "#2C2929",
    "#6B605E",
    "#8A8080",
    "#DE2910",
    "#4C4747",
    "#F04A30",
    "#DE2910",                  // accent
    "#F04A30",                  // accentHover
    "#A81F0A",                  // accentPressed
    "#FFFFFF",                  // onAccent
    "#E58A7E",                  // danger
    "#3A2420",                  // dangerHover
    "#6B605E",                  // disabledText
    "#E0B341",                  // warning
    "#6FBF73",                  // success
};

const ThemeManager::Ui kNeutralLight = {
    "#F3F3EF",
    "transparent",
    "#FFFFFF",                  // field（输入框比窗口亮一档，桌面端常见）
    "#ECECEA",
    "#DCDCD8",
    "#F0F0EC",                  // alt
    "#C8C8C4",
    "#333333",
    "#FFFFFF",
    "#999999",
    "#8A8A8A",
    "#2F7DBF",                  // highlight（桌面端蓝，非移动端品牌色）
    "#A8A8A4",
    "#8A8A86",
    "#2F7DBF",                  // accent
    "#3B8FD0",                  // accentHover
    "#25689F",                  // accentPressed
    "#FFFFFF",                  // onAccent
    "#C0392B",                  // danger
    "#F7E3E0",                  // dangerHover
    "#9A9A96",                  // disabledText
    "#9A6B00",                  // warning
    "#2E7D32",                  // success
};

const ThemeManager::Ui kNeutralDark = {
    "#2D2D30",
    "transparent",
    "#1E1E1E",
    "#3D3D40",
    "#4A4A4D",
    "#252525",
    "#3C3C3C",
    "#E6E6E6",
    "#2A2A2A",
    "#5A5A5A",
    "#909090",
    "#4FA3DC",                  // highlight
    "#5A5A5A",
    "#6E6E6E",
    "#4FA3DC",                  // accent
    "#66B6EA",                  // accentHover
    "#3A87BC",                  // accentPressed
    "#FFFFFF",                  // onAccent
    "#E06C60",                  // danger
    "#3A2420",                  // dangerHover
    "#757575",                  // disabledText
    "#E0B341",                  // warning
    "#6FBF73",                  // success
};

const ThemeManager::Ui& pick(bool dark) {
    if (ThemeManager::isNationalDay()) return dark ? kRedDark : kRedLight;
    return dark ? kNeutralDark : kNeutralLight;
}

}

const ThemeManager::Ui& ThemeManager::ui() {
    return pick(g_darkActive);
}

const char* ThemeManager::mutedTextHex() {
    return ui().placeholder;
}

const char* ThemeManager::dangerHex() { return ui().danger; }
const char* ThemeManager::warningHex() { return ui().warning; }
const char* ThemeManager::successHex() { return ui().success; }

QString ThemeManager::styleSheet() {
    const Ui& r = ui();
    // 只修饰一致性：桌面端控件高度与圆角、主/次/危险层级、焦点态。
    // 窗口与文字底色始终由 QPalette 提供，配色全部取自上面的集中色表。
    QString s = QStringLiteral(R"(
QPushButton {
    min-height: 22px;
    padding: 3px 12px;
    border-radius: 4px;
    background: @ctrl;
    color: @text;
    border: 1px solid @border;
}
QPushButton:hover { background: @ctrlHover; }
QPushButton:pressed { background: @ctrlHover; border-color: @accent; }
QPushButton[uiRole="primary"] {
    background: @accent;
    color: @onAccent;
    border: 1px solid @accent;
    font-weight: 600;
}
QPushButton[uiRole="primary"]:hover { background: @accentHover; border-color: @accentHover; }
QPushButton[uiRole="primary"]:pressed { background: @accentPressed; border-color: @accentPressed; }
QPushButton[uiRole="primary"]:disabled { background: @ctrl; color: @disabledText; border-color: @border; }
QPushButton[uiRole="secondary"] { background: @field; color: @text; border: 1px solid @border; }
QPushButton[uiRole="secondary"]:hover { background: @ctrlHover; }
QPushButton[uiRole="quiet"] { background: transparent; color: @placeholder; border: 1px solid transparent; }
QPushButton[uiRole="quiet"]:hover { color: @text; background: @ctrlHover; }
QPushButton[uiRole="danger"] { background: transparent; color: @danger; border: 1px solid @danger; }
QPushButton[uiRole="danger"]:hover { background: @dangerHover; }
QPushButton[uiRole="danger"]:disabled { background: transparent; color: @disabledText; border-color: @border; }
QPushButton:disabled { color: @disabledText; }

QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QAbstractSpinBox {
    min-height: 22px;
    padding: 2px 6px;
    border: 1px solid @border;
    border-radius: 3px;
    background: @field;
    color: @text;
    selection-background-color: @accent;
    selection-color: @onAccent;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border-color: @accent; }
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled {
    background: @ctrl;
    color: @disabledText;
}
QComboBox::drop-down { border: none; width: 16px; }
QComboBox QAbstractItemView {
    background: @field;
    color: @text;
    border: 1px solid @border;
    selection-background-color: @accent;
    selection-color: @onAccent;
    outline: 0;
}

QCheckBox, QRadioButton { spacing: 6px; }
QCheckBox::indicator, QRadioButton::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid @indicatorBorder;
    background: @indicator;
}
QCheckBox::indicator { border-radius: 2px; }
QRadioButton::indicator { border-radius: 8px; }
QCheckBox::indicator:hover, QRadioButton::indicator:hover { border-color: @accent; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background: @accent;
    border-color: @accent;
}

QGroupBox {
    border: 1px solid @border;
    border-radius: 4px;
    margin-top: 10px;
    padding-top: 6px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    color: @text;
}

QListWidget, QTableWidget, QTableView, QTreeView {
    background: @field;
    alternate-background-color: @alt;
    border: 1px solid @border;
    border-radius: 3px;
    selection-background-color: @accent;
    selection-color: @onAccent;
    outline: 0;
}
QListWidget::item { padding: 3px 6px; border: 0; }
QHeaderView::section {
    background: @ctrl;
    color: @text;
    border: 0;
    border-bottom: 1px solid @border;
    padding: 4px 6px;
}

QPlainTextEdit, QTextEdit, QTextBrowser {
    background: @field;
    color: @text;
    border: 1px solid @border;
    border-radius: 3px;
    selection-background-color: @accent;
    selection-color: @onAccent;
}

QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: @scrollHandle; min-height: 24px; border-radius: 4px; }
QScrollBar::handle:vertical:hover { background: @scrollHover; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: @scrollHandle; min-width: 24px; border-radius: 4px; }
QScrollBar::handle:horizontal:hover { background: @scrollHover; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QProgressBar {
    min-height: 14px;
    background: @ctrl;
    border: 1px solid @border;
    border-radius: 3px;
    text-align: center;
}
QProgressBar::chunk { background: @accent; border-radius: 2px; }

QMenuBar::item { padding: 4px 9px; background: transparent; }
QMenuBar::item:selected { background: @ctrlHover; }
QMenu::item { padding: 4px 24px 4px 12px; }
QMenu::item:selected { background: @accent; color: @onAccent; }
QStatusBar::item { border: 0; }
QToolTip {
    background: @alt;
    color: @text;
    border: 1px solid @border;
    padding: 4px 6px;
}
)");
    s.replace(QStringLiteral("@window"), QLatin1String(r.window))
     .replace(QStringLiteral("@field"), QLatin1String(r.field))
     .replace(QStringLiteral("@ctrlHover"), QLatin1String(r.ctrlHover))
     .replace(QStringLiteral("@ctrl"), QLatin1String(r.ctrl))
     .replace(QStringLiteral("@alt"), QLatin1String(r.alt))
     .replace(QStringLiteral("@border"), QLatin1String(r.border))
     .replace(QStringLiteral("@text"), QLatin1String(r.text))
     .replace(QStringLiteral("@indicatorBorder"), QLatin1String(r.indicatorBorder))
     .replace(QStringLiteral("@indicator"), QLatin1String(r.indicator))
     .replace(QStringLiteral("@placeholder"), QLatin1String(r.placeholder))
     .replace(QStringLiteral("@scrollHandle"), QLatin1String(r.scrollHandle))
     .replace(QStringLiteral("@scrollHover"), QLatin1String(r.scrollHover))
     .replace(QStringLiteral("@accentHover"), QLatin1String(r.accentHover))
     .replace(QStringLiteral("@accentPressed"), QLatin1String(r.accentPressed))
     .replace(QStringLiteral("@accent"), QLatin1String(r.accent))
     .replace(QStringLiteral("@onAccent"), QLatin1String(r.onAccent))
     .replace(QStringLiteral("@dangerHover"), QLatin1String(r.dangerHover))
     .replace(QStringLiteral("@danger"), QLatin1String(r.danger))
     .replace(QStringLiteral("@disabledText"), QLatin1String(r.disabledText));
    return s;
}

QString ThemeManager::birthdayMessage(const QDate& d) {
    // 三语与 WinUI 侧 L10n 译文逐字一致
    const QString lang=I18n::instance().currentLanguage();
    if (lang==QStringLiteral("en"))
        return QString("Happy %1th Birthday to the People's Republic of China! "
                       "May it always prosper!")
            .arg(nationalDayAge(d));
    if (lang==QStringLiteral("ru"))
        return QString("С днём рождения %1 Китайской Народной Республики! "
                       "Пусть она всегда процветает!")
            .arg(nationalDayAge(d));
    return QString("祝祖国%1岁生日快乐！永远繁荣昌盛！").arg(nationalDayAge(d));
}

// 调色板
QPalette ThemeManager::buildLightPalette() {
    const Ui& r = pick(false);
    QPalette p;
    p.setColor(QPalette::Window,          QColor(r.window));
    p.setColor(QPalette::WindowText,      QColor(r.text));
    p.setColor(QPalette::Base,            QColor(r.field));
    p.setColor(QPalette::AlternateBase,   QColor(r.alt));
    p.setColor(QPalette::Text,            QColor(r.text));
    p.setColor(QPalette::Button,          QColor(r.ctrl));
    p.setColor(QPalette::ButtonText,      QColor(r.text));
    p.setColor(QPalette::BrightText,      QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Highlight,       QColor(r.highlight));
    p.setColor(QPalette::HighlightedText,  QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Link,            QColor(r.highlight));
    p.setColor(QPalette::ToolTipBase,     QColor(r.field));
    p.setColor(QPalette::ToolTipText,     QColor(r.text));
    p.setColor(QPalette::PlaceholderText, QColor(r.placeholder));
    p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(r.disabledText));
    p.setColor(QPalette::Disabled, QPalette::Text, QColor(r.disabledText));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(r.disabledText));
    p.setColor(QPalette::Disabled, QPalette::Highlight, QColor(r.ctrl));
    p.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(r.disabledText));
    return p;
}

QPalette ThemeManager::buildDarkPalette() {
    const Ui& r = pick(true);
    QPalette p;
    p.setColor(QPalette::Window,          QColor(r.window));
    p.setColor(QPalette::WindowText,      QColor(r.text));
    p.setColor(QPalette::Base,            QColor(r.field));
    p.setColor(QPalette::AlternateBase,   QColor(r.alt));
    p.setColor(QPalette::Text,            QColor(r.text));
    p.setColor(QPalette::Button,          QColor(r.ctrl));
    p.setColor(QPalette::ButtonText,      QColor(r.text));
    p.setColor(QPalette::BrightText,      QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Highlight,       QColor(r.highlight));
    p.setColor(QPalette::HighlightedText,  QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Link,            QColor(r.highlight));
    p.setColor(QPalette::ToolTipBase,     QColor(r.field));
    p.setColor(QPalette::ToolTipText,     QColor(r.text));
    p.setColor(QPalette::PlaceholderText, QColor(r.placeholder));
    p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(r.disabledText));
    p.setColor(QPalette::Disabled, QPalette::Text, QColor(r.disabledText));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(r.disabledText));
    p.setColor(QPalette::Disabled, QPalette::Highlight, QColor(r.ctrl));
    p.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(r.disabledText));
    return p;
}

// 持久化
// 存字符串而非枚举值：早期读写过 1/2 的旧值，数字含义有过漂移，字符串无歧义
void ThemeManager::persist(Theme t) {
    QSettings s(kOrg, kApp);
    s.setValue(kKey, t == Theme::Dark ? QStringLiteral("dark")
            : t == Theme::System ? QStringLiteral("system")
            : QStringLiteral("light"));
}

ThemeManager::Theme ThemeManager::load() {
    QSettings s(kOrg, kApp);
    const QVariant v = s.value(kKey);
    const QString str = v.toString();
    if (str.compare(QStringLiteral("dark"), Qt::CaseInsensitive) == 0) return Theme::Dark;
    if (str.compare(QStringLiteral("light"), Qt::CaseInsensitive) == 0) return Theme::Light;
    if (str.compare(QStringLiteral("system"), Qt::CaseInsensitive) == 0) return Theme::System;
    // 兼容旧数字值：现行枚举 1 = 深色，早期还有用 2 表示深色的
    bool ok = false;
    const int n = v.toInt(&ok);
    if (!ok) return Theme::Light;
    return (n == static_cast<int>(Theme::Dark) || n == 2) ? Theme::Dark : Theme::Light;
}

ThemeManager::Theme ThemeManager::effectiveTheme() {
    if (g_chosen != Theme::System) return g_chosen;
    // 跟随系统：读 QPalette 的当前窗口色亮度判断深浅
    const QColor c = qApp ? qApp->palette().color(QPalette::Window) : QColor(Qt::white);
    return c.lightness() < 128 ? Theme::Dark : Theme::Light;
}

void ThemeManager::initialize(QApplication* app) {
    g_chosen = load();
    // System 档：QApplication 构造时已装载系统调色板，直接据此判深浅
    g_darkActive = (effectiveTheme() == Theme::Dark);
    app->setPalette(g_darkActive ? buildDarkPalette() : buildLightPalette());
    // 全局 QSS 与调色板同一份色表，切档时一起换
    app->setStyleSheet(styleSheet());
    // 跟随系统时，系统主题切换要实时跟上
    if (g_chosen == Theme::System && app->styleHints()) {
        QObject::connect(app->styleHints(), &QStyleHints::colorSchemeChanged,
                         app, [] { setTheme(Theme::System); });
    }
}

void ThemeManager::setTheme(Theme t) {
    g_chosen = t;
    persist(t);
    g_darkActive = (effectiveTheme() == Theme::Dark);
    if (auto* app = qApp) {
        app->setPalette(g_darkActive ? buildDarkPalette() : buildLightPalette());
    // 全局 QSS 与调色板同一份色表，切档时一起换
    app->setStyleSheet(styleSheet());
        for (QWidget* w : app->topLevelWidgets()) w->update();
    }
    emit instance().themeChanged(g_darkActive);
}

ThemeManager& ThemeManager::instance() {
    static ThemeManager s;
    return s;
}

ThemeManager::Theme ThemeManager::chosenTheme() { return g_chosen; }

bool ThemeManager::isDarkActive() { return g_darkActive; }

unsigned int ThemeManager::stdoutColorRGB() {
    if (isNationalDay()) return g_darkActive ? 0xF2DAD6u : 0x3A1512u;
    return g_darkActive ? 0xE6E6E6u : 0x333333u;
}

unsigned int ThemeManager::stderrColorRGB() {
    return g_darkActive ? 0xFF8A80u : 0xC0392Bu;
}

// HTML 调色板派生
namespace {

struct HtmlPaletteStore {
    std::string bodyFg, bodyBg, preBg, preFg, mutedFg;
    ThemeManager::HtmlPalette view;
};

std::string toHex(const QColor& c) {
    return QStringLiteral("#%1")
        .arg(c.rgb() & 0x00FFFFFF, 6, 16, QLatin1Char('0'))
        .toStdString();
}

HtmlPaletteStore makeHtmlPalette(const QPalette& p,
                                 const char* headingGreen,
                                 const char* headingBlue) {
    HtmlPaletteStore s;
    s.bodyFg  = toHex(p.color(QPalette::WindowText));
    s.bodyBg  = toHex(p.color(QPalette::Base));
    s.preBg   = toHex(p.color(QPalette::AlternateBase));
    s.preFg   = toHex(p.color(QPalette::Text));
    s.mutedFg = toHex(p.color(QPalette::PlaceholderText));
    s.view = { s.bodyFg.c_str(), s.bodyBg.c_str(), s.preBg.c_str(),
               s.preFg.c_str(), s.mutedFg.c_str(),
               headingGreen, headingBlue, headingBlue };
    return s;
}

}

const ThemeManager::HtmlPalette& ThemeManager::htmlPalette() {
    static const HtmlPaletteStore lightNeutral = makeHtmlPalette(
        buildLightPalette(), "#4A7C50", "#2E5C9A");
    static const HtmlPaletteStore darkNeutral = makeHtmlPalette(
        buildDarkPalette(), "#66BB6A", "#64B5F6");
    static const HtmlPaletteStore lightRed = makeHtmlPalette(
        buildLightPalette(), "#C0392B", "#DE2910");
    static const HtmlPaletteStore darkRed = makeHtmlPalette(
        buildDarkPalette(), "#FF8A80", "#FF6B6B");
    if (isNationalDay()) return g_darkActive ? darkRed.view : lightRed.view;
    return g_darkActive ? darkNeutral.view : lightNeutral.view;
}
