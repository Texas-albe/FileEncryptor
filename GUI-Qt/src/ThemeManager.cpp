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
};

const ThemeManager::Ui kNeutralLight = {
    "#F3F3EF",
    "transparent",
    "#F0F0EC",
    "#ECECEA",
    "#DCDCD8",
    "#E8E8E4",
    "#C8C8C4",
    "#333333",
    "#FFFFFF",
    "#999999",
    "#8A8A8A",
    "#4A7C50",
    "#A8A8A4",
    "#8A8A86",
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
    "#2E7D32",
    "#5A5A5A",
    "#6E6E6E",
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
