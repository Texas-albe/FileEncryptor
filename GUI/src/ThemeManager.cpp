// ThemeManager 实现
#include "ThemeManager.h"
#include <QApplication>
#include <QGuiApplication>
#include <QPalette>
#include <QSettings>
#include <QWidget>

static const char* kOrg = "FileEncryptor";
static const char* kApp = "FileEncryptorGUI";
static const char* kKey = "theme";
static ThemeManager::Theme g_chosen = ThemeManager::Theme::Light;
static bool g_darkActive = false;

// ---------- 调色板 ----------
QPalette ThemeManager::buildLightPalette() {
    // 柔和浅色调色板：暖白底 + 中灰文字，降低对比度（约 9~10:1，仍满足 WCAG AA），
    // 长时间使用不易视觉疲劳
    QPalette p;
    p.setColor(QPalette::Window,          QColor(0xF3, 0xF3, 0xEF));  // 暖白
    p.setColor(QPalette::WindowText,      QColor(0x33, 0x33, 0x33));  // 中灰文字
    p.setColor(QPalette::Base,            QColor(0xFA, 0xFA, 0xFA));  // 非纯白，减刺眼
    p.setColor(QPalette::AlternateBase,   QColor(0xEC, 0xEC, 0xEA));
    p.setColor(QPalette::Text,            QColor(0x33, 0x33, 0x33));
    p.setColor(QPalette::Button,          QColor(0xE8, 0xE8, 0xE6));
    p.setColor(QPalette::ButtonText,      QColor(0x33, 0x33, 0x33));
    p.setColor(QPalette::BrightText,      QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Highlight,       QColor(0x4A, 0x7C, 0x50));  // 柔化绿
    p.setColor(QPalette::HighlightedText,  QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::ToolTipBase,     QColor(0xFA, 0xFA, 0xFA));
    p.setColor(QPalette::ToolTipText,     QColor(0x33, 0x33, 0x33));
    p.setColor(QPalette::PlaceholderText, QColor(0x8A, 0x8A, 0x8A));  // 更柔和的占位符
    return p;
}

QPalette ThemeManager::buildDarkPalette() {
    // 深色调色板：深灰背景 + 高亮浅色文字，保证 WCAG AA
    QPalette p;
    p.setColor(QPalette::Window,          QColor(0x2D, 0x2D, 0x30));
    p.setColor(QPalette::WindowText,      QColor(0xE6, 0xE6, 0xE6));  // 对 #2D2D30 对比 ~11:1
    p.setColor(QPalette::Base,            QColor(0x1E, 0x1E, 0x1E));  // 输入框更深
    p.setColor(QPalette::AlternateBase,   QColor(0x25, 0x25, 0x26));
    p.setColor(QPalette::Text,            QColor(0xE6, 0xE6, 0xE6));  // 对 #1E1E1E 对比 ~13:1
    p.setColor(QPalette::Button,          QColor(0x3D, 0x3D, 0x40));
    p.setColor(QPalette::ButtonText,      QColor(0xE6, 0xE6, 0xE6));
    p.setColor(QPalette::BrightText,      QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::Highlight,       QColor(0x2E, 0x7D, 0x32));
    p.setColor(QPalette::HighlightedText,  QColor(0xFF, 0xFF, 0xFF));
    p.setColor(QPalette::ToolTipBase,     QColor(0x1E, 0x1E, 0x1E));
    p.setColor(QPalette::ToolTipText,     QColor(0xE6, 0xE6, 0xE6));
    p.setColor(QPalette::PlaceholderText, QColor(0x90, 0x90, 0x90));
    return p;
}

// ---------- 持久化 ----------
void ThemeManager::persist(Theme t) {
    QSettings s(kOrg, kApp);
    s.setValue(kKey, static_cast<int>(t));
}

ThemeManager::Theme ThemeManager::load() {
    QSettings s(kOrg, kApp);
    bool ok = false;
    const int v = s.value(kKey, static_cast<int>(Theme::Light)).toInt(&ok);
    if (!ok) return Theme::Light;
    // 兼容旧版持久化值（旧：0=System 1=Light 2=Dark；新：0=Light 1=Dark）
    if (v == 2) return Theme::Dark;   // 原 Dark
    if (v == 1) return Theme::Light; // 原 Light
    return Theme::Light;              // 0（原 System）/ 非法 → 浅色
}

// ---------- 公开 API ----------
void ThemeManager::initialize(QApplication* app) {
    g_chosen = load();
    const bool dark = (g_chosen == Theme::Dark);
    g_darkActive = dark;
    app->setPalette(dark ? buildDarkPalette() : buildLightPalette());
}

void ThemeManager::setTheme(Theme t) {
    g_chosen = t;
    persist(t);
    const bool dark = (t == Theme::Dark);
    g_darkActive = dark;
    if (auto* app = qApp) {
        app->setPalette(dark ? buildDarkPalette() : buildLightPalette());
    }
    // 通知 UI 重绘
    if (auto* app = qApp) {
        for (QWidget* w : app->topLevelWidgets()) w->update();
    }
    // 发射信号（单例），供导航栏下拉框 / 面板透明度同步
    emit instance().themeChanged(g_darkActive);
}

ThemeManager& ThemeManager::instance() {
    static ThemeManager s;
    return s;
}

ThemeManager::Theme ThemeManager::chosenTheme() { return g_chosen; }

bool ThemeManager::isDarkActive() { return g_darkActive; }

unsigned int ThemeManager::stdoutColorRGB() {
    return g_darkActive ? 0xE6E6E6u : 0x333333u;
}

unsigned int ThemeManager::stderrColorRGB() {
    return g_darkActive ? 0xFF8A80u : 0xC0392Bu;
}

const ThemeManager::HtmlPalette& ThemeManager::htmlPalette() {
    static const HtmlPalette light = {
        "#333333", "#FAFAFA", "#ECECEA", "#333333", "#888888",
        "#4A7C50", "#2E5C9A", "#2E5C9A"};
    static const HtmlPalette dark = {
        "#E6E6E6", "#1E1E1E", "#2D2D30", "#E6E6E6", "#999999",
        "#66BB6A", "#64B5F6", "#64B5F6"};
    return g_darkActive ? dark : light;
}
