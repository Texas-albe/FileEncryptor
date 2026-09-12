// ThemeManager - 浅色/深色 主题管理
// 职责：
//   1) 提供 Light / Dark 两种主题，统一通过 QPalette 应用到 QApplication
//   2) 用 QSettings 持久化用户选择（键 "theme"，值 0=Light 1=Dark）
//   3) 暴露 currentTheme() / isDarkActive() 供 UI 组件（如输出着色、对话框 HTML）
//      在当前主题下选用高对比度颜色，满足 WCAG AA（对比度 >= 4.5:1）
// 跨平台；自行管理调色板，保证 Win/Linux/macOS 一致。
#pragma once
#include <QObject>

class QApplication;
class QPalette;

class ThemeManager : public QObject {
    Q_OBJECT
public:
    enum class Theme { Light = 0, Dark = 1 };

    // 应用启动期调用：读取持久化偏好并应用到 app。
    // forceSystemDarkDetection 仅用于单元测试，生产路径不传。
    static void initialize(QApplication* app);

    // 单例（供信号连接；themeChanged 在 setTheme 时发射）
    static ThemeManager& instance();

    // 切换主题（同时持久化 + 应用 + 发射信号）
    static void setTheme(Theme t);

    // 当前用户选择（持久化的偏好，未必等于实际生效的浅/深）
    static Theme chosenTheme();

    // 当前实际生效的是否为深色
    static bool isDarkActive();

    // 输出着色：stdout/stderr 在当前主题下的高对比度颜色
    //   浅色：stdout 深灰 #1F1F1F（对白底对比 ~14:1），stderr 深红 #C62828（对白底 ~5.9:1）
    //   深色：stdout 浅灰 #E6E6E6（对 #1E1E1E 底 ~13:1），stderr 亮红 #FF8A80（对 #1E1E1E 底 ~5.4:1）
    static unsigned int stdoutColorRGB();
    static unsigned int stderrColorRGB();

    // 对话框 HTML 在当前主题下的配色（避免硬编码 #f5f5f5/#666 在深色下不可读）
    struct HtmlPalette {
        const char* bodyFg;       // 正文文字色
        const char* bodyBg;       // 正文背景色
        const char* preBg;        // <pre> 代码块背景
        const char* preFg;        // <pre> 代码块文字
        const char* mutedFg;      // 弱化文字（页脚等）
        const char* headingGreen; // 标题绿
        const char* headingBlue;  // 标题蓝
        const char* linkColor;    // 链接色
    };
    static const HtmlPalette& htmlPalette();

signals:
    void themeChanged(bool darkActive);  // 主题切换后发射，UI 据此重绘已显示内容

private:
    ThemeManager() = default;
    static QPalette buildLightPalette();
    static QPalette buildDarkPalette();
    static void persist(Theme t);
    static Theme load();
};
