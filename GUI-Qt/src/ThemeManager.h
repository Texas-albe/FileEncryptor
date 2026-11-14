// 主题管理
#pragma once
#include <QObject>
#include <QDate>
#include <QString>

class QApplication;
class QPalette;

class ThemeManager : public QObject {
    Q_OBJECT
public:
    enum class Theme { Light = 0, Dark = 1, System = 2 };

    // 启动期应用主题
    static void initialize(QApplication* app);

    // 单例
    static ThemeManager& instance();

    // 切换并持久化
    static void setTheme(Theme t);

    static Theme chosenTheme();

    // System 档解析
    static Theme effectiveTheme();

    // 当前是否深色
    static bool isDarkActive();

    // 输出区高对比颜
    static unsigned int stdoutColorRGB();
    static unsigned int stderrColorRGB();

    // HTML 配色
    struct HtmlPalette {
        const char* bodyFg;
        const char* bodyBg;
        const char* preBg;
        const char* preFg;
        const char* mutedFg;
        const char* headingGreen;
        const char* headingBlue;
        const char* linkColor;
    };
    static const HtmlPalette& htmlPalette();

    // 界面配色
    // 调色板
    struct Ui {
        const char* window;
        const char* panelRgba;
        const char* field;
        const char* ctrl;
        const char* ctrlHover;
        const char* alt;
        const char* border;
        const char* text;
        const char* indicator;
        const char* indicatorBorder;
        const char* placeholder;
        const char* highlight;
        const char* scrollHandle;
        const char* scrollHover;
        // 操作层级
        // 深色
        const char* accent;
        const char* accentHover;
        const char* accentPressed;
        const char* onAccent;
        const char* danger;
        const char* dangerHover;
        const char* disabledText;
        const char* warning;
        const char* success;
    };
    // 国庆周取国旗红
    static const Ui& ui();
    // 次要说明文字色
    static const char* mutedTextHex();
    // 状态色
    static const char* dangerHex();
    static const char* warningHex();
    static const char* successHex();
    // 全局 QSS
    static QString styleSheet();

    static bool isNationalDay(const QDate& d = QDate::currentDate());
    static int nationalDayAge(const QDate& d = QDate::currentDate());
    static const char* chinaRedHex();
    static const char* lightRedBgHex();
    static QString birthdayMessage(const QDate& d = QDate::currentDate());

signals:
    void themeChanged(bool darkActive);

private:
    ThemeManager() = default;
    static QPalette buildLightPalette();
    static QPalette buildDarkPalette();
    static void persist(Theme t);
    static Theme load();
};
