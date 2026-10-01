// 跨平台字体引导
#pragma once
#include <QFont>
#include <QString>

class FontBootstrap {
public:
    // 启动期调用一次
    static void initialize();

    // 含 CJK 的等宽字体
    static QFont monoFont();

    // 选中的界面字体族
    static QString uiFamily();

    // 是否找到中文字体
    static bool cjkAvailable();

private:
    static QString s_family;
    static bool s_initialized;
    static bool s_cjk;
};
