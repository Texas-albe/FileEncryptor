// 跨平台字体引导
#pragma once
#include <QFont>
#include <QString>

class FontBootstrap {
public:
    // 启动期调用一次
    static void initialize();

    // 含 CJK
    static QFont monoFont();

    static QString uiFamily();

    // 是否找到中文字
    static bool cjkAvailable();

private:
    static QString s_family;
    static bool s_initialized;
    static bool s_cjk;
};
