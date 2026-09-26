// FontBootstrap - 跨平台字体引导：修复 Linux 最小化安装下默认字体不含 CJK 字形导致的中文方块。
// 启动时按序选字体：环境变量 FILEENCRYPTOR_UI_FONT > 现字体已含中文 > 系统候选 > 嵌入资源字体 > 保留默认告警；monoFont() 在等宽字体缺中文时退回含中文的界面字体，宁可不等宽也不要方块。
#pragma once
#include <QFont>
#include <QString>

class FontBootstrap {
public:
    // 必须在 QApplication 构造之后、创建任何窗口之前调用
    static void initialize();

    // 含 CJK 字形的等宽字体（命令输出窗口用）
    static QFont monoFont();

    // 最终选中的界面字体族；空串表示没找到任何中文字体
    static QString uiFamily();

    // 是否找到了含中文的字体
    static bool cjkAvailable();

private:
    static QString s_family;
    static bool s_initialized;
    static bool s_cjk;
};
