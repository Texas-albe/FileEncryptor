// FontBootstrap - 跨平台字体引导
//
// 问题：Linux 发行版（尤其最小化安装 / 服务器 / 容器里跑的桌面会话）默认字体
// 常为 DejaVu Sans / Ubuntu 等**不含 CJK 字形**的字体，界面中文全部渲染成
// “豆腐块”（□）；静态 Qt 若未启用 fontconfig，QFontDatabase 甚至可能拿不到任何
// 系统字体，连英文都是空的。
//
// 对策（启动时一次，顺序递减）：
//   1) 环境变量 FILEENCRYPTOR_UI_FONT 显式指定（排障 / 用户偏好，最高优先）；
//   2) 当前应用字体已含中文 → 保持不动（Windows / macOS 常见情况）；
//   3) 在系统字体里按候选清单挑第一款含中文的；
//   4) 仍没有 → 加载构建期嵌入的资源字体（GUI/fonts/*.ttf|*.otf，由 CMake 自动打进 exe）；
//   5) 都没有 → 保留系统默认并告警（qWarning），不阻塞启动。
//
// 另提供 monoFont()：命令输出窗口需要等宽字体，但 DejaVu Sans Mono 同样没有中文，
// 故在等宽字体不含中文时退回“含中文的界面字体”——宁可不等宽，也不要豆腐块。
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
