// 轻量多语言管理
#pragma once
#include <QString>

class QWidget;

class I18n {
public:
    static I18n& instance();

    // 启动期安装翻译
    void init();

    // 当前语言
    QString currentLanguage() const;

    // 切换语言并提示
    void changeLanguage(const QString& lang, QWidget* parent);

private:
    I18n() = default;
    QString m_lang = QStringLiteral("zh");
};
