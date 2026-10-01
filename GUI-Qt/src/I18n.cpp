#include "I18n.h"

#include <QTranslator>
#include <QSettings>
#include <QLocale>
#include <QCoreApplication>
#include <QMessageBox>
#include <QPushButton>
#include <QAbstractButton>
#include <QProcess>
#include <QWidget>

namespace {
QTranslator* g_translator = nullptr;

QSettings langSettings() {
    return QSettings(QStringLiteral("FileEncryptor"), QStringLiteral("FileEncryptorGUI"));
}
}

I18n& I18n::instance() {
    static I18n i;
    return i;
}

void I18n::init() {
    QSettings s = langSettings();
    m_lang = s.value(QStringLiteral("language")).toString();
    if (m_lang.isEmpty()) {
        // 首次启动跟随系统语言
        m_lang = QLocale::system().name().startsWith(QStringLiteral("zh"))
            ? QStringLiteral("zh")
            : QStringLiteral("en");
    }
    if (m_lang == QStringLiteral("ru")) {
        auto* t = new QTranslator(qApp);
        if (t->load(QStringLiteral(":/i18n/gui_ru_RU.qm"))) {
            qApp->installTranslator(t);
            g_translator = t;
        } else {
            // .qm 缺失时回退中文
            delete t;
            m_lang = QStringLiteral("zh");
        }
    } else if (m_lang == QStringLiteral("en")) {
        auto* t = new QTranslator(qApp);
        if (t->load(QStringLiteral(":/i18n/gui_en_US.qm"))) {
            qApp->installTranslator(t);
            g_translator = t;
        } else {
            // .qm 缺失时回退中文
            delete t;
            m_lang = QStringLiteral("zh");
        }
    }
}

QString I18n::currentLanguage() const {
    return m_lang;
}

void I18n::changeLanguage(const QString& lang, QWidget* parent) {
    if (lang == m_lang) return;
    {
        QSettings s = langSettings();
        s.setValue(QStringLiteral("language"), lang);
    }
    m_lang = lang;

    // 提示文案随界面语言翻译（I18n context）
    QMessageBox box(parent);
    box.setWindowTitle(QCoreApplication::translate("I18n", "语言"));
    box.setText(QCoreApplication::translate("I18n", "语言设置已保存，重启应用后完整生效。"));
    auto* restart = box.addButton(QCoreApplication::translate("I18n", "立即重启"), QMessageBox::AcceptRole);
    box.addButton(QCoreApplication::translate("I18n", "稍后"), QMessageBox::RejectRole);
    box.exec();
    if (box.clickedButton() == static_cast<QAbstractButton*>(restart)) {
        QProcess::startDetached(QCoreApplication::applicationFilePath(), {});
        qApp->quit();
    }
}
