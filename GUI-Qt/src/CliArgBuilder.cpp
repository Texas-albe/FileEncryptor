#include "CliArgBuilder.h"
#include <QCoreApplication>
#include <QDir>

// 命令预览随界面语言

QStringList CliArgBuilder::buildArguments(const ShellOptions& o) {
    QStringList args;

    // 三个 rage 密钥动作无需输入文件
    if (o.action == CryptoAction::KeyGen) {
        args << QStringLiteral("-g");
        if (!o.outputDir.isEmpty()) {
            args << QStringLiteral("-o") << o.outputDir;
        }
        return args;
    }
    if (o.action == CryptoAction::Derive) {
        args << QStringLiteral("-G");
        if (!o.outputDir.isEmpty()) {
            args << QStringLiteral("-o") << o.outputDir;
        }
        if (o.forceOverwrite) {
            args << QStringLiteral("-y");
        }
        args << QStringLiteral("--key-stdin");
        return args;
    }
    if (o.action == CryptoAction::PubKey) {
        args << QStringLiteral("-Y");
        if (!o.identityPath.isEmpty()) {
            args << QStringLiteral("-k") << o.identityPath;
        }
        return args;
    }

    // 处理单/批加密解密
    switch (o.action) {
    case CryptoAction::Encrypt:       args << QStringLiteral("-e");  break;
    case CryptoAction::Decrypt:      args << QStringLiteral("-d");  break;
    case CryptoAction::BatchEncrypt:  args << QStringLiteral("-be"); break;
    case CryptoAction::BatchDecrypt:  args << QStringLiteral("-bd"); break;
    case CryptoAction::KeyGen:
    case CryptoAction::Derive:
    case CryptoAction::PubKey:
        break;
    }

    if (!o.outputDir.isEmpty()) {
        args << QStringLiteral("-o") << o.outputDir;
    }

    if (o.sourceDisposition == 1) {
        args << QStringLiteral("-de");
    } else if (o.sourceDisposition == 2) {
        args << QStringLiteral("--wipe-source");
    } else if (o.sourceDisposition == 3) {
        args << QStringLiteral("--recycle-source");
    }

    const bool isAsym = (o.mode == CryptoMode::Asymmetric);
    const bool isEnc = (o.action == CryptoAction::Encrypt ||
                        o.action == CryptoAction::BatchEncrypt);

    if (o.mode == CryptoMode::XChaCha20) {
        args << QStringLiteral("-m") << QStringLiteral("xchacha20");
    } else if (o.mode == CryptoMode::Aegis256) {
        args << QStringLiteral("-m") << QStringLiteral("aegis256");
    } else {
        args << QStringLiteral("-m") << QStringLiteral("rage");
    }

    // 压缩：开关 + 级别
    if (o.compress && isEnc && !isAsym) {
        args << QStringLiteral("-zstd");
        if (o.compressionLevel != 0) {
            args << QStringLiteral("--compression-level") << QString::number(o.compressionLevel);
        }
    }

    // 加密成功后生成校验单
    if (o.writeSha256 && isEnc) {
        args << QStringLiteral("--sha256");
    }

    if (isAsym && isEnc && !o.recipientPath.isEmpty()) {
        args << QStringLiteral("-r") << o.recipientPath;
    }

    bool isBatch = (o.action == CryptoAction::BatchEncrypt ||
                    o.action == CryptoAction::BatchDecrypt);
    if (isBatch) {
        // 批模式：每条路径用 -i
        for (const QString& p : o.inputPaths) {
            args << QStringLiteral("-i") << p;
        }
    } else {
        if (!o.inputPaths.isEmpty()) {
            args << o.inputPaths.first();
        }
    }

    if (o.forceOverwrite) {
        args << QStringLiteral("-y");
    }


    // 批量解密还原文件名
    if (o.action == CryptoAction::BatchDecrypt && o.restoreName) {
        args << QStringLiteral("--restore-name");
    }

    if (!o.keyfilePath.isEmpty()) {
        args << QStringLiteral("-k") << o.keyfilePath;
    }

    if (!isAsym) {
        if (o.keyfilePath.isEmpty()) {
            args << QStringLiteral("--key-stdin");
        }
    }

    return args;
}

QProcessEnvironment CliArgBuilder::buildEnvironment(const ShellOptions& ) {
    return QProcessEnvironment::systemEnvironment();
}

QString CliArgBuilder::buildPreview(const QString& programPath, const ShellOptions& o) {
    // 命令预览的引号策略
    QString cmd = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(programPath));

    static const QStringList valueFlags = {
        QStringLiteral("-o"), QStringLiteral("-i"), QStringLiteral("-k"),
        QStringLiteral("-r"), QStringLiteral("--salt"),
        QStringLiteral("--compression-level"), QStringLiteral("-cl")
    };

    const QStringList args = buildArguments(o);
    bool expectValue = false;
    auto isIntLiteral=[](const QString& s)->bool {
        if(s.isEmpty()) return false;
        int i=(s.at(0)==QLatin1Char('-')||s.at(0)==QLatin1Char('+'))?1:0;
        if(i>=s.size()) return false;
        for(;i<s.size();++i) if(!s.at(i).isDigit()) return false;
        return true;
    };
    for (int i=0; i<args.size(); ++i) {
        const QString& a = args[i];
        // 预览显示收件人数而非路径
        if (expectValue && o.recipientCount > 1 && a == o.recipientPath) {
            cmd += QCoreApplication::translate("CliArgBuilder", " %1 个收件人").arg(o.recipientCount);
            expectValue = false;
            continue;
        }
        const bool needsQuote = (expectValue && !isIntLiteral(a)) ||
                                a.contains(QLatin1Char(' ')) ||
                                a.contains(QLatin1Char('\t')) ||
                                a.contains(QLatin1Char('"'));
        QString shown;
        if (needsQuote) {
            QString escaped = a;
            escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
            shown = QStringLiteral("\"%1\"").arg(escaped);
        } else {
            shown = a;
        }
        cmd += QStringLiteral(" %1").arg(shown);
        expectValue = valueFlags.contains(a);
    }

    // 密钥经 stdin 注入
    if (o.action == CryptoAction::KeyGen) {
        return cmd;
    }
    if (o.action == CryptoAction::Derive) {
        return cmd + QCoreApplication::translate("CliArgBuilder", "   [派生口令经 stdin 注入]");
    }
    if (o.action == CryptoAction::PubKey) {
        return cmd + QCoreApplication::translate("CliArgBuilder", "   [私钥来自 -k 文件]");
    }

    const bool isAsym = (o.mode == CryptoMode::Asymmetric);
    bool usesStdin = false;
    if (!isAsym && o.keyfilePath.isEmpty()) usesStdin = true;
    if (usesStdin) {
        cmd += QCoreApplication::translate("CliArgBuilder", "   [口令经 stdin 注入]");
    } else if (!o.keyfilePath.isEmpty()) {
        cmd += QCoreApplication::translate("CliArgBuilder", "   [密钥来自 -k 文件]");
    }

    return cmd;
}
