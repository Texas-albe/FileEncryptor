#include "CliArgBuilder.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryFile>

// 命令预览随界面语言

// -m 取值：GUI 的选项下标与 CLI 模式名一一对应
static const char* modeToken(CryptoMode m) {
    switch (m) {
    case CryptoMode::Aegis256: return "aegis256";
    case CryptoMode::Sm4:      return "sm4";
    default:                   return "xchacha20";
    }
}

// 密码框里存的是私钥明文，而 CLI 的 --wm-sign 只收文件路径：
// 是密钥材料就落一份临时文件给 CLI 用，路径在任务结束时清掉。
static QString s_wmKeyTempPath;

bool CliArgBuilder::isPrivateKeyMaterial(const QString& key)
{
    return key.contains(QStringLiteral("PRIVATE KEY"));
}

// 私钥明文落 0600 临时文件；成功返回 true。失败一律返回 false，
// 调用方必须放弃任务——绝不能把明文私钥当 argv 元素下发（/proc/<pid>/cmdline 世界可读）。
static bool write_wm_key_temp(const QString& pem) {
    // X 必须收尾：Qt 只替换模板末尾 6 个字符位，写 ".pem" 后缀会把后缀一起换掉
    QTemporaryFile tmp(QDir::temp().absoluteFilePath(
        QStringLiteral("fe_wm_XXXXXX")));
    // 不自动删：文件要活到 CLI 读完，统一由 cleanupWatermarkTemp() 收尾
    tmp.setAutoRemove(false);
    // 0600：多用户 POSIX 下默认 0644 会让同机其他用户读到签名私钥
    tmp.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    // 无参 open() 是 public；带参数的重载在 QTemporaryFile 里是 protected
    if (!tmp.open()) return false;
    const QByteArray blob = pem.toUtf8();
    if (tmp.write(blob) != static_cast<qint64>(blob.size())) {
        // 半截私钥不能留在磁盘，删掉再报失败
        tmp.close();
        QFile::remove(tmp.fileName());
        s_wmKeyTempPath.clear();
        return false;
    }
    tmp.flush();
    s_wmKeyTempPath = tmp.fileName();
    return true;
}

QStringList CliArgBuilder::buildArguments(const ShellOptions& o) {
    QStringList args;

    // 三个密钥动作无需输入文件
    if (o.action == CryptoAction::KeyGen) {
        args << QStringLiteral("-g");
        if (o.useX448) {
            args << QStringLiteral("-x448");
        }
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

    const bool isAsym = (o.mode == CryptoMode::Asymmetric);
    const bool isEnc = (o.action == CryptoAction::Encrypt ||
                        o.action == CryptoAction::BatchEncrypt);
    const bool isBatch = (o.action == CryptoAction::BatchEncrypt ||
                          o.action == CryptoAction::BatchDecrypt);

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

    // CLI 的 -m 后写覆盖前写，但 -m x25519/x448 只置 asym 标志、不改算法，
    // 所以两条都带上即为「非对称封装 + 指定文件载荷对称算法」。
    // 解密一律不带 -m：非对称通道由 CLI 按「.ptd + 身份私钥文件」自动识别。
    if (isEnc) {
        if (isAsym) {
            args << QStringLiteral("-m") << (o.useX448 ? QStringLiteral("x448") : QStringLiteral("x25519"));
            args << QStringLiteral("-m") << modeToken(o.fileMode);
        } else {
            args << QStringLiteral("-m") << modeToken(o.mode);
        }
    }

    if (!o.outputDir.isEmpty()) {
        args << QStringLiteral("-o") << o.outputDir;
    }

    // 加密压缩包：目录树 / 多文件打成单个 .ptd。短选项 -p，长选项 --pack。必须在 -- 之前。
    if (o.pack && isEnc) {
        args << QStringLiteral("-p");
    }

    // 源文件处理（仅加密动作）
    if (isEnc) {
        if (o.sourceDisposition == 1) {
            args << QStringLiteral("-de");
        } else if (o.sourceDisposition == 2) {
            args << QStringLiteral("--wipe-source");
        } else if (o.sourceDisposition == 3) {
            args << QStringLiteral("--recycle-source");
        }
        // 目录 + 删除类处置：界面已弹窗确认，告知 CLI 免掉交互询问
        if (o.sourceDeleteOk && o.sourceDisposition != 0) {
            args << QStringLiteral("--source-delete-ok");
        }
    }

    if (o.forceOverwrite) {
        args << QStringLiteral("-y");
    }

    // 密钥文件：界面把「对称口令文件」与「非对称身份私钥」都填到这里，
    // 非对称时它走 identityPath，因此此处按原样下发即同时覆盖两种用途。
    if (!o.keyfilePath.isEmpty()) {
        args << QStringLiteral("-k") << o.keyfilePath;
    }

    if (isAsym && isEnc && !o.recipientPath.isEmpty()) {
        args << QStringLiteral("-r") << o.recipientPath;
    }

    if (o.action == CryptoAction::BatchDecrypt && o.restoreName) {
        args << QStringLiteral("--restore-name");
    }

    if (o.writeSha256 && isEnc) {
        args << QStringLiteral("--sha256");
    }

    // 后量子开关：CLI 仅在密钥生成、水印签名 / 验签处读取该开关（纯对称加密无影响），
    // 因此只在真正受影响的下发路径上带参数，避免给不认它的旧 CLI 造成未知开关报错。
    const bool pqcAffects = (o.action == CryptoAction::KeyGen) || o.watermark;
    if (pqcAffects && !o.pqc) {
        args << QStringLiteral("--no-pqc");
    }

    // 尾部水印：仅加密动作下发；带签名私钥时一并下发 --wm-sign
    if (o.watermark && isEnc) {
        args << QStringLiteral("--watermark");
        QString key = o.watermarkKeyPath.trimmed();
        if (!key.isEmpty()) {
            if (isPrivateKeyMaterial(key)) {
                // 唯一出口是 0600 临时文件：落盘失败即中止，不回退明文
                if (s_wmKeyTempPath.isEmpty() && !write_wm_key_temp(key)) return {};
                if (s_wmKeyTempPath.isEmpty()) return {};
                key = s_wmKeyTempPath;
            }
            args << QStringLiteral("--wm-sign") << key;
        }
    }

    // 压缩：开关 + 级别（非对称 .ptd 同样支持，CLI run_asym 会把级别透传给 encrypt_file）
    if (o.compress && isEnc) {
        args << QStringLiteral("-zstd");
        if (o.compressionLevel != 0) {
            args << QStringLiteral("--compression-level") << QString::number(o.compressionLevel);
        }
    }

    // 口令经 stdin 注入：必须早于输入路径，否则会被 -- 吞成输入文件
    if (!isAsym && o.keyfilePath.isEmpty()) {
        args << QStringLiteral("--key-stdin");
    }

    // 输入路径放最后：CLI 用 -- 终止选项解析，其后的参数一律是输入文件
    if (isBatch) {
        for (const QString& p : o.inputPaths) {
            args << QStringLiteral("-i") << p;
        }
    } else if (!o.inputPaths.isEmpty()) {
        args << QStringLiteral("--") << o.inputPaths.first();
    }

    return args;
}

QProcessEnvironment CliArgBuilder::buildEnvironment(const ShellOptions& ) {
    return QProcessEnvironment::systemEnvironment();
}

void CliArgBuilder::cleanupWatermarkTemp() {
    if (s_wmKeyTempPath.isEmpty()) return;
    QFile::remove(s_wmKeyTempPath);
    s_wmKeyTempPath.clear();
}

QString CliArgBuilder::buildPreview(const QString& programPath, const ShellOptions& o) {
    // 命令预览的引号策略
    QString cmd = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(programPath));

    static const QStringList valueFlags = {
        QStringLiteral("-o"), QStringLiteral("-i"), QStringLiteral("-k"),
        QStringLiteral("-r"), QStringLiteral("--salt"),
        QStringLiteral("--compression-level"), QStringLiteral("-cl"),
        QStringLiteral("--wm-sign"), QStringLiteral("--wm-verify")
    };

    const QStringList args = buildArguments(o);
    bool expectValue = false;
    bool expectKey = false;
    for (int i=0; i<args.size(); ++i) {
        const QString& a = args[i];
        // 密钥取值只显示占位符：临时文件落盘失败时这里是私钥明文
        if (!a.startsWith(QLatin1Char('-')) && (expectKey || isPrivateKeyMaterial(a))) {
            cmd += QCoreApplication::translate("CliArgBuilder", " <private-key>");
            expectValue = false;
            expectKey = false;
            continue;
        }
        // 预览显示收件人数而非路径
        if (expectValue && o.recipientCount > 1 && a == o.recipientPath) {
            cmd += QCoreApplication::translate("CliArgBuilder", " %1 个收件人").arg(o.recipientCount);
            expectValue = false;
            continue;
        }
        // 预览引号策略与 WinUI 版对齐：选项本身不加引号，取值一律加引号
        QString shown;
        if (a.startsWith(QLatin1Char('-'))) {
            shown = a;
        } else {
            QString escaped = a;
            escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
            shown = QStringLiteral("\"%1\"").arg(escaped);
        }
        cmd += QStringLiteral(" %1").arg(shown);
        expectValue = valueFlags.contains(a);
        expectKey = (a == QStringLiteral("--wm-sign") || a == QStringLiteral("--wm-verify"));
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
