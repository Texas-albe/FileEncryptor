// CliArgBuilder 实现
#include "CliArgBuilder.h"
#include <QDir>

QStringList CliArgBuilder::buildArguments(const ShellOptions& o) {
    QStringList args;

    // 三个 rage 密钥动作（-g 生成 / -G 口令派生 / -Y 私钥导公钥）只需密钥材料与输出目录，无需输入文件与模式
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
        // GUI 非交互，默认带 -y，允许覆盖同名密钥文件
        if (o.forceOverwrite) {
            args << QStringLiteral("-y");
        }
        args << QStringLiteral("--key-stdin");   // 口令走 stdin 管道，不经 argv / 环境变量
        return args;
    }
    if (o.action == CryptoAction::PubKey) {
        args << QStringLiteral("-Y");
        if (!o.identityPath.isEmpty()) {
            args << QStringLiteral("-k") << o.identityPath;
        }
        return args;
    }

    // 模式（KeyGen / Derive / PubKey 已在上方提前 return，此处仅处理单/批加密解密）
    switch (o.action) {
    case CryptoAction::Encrypt:       args << QStringLiteral("-e");  break;
    case CryptoAction::Decrypt:      args << QStringLiteral("-d");  break;
    case CryptoAction::BatchEncrypt:  args << QStringLiteral("-be"); break;
    case CryptoAction::BatchDecrypt:  args << QStringLiteral("-bd"); break;
    case CryptoAction::KeyGen:        // 不可达：上方已 return
    case CryptoAction::Derive:        // 不可达：上方已 return
    case CryptoAction::PubKey:        // 不可达：上方已 return
        break;
    }

    // 输出目录（main.cpp L226-232，含 path traversal 校验由子进程负责）
    if (!o.outputDir.isEmpty()) {
        args << QStringLiteral("-o") << o.outputDir;
    }

    // 加密后处理源文件（main.cpp：仅加密有效，子进程校验）
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

    // Encryption mode (main.cpp -m rage asymmetric branch)
    if (o.mode == CryptoMode::XChaCha20) {
        args << QStringLiteral("-m") << QStringLiteral("xchacha20");
    } else if (o.mode == CryptoMode::Aegis256) {
        args << QStringLiteral("-m") << QStringLiteral("aegis256");
    } else { // Asymmetric
        args << QStringLiteral("-m") << QStringLiteral("rage");
    }

    // 压缩：开关 -zstd 为布尔型不带值；仅需非默认级别时追加 --compression-level <N>。先布尔后级别，CLI 后者生效，语义稳定。
    if (o.compress && isEnc && !isAsym) {
        args << QStringLiteral("-zstd");
        if (o.compressionLevel != 0) {
            args << QStringLiteral("--compression-level") << QString::number(o.compressionLevel);
        }
    }

    // SHA-256 校验单（main.cpp --sha256）：加密成功后生成 <out>.ptd.sha256；仅加密动作下发
    // （对称与非对称加密均可，CLI 侧解密方向忽略）
    if (o.writeSha256 && isEnc) {
        args << QStringLiteral("--sha256");
    }

    // 非对称加密：收件人公钥文件（main.cpp -r）
    if (isAsym && isEnc && !o.recipientPath.isEmpty()) {
        args << QStringLiteral("-r") << o.recipientPath;
    }

    // 输入路径（main.cpp L242-244 批模式 -i；L254-256 单模式位置参数）
    bool isBatch = (o.action == CryptoAction::BatchEncrypt ||
                    o.action == CryptoAction::BatchDecrypt);
    if (isBatch) {
        // 批模式：每条路径用 -i
        for (const QString& p : o.inputPaths) {
            args << QStringLiteral("-i") << p;
        }
    } else {
        // 单模式：位置参数（main.cpp L254-255）
        if (!o.inputPaths.isEmpty()) {
            args << o.inputPaths.first();
        }
    }

    // 覆盖（main.cpp L245-247）。GUI 非交互默认带 -y，避开 stdin 覆盖提示
    if (o.forceOverwrite) {
        args << QStringLiteral("-y");
    }


    // 批量解密文件名还原（main.cpp --restore-name）：默认关闭以省去每文件昂贵 KDF，
    // 仅保留输出文件扩展名；开启后还原完整原始文件名。
    if (o.action == CryptoAction::BatchDecrypt && o.restoreName) {
        args << QStringLiteral("--restore-name");
    }

    // 密钥文件（main.cpp L251-253）。若提供 -k，则子进程用密钥文件，不经 stdin。
    if (!o.keyfilePath.isEmpty()) {
        args << QStringLiteral("-k") << o.keyfilePath;
    }

    // Asymmetric decryption hands the private key to the CLI as a file (-k); nothing is piped via stdin. Symmetric modes pipe the password through stdin when no -k file is used.
    if (!isAsym) {
        if (o.keyfilePath.isEmpty()) {
            args << QStringLiteral("--key-stdin");
        }
    }

    return args;
}

QProcessEnvironment CliArgBuilder::buildEnvironment(const ShellOptions& /*o*/) {
    // 不再注入 ENCRYPTOR_KEY：密钥/身份经子进程 stdin 管道注入（见 buildArguments 的 --key-stdin），
    // 较环境变量更不易被其它进程通过 /proc 或环境窥探。此处仅返回系统环境。
    return QProcessEnvironment::systemEnvironment();
}

QString CliArgBuilder::buildPreview(const QString& programPath, const ShellOptions& o) {
    // 命令预览（口令经 stdin 注入，不展示明文）：按位置判断引号——上一项是取值 flag（-o/-i/-k/-r/--salt 等）则当前项为路径值需加引号；含空格/制表符/双引号的参数也加引号并转义内嵌双引号。
    // 注意：预览仅供展示；实际执行走 buildArguments() 交 QProcess 逐参数传递，不经本引号层。
    QString cmd = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(programPath));

    // 取值型 flag 清单：其后紧跟的那一项是参数值（需加引号）；布尔开关（-zstd/-de/-y/--sha256/--restore-name 等）不得列入，否则其后独立参数会被误判成取值。
    static const QStringList valueFlags = {
        QStringLiteral("-o"), QStringLiteral("-i"), QStringLiteral("-k"),
        QStringLiteral("-r"), QStringLiteral("--salt"),
        QStringLiteral("--compression-level"), QStringLiteral("-cl")
    };

    const QStringList args = buildArguments(o);
    bool expectValue = false;
    // 纯整数字面量（如 --compression-level 的 3 / -3）即使紧跟取值 flag 也不加引号
    auto isIntLiteral=[](const QString& s)->bool {
        if(s.isEmpty()) return false;
        int i=(s.at(0)==QLatin1Char('-')||s.at(0)==QLatin1Char('+'))?1:0;
        if(i>=s.size()) return false;
        for(;i<s.size();++i) if(!s.at(i).isDigit()) return false;
        return true;
    };
    for (int i=0; i<args.size(); ++i) {
        const QString& a = args[i];
        // 多收件人：预览不以临时公钥文件路径泄露（临时文件仅含公钥、非机密，但应展示语义）。
        // 预览显示"N 个收件人"，实际执行仍经 -r 传递临时文件（buildArguments 不受影响）。
        if (expectValue && o.recipientCount > 1 && a == o.recipientPath) {
            cmd += QStringLiteral(" %1 个收件人").arg(o.recipientCount);
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

    // 密钥/身份经 stdin 注入（不展示明文）
    // Keypair generation injects no key material via stdin.
    if (o.action == CryptoAction::KeyGen) {
        return cmd;
    }
    if (o.action == CryptoAction::Derive) {
        return cmd + QStringLiteral("   [派生口令经 stdin 注入]");
    }
    if (o.action == CryptoAction::PubKey) {
        return cmd + QStringLiteral("   [私钥来自 -k 文件]");
    }

    const bool isAsym = (o.mode == CryptoMode::Asymmetric);
    bool usesStdin = false;
    // Asymmetric decryption passes the private key as a file (-k), never via stdin.
    if (!isAsym && o.keyfilePath.isEmpty()) usesStdin = true;
    if (usesStdin) {
        cmd += QStringLiteral("   [password via stdin]");
    } else if (!o.keyfilePath.isEmpty()) {
        cmd += QStringLiteral("   [key from -k file]");
    }

    return cmd;
}
