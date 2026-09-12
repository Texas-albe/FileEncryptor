// CliArgBuilder 实现
#include "CliArgBuilder.h"
#include <QDir>

QStringList CliArgBuilder::buildArguments(const ShellOptions& o) {
    QStringList args;

    // 三个 rage 密钥动作都只需要密钥材料 / 输出目录，不需要输入文件与模式：
    //   -g          随机生成密钥对
    //   -G          由口令派生密钥对（口令经 stdin 注入，避免出现在命令行）
    //   -Y          由私钥文件导出公钥
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

    // 加密后删除源文件（main.cpp L233-235，仅加密有效，子进程校验 L283-286）
    if (o.deleteSource) {
        args << QStringLiteral("-de");
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

    // 详细（main.cpp L248-250）
    if (o.verbose) {
        args << QStringLiteral("-v");
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

    // Asymmetric decryption hands the private key to the CLI as a file (-k);
    // nothing is piped through stdin there. Symmetric modes keep piping the
    // password through stdin whenever no -k file is used.
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

// 路径类参数（值而非 flag）统一用双引号包裹，确保带空格路径的规范与安全。
// flag（如 -e / -m xchacha20 / -y）不加引号。
static QString quotePathArg(const QString& a, const ShellOptions& o) {
    if (a.isEmpty()) return a;
    if (a == o.outputDir)        return QStringLiteral("\"%1\"").arg(a);
    if (a == o.keyfilePath)      return QStringLiteral("\"%1\"").arg(a);
    if (a == o.recipientPath)    return QStringLiteral("\"%1\"").arg(a);
    if (a == o.identityPath)     return QStringLiteral("\"%1\"").arg(a);
    for (const QString& p : o.inputPaths) {
        if (a == p) return QStringLiteral("\"%1\"").arg(a);
    }
    return a;
}

QString CliArgBuilder::buildPreview(const QString& programPath, const ShellOptions& o) {
    // 命令预览：program arg1 arg2 ...（口令经 stdin 注入，不展示明文）
    // 所有路径字符串（程序、输出目录、输入/密钥/公钥/私钥文件路径）统一用双引号包裹。
    QString cmd = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(programPath));

    const QStringList args = buildArguments(o);
    for (const QString& a : args) {
        cmd += QStringLiteral(" %1").arg(quotePathArg(a, o));
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
