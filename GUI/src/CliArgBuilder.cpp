// CliArgBuilder 实现
#include "CliArgBuilder.h"
#include <QDir>

QStringList CliArgBuilder::buildArguments(const ShellOptions& o) {
    QStringList args;

    // 模式（main.cpp L210-225）
    switch (o.action) {
    case CryptoAction::Encrypt:       args << QStringLiteral("-e");  break;
    case CryptoAction::Decrypt:      args << QStringLiteral("-d");  break;
    case CryptoAction::BatchEncrypt:  args << QStringLiteral("-be"); break;
    case CryptoAction::BatchDecrypt:  args << QStringLiteral("-bd"); break;
    }

    // 输出目录（main.cpp L226-232，含 path traversal 校验由子进程负责）
    if (!o.outputDir.isEmpty()) {
        args << QStringLiteral("-o") << o.outputDir;
    }

    // 加密后删除源文件（main.cpp L233-235，仅加密有效，子进程校验 L283-286）
    if (o.deleteSource) {
        args << QStringLiteral("-de");
    }

    // 加密模式（main.cpp L236-241）
    if (o.mode == CryptoMode::XChaCha20) {
        args << QStringLiteral("-m") << QStringLiteral("xchacha20");
    } else {
        args << QStringLiteral("-m") << QStringLiteral("aegis256");
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

    // 密钥文件（main.cpp L251-253）。若提供 -k，则子进程用密钥文件而非 ENCRYPTOR_KEY env
    if (!o.keyfilePath.isEmpty()) {
        args << QStringLiteral("-k") << o.keyfilePath;
    }

    return args;
}

QProcessEnvironment CliArgBuilder::buildEnvironment(const ShellOptions& o) {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    // 仅当未用 -k 密钥文件时，把右侧密码框内容注入 ENCRYPTOR_KEY
    // （main.cpp L326-333：keyfile_path 空时读 ENCRYPTOR_KEY env）
    if (o.keyfilePath.isEmpty() && !o.password.isEmpty()) {
        env.insert(QStringLiteral("ENCRYPTOR_KEY"), o.password);
    }
    return env;
}

QString CliArgBuilder::buildPreview(const QString& programPath, const ShellOptions& o) {
    // 命令预览：program arg1 arg2 ...（密码以 ****** 替代，避免明文展示）
    QString cmd = QDir::toNativeSeparators(programPath);
    if (cmd.contains(QLatin1Char(' '))) {
        cmd = QStringLiteral("\"%1\"").arg(cmd);
    }

    // 临时构造一份预览 options，把密码替换为掩码
    ShellOptions preview = o;
    preview.password = o.password.isEmpty() ? QStringLiteral("(无密码)")
                                             : QStringLiteral("******");

    const QStringList args = buildArguments(preview);
    for (const QString& a : args) {
        if (a.contains(QLatin1Char(' '))) {
            cmd += QStringLiteral(" \"%1\"").arg(a);
        } else {
            cmd += QStringLiteral(" %1").arg(a);
        }
    }

    // 若密码经 env 注入，预览里标注（不展示明文）
    if (o.keyfilePath.isEmpty() && !o.password.isEmpty()) {
        cmd += QStringLiteral("   [ENCRYPTOR_KEY=******]");
    }

    return cmd;
}
