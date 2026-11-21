#include "CliArgBuilder.h"
#include "secure_zero.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryFile>
#include <QSet>
#include <vector>
#include <cstring>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#else
#include <unistd.h>
#endif

// 命令预览随界面

// m 取值
static const char* modeToken(CryptoMode m) {
    switch (m) {
    case CryptoMode::Aegis256: return "aegis256";
    case CryptoMode::AesGcm:   return "aes-gcm";
    case CryptoMode::Sm4:      return "sm4";
    default:                   return "xchacha20";
    }
}

static const char* wrapAlgToken(WrapAlg a) {
    switch (a) {
    case WrapAlg::AesKw:   return "aes-kw";
    case WrapAlg::Pubkey: return "pubkey";
    default:              return "kwp";
    }
}

// 密码框里存
// 是密钥材料
static QString s_wmKeyTempPath;

bool CliArgBuilder::isPrivateKeyMaterial(const QString& key)
{
    return key.contains(QStringLiteral("PRIVATE KEY"));
}

// P2-3
// H6a
// flush 只刷用户态缓冲
static void shred_file(const QString& path) {
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.exists()) return;
    if (f.open(QIODevice::ReadWrite)) {
        const qint64 n = f.size();
        if (n > 0) {
            f.write(QByteArray(static_cast<int>(n), '\0'));
            f.flush();
#ifdef Q_OS_WIN
            FlushFileBuffers(reinterpret_cast<HANDLE>(f.handle()));
#else
            fsync(f.handle());
#endif
        }
        f.close();
    }
    QFile::remove(path);
}

// H6b
// Administrators 完全控制。Windows
// 只读属性）
void CliArgBuilder::setTempFileAcl(const QString& path) {
    if (path.isEmpty()) return;
#ifdef Q_OS_WIN
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return;
    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    std::vector<unsigned char> buf(need ? need : 256);
    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    BOOL got = GetTokenInformation(tok, TokenUser, buf.data(), (DWORD)buf.size(), &need);
    CloseHandle(tok);
    if (!got || !tu->User.Sid) return;

    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0, 0, 0, 0, 0, 0, 0, &systemSid);

    EXPLICIT_ACCESSW ea[2];
    memset(ea, 0, sizeof ea);
    int n = 0;
    PSID sids[2] = { tu->User.Sid, systemSid };
    for (int i = 0; i < 2; ++i) {
        if (!sids[i]) continue;
        ea[n].grfAccessPermissions = GENERIC_ALL;
        ea[n].grfAccessMode = SET_ACCESS;
        ea[n].grfInheritance = NO_INHERITANCE;
        ea[n].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[n].Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea[n].Trustee.ptstrName = reinterpret_cast<LPWSTR>(sids[i]);
        ++n;
    }
    PACL dacl = NULL;
    if (SetEntriesInAclW(n, ea, NULL, &dacl) == ERROR_SUCCESS && dacl) {
        // PROTECTED
        SetNamedSecurityInfoW(
            reinterpret_cast<LPWSTR>(const_cast<ushort*>(path.utf16())),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        LocalFree(dacl);
    }
    if (systemSid) FreeSid(systemSid);
#else
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
}

// 私钥明文落 0600 临
// 调用方必须放弃
static bool write_wm_key_temp(const QString& pem) {
    // X 必须收尾
    QTemporaryFile tmp(QDir::temp().absoluteFilePath(
        QStringLiteral("fe_wm_XXXXXX")));
    // 不自动删
    tmp.setAutoRemove(false);
    // 0600
    tmp.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    // 无参 open
    if (!tmp.open()) return false;
    // H6b
    CliArgBuilder::setTempFileAcl(tmp.fileName());
    QByteArray blob = pem.toUtf8();
    if (tmp.write(blob) != static_cast<qint64>(blob.size())) {
        // 半截私钥不能留
        tmp.close();
        shred_file(tmp.fileName());
        secure_zero(blob.data(), static_cast<size_t>(blob.size()));
        s_wmKeyTempPath.clear();
        return false;
    }
    tmp.flush();
    s_wmKeyTempPath = tmp.fileName();
    secure_zero(blob.data(), static_cast<size_t>(blob.size()));   // P2-3
    return true;
}

// 以 '-' 开头
// 强制回落成普通
static QStringList guardDashPaths(const QStringList& args) {
    static const QSet<QString> kValueFlags = {
        QStringLiteral("-o"), QStringLiteral("-i"), QStringLiteral("-k"),
        QStringLiteral("-r"), QStringLiteral("--into-vault"),
        QStringLiteral("--identity"), QStringLiteral("--wrap-key"),
        QStringLiteral("--wrap-out"), QStringLiteral("--wrap-to"),
        QStringLiteral("--unwrap-key"), QStringLiteral("--unwrap-out"),
        QStringLiteral("--wm-sign"), QStringLiteral("--wm-verify")
    };
    QStringList out;
    out.reserve(args.size());
    bool afterDashDash = false;
    bool expectValue = false;
    for (const QString& a : args) {
        if (afterDashDash) {
            out << (a.startsWith(QLatin1Char('-')) ? QStringLiteral("./") + a : a);
            continue;
        }
        if (expectValue && a.startsWith(QLatin1Char('-'))) {
            out << QStringLiteral("./") + a;
        } else {
            out << a;
        }
        if (a == QStringLiteral("--")) afterDashDash = true;
        expectValue = kValueFlags.contains(a);
    }
    return out;
}

// M49
// allowKeyFileWrite=false
static QStringList buildArgumentsImpl(const ShellOptions& o, bool allowKeyFileWrite) {
    QStringList args;

    // 三个密钥动作无
    if (o.action == CryptoAction::KeyGen) {
        args << QStringLiteral("-g");
        if (o.useX448) {
            args << QStringLiteral("-x448");
        }
        if (!o.outputDir.isEmpty()) {
            args << QStringLiteral("-o") << o.outputDir;
        }
        return guardDashPaths(args);
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
        return guardDashPaths(args);
    }
    if (o.action == CryptoAction::PubKey) {
        args << QStringLiteral("-Y");
        if (!o.identityPath.isEmpty()) {
            args << QStringLiteral("-k") << o.identityPath;
        }
        return guardDashPaths(args);
    }
    // 密钥包装
    // 密码 / 私钥不落 argv
    if (o.action == CryptoAction::WrapKey) {
        args << QStringLiteral("--wrap-key") << o.wrapInput;
        args << QStringLiteral("--wrap-alg") << wrapAlgToken(o.wrapAlg);
        if (!o.wrapOutput.isEmpty()) {
            args << QStringLiteral("--wrap-out") << o.wrapOutput;
        }
        if (o.wrapAlg == WrapAlg::Pubkey) {
            // 公钥路线
            args << QStringLiteral("--wrap-to") << o.recipientPath;
        } else if (!o.keyfilePath.isEmpty()) {
            args << QStringLiteral("-k") << o.keyfilePath;
        } else {
            args << QStringLiteral("--key-stdin");
        }
        if (o.forceOverwrite) args << QStringLiteral("-y");
        return guardDashPaths(args);
    }
    if (o.action == CryptoAction::UnwrapKey) {
        args << QStringLiteral("--unwrap-key") << o.wrapInput;
        if (o.wrapAlg != WrapAlg::Pubkey) {
            // 解包时算法存
            if (!o.keyfilePath.isEmpty()) {
                args << QStringLiteral("-k") << o.keyfilePath;
            } else {
                args << QStringLiteral("--key-stdin");
            }
        } else {
            args << QStringLiteral("--identity") << o.identityPath;
        }
        if (!o.wrapOutput.isEmpty()) {
            args << QStringLiteral("--unwrap-out") << o.wrapOutput;
        }
        if (o.forceOverwrite) args << QStringLiteral("-y");
        return guardDashPaths(args);
    }

    const bool isAsym = (o.mode == CryptoMode::Asymmetric);
    const bool isEnc = (o.action == CryptoAction::Encrypt ||
                        o.action == CryptoAction::BatchEncrypt);
    const bool isBatch = (o.action == CryptoAction::BatchEncrypt ||
                          o.action == CryptoAction::BatchDecrypt);

    // 处理单/批加密解
    switch (o.action) {
    case CryptoAction::Encrypt:       args << QStringLiteral("-e");  break;
    case CryptoAction::Decrypt:      args << QStringLiteral("-d");  break;
    case CryptoAction::BatchEncrypt:  args << QStringLiteral("-be"); break;
    case CryptoAction::BatchDecrypt:  args << QStringLiteral("-bd"); break;
    case CryptoAction::KeyGen:
    case CryptoAction::Derive:
    case CryptoAction::PubKey:
    case CryptoAction::WrapKey:
    case CryptoAction::UnwrapKey:
        break;   // 包装动作
    }

    // CLI 的 -m 后写覆盖前写
    // 两条
    // 解密一律不带 -m
    if (isEnc) {
        if (isAsym) {
            args << QStringLiteral("-m") << (o.useX448 ? QStringLiteral("x448") : QStringLiteral("x25519"));
            args << QStringLiteral("-m") << modeToken(o.fileMode);
        } else {
            args << QStringLiteral("-m") << modeToken(o.mode);
        }
    }

    // 加密盘入盘
    if (isEnc && !o.intoVault.isEmpty()) {
        args << QStringLiteral("--into-vault") << o.intoVault;
    }

    if (!o.outputDir.isEmpty()) {
        args << QStringLiteral("-o") << o.outputDir;
    }

    // 分卷
    if (isEnc && o.split) {
        static const char* kUnit[3] = { "MB", "GB", "TB" };
        const char* unit = kUnit[(o.splitUnit >= 0 && o.splitUnit <= 2) ? o.splitUnit : 0];
        args << QStringLiteral("--split")
             << QString::number(o.splitSize > 0 ? o.splitSize : 1) + QLatin1String(unit);
    }

    // 加密压缩包
    if (o.pack && isEnc) {
        args << QStringLiteral("-p");
    }

    // 源文件处理
    if (isEnc) {
        if (o.sourceDisposition == 1) {
            args << QStringLiteral("-de");
        } else if (o.sourceDisposition == 2) {
            args << QStringLiteral("--wipe-source");
        } else if (o.sourceDisposition == 3) {
            args << QStringLiteral("--recycle-source");
        }
        // 目录 + 删除类处置
        if (o.sourceDeleteOk && o.sourceDisposition != 0) {
            args << QStringLiteral("--source-delete-ok");
        }
    }

    if (o.forceOverwrite) {
        args << QStringLiteral("-y");
    }

    // 密钥文件
    // 非对称时它走 identityPath，因
    if (!o.keyfilePath.isEmpty()) {
        args << QStringLiteral("-k") << o.keyfilePath;
    }

    if (isAsym && isEnc && !o.recipientPath.isEmpty()) {
        args << QStringLiteral("-r") << o.recipientPath;
    }

    if (o.action == CryptoAction::BatchDecrypt && o.restoreName) {
        args << QStringLiteral("--restore-name");
    }

    // 批量过滤
    if (isBatch) {
        for (const QString& pat : o.excludePatterns) {
            if (!pat.trimmed().isEmpty()) {
                args << QStringLiteral("--exclude") << pat.trimmed();
            }
        }
        if (o.skipHidden) args << QStringLiteral("--skip-hidden");
    }

    if (o.writeSha256 && isEnc) {
        args << QStringLiteral("--sha256");
    }

    // 后量子开关
    // 因此只
    const bool pqcAffects = (o.action == CryptoAction::KeyGen) || o.watermark;
    if (pqcAffects && !o.pqc) {
        args << QStringLiteral("--no-pqc");
    }

    // 尾部水印
    if (o.watermark && isEnc) {
        args << QStringLiteral("--watermark");
        QString key = o.watermarkKeyPath.trimmed();
        if (!key.isEmpty()) {
            // buildArgumentsImpl 是文件级静态函
            if (CliArgBuilder::isPrivateKeyMaterial(key)) {
                if (allowKeyFileWrite) {
                    // 唯一出口是 0600 临
                    if (s_wmKeyTempPath.isEmpty() && !write_wm_key_temp(key)) return {};
                    if (s_wmKeyTempPath.isEmpty()) return {};
                    key = s_wmKeyTempPath;
                }
                // 预览
                // buildPreview 会显示
            }
            args << QStringLiteral("--wm-sign") << key;
        }
    }

    // 压缩
    if (o.compress && isEnc) {
        args << QStringLiteral("-zstd");
        if (o.compressionLevel != 0) {
            args << QStringLiteral("--compression-level") << QString::number(o.compressionLevel);
        }
    }

    // 密码经 stdin 注入
    if (!isAsym && o.keyfilePath.isEmpty()) {
        args << QStringLiteral("--key-stdin");
    }

    // 输入路径放
    if (isBatch) {
        for (const QString& p : o.inputPaths) {
            args << QStringLiteral("-i") << p;
        }
    } else if (!o.inputPaths.isEmpty()) {
        args << QStringLiteral("--") << o.inputPaths.first();
    }

    return guardDashPaths(args);
}

QStringList CliArgBuilder::buildArguments(const ShellOptions& options) {
    return buildArgumentsImpl(options, true);
}

QStringList CliArgBuilder::buildArgumentsForPreview(const ShellOptions& options) {
    return buildArgumentsImpl(options, false);
}

QProcessEnvironment CliArgBuilder::buildEnvironment(const ShellOptions& ) {
    return QProcessEnvironment::systemEnvironment();
}

void CliArgBuilder::cleanupWatermarkTemp() {
    if (s_wmKeyTempPath.isEmpty()) return;
    shred_file(s_wmKeyTempPath);   // P2-3
    s_wmKeyTempPath.clear();
}

QString CliArgBuilder::buildPreview(const QString& programPath, const ShellOptions& o) {
    // 命令预览
    QString cmd = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(programPath));

    static const QStringList valueFlags = {
        QStringLiteral("-o"), QStringLiteral("-i"), QStringLiteral("-k"),
        QStringLiteral("-r"), QStringLiteral("--salt"),
        QStringLiteral("--compression-level"), QStringLiteral("-cl"),
        QStringLiteral("--wm-sign"), QStringLiteral("--wm-verify"),
        QStringLiteral("--wrap-key"), QStringLiteral("--wrap-out"),
        QStringLiteral("--wrap-alg"), QStringLiteral("--wrap-to"),
        QStringLiteral("--unwrap-key"), QStringLiteral("--unwrap-out"),
        QStringLiteral("--identity")
    };

    // M49
    const QStringList args = buildArgumentsForPreview(o);
    bool expectValue = false;
    bool expectKey = false;
    for (int i=0; i<args.size(); ++i) {
        const QString& a = args[i];
        // 密钥取值只显示
        if (!a.startsWith(QLatin1Char('-')) && (expectKey || isPrivateKeyMaterial(a))) {
            cmd += QCoreApplication::translate("CliArgBuilder", " <private-key>");
            expectValue = false;
            expectKey = false;
            continue;
        }
        // 预览显示收件人
        if (expectValue && o.recipientCount > 1 && a == o.recipientPath) {
            cmd += QCoreApplication::translate("CliArgBuilder", " %1 个收件人").arg(o.recipientCount);
            expectValue = false;
            continue;
        }
        // 预览引号策略
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
        return cmd + QCoreApplication::translate("CliArgBuilder", "   [派生密码经 stdin 注入]");
    }
    if (o.action == CryptoAction::PubKey) {
        return cmd + QCoreApplication::translate("CliArgBuilder", "   [私钥来自 -k 文件]");
    }
    // 包装动作
    if (o.action == CryptoAction::WrapKey || o.action == CryptoAction::UnwrapKey) {
        if (o.wrapAlg == WrapAlg::Pubkey) {
            return cmd + QCoreApplication::translate("CliArgBuilder", "   [使用收件人密钥材料]");
        }
        if (!o.keyfilePath.isEmpty()) {
            return cmd + QCoreApplication::translate("CliArgBuilder", "   [密码来自 -k 文件]");
        }
        return cmd + QCoreApplication::translate("CliArgBuilder", "   [密码经 stdin 注入]");
    }

    const bool isAsym = (o.mode == CryptoMode::Asymmetric);
    bool usesStdin = false;
    if (!isAsym && o.keyfilePath.isEmpty()) usesStdin = true;
    if (usesStdin) {
        cmd += QCoreApplication::translate("CliArgBuilder", "   [密码经 stdin 注入]");
    } else if (!o.keyfilePath.isEmpty()) {
        cmd += QCoreApplication::translate("CliArgBuilder", "   [密钥来自 -k 文件]");
    }

    return cmd;
}
