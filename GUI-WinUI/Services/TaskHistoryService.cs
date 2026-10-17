using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

public static class TaskHistoryService
{
    // 同一文件加锁防并发截断
    private static readonly object _gate = new();

    private static string HistoryDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FileEncryptor", "GUI", "history");
    private static string HistoryFile => Path.Combine(HistoryDir, "tasks.log");

    // 进程内只收紧一次：目录与文件 ACL 都在首次写历史前落地
    private static bool _aclApplied;

    private static void EnsureAcl()
    {
        if (_aclApplied) return;
        _aclApplied = true;
        RestrictToCurrentUser(HistoryDir, isDirectory: true);
        RestrictToCurrentUser(HistoryFile, isDirectory: false);
    }

    // M18：默认不把完整路径写进 tasks.log。ACL 只挡同机其他用户，挡不住「用户到底
    // 加密了哪些文件」这一隐私被明文留在磁盘上。未开启 HistoryStorePaths 时：
    // 文件类字段只留文件名（Path.GetFileName 对不含分隔符的公钥串原样返回，不会误伤），
    // 目录类字段直接清空。代价是该条无法双击回放，读取侧按 PathsStripped 提示用户。
    private static TaskRecord SanitizeForStorage(TaskRecord r)
    {
        if (App.Settings.Current.HistoryStorePaths) return r;
        // 借序列化做浅拷贝，避免手工复制字段时漏掉新增项
        var copy = JsonSerializer.Deserialize<TaskRecord>(JsonSerializer.Serialize(r));
        if (copy == null) return r;
        copy.InputPaths = r.InputPaths.Select(p => Path.GetFileName(p) ?? p).ToList();
        copy.OutputDir = "";
        copy.IntoVault = "";
        copy.Keyfile = Path.GetFileName(r.Keyfile) ?? "";
        copy.Identity = Path.GetFileName(r.Identity) ?? "";
        copy.WrapInput = Path.GetFileName(r.WrapInput) ?? "";
        copy.WrapOutput = Path.GetFileName(r.WrapOutput) ?? "";
        copy.WatermarkKey = Path.GetFileName(r.WatermarkKey) ?? "";
        copy.Recipient = Path.GetFileName(r.Recipient) ?? "";
        copy.PathsStripped = true;
        return copy;
    }

    public static bool Append(TaskRecord record, out string error)
    {
        error = "";
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(HistoryDir);
                EnsureAcl();
                var newFile = !File.Exists(HistoryFile);
                var json = JsonSerializer.Serialize(SanitizeForStorage(record));
                File.AppendAllText(HistoryFile, json + "\n");
                if (newFile) RestrictToCurrentUser(HistoryFile, isDirectory: false);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    public static List<TaskRecord> Load(out string error)
    {
        error = "";
        var result = new List<TaskRecord>();
        lock (_gate)
        {
            try
            {
                if (!File.Exists(HistoryFile)) return result;
                foreach (var line in File.ReadAllLines(HistoryFile))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var r = JsonSerializer.Deserialize<TaskRecord>(line);
                        if (r != null) result.Add(r);
                    }
                    catch {  }
                }
                result.Reverse();
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }
        return result;
    }

    public static bool Clear(out string error)
    {
        error = "";
        lock (_gate)
        {
            try
            {
                if (File.Exists(HistoryFile)) File.Delete(HistoryFile);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }


    public static bool Save(List<TaskRecord> records, out string error)
    {
        error = "";
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(HistoryDir);
                EnsureAcl();
                // 写回时反转为正序
                var ordered = records.AsEnumerable().Reverse().ToList();
                var lines = ordered.Select(r => JsonSerializer.Serialize(r));
                File.WriteAllLines(HistoryFile, lines);
                // 重写后重新收紧 ACL
                RestrictToCurrentUser(HistoryFile, isDirectory: false);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    private static void RestrictToCurrentUser(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var user = WindowsIdentity.GetCurrent().User;
            if (user == null) return;
            FileSystemSecurity sec = isDirectory
                ? new DirectorySecurity()
                : new FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            sec.AddAccessRule(new FileSystemAccessRule(user,
                FileSystemRights.FullControl, AccessControlType.Allow));
            if (isDirectory)
            {
                // 目录须先存在才能改 ACL
                if (!Directory.Exists(path)) return;
                new DirectoryInfo(path).SetAccessControl((DirectorySecurity)sec);
            }
            else
            {
                if (!File.Exists(path)) return;
                new FileInfo(path).SetAccessControl((FileSecurity)sec);
            }
        }
        catch {  }
    }

    public static string NewId() => Guid.NewGuid().ToString("N");

    public static string ActionLabel(string actionKey) => actionKey switch
    {
        "encrypt" => L10n.T("加密"),
        "decrypt" => L10n.T("解密"),
        "batch-encrypt" => L10n.T("批量加密"),
        "batch-decrypt" => L10n.T("批量解密"),
        "keygen" => L10n.T("生成密钥对"),
        "derive" => L10n.T("密码派生密钥对"),
        "pubkey" => L10n.T("导出公钥"),
        "wrap" => L10n.T("包装密钥"),
        "unwrap" => L10n.T("解包密钥"),
        _ => actionKey
    };
}
