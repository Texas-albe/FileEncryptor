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

    public static bool Append(TaskRecord record, out string error)
    {
        error = "";
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(HistoryDir);
                // 历史含敏感路径，收紧 ACL
                var newFile = !File.Exists(HistoryFile);
                var json = JsonSerializer.Serialize(record);
                File.AppendAllText(HistoryFile, json + "\n");
                if (newFile) RestrictToCurrentUser(HistoryFile);
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
                // 写回时反转为正序
                var ordered = records.AsEnumerable().Reverse().ToList();
                var lines = ordered.Select(r => JsonSerializer.Serialize(r));
                File.WriteAllLines(HistoryFile, lines);
                // 重新收紧 ACL
                RestrictToCurrentUser(HistoryFile);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    private static void RestrictToCurrentUser(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var fs = new FileSecurity();
            var user = WindowsIdentity.GetCurrent().User;
            if (user == null) return;
            fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            fs.AddAccessRule(new FileSystemAccessRule(user,
                FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(fs);
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
        "derive" => L10n.T("口令派生密钥对"),
        "pubkey" => L10n.T("导出公钥"),
        _ => actionKey
    };
}
