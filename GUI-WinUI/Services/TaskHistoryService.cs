using System.IO;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

public static class TaskHistoryService
{
    // 同一文件加锁防
    private static readonly object _gate = new();

    private static string HistoryDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FileEncryptor", "GUI", "history");
    private static string HistoryFile => Path.Combine(HistoryDir, "tasks.log");

    // 进程内只收紧一
    private static bool _aclApplied;

    private static void EnsureAcl()
    {
        if (_aclApplied) return;
        _aclApplied = true;
        RestrictToCurrentUser(HistoryDir, isDirectory: true);
        RestrictToCurrentUser(HistoryFile, isDirectory: false);
    }

    // M18
    // 加密了哪些文件」
    // 文件类字段只留
    // 目录类字段直接
    private static readonly byte[] PathEntropy =
        System.Text.Encoding.ASCII.GetBytes("FE_TASK_PATH");

    private static string EncryptPaths(TaskRecord r)
    {
        var payload = new
        {
            inputPaths = r.InputPaths,
            outputDir = r.OutputDir,
            intoVault = r.IntoVault,
            keyfile = r.Keyfile,
            identity = r.Identity,
            wrapInput = r.WrapInput,
            wrapOutput = r.WrapOutput,
            watermarkKey = r.WatermarkKey,
            recipient = r.Recipient
        };
        var json = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
        var blob = ProtectedData.Protect(json, PathEntropy, DataProtectionScope.CurrentUser);
        CryptographicOperations.ZeroMemory(json);
        return Convert.ToBase64String(blob);
    }

    private static void RestorePaths(TaskRecord r)
    {
        if (string.IsNullOrEmpty(r.PathCt)) return;
        try
        {
            var blob = Convert.FromBase64String(r.PathCt);
            var json = ProtectedData.Unprotect(blob, PathEntropy, DataProtectionScope.CurrentUser);
            using var doc = JsonDocument.Parse(json);
            CryptographicOperations.ZeroMemory(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("inputPaths", out var ip) && ip.ValueKind == JsonValueKind.Array)
                r.InputPaths = ip.EnumerateArray().Select(x => x.GetString() ?? "").ToList();
            string Get(string n) => root.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String
                ? (v.GetString() ?? "") : "";
            r.OutputDir = Get("outputDir");
            r.IntoVault = Get("intoVault");
            r.Keyfile = Get("keyfile");
            r.Identity = Get("identity");
            r.WrapInput = Get("wrapInput");
            r.WrapOutput = Get("wrapOutput");
            r.WatermarkKey = Get("watermarkKey");
            r.Recipient = Get("recipient");
            r.PathsStripped = false;
        }
        catch
        {
            // DPAPI 解不开时保留落盘内容，不判失败
        }
    }

    private static TaskRecord SanitizeForStorage(TaskRecord r)
    {
        var copy = JsonSerializer.Deserialize<TaskRecord>(JsonSerializer.Serialize(r));
        if (copy == null) return r;
        if (!App.Settings.Current.HistoryStorePaths)
        {
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
            copy.PathCt = "";
        }
        else
        {
            copy.PathCt = EncryptPaths(r);
            copy.InputPaths = new List<string>();
            copy.OutputDir = "";
            copy.IntoVault = "";
            copy.Keyfile = "";
            copy.Identity = "";
            copy.WrapInput = "";
            copy.WrapOutput = "";
            copy.WatermarkKey = "";
            copy.Recipient = "";
            copy.PathsStripped = false;
        }
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
                        if (r != null) { RestorePaths(r); result.Add(r); }
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
                // 写回时反转
                // M43: 与读取/追加路径
                var ordered = records.AsEnumerable().Reverse().ToList();
                var lines = ordered.Select(r => JsonSerializer.Serialize(SanitizeForStorage(r)));
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
                // 目录须先存
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
