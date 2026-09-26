using System.IO;
using System.Text.Json;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

public static class TaskHistoryService
{
    private static string HistoryDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "FileEncryptor", "GUI", "history");
    private static string HistoryFile => Path.Combine(HistoryDir, "tasks.log");

    public static bool Append(TaskRecord record, out string error)
    {
        error = "";
        try
        {
            Directory.CreateDirectory(HistoryDir);
            var json = JsonSerializer.Serialize(record);
            File.AppendAllText(HistoryFile, json + "\n");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static List<TaskRecord> Load(out string error)
    {
        error = "";
        var result = new List<TaskRecord>();
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
                catch { /* 跳过损坏行 */ }
            }
            result.Reverse(); // 最新在前
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        return result;
    }

    public static bool Clear(out string error)
    {
        error = "";
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


    public static bool Save(List<TaskRecord> records, out string error)
    {
        error = "";
        try
        {
            Directory.CreateDirectory(HistoryDir);
            // Load 返回最新在前，写入时需要反转回正序
            var ordered = records.AsEnumerable().Reverse().ToList();
            var lines = ordered.Select(r => JsonSerializer.Serialize(r));
            File.WriteAllLines(HistoryFile, lines);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
    public static string NewId() => Guid.NewGuid().ToString("N");

    public static string ActionLabel(string actionKey) => actionKey switch
    {
        "encrypt" => "加密",
        "decrypt" => "解密",
        "batch-encrypt" => "批量加密",
        "batch-decrypt" => "批量解密",
        "keygen" => "生成密钥对",
        "derive" => "口令派生密钥对",
        "pubkey" => "导出公钥",
        _ => actionKey
    };
}
