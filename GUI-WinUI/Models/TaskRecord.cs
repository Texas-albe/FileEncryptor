using System.Text.Json.Serialization;

namespace FileEncryptorGUI.Models;

public class TaskRecord
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("startedAt")] public string StartedAt { get; set; } = "";
    [JsonPropertyName("finishedAt")] public string FinishedAt { get; set; } = "";
    [JsonPropertyName("durationMs")] public long DurationMs { get; set; }
    [JsonPropertyName("action")] public string Action { get; set; } = "";
    [JsonPropertyName("actionLabel")] public string ActionLabel { get; set; } = "";
    [JsonPropertyName("mode")] public string Mode { get; set; } = "";
    [JsonPropertyName("inputCount")] public int InputCount { get; set; }
    [JsonPropertyName("inputPaths")] public List<string> InputPaths { get; set; } = new();
    [JsonPropertyName("totalBytes")] public long TotalBytes { get; set; }
    [JsonPropertyName("filesDone")] public int FilesDone { get; set; }
    [JsonPropertyName("outputDir")] public string OutputDir { get; set; } = "";
    [JsonPropertyName("exitCode")] public int ExitCode { get; set; }
    [JsonPropertyName("cancelled")] public bool Cancelled { get; set; }
    [JsonPropertyName("error")] public string Error { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    // 完整参数快照，用于任务还原
    [JsonPropertyName("sourceIndex")] public int SourceIndex { get; set; }
    [JsonPropertyName("force")] public bool Force { get; set; }
    [JsonPropertyName("sha256")] public bool Sha256 { get; set; }
    [JsonPropertyName("compress")] public bool Compress { get; set; }
    [JsonPropertyName("compressionLevel")] public int CompressionLevel { get; set; }
    [JsonPropertyName("keyfile")] public string Keyfile { get; set; } = "";
    [JsonPropertyName("recipient")] public string Recipient { get; set; } = "";
    [JsonPropertyName("identity")] public string Identity { get; set; } = "";
    [JsonPropertyName("restoreName")] public bool RestoreName { get; set; }
}