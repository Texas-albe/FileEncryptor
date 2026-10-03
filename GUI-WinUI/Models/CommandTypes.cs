namespace FileEncryptorGUI.Models;

public class OutputLine
{
    public string Text { get; set; } = "";
    public bool IsError { get; set; }
    public bool IsProgress { get; set; }
    public bool IsFrame { get; set; }
}

public class CommandRequest
{
    public string ProgramPath { get; set; } = "";
    public List<string> Arguments { get; set; } = new();
    public string WorkingDirectory { get; set; } = "";
    public byte[] StdinData { get; set; } = Array.Empty<byte>();
    public Dictionary<string, string> ExtraEnv { get; set; } = new();
    // 用系统控制台窗口运行：进度直接显示在控制台
    public bool ShowConsole { get; set; }
    // CLI 询问 y/n 确认时的握手文件路径（空 = 不启用）
    public string ConfirmFile { get; set; } = "";
}

public class CommandResult
{
    public int ExitCode { get; set; } = -1;
    public bool WasCancelled { get; set; }
    public string ErrorString { get; set; } = "";
}
