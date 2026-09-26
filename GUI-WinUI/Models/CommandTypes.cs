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
}

public class CommandResult
{
    public int ExitCode { get; set; } = -1;
    public bool WasCancelled { get; set; }
    public string ErrorString { get; set; } = "";
}
