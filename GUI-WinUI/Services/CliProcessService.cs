using System.Diagnostics;
using System.Text;
using System.Text.Json;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

/// <summary>直接启动 CLI（系统控制台显示输出），结束时通过统计文件返回数据。</summary>
public class CliProcessService
{
    public event Action<CommandResult>? Finished;

    private Process? _process;
    private bool _cancelled;
    private bool _finishedEmitted;
    private string _statsFile = "";

    public bool IsRunning => _process is { HasExited: false };
    public long TotalBytes { get; private set; }
    public int FilesDone { get; private set; }
    public int FilesSkip { get; private set; }
    public int FilesFail { get; private set; }

    public void Execute(CommandRequest request)
    {
        _cancelled = false;
        _finishedEmitted = false;
        TotalBytes = 0;
        FilesDone = FilesSkip = FilesFail = 0;

        _statsFile = Path.Combine(Path.GetTempPath(), $"fe_stats_{Guid.NewGuid():N}.json");

        var psi = new ProcessStartInfo
        {
            FileName = request.ProgramPath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            CreateNoWindow = false,
        };
        foreach (var a in request.Arguments) psi.ArgumentList.Add(a);
        if (!string.IsNullOrEmpty(request.WorkingDirectory))
            psi.WorkingDirectory = request.WorkingDirectory;
        psi.Environment["FILEENCRYPTOR_STATS_FILE"] = _statsFile;

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _process.Exited += (_, _) => OnProcessExited();

        _ = Task.Run(() =>
        {
            try
            {
                _process.Start();
                if (request.StdinData.Length > 0)
                    _process.StandardInput.BaseStream.Write(request.StdinData);
                _process.StandardInput.Close();
            }
            catch (Exception ex)
            {
                EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
            }
        });
    }

    public void Cancel()
    {
        if (_process is { HasExited: false })
        {
            _cancelled = true;
            try { _process.Kill(entireProcessTree: true); } catch { }
        }
    }

    private void OnProcessExited()
    {
        try
        {
            if (_process == null) return;
            int code = _process.ExitCode;
            if (File.Exists(_statsFile))
            {
                try
                {
                    var json = File.ReadAllText(_statsFile);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("total_bytes", out var tb)) TotalBytes = tb.GetInt64();
                    if (root.TryGetProperty("files_done", out var fd)) FilesDone = fd.GetInt32();
                    if (root.TryGetProperty("files_failed", out var ff)) FilesFail = ff.GetInt32();
                    if (root.TryGetProperty("files_skipped", out var fs)) FilesSkip = fs.GetInt32();
                }
                catch { }
                finally { try { File.Delete(_statsFile); } catch { } }
            }
            EmitFinished(new CommandResult { ExitCode = code, WasCancelled = _cancelled });
        }
        catch (Exception ex)
        {
            EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
        }
    }

    private void EmitFinished(CommandResult r)
    {
        if (_finishedEmitted) return;
        _finishedEmitted = true;
        Finished?.Invoke(r);
    }
}