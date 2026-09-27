using System.Diagnostics;
using System.Security.Cryptography;
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

        // 统计文件放到用户专属目录，文件名用 CSPRNG 随机数生成，避免同机其他进程预判/预创建
        var statsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FileEncryptor", "GUI");
        Directory.CreateDirectory(statsDir);
        var statsRand = RandomNumberGenerator.GetBytes(16);
        _statsFile = Path.Combine(statsDir, $"fe_stats_{Convert.ToHexString(statsRand).ToLowerInvariant()}.json");

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
                // 启动失败时 Exited 不会触发，这里直接结束并释放进程对象
                EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
                try { _process?.Dispose(); } catch { }
            }
            finally
            {
                // 口令字节写入子进程后立即清零，缩短明文在托管堆的驻留窗口
                if (request.StdinData.Length > 0)
                    Array.Clear(request.StdinData, 0, request.StdinData.Length);
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
        var proc = _process;
        try
        {
            if (proc == null) return;
            int code = proc.ExitCode;
            // 以 FileShare.None 独占打开统计文件，消除 Exists 与读取之间的 TOCTOU 窗口
            try
            {
                using var fs = new FileStream(_statsFile, FileMode.Open, FileAccess.Read, FileShare.None);
                using var sr = new StreamReader(fs, Encoding.UTF8);
                var json = sr.ReadToEnd();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("total_bytes", out var tb)) TotalBytes = tb.GetInt64();
                if (root.TryGetProperty("files_done", out var fd)) FilesDone = fd.GetInt32();
                if (root.TryGetProperty("files_failed", out var ff)) FilesFail = ff.GetInt32();
                if (root.TryGetProperty("files_skipped", out var fs2)) FilesSkip = fs2.GetInt32();
            }
            catch (FileNotFoundException) { /* 无统计文件时忽略 */ }
            catch { /* 损坏的统计 JSON 忽略 */ }
            finally { try { File.Delete(_statsFile); } catch { } }
            EmitFinished(new CommandResult { ExitCode = code, WasCancelled = _cancelled });
        }
        catch (Exception ex)
        {
            EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
        }
        finally
        {
            // 正常退出与取消路径都会走到这里，统一释放进程句柄
            try { proc?.Dispose(); } catch { }
            _process = null;
        }
    }

    private void EmitFinished(CommandResult r)
    {
        if (_finishedEmitted) return;
        _finishedEmitted = true;
        Finished?.Invoke(r);
    }
}
