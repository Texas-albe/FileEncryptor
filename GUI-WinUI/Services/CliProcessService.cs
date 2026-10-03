using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

// 直接启动 CLI 并回传输出
public class CliProcessService
{
    public event Action<CommandResult>? Finished;
    // 子进程逐行输出事件
    public event Action<string>? OutputLine;
    // raw 模式：stdout 原始字节（不经行解析），供预览解密显示二进制明文前缀
    public event Action<byte[]>? RawStdout;

    private Process? _process;
    private bool _cancelled;
    private bool _finishedEmitted;
    private string _statsFile = "";
    // stderr 累积文本
    private readonly StringBuilder _stderr = new();
    private bool _raw;

    public bool IsRunning => _process is { HasExited: false };
    public long TotalBytes { get; private set; }
    public int FilesDone { get; private set; }
    public int FilesSkip { get; private set; }
    public int FilesFail { get; private set; }

    // 预览解密要用：stdout 是二进制明文，不能按行切
    public void SetRawMode(bool on) => _raw = on;

    public void Execute(CommandRequest request)
    {
        _cancelled = false;
        _finishedEmitted = false;
        TotalBytes = 0;
        FilesDone = FilesSkip = FilesFail = 0;
        lock (_stderr) { _stderr.Clear(); }

        // 统计文件随机命名入用户目录
        var statsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FileEncryptor", "GUI");
        Directory.CreateDirectory(statsDir);
        var statsRand = RandomNumberGenerator.GetBytes(16);
        _statsFile = Path.Combine(statsDir, $"fe_stats_{Convert.ToHexString(statsRand).ToLowerInvariant()}.json");

        if (request.ShowConsole && OperatingSystem.IsWindows())
            StartConsole(request);
        else
            StartRedirected(request);
    }

    // 系统控制台模式：进度与口令交互都交给 cmd 窗口
    private void StartConsole(CommandRequest request)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = BuildConsoleCommand(request),
            UseShellExecute = false,
            // 窗口可见：进度与结果都在控制台里
            CreateNoWindow = false,
            // 口令与 Qt 一样走 stdin 管道，控制台只负责显示
            RedirectStandardInput = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        if (!string.IsNullOrEmpty(request.WorkingDirectory))
            psi.WorkingDirectory = request.WorkingDirectory;
        psi.Environment["FILEENCRYPTOR_STATS_FILE"] = _statsFile;
        foreach (var kv in request.ExtraEnv) psi.Environment[kv.Key] = kv.Value;

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _process.Exited += (_, _) => OnProcessExited();
        _ = Task.Run(() =>
        {
            try
            {
                _process.Start();
                if (request.StdinData.Length > 0)
                {
                    _process.StandardInput.BaseStream.Write(request.StdinData);
                    _process.StandardInput.Flush();
                    // 口令字节写入后立即清零
                    Array.Clear(request.StdinData, 0, request.StdinData.Length);
                }
                _process.StandardInput.Close();
            }
            catch (Exception ex)
            {
                EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
                try { _process?.Dispose(); } catch { }
            }
        });
    }

    // 结束后保留 3 秒再关窗；延迟展开取 CLI 真实退出码
    // 不用 psi.ArgumentList：走 cmd.exe 才有可见控制台窗口，而 cmd 只能吃字符串命令行。
    // 参数写进临时 .cmd 批处理（每行一条，DisableDelayedExpansion），
    // 避免字符串拼接把含 & | < > ^ % ! 的路径改坏 —— 引号只对空格类生效是常见错法。
    private string BuildConsoleCommand(CommandRequest request)
    {
        var cmdPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FileEncryptor", "GUI",
            $"fe_run_{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}.cmd");
        var sb = new StringBuilder();
        sb.AppendLine("@echo off");
        // 关闭延迟展开：路径里的 ! 才不会被吃掉；同时 %errorlevel% 逐行解析仍能拿到真实退出码
        sb.AppendLine("setlocal EnableExtensions DisableDelayedExpansion");
        sb.Append(QuoteCmd(request.ProgramPath));
        foreach (var a in request.Arguments)
        {
            sb.Append(' ');
            sb.Append(QuoteCmd(a));
        }
        sb.AppendLine();
        sb.AppendLine("exit /b %errorlevel%");
        File.WriteAllText(cmdPath, sb.ToString(), new UTF8Encoding(false));
        _consoleCmdFile = cmdPath;
        // /c ""<脚本路径>"" ：路径含空格时外层还要再包一层引号
        return "/c \"\"" + cmdPath + "\"\"";
    }

    // 临时批处理文件用完即删
    private string? _consoleCmdFile;

    private void CleanupConsoleCmd()
    {
        var p = _consoleCmdFile;
        if (p == null) return;
        _consoleCmdFile = null;
        try { File.Delete(p); } catch { }
    }

    // cmd 参数转义：% 必须写成 %%，其余特殊字符靠双引号隔离
    private static string QuoteCmd(string arg)
    {
        var s = arg.Replace("%", "%%");
        // Windows 文件名不允许含 "，但命令行参数可能出现：内层成对写出交给 CommandLineToArgvW 处理
        s = s.Replace("\"", "\"\"");
        return "\"" + s + "\"";
    }

    private void StartRedirected(CommandRequest request)
    {
        var psi = new ProcessStartInfo
        {
            FileName = request.ProgramPath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            // 必须重定向 stdout/stderr
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // 不弹出控制台窗口
            CreateNoWindow = true,
        };
        foreach (var a in request.Arguments) psi.ArgumentList.Add(a);
        if (!string.IsNullOrEmpty(request.WorkingDirectory))
            psi.WorkingDirectory = request.WorkingDirectory;
        psi.Environment["FILEENCRYPTOR_STATS_FILE"] = _statsFile;
        foreach (var kv in request.ExtraEnv) psi.Environment[kv.Key] = kv.Value;

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        // 异步逐行读取输出；raw 模式改由 ReadRawStdout 直读字节流
        if (!_raw)
        {
            _process.OutputDataReceived += (_, e) =>
            {
                if (e.Data == null) return;
                OutputLine?.Invoke(e.Data);
            };
        }
        _process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) return;
            lock (_stderr) { _stderr.AppendLine(e.Data); }
            OutputLine?.Invoke(e.Data);
        };
        _process.Exited += (_, _) => OnProcessExited();

        _ = Task.Run(() =>
        {
            try
            {
                _process.Start();
                if (_raw) _ = Task.Run(() => ReadRawStdout(_process!));
                else _process.BeginOutputReadLine();
                _process.BeginErrorReadLine();
                if (request.StdinData.Length > 0)
                    _process.StandardInput.BaseStream.Write(request.StdinData);
                _process.StandardInput.Close();
            }
            catch (Exception ex)
            {
                // 启动失败直接结束
                EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
                try { _process?.Dispose(); } catch { }
            }
            finally
            {
                // 口令字节写入后立即清零
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

    // 预览解密：stdout 是二进制明文前缀，按字节读，不做行切分与字符解码
    private async Task ReadRawStdout(Process proc)
    {
        try
        {
            var stream = proc.StandardOutput.BaseStream;
            var buf = new byte[8192];
            while (true)
            {
                int n = await stream.ReadAsync(buf.AsMemory(0, buf.Length)).ConfigureAwait(false);
                if (n <= 0) break;
                var chunk = new byte[n];
                Array.Copy(buf, chunk, n);
                RawStdout?.Invoke(chunk);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // 进程被 kill 或管道关闭：属正常收尾
        }
    }

    private void OnProcessExited()
    {
        var proc = _process;
        try
        {
            if (proc == null) return;
            proc.WaitForExit();
            int code = proc.ExitCode;
            // 临时批处理用完即删
            CleanupConsoleCmd();
            // 独占打开统计文件
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
            catch (FileNotFoundException) {  }
            catch {  }
            finally { try { File.Delete(_statsFile); } catch { } }

            string stderr;
            lock (_stderr) { stderr = _stderr.ToString().Trim(); }
            EmitFinished(new CommandResult
            {
                ExitCode = code,
                WasCancelled = _cancelled,
                // 失败时带回 stderr
                ErrorString = code == 0 ? "" : stderr,
            });
        }
        catch (Exception ex)
        {
            EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
        }
        finally
        {
            // 统一释放进程句柄
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
