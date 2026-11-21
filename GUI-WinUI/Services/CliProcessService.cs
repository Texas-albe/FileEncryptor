using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using FileEncryptorGUI.Models;

namespace FileEncryptorGUI.Services;

// 启动 CLI 并回传输出
public class CliProcessService
{
    public event Action<CommandResult>? Finished;
    // 子进程逐行输出
    public event Action<string>? OutputLine;
    // raw 模式
    public event Action<byte[]>? RawStdout;
    // CLI 请求 y/n 确认
    public event Action<string>? ConfirmPrompt;

    // 聚合输出
    public static event Action<string>? GlobalOutput;
    // 批量进度帧（结构化，替换式显示）
    public static event Action<string[]?, bool>? GlobalFrame;

    // 日志聚合缓冲
    // 高频逐行调度会拖死 UI
    private static readonly object s_bufLock = new();
    private static readonly List<string> s_pending = new();
    private static Timer? s_flushTimer;

    private static void EnqueueOutput(string line)
    {
        bool first;
        lock (s_bufLock)
        {
            s_pending.Add(line);
            first = s_flushTimer == null;
            if (first) s_flushTimer = new Timer(FlushPending, null, 100, Timeout.Infinite);
        }
    }

    private static void FlushPending(object? state)
    {
        string? batch;
        lock (s_bufLock)
        {
            s_flushTimer?.Dispose();
            s_flushTimer = null;
            batch = s_pending.Count == 0 ? null : string.Join("\n", s_pending) + "\n";
            s_pending.Clear();
        }
        if (batch != null) GlobalOutput?.Invoke(batch);
    }

    // 解析 stderr 的 progress_frame JSON 行
    private static bool TryParseFrame(string data, out string[]? lines, out bool final)
    {
        lines = null; final = false;
        if (!data.StartsWith("{\"type\":\"progress_frame\"", StringComparison.Ordinal)) return false;
        try
        {
            using var doc = JsonDocument.Parse(data);
            var root = doc.RootElement;
            final = root.TryGetProperty("final", out var f) && f.ValueKind == JsonValueKind.True;
            if (root.TryGetProperty("lines", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                var list = new List<string>();
                foreach (var it in arr.EnumerateArray())
                    list.Add(it.GetString() ?? "");
                lines = list.ToArray();
                return true;
            }
        }
        catch { }
        return false;
    }

    // 有 CLI
    // 用计数
    public static event Action? RunStarted;
    public static event Action? RunEnded;
    private static int s_activeRuns;
    private bool _countedRun;   // 本次执行是否已

    private static void NotifyRunStarted()
    {
        if (Interlocked.Increment(ref s_activeRuns) == 1) RunStarted?.Invoke();
    }

    private static void NotifyRunEnded()
    {
        int n = Interlocked.Decrement(ref s_activeRuns);
        if (n > 0) return;
        Interlocked.Exchange(ref s_activeRuns, 0);   // 异常路径下别
        RunEnded?.Invoke();
    }

    private Process? _process;
    private bool _cancelled;
    private bool _finishedEmitted;
    private string _statsFile = "";
    // stderr 累积文本
    private readonly StringBuilder _stderr = new();
    private bool _raw;
    // FEPRG 块状态机
    // 兼容未开 EVENTS 的 CLI
    private bool _inFrameBlock;
    private readonly List<string> _frameLines = new();

    // 握手确认
    // 走文件
    private string _confirmFile = "";
    private volatile bool _confirmPending;
    private volatile bool _confirmAnswered;
    private CancellationTokenSource? _confirmCts;

    public bool IsRunning => _process is { HasExited: false };
    public long TotalBytes { get; private set; }
    public int FilesDone { get; private set; }
    public int FilesSkip { get; private set; }
    public int FilesFail { get; private set; }

    // 预览解密要用
    public void SetRawMode(bool on) => _raw = on;

    // 握手文件轮询
    // 三态严格串行
    // 缺了这层串行
    private void StartConfirmWatch(string file)
    {
        StopConfirmWatch();
        _confirmFile = file;
        if (string.IsNullOrEmpty(file)) return;
        _confirmPending = false;
        _confirmAnswered = false;
        // 上一轮
        try { if (File.Exists(file)) File.Delete(file); } catch { }

        var cts = new CancellationTokenSource();
        _confirmCts = cts;
        var token = cts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    string content = "";
                    if (File.Exists(file))
                        content = File.ReadAllText(file, Encoding.UTF8).Trim();
                    if (content.Length == 0)
                    {
                        // CLI 取走答案
                        _confirmPending = false;
                        _confirmAnswered = false;
                    }
                    else if (!_confirmPending)
                    {
                        _confirmPending = true;
                        ConfirmPrompt?.Invoke(content);
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch { }
                try { await Task.Delay(120, token); } catch { break; }
            }
        }, token);
    }

    // 回答 CLI
    public void AnswerConfirm(bool yes)
    {
        if (!_confirmPending || _confirmAnswered || string.IsNullOrEmpty(_confirmFile)) return;
        try
        {
            if (File.Exists(_confirmFile)) File.Delete(_confirmFile);
            File.WriteAllText(_confirmFile, yes ? "y\n" : "n\n", new UTF8Encoding(false));
            _confirmAnswered = true;   // 等 CLI 清空文件后才
        }
        catch (IOException)
        {
            _confirmPending = false;
        }
    }

    private void StopConfirmWatch()
    {
        var cts = _confirmCts;
        _confirmCts = null;
        if (cts != null) { try { cts.Cancel(); } catch { } cts.Dispose(); }
        if (!string.IsNullOrEmpty(_confirmFile))
        {
            try { if (File.Exists(_confirmFile)) File.Delete(_confirmFile); } catch { }
            _confirmFile = "";
        }
        _confirmPending = false;
        _confirmAnswered = false;
    }

    public void Execute(CommandRequest request)
    {
        _cancelled = false;
        _finishedEmitted = false;
        // 预览解密是 raw 模式
        _countedRun = !_raw;
        if (_countedRun) NotifyRunStarted();
        TotalBytes = 0;
        FilesDone = FilesSkip = FilesFail = 0;
        lock (_stderr) { _stderr.Clear(); }

        // 统计文件随机命
        var statsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FileEncryptor", "GUI");
        Directory.CreateDirectory(statsDir);
        var statsRand = RandomNumberGenerator.GetBytes(16);
        _statsFile = Path.Combine(statsDir, $"fe_stats_{Convert.ToHexString(statsRand).ToLowerInvariant()}.json");

        StartConfirmWatch(request.ConfirmFile);

        // 控制台模式
        // 用 ArgumentList 传参
        // 经 cmd.exe /c
        if (request.ShowConsole && OperatingSystem.IsWindows())
            StartConsole(request);
        else
            StartRedirected(request);
    }

    // 系统控制台模式
    // 密码仍走 stdin 管道
    private void StartConsole(CommandRequest request)
    {
        var psi = new ProcessStartInfo
        {
            FileName = request.ProgramPath,
            UseShellExecute = false,
            // 窗口可见
            CreateNoWindow = false,
            // 密码走 stdin 管道
            RedirectStandardInput = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        foreach (var a in request.Arguments) psi.ArgumentList.Add(a);
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
                    // 密码字节写入
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

    // 结束后保留 3 秒
    private void CleanupConsoleCmd() { }

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
            // 不弹出控制台窗
            CreateNoWindow = true,
            // CLI 输出固定 UTF-8
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        foreach (var a in request.Arguments) psi.ArgumentList.Add(a);
        if (!string.IsNullOrEmpty(request.WorkingDirectory))
            psi.WorkingDirectory = request.WorkingDirectory;
        psi.Environment["FILEENCRYPTOR_STATS_FILE"] = _statsFile;
        foreach (var kv in request.ExtraEnv) psi.Environment[kv.Key] = kv.Value;

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        // 异步逐行读取输
        if (!_raw)
        {
            _process.OutputDataReceived += (_, e) =>
            {
                if (e.Data == null) return;
                // FEPRG 定界块转帧事件
                // ESC 开头的定界行
                if (e.Data.Contains("\x1b[FEPRG+") || e.Data.Contains("\x1b[FEPRG-"))
                {
                    if (e.Data.Contains("\x1b[FEPRG+"))
                    {
                        lock (_frameLines) { _frameLines.Clear(); _inFrameBlock = true; }
                    }
                    else
                    {
                        string[]? rows;
                        lock (_frameLines)
                        {
                            rows = _frameLines.ToArray();
                            _frameLines.Clear();
                            _inFrameBlock = false;
                        }
                        GlobalFrame?.Invoke(rows, false);
                    }
                    return;
                }
                bool collecting;
                lock (_frameLines) collecting = _inFrameBlock;
                if (collecting)
                {
                    lock (_frameLines) _frameLines.Add(e.Data);
                    return;
                }
                OutputLine?.Invoke(e.Data);
                EnqueueOutput(e.Data);
            };
        }
        _process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) return;
            // 批量帧 JSON 单独分流
            if (TryParseFrame(e.Data, out var lines, out var final))
            {
                GlobalFrame?.Invoke(lines, final);
                return;
            }
            lock (_stderr) { _stderr.AppendLine(e.Data); }
            OutputLine?.Invoke(e.Data);
            EnqueueOutput(e.Data);
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
                // 启动失败直接结
                EmitFinished(new CommandResult { ExitCode = -1, ErrorString = ex.Message });
                try { _process?.Dispose(); } catch { }
            }
            finally
            {
                // 密码字节写入
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

    // 预览解密
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
            // 进程
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
            // 临时批处理用完
            CleanupConsoleCmd();
            // 独占打开统计文
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
            // 统一释放进程句
            try { proc?.Dispose(); } catch { }
            _process = null;
        }
    }

    private void EmitFinished(CommandResult r)
    {
        if (_finishedEmitted) return;
        _finishedEmitted = true;
        StopConfirmWatch();
        if (_countedRun) { _countedRun = false; NotifyRunEnded(); }
        Finished?.Invoke(r);
    }
}
