using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Input;
using FileEncryptorGUI.Models;
using FileEncryptorGUI.Services;
using Microsoft.UI.Dispatching;

namespace FileEncryptorGUI.ViewModels;

public class TaskSummaryInfo
{
    public string Duration = "";
    public string AvgSpeed = "";
    public string EncryptedSize = "";
    public int Done, Skip, Fail;
    public string Title = "";
}

public class MainViewModel : ObservableObject
{
    private readonly CliProcessService _cli = new();
    private readonly DispatcherQueue _dispatcher;
    private string? _cliPath;
    private bool _zstdAvailable = true;
    private bool _aegisAvailable = true;
    private readonly Stopwatch _runTimer = new();
    private int _doneFiles, _skipFiles, _failFiles, _totalFiles;
    private string _currentFile = "";
    private readonly StringBuilder _outputBuffer = new();

    public MainViewModel()
    {
        _dispatcher = DispatcherQueue.GetForCurrentThread();
        _cli.Finished += OnFinished;
    }

    // ===== 输入 =====
    public ObservableCollection<SelectablePath> InputPaths { get; } = new();

    // ===== 选项 =====
    private int _actionIndex;
    public int ActionIndex { get => _actionIndex; set { SetProperty(ref _actionIndex, value); OnPropertyChanged(nameof(IsAsymmetric)); OnPropertyChanged(nameof(IsEncryptMode)); OnPropertyChanged(nameof(IsKeyGenMode)); RefreshCommandPreview(); } }

    private int _modeIndex;
    public int ModeIndex { get => _modeIndex; set { SetProperty(ref _modeIndex, value); OnPropertyChanged(nameof(IsAsymmetric)); RefreshCommandPreview(); } }

    public bool IsAsymmetric => ModeIndex == 2;
    public bool IsEncryptMode => ActionIndex is 0 or 2;
    public bool IsKeyGenMode => ActionIndex is 4 or 5 or 6;

    private int _sourceIndex;
    public int SourceIndex { get => _sourceIndex; set { SetProperty(ref _sourceIndex, value); RefreshCommandPreview(); } }

    private bool _force = true;
    public bool Force { get => _force; set { SetProperty(ref _force, value); RefreshCommandPreview(); } }

    private bool _sha256;
    public bool Sha256 { get => _sha256; set { SetProperty(ref _sha256, value); RefreshCommandPreview(); } }

    private bool _compress;
    public bool Compress { get => _compress; set { SetProperty(ref _compress, value); RefreshCommandPreview(); } }

    private int _compressLevel = 1;
    public int CompressLevel { get => _compressLevel; set { SetProperty(ref _compressLevel, value); RefreshCommandPreview(); } }

    private string _outputDir = "";
    public string OutputDir { get => _outputDir; set { SetProperty(ref _outputDir, value); RefreshCommandPreview(); } }

    private string _keyfile = "";
    public string Keyfile { get => _keyfile; set { SetProperty(ref _keyfile, value); RefreshCommandPreview(); } }

    private string _recipient = "";
    public string Recipient { get => _recipient; set { SetProperty(ref _recipient, value); RefreshCommandPreview(); } }

    private string _identity = "";
    public string Identity { get => _identity; set { SetProperty(ref _identity, value); RefreshCommandPreview(); } }

    private bool _restoreName;
    public bool RestoreName { get => _restoreName; set { SetProperty(ref _restoreName, value); RefreshCommandPreview(); } }

    // ===== 输出 =====
    private string _outputText = "";
    public string OutputText { get => _outputText; set => SetProperty(ref _outputText, value); }

    private string _statusText = "就绪";
    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }

    private string _progressLabel = "";
    public string ProgressLabel { get => _progressLabel; set => SetProperty(ref _progressLabel, value); }

    private string _commandPreview = "";
    public string CommandPreview { get => _commandPreview; set => SetProperty(ref _commandPreview, value); }

    private bool _isRunning;
    public bool IsRunning { get => _isRunning; set => SetProperty(ref _isRunning, value); }

    public bool ZstdAvailable { get => _zstdAvailable; set => SetProperty(ref _zstdAvailable, value); }
    public bool AegisAvailable { get => _aegisAvailable; set => SetProperty(ref _aegisAvailable, value); }

    public string? CliPath => _cliPath;

    // ===== 命令 =====
    public ICommand RunCommand => new RelayCommand(_ => Run(), _ => !IsRunning && InputPaths.Any(p => p.IsSelected) || IsKeyGenMode);
    public ICommand CancelCommand => new RelayCommand(_ => Cancel(), _ => IsRunning);

    // ===== CLI 探测 =====
    public bool DetectCli(out string? path)
    {
        path = FileEncryptorLocator.Locate();
        _cliPath = path;
        if (path != null)
        {
            ProbeFeatures(path);
            return true;
        }
        return false;
    }

    private void ProbeFeatures(string cliPath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = "--features",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            _zstdAvailable = output.Contains("zstd=1");
            _aegisAvailable = output.Contains("aegis=1");
            OnPropertyChanged(nameof(ZstdAvailable));
            OnPropertyChanged(nameof(AegisAvailable));
        }
        catch { /* 探测失败用默认值 */ }
    }

    // ===== 运行 =====
    public void RunWithPassword(string password)
    {
        if (_cliPath == null) return;
        var opts = CollectOptions();
        var args = CliArgBuilder.BuildArguments(opts);
        // 设置工作目录：优先第一个输入文件所在目录，其次输出目录，最后用户目录
        string? workDir = null;
        if (opts.InputPaths.Count > 0)
        {
            var first = opts.InputPaths[0];
            if (File.Exists(first)) workDir = Path.GetDirectoryName(first);
            else if (Directory.Exists(first)) workDir = first;
        }
        if (string.IsNullOrEmpty(workDir) && !string.IsNullOrEmpty(opts.OutputDir) && Directory.Exists(opts.OutputDir))
            workDir = opts.OutputDir;
        if (string.IsNullOrEmpty(workDir))
            workDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var req = new CommandRequest
        {
            ProgramPath = _cliPath,
            Arguments = args,
            StdinData = Encoding.UTF8.GetBytes(password + "\n"),
            WorkingDirectory = workDir
        };

        _doneFiles = _skipFiles = _failFiles = 0;
        _totalFiles = InputPaths.Count(p => p.IsSelected);
        _runTimer.Restart();
        IsRunning = true;
        StatusText = "运行中...";
        _outputBuffer.Clear();
        OutputText = "";

        // 计算总大小（含目录递归）
        long totalBytes = 0;
        foreach (var p in opts.InputPaths)
        {
            try
            {
                if (File.Exists(p)) totalBytes += new FileInfo(p).Length;
                else if (Directory.Exists(p))
                    totalBytes += Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories)
                        .Sum(f => new FileInfo(f).Length);
            }
            catch { }
        }

        // 记录任务（完整参数快照）
        _currentTask = new TaskRecord
        {
            Id = TaskHistoryService.NewId(),
            StartedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            Action = ActionKey(opts.Action),
            ActionLabel = ActionLabel(opts.Action),
            Mode = ModeKey(opts.Mode),
            InputCount = opts.InputPaths.Count,
            InputPaths = new List<string>(opts.InputPaths),
            TotalBytes = totalBytes,
            OutputDir = opts.OutputDir,
            SourceIndex = SourceIndex,
            Force = Force,
            Sha256 = Sha256,
            Compress = Compress,
            CompressionLevel = Compress ? CompressLevel : 0,
            Keyfile = Keyfile ?? "",
            Recipient = Recipient ?? "",
            Identity = Identity ?? "",
            RestoreName = RestoreName,
        };

        _cli.Execute(req);
    }

    private TaskRecord? _currentTask;

    public void Run()
    {
        // 密码由 View 层弹窗获取后调用 RunWithPassword
        PasswordRequested?.Invoke();
    }

    public event Action? PasswordRequested;
    public event Action<string>? TaskCompleted;
    public event Action<TaskSummaryInfo>? TaskSummary;

    public void Cancel()
    {
        _cli.Cancel();
    }

    private void OnOutputLine(string text)
    {
        _dispatcher.TryEnqueue(() =>
        {
            _outputBuffer.Append(text);
            // 限制最大行数，避免内存膨胀
            if (_outputBuffer.Length > 50000)
                _outputBuffer.Remove(0, _outputBuffer.Length - 50000);
            OutputText = _outputBuffer.ToString();
        });
    }
    private void OnFinished(CommandResult result)
    {
        _dispatcher.TryEnqueue(() =>
        {
            _runTimer.Stop();
            IsRunning = false;
            StatusText = result.WasCancelled ? "已取消" : (result.ExitCode == 0 ? "完成" : $"失败 (exit {result.ExitCode})");

            if (_currentTask != null)
            {
                _currentTask.FinishedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                _currentTask.DurationMs = _runTimer.ElapsedMilliseconds;
                _currentTask.ExitCode = result.ExitCode;
                _currentTask.Cancelled = result.WasCancelled;
                _currentTask.Status = result.WasCancelled ? "cancelled" : (result.ExitCode == 0 ? "success" : "failed");
                _currentTask.FilesDone = _cli.FilesDone;
                _currentTask.TotalBytes = _cli.TotalBytes > 0 ? _cli.TotalBytes : _currentTask.TotalBytes;
                TaskHistoryService.Append(_currentTask, out _);
            }

            // 构建汇总
            var summary = new TaskSummaryInfo
            {
                Title = result.WasCancelled ? "任务已取消" : (result.ExitCode == 0 ? "任务完成" : $"任务结束 (exit {result.ExitCode})"),
                Duration = EtaEstimatorService.FormatDuration(_runTimer.ElapsedMilliseconds),
                Done = _cli.FilesDone,
                Skip = _cli.FilesSkip,
                Fail = _cli.FilesFail,
            };
            // 平均速度
            long totalBytes = _cli.TotalBytes > 0 ? _cli.TotalBytes : (_currentTask?.TotalBytes ?? 0);
            if (totalBytes > 0 && _runTimer.ElapsedMilliseconds > 0)
            {
                double bps = totalBytes * 1000.0 / _runTimer.ElapsedMilliseconds;
                summary.AvgSpeed = EtaEstimatorService.FormatRate(bps);
            }
            else summary.AvgSpeed = "-";
            // 加密后大小：扫描输出目录 .ptd 文件
            try
            {
                if (!string.IsNullOrEmpty(OutputDir) && Directory.Exists(OutputDir))
                {
                    long encBytes = Directory.EnumerateFiles(OutputDir, "*.ptd", SearchOption.AllDirectories)
                        .Sum(f => new FileInfo(f).Length);
                    summary.EncryptedSize = EtaEstimatorService.FormatBytes(encBytes);
                }
                else summary.EncryptedSize = "-";
            }
            catch { summary.EncryptedSize = "-"; }

            TaskCompleted?.Invoke(StatusText);
            TaskSummary?.Invoke(summary);
            // 完成后恢复命令预览
            RefreshCommandPreview();
        });
    }

    private void ParseProgress(string line)
    {
        // 解析 "Done: N, Skip: N, Fail: N" 等
        if (line.Contains("skipped"))
        {
            var m = System.Text.RegularExpressions.Regex.Match(line, @"skipped\s+(\d+)");
            if (m.Success) _skipFiles = int.Parse(m.Groups[1].Value);
        }
        UpdateProgressLabel();
    }

    private void UpdateProgressLabel()
    {
        ProgressLabel = $"当前: {_currentFile} | 完成 {_doneFiles} | 跳过 {_skipFiles} | 失败 {_failFiles} / 共 {_totalFiles}";
    }

    public ShellOptions CollectOptions()
    {
        var action = ActionIndex switch
        {
            0 => CryptoAction.Encrypt,
            1 => CryptoAction.Decrypt,
            2 => CryptoAction.BatchEncrypt,
            3 => CryptoAction.BatchDecrypt,
            4 => CryptoAction.KeyGen,
            5 => CryptoAction.Derive,
            6 => CryptoAction.PubKey,
            _ => CryptoAction.Encrypt
        };
        var mode = ModeIndex switch
        {
            0 => CryptoMode.XChaCha20,
            1 => CryptoMode.Aegis256,
            2 => CryptoMode.Asymmetric,
            _ => CryptoMode.XChaCha20
        };
        return new ShellOptions
        {
            Action = action,
            Mode = mode,
            InputPaths = new List<string>(InputPaths.Where(p => p.IsSelected).Select(p => p.Path)),
            OutputDir = OutputDir,
            SourceDisposition = (SourceDisposition)SourceIndex,
            ForceOverwrite = Force,
            KeyfilePath = Keyfile,
            RecipientPath = Recipient,
            IdentityPath = Identity,
            RestoreName = RestoreName,
            WriteSha256 = Sha256,
            Compress = Compress,
            CompressionLevel = Compress ? CompressLevel : 0,
        };
    }

    public void RefreshCommandPreview()
    {
        var opts = CollectOptions();
        var args = CliArgBuilder.BuildArguments(opts);
        var argStr = string.Join(" ", args.Select(a => a.StartsWith("-") ? a : "\"" + a.Replace("\"", "\\\"") + "\""));
        if (_cliPath == null)
        {
            // 未检测到 CLI：只显示已选参数
            CommandPreview = argStr;
        }
        else
        {
            // 检测到 CLI：显示完整可执行文件路径 + 参数
            CommandPreview = "\"" + _cliPath + "\"" + (string.IsNullOrEmpty(argStr) ? "" : " " + argStr);
        }
        OutputText = ">>> " + CommandPreview;
    }

    public void AddInputPaths(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            if (!InputPaths.Any(x => x.Path == path))
                InputPaths.Add(new SelectablePath { Path = path, IsSelected = true });
            // 单文件模式下加入目录，自动切换到批量模式
            if (Directory.Exists(path))
            {
                if (ActionIndex == 0) ActionIndex = 2;       // 加密 → 批量加密
                else if (ActionIndex == 1) ActionIndex = 3;  // 解密 → 批量解密
            }
        }
        RefreshCommandPreview();
    }

    public void ClearInputPaths()
    {
        InputPaths.Clear();
        RefreshCommandPreview();
    }

    private static string ActionKey(CryptoAction a) => a switch
    {
        CryptoAction.Encrypt => "encrypt",
        CryptoAction.Decrypt => "decrypt",
        CryptoAction.BatchEncrypt => "batch-encrypt",
        CryptoAction.BatchDecrypt => "batch-decrypt",
        CryptoAction.KeyGen => "keygen",
        CryptoAction.Derive => "derive",
        CryptoAction.PubKey => "pubkey",
        _ => "encrypt"
    };

    private static string ActionLabel(CryptoAction a) => a switch
    {
        CryptoAction.Encrypt => "加密",
        CryptoAction.Decrypt => "解密",
        CryptoAction.BatchEncrypt => "批量加密",
        CryptoAction.BatchDecrypt => "批量解密",
        CryptoAction.KeyGen => "生成密钥对",
        CryptoAction.Derive => "口令派生密钥对",
        CryptoAction.PubKey => "导出公钥",
        _ => "加密"
    };

    private static string ModeKey(CryptoMode m) => m switch
    {
        CryptoMode.XChaCha20 => "xchacha20",
        CryptoMode.Aegis256 => "aegis256",
        CryptoMode.Asymmetric => "asymmetric",
        _ => "xchacha20"
    };
}

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;
    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? p) => _canExecute?.Invoke(p) ?? true;
    public void Execute(object? p) => _execute(p);
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
