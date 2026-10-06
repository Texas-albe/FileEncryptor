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
    // AES-GCM 依赖 AES-NI：--features 缺 aesgcm=1 的旧 CLI 不认 -m aes-gcm
    private bool _aesGcmAvailable;
    // 后量子能力：缺 pqc= 字段的旧 CLI 视为不支持（fail-closed，同 Qt 侧 m_pqcAvailable）
    private bool _pqcAvailable;
    // 打包能力：默认乐观，仅当 --features 里没有 pack=1（旧 CLI 不认 -p）才置 false
    private bool _packAvailable = true;
    // 密钥包装能力：--features 缺 keywrap=1 的旧 CLI 不认 --wrap-key（fail-closed）
    private bool _keywrapAvailable;
    // 加密盘能力：--features 缺 vault=1 的旧 CLI 不认 --into-vault（fail-closed）
    private bool _vaultAvailable;
    private readonly Stopwatch _runTimer = new();
    private int _doneFiles, _skipFiles, _failFiles, _totalFiles;
    private string _currentFile = "";
    private ShellOptions? _runOptions;   // 本次运行的参数，任务结束用它删对应的临时私钥

    public MainViewModel()
    {
        _dispatcher = DispatcherQueue.GetForCurrentThread();
        _cli.Finished += OnFinished;
        // 进度计数来源（控制台模式下不触发）
        _cli.OutputLine += OnOutputLine;
        _cli.ConfirmPrompt += OnConfirmPrompt;
    }

    // ===== 输入 =====
    public ObservableCollection<SelectablePath> InputPaths { get; } = new();

    // ===== 选项 =====
    private int _actionIndex;
    public int ActionIndex
    {
        get => _actionIndex;
        set
        {
            SetProperty(ref _actionIndex, value);
            OnPropertyChanged(nameof(IsAsymmetric));
            OnPropertyChanged(nameof(IsEncryptMode));
            OnPropertyChanged(nameof(IsKeyGenMode));
            OnPropertyChanged(nameof(IsWrapMode));
            OnPropertyChanged(nameof(IsWrapKeyMode));
            OnPropertyChanged(nameof(IsUnwrapMode));
            OnPropertyChanged(nameof(PasswordNeedsConfirm));
            RefreshCommandPreview();
        }
    }

    // 模式索引与 ModeCombo 对齐：0=XChaCha20 1=AEGIS-256 2=AES-256-GCM 3=SM4-GCM 4=X25519 非对称
    private int _modeIndex;
    public int ModeIndex { get => _modeIndex; set { SetProperty(ref _modeIndex, value); OnPropertyChanged(nameof(IsAsymmetric)); RefreshCommandPreview(); } }

    // 非对称模式下文件载荷的对称算法（0=XChaCha20 1=AEGIS-256 2=AES-256-GCM 3=SM4-GCM）
    private int _fileCipherIndex;
    public int FileCipherIndex { get => _fileCipherIndex; set { SetProperty(ref _fileCipherIndex, value); RefreshCommandPreview(); } }

    public bool IsAsymmetric => ModeIndex == 4;
    public bool IsEncryptMode => ActionIndex is 0 or 2;
    public bool IsKeyGenMode => ActionIndex is 4 or 5 or 6;
    // 密钥包装：7=包装 8=解开
    public bool IsWrapMode => ActionIndex is 7 or 8;
    public bool IsWrapKeyMode => ActionIndex == 7;
    public bool IsUnwrapMode => ActionIndex == 8;
    // 公钥路线没有 KEK，不需要密码
    public bool WrapUsesPublicKey => WrapAlgIndex == 2;
    // 解密与解包只需输入一次密码（1=解密 / 3=批解密 / 8=解包）
    public bool PasswordNeedsConfirm => ActionIndex is not (1 or 3 or 8);

    // 包装算法：0=KWP 1=AES-KW 2=收件人公钥，与 WrapAlgCombo 索引对齐
    private int _wrapAlgIndex;
    public int WrapAlgIndex { get => _wrapAlgIndex; set { SetProperty(ref _wrapAlgIndex, value); OnPropertyChanged(nameof(WrapUsesPublicKey)); RefreshCommandPreview(); } }

    private string _wrapInput = "";
    public string WrapInput { get => _wrapInput; set { SetProperty(ref _wrapInput, value); RefreshCommandPreview(); } }

    private string _wrapOutput = "";
    public string WrapOutput { get => _wrapOutput; set { SetProperty(ref _wrapOutput, value); RefreshCommandPreview(); } }

    // 包装能力探测：--features 缺 keywrap=1 的旧 CLI 会把 --wrap-key 当未知参数
    public bool KeywrapAvailable
    {
        get => _keywrapAvailable;
        set
        {
            if (_keywrapAvailable == value) return;
            SetProperty(ref _keywrapAvailable, value);
            RefreshCommandPreview();
        }
    }

    private int _sourceIndex;
    public int SourceIndex { get => _sourceIndex; set { SetProperty(ref _sourceIndex, value); RefreshCommandPreview(); } }

    private bool _force = true;
    public bool Force { get => _force; set { SetProperty(ref _force, value); RefreshCommandPreview(); } }

    // 加密压缩包：目录树 / 多文件打成单个 .ptd（--pack）
    private bool _pack;
    public bool Pack { get => _pack; set { SetProperty(ref _pack, value); RefreshCommandPreview(); } }

    // 打包能力探测：--features 缺 pack=1 的旧 CLI 会把 -p 当未知参数，这里自动关掉勾选框
    public bool PackAvailable
    {
        get => _packAvailable;
        set
        {
            if (_packAvailable == value) return;
            SetProperty(ref _packAvailable, value);
            if (!value) Pack = false;   // 不支持就别让用户以为已启用
            RefreshCommandPreview();
        }
    }

    // 加密盘：勾选后产物入该目录并登记进加密索引（CLI --into-vault）
    private string _intoVault = "";
    public string IntoVault { get => _intoVault; set { SetProperty(ref _intoVault, value); RefreshCommandPreview(); } }

    // 加密盘能力探测：--features 缺 vault=1 的旧 CLI 不认 --into-vault
    public bool VaultAvailable
    {
        get => _vaultAvailable;
        set
        {
            if (_vaultAvailable == value) return;
            SetProperty(ref _vaultAvailable, value);
            if (!value) IntoVault = "";   // 不支持就清掉，免得残留路径又被下发
            RefreshCommandPreview();
        }
    }

    // 可写挂载能力：--features 缺 vault_rw=1 的旧 CLI / 不装 M6 时不出现「可写挂载」（fail-closed）
    private bool _vaultRwAvailable;
    public bool VaultRwAvailable
    {
        get => _vaultRwAvailable;
        set
        {
            if (_vaultRwAvailable == value) return;
            SetProperty(ref _vaultRwAvailable, value);
            RefreshCommandPreview();
        }
    }

    // 分卷输出：默认不勾选；勾选后由 CliArgBuilder 下发 --split <size>
    private bool _split;
    public bool Split { get => _split; set { SetProperty(ref _split, value); RefreshCommandPreview(); } }

    private double _splitSize = 100;
    public double SplitSize { get => _splitSize; set { SetProperty(ref _splitSize, value); RefreshCommandPreview(); } }

    private int _splitUnitIndex;
    public int SplitUnitIndex { get => _splitUnitIndex; set { SetProperty(ref _splitUnitIndex, value); RefreshCommandPreview(); } }

    // 目录 + 删除类源处置已由界面弹窗确认
    private bool _sourceDeleteOk;
    public bool SourceDeleteOk { get => _sourceDeleteOk; set => SetProperty(ref _sourceDeleteOk, value); }

    private bool _sha256;
    public bool Sha256 { get => _sha256; set { SetProperty(ref _sha256, value); RefreshCommandPreview(); } }

    private bool _compress;
    public bool Compress { get => _compress; set { SetProperty(ref _compress, value); RefreshCommandPreview(); } }

    private int _compressLevel = 1;
    public int CompressLevel { get => _compressLevel; set { SetProperty(ref _compressLevel, value); RefreshCommandPreview(); } }

    // 生成密钥对时的曲线选择（默认 X25519）
    private bool _useX448;
    public bool UseX448 { get => _useX448; set { SetProperty(ref _useX448, value); RefreshCommandPreview(); } }

    // 后量子：默认开启，取消勾选时 CliArgBuilder 才下发 --no-pqc
    private bool _pqc = true;
    public bool Pqc { get => _pqc; set { SetProperty(ref _pqc, value); RefreshCommandPreview(); } }

    public bool PqcAvailable
    {
        get => _pqcAvailable;
        set
        {
            if (_pqcAvailable == value) return;
            SetProperty(ref _pqcAvailable, value);
            // CLI 不支持时把勾选框一并关掉，避免用户以为后量子已启用
            if (!value) Pqc = false;
            RefreshCommandPreview();
        }
    }

    private bool _watermark;
    public bool Watermark { get => _watermark; set { SetProperty(ref _watermark, value); RefreshCommandPreview(); } }

    private string _watermarkKey = "";
    public string WatermarkKey { get => _watermarkKey; set { SetProperty(ref _watermarkKey, value); RefreshCommandPreview(); } }

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

    // ===== 状态 =====
    private string _statusText = L10n.T("就绪");
    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }

    // 记下键与参数，切换语言后可原样重翻译
    private string _statusKey = "就绪";
    private object?[] _statusArgs = Array.Empty<object?>();
    public void SetStatus(string key, params object?[] args)
    {
        _statusKey = key;
        _statusArgs = args;
        StatusText = L10n.F(key, args);
    }

    private string _progressLabel = "";
    public string ProgressLabel { get => _progressLabel; set => SetProperty(ref _progressLabel, value); }

    private string _commandPreview = "";
    public string CommandPreview { get => _commandPreview; set => SetProperty(ref _commandPreview, value); }

    private bool _isRunning;
    public bool IsRunning { get => _isRunning; set => SetProperty(ref _isRunning, value); }

    public bool ZstdAvailable { get => _zstdAvailable; set => SetProperty(ref _zstdAvailable, value); }
    public bool AegisAvailable { get => _aegisAvailable; set => SetProperty(ref _aegisAvailable, value); }
    public bool AesGcmAvailable { get => _aesGcmAvailable; set => SetProperty(ref _aesGcmAvailable, value); }

    public string? CliPath => _cliPath;

    // ===== 命令 =====
    public ICommand RunCommand => new RelayCommand(_ => Run(), _ => !IsRunning && (InputPaths.Any(p => p.IsSelected) || IsKeyGenMode || IsWrapMode));
    public ICommand CancelCommand => new RelayCommand(_ => Cancel(), _ => IsRunning);

    // ===== CLI 探测 =====
    public bool DetectCli(out string? path)
    {
        path = FileEncryptorLocator.Locate();
        _cliPath = path;
        if (path != null)
        {
            _ = ProbeFeaturesAsync(path);
            return true;
        }
        return false;
    }

    private async Task ProbeFeaturesAsync(string cliPath)
    {
        Process? p = null;
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
            p = Process.Start(psi);
            if (p == null) return;
            var output = await p.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            // 5s 超时放弃探测
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(5000));
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            _zstdAvailable = output.Contains("zstd=1");
            _aegisAvailable = output.Contains("aegis=1");
            _aesGcmAvailable = output.Contains("aesgcm=1");
            _pqcAvailable = output.Contains("pqc=1");
            _packAvailable = output.Contains("pack=1");
            _keywrapAvailable = output.Contains("keywrap=1");
            _vaultAvailable = output.Contains("vault=1");
            _vaultRwAvailable = output.Contains("vault_rw=1");
            _dispatcher.TryEnqueue(() =>
            {
                OnPropertyChanged(nameof(ZstdAvailable));
                OnPropertyChanged(nameof(AegisAvailable));
                OnPropertyChanged(nameof(AesGcmAvailable));
                OnPropertyChanged(nameof(PqcAvailable));
                OnPropertyChanged(nameof(PackAvailable));
                OnPropertyChanged(nameof(KeywrapAvailable));
                OnPropertyChanged(nameof(VaultAvailable));
                OnPropertyChanged(nameof(VaultRwAvailable));
                if (!_packAvailable) Pack = false;   // 旧 CLI 不支持打包，强制取消勾选
            });
        }
        catch (OperationCanceledException) { try { p?.Kill(); } catch { } }
        catch {  }
    }

    // ===== 运行 =====
    // 默认走系统控制台：进度与密码交互都在控制台完成
    public bool UseSystemConsole { get; set; } = true;

    public void RunWithPassword(string password)
    {
        // 与 Qt / 交互式一致：原样发送密码字节，不追加换行
        StartCli(Encoding.UTF8.GetBytes(password), UseSystemConsole);
    }

    private void StartCli(byte[] stdinData, bool console)
    {
        if (_cliPath == null) return;
        var opts = CollectOptions();
        _runOptions = opts;
        var args = CliArgBuilder.BuildArguments(opts);
        // --source-delete-ok 仅本次任务有效：弹窗确认一遍，下发就清掉，别保留到下次
        opts.SourceDeleteOk = false;
        SourceDeleteOk = false;
        string? workDir = null;
        // 包装动作的输入不走文件清单，取 WrapInput 推工作目录
        var firstInput = opts.Action is CryptoAction.WrapKey or CryptoAction.UnwrapKey
            ? opts.WrapInput : opts.InputPaths.FirstOrDefault();
        if (!string.IsNullOrEmpty(firstInput))
        {
            if (File.Exists(firstInput)) workDir = Path.GetDirectoryName(firstInput);
            else if (Directory.Exists(firstInput)) workDir = firstInput;
        }
        if (string.IsNullOrEmpty(workDir) && !string.IsNullOrEmpty(opts.OutputDir) && Directory.Exists(opts.OutputDir))
            workDir = opts.OutputDir;
        if (string.IsNullOrEmpty(workDir))
            workDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // 确认握手：CLI 把 y/n 询问写进这个文件，界面读到后弹窗，再把答案写回去
        var confirmDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FileEncryptor", "GUI");
        Directory.CreateDirectory(confirmDir);
        var confirmFile = Path.Combine(confirmDir,
            "fe_confirm_" + Guid.NewGuid().ToString("N") + ".txt");

        var req = new CommandRequest
        {
            ProgramPath = _cliPath,
            Arguments = args,
            StdinData = stdinData,
            WorkingDirectory = workDir,
            ShowConsole = console,
            ConfirmFile = confirmFile,
        };
        req.ExtraEnv["FILEENCRYPTOR_CONFIRM_FILE"] = confirmFile;
        // 批量（含入加密盘）开帧式进度：哨兵帧可被界面整帧解析后原地重绘
        if (opts.Action is CryptoAction.BatchEncrypt or CryptoAction.BatchDecrypt)
        {
            req.ExtraEnv["FILEENCRYPTOR_PROGRESS_FRAME"] = "1";
            req.ExtraEnv["COLUMNS"] = "100";
        }

        _doneFiles = _skipFiles = _failFiles = 0;
        _totalFiles = InputPaths.Count(p => p.IsSelected);
        _runTimer.Restart();
        IsRunning = true;
        SetStatus("运行中...");

        // 计算总大小
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

        // 记录任务快照
        _currentTask = new TaskRecord
        {
            Id = TaskHistoryService.NewId(),
            StartedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            Action = ActionKey(opts.Action),
            ActionLabel = ActionLabel(opts.Action),
            Mode = ModeKey(opts.Mode),
            FileCipher = opts.Mode == CryptoMode.Asymmetric ? ModeKey(opts.FileMode) : "",
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
            WrapInput = WrapInput ?? "",
            WrapOutput = WrapOutput ?? "",
            WrapAlg = opts.Action is CryptoAction.WrapKey or CryptoAction.UnwrapKey
                ? WrapAlgKey(opts.WrapAlg) : "",
            RestoreName = RestoreName,
            Pqc = Pqc,
            Watermark = Watermark,
            // 私钥明文不落盘任务历史，只留占位（恢复任务时提示重新输入）
            WatermarkKey = CliArgBuilder.IsPrivateKeyMaterial(WatermarkKey) ? "<protected>" : (WatermarkKey ?? ""),
            Pack = opts.Pack,
            IntoVault = opts.IntoVault ?? "",
        };

        _cli.Execute(req);
    }

    private TaskRecord? _currentTask;

    public void Run()
    {
        // 需要密码时先由 GUI 采集，再传给 CLI
        if (NeedsPassword()) PasswordRequested?.Invoke();
        else StartCli(Array.Empty<byte>(), UseSystemConsole);
    }

    // 对称模式且未指定密钥文件/身份时才需要密码
    private bool NeedsPassword()
    {
        // 公钥路线没有 KEK，密码与身份都不参与
        if (IsWrapMode) return !WrapUsesPublicKey && string.IsNullOrEmpty(Keyfile);
        if (IsAsymmetric) return false;
        if (!string.IsNullOrEmpty(Keyfile)) return false;
        return ActionIndex is 0 or 1 or 2 or 3 or 5;
    }

    public event Action? PasswordRequested;

    // CLI 请求确认：text 为完整问题（已含 y/N 提示）
    public event Action<string>? ConfirmPromptRequested;

    private void OnConfirmPrompt(string text)
        => _dispatcher.TryEnqueue(() => ConfirmPromptRequested?.Invoke(text));

    // 回答 CLI 的 y/n 询问
    public void AnswerConfirm(bool yes) => _cli.AnswerConfirm(yes);
    public event Action<string>? TaskCompleted;
    public event Action<TaskSummaryInfo>? TaskSummary;

    public void Cancel()
    {
        _cli.Cancel();
    }

    private void OnOutputLine(string text)
    {
        // 仅解析进度计数，输出本身显示在系统控制台
        _dispatcher.TryEnqueue(() => ParseProgress(text));
    }
    private void OnFinished(CommandResult result)
    {
        _dispatcher.TryEnqueue(() =>
        {
            _runTimer.Stop();
            IsRunning = false;
            if (result.WasCancelled) SetStatus("已取消");
            else if (result.ExitCode == 0) SetStatus("完成");
            else SetStatus("失败 (exit {0})", result.ExitCode);

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
            CliArgBuilder.CleanupWatermarkTemp(_runOptions!);

            // 构建汇总
            var summary = new TaskSummaryInfo
            {
                Title = result.WasCancelled
                    ? L10n.T("任务已取消")
                    : (result.ExitCode == 0 ? L10n.T("任务完成") : L10n.F("任务结束 (exit {0})", result.ExitCode)),
                Duration = EtaEstimatorService.FormatDuration(_runTimer.ElapsedMilliseconds),
                Done = _cli.FilesDone,
                Skip = _cli.FilesSkip,
                Fail = _cli.FilesFail,
            };
            long totalBytes = _cli.TotalBytes > 0 ? _cli.TotalBytes : (_currentTask?.TotalBytes ?? 0);
            if (totalBytes > 0 && _runTimer.ElapsedMilliseconds > 0)
            {
                double bps = totalBytes * 1000.0 / _runTimer.ElapsedMilliseconds;
                summary.AvgSpeed = EtaEstimatorService.FormatRate(bps);
            }
            else summary.AvgSpeed = "-";
            // 加密后大小后台统计
            summary.EncryptedSize = "-";

            TaskCompleted?.Invoke(StatusText);

            var outDir = OutputDir;
            _ = Task.Run(() =>
            {
                string sizeText = "-";
                try
                {
                    if (!string.IsNullOrEmpty(outDir) && Directory.Exists(outDir))
                    {
                        long encBytes = Directory.EnumerateFiles(outDir, "*.ptd", SearchOption.AllDirectories)
                            .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0; } });
                        sizeText = EtaEstimatorService.FormatBytes(encBytes);
                    }
                }
                catch { }
                _dispatcher.TryEnqueue(() =>
                {
                    summary.EncryptedSize = sizeText;
                    TaskSummary?.Invoke(summary);
                    RefreshCommandPreview();
                });
            });
        });
    }

    private void ParseProgress(string line)
    {
        // 解析 Done/Skip/Fail
        if (line.Contains("skipped"))
        {
            var m = System.Text.RegularExpressions.Regex.Match(line, @"skipped\s+(\d+)");
            if (m.Success && int.TryParse(m.Groups[1].Value, out var n)) _skipFiles = n;
        }
        UpdateProgressLabel();
    }

    private void UpdateProgressLabel()
    {
        ProgressLabel = L10n.F("当前: {0} | 完成 {1} | 跳过 {2} | 失败 {3} / 共 {4}",
            _currentFile, _doneFiles, _skipFiles, _failFiles, _totalFiles);
    }

    // 切换语言后刷新尚未重算的运行态文本
    public void RefreshRuntimeTexts()
    {
        StatusText = L10n.F(_statusKey, _statusArgs);
        if (_totalFiles > 0 || _currentFile.Length > 0) UpdateProgressLabel();
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
            7 => CryptoAction.WrapKey,
            8 => CryptoAction.UnwrapKey,
            _ => CryptoAction.Encrypt
        };
        var mode = ModeIndex switch
        {
            0 => CryptoMode.XChaCha20,
            1 => CryptoMode.Aegis256,
            2 => CryptoMode.AesGcm,
            3 => CryptoMode.Sm4,
            4 => CryptoMode.Asymmetric,
            _ => CryptoMode.XChaCha20
        };
        // 非对称模式下会话密钥由文件算法产生，非对称部分只负责包裹它
        var fileMode = FileCipherIndex switch
        {
            1 => CryptoMode.Aegis256,
            2 => CryptoMode.AesGcm,
            3 => CryptoMode.Sm4,
            _ => CryptoMode.XChaCha20
        };
        return new ShellOptions
        {
            Action = action,
            Mode = mode,
            FileMode = fileMode,
            InputPaths = new List<string>(InputPaths.Where(p => p.IsSelected).Select(p => p.Path)),
            OutputDir = OutputDir,
            // 加密盘：不支持或未勾选时为空，CLI 侧就看不出这是入盘任务
            IntoVault = VaultAvailable ? (IntoVault ?? "") : "",
            SourceDisposition = (SourceDisposition)SourceIndex,
            Pack = Pack,
            Split = Split,
            SplitSize = SplitSize,
            SplitUnit = (SplitUnit)SplitUnitIndex,
            SourceDeleteOk = SourceDeleteOk,
            ForceOverwrite = Force,
            KeyfilePath = Keyfile,
            RecipientPath = Recipient,
            IdentityPath = Identity,
            RestoreName = RestoreName,
            WriteSha256 = Sha256,
            Compress = Compress,
            CompressionLevel = Compress ? CompressLevel : 0,
            UseX448 = UseX448,
            ConsoleMode = UseSystemConsole,
            Pqc = Pqc,
            Watermark = Watermark,
            WatermarkKeyPath = WatermarkKey ?? "",
            WrapInput = WrapInput ?? "",
            WrapOutput = WrapOutput ?? "",
            WrapAlg = (WrapAlg)WrapAlgIndex,
        };
    }

    public void RefreshCommandPreview()
    {
        var opts = CollectOptions();
        var args = CliArgBuilder.BuildArguments(opts);
        // 预览只拼参数不真正跑 CLI，落盘的临时私钥立刻清掉
        if (opts.WatermarkTempKeyPath != null)
        {
            try { File.Delete(opts.WatermarkTempKeyPath); } catch { }
            opts.WatermarkTempKeyPath = null;
        }
        var argStr = string.Join(" ", args.Select(a =>
            CliArgBuilder.IsPrivateKeyMaterial(a) ? "<private-key>"
            : a.StartsWith("-") ? a
            : "\"" + a.Replace("\"", "\\\"") + "\""));
        if (_cliPath == null)
        {
            CommandPreview = argStr;
        }
        else
        {
            CommandPreview = "\"" + _cliPath + "\"" + (string.IsNullOrEmpty(argStr) ? "" : " " + argStr);
        }
        // 预览写入独立区域
    }

    public void AddInputPaths(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            if (!InputPaths.Any(x => x.Path == path))
                InputPaths.Add(new SelectablePath { Path = path, IsSelected = true });
            // 单文件加目录转批量
            if (Directory.Exists(path))
            {
                if (ActionIndex == 0) ActionIndex = 2;
                else if (ActionIndex == 1) ActionIndex = 3;
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
        CryptoAction.WrapKey => "wrap",
        CryptoAction.UnwrapKey => "unwrap",
        _ => "encrypt"
    };

    private static string ActionLabel(CryptoAction a) => a switch
    {
        CryptoAction.Encrypt => "加密",
        CryptoAction.Decrypt => "解密",
        CryptoAction.BatchEncrypt => "批量加密",
        CryptoAction.BatchDecrypt => "批量解密",
        CryptoAction.KeyGen => "生成密钥对",
        CryptoAction.Derive => "密码派生密钥对",
        CryptoAction.PubKey => "导出公钥",
        CryptoAction.WrapKey => "包装密钥",
        CryptoAction.UnwrapKey => "解开密钥",
        _ => "加密"
    };

    private static string ModeKey(CryptoMode m) => m switch
    {
        CryptoMode.XChaCha20 => "xchacha20",
        CryptoMode.Aegis256 => "aegis256",
        CryptoMode.AesGcm => "aes-gcm",
        CryptoMode.Sm4 => "sm4",
        CryptoMode.Asymmetric => "x25519",
        _ => "xchacha20"
    };

    private static string WrapAlgKey(WrapAlg a) => a switch
    {
        WrapAlg.AesKw => "aes-kw",
        WrapAlg.Pubkey => "pubkey",
        _ => "kwp"
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
