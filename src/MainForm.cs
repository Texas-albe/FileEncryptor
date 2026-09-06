using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace FileEncryptorGUI
{
    public class MainForm : Form
    {
        private enum OpMode { Encrypt, Decrypt, BatchEncrypt, BatchDecrypt }

        // Theme backdrop
        private Backdrop _backdrop;
        private Image _bgLight, _bgDark, _bg;
        private Bitmap _bgCache;

        // Glass container
        private GlassPanel _container;
        private GlassPanel _inputBox, _outputBox, _keyBox, _optionBox;

        // Inner controls
        private Label _title, _subtitle, _cliStatus, _lblModeLabel, _lblStatus, _lblVersion, _lblTheme, _lblPw, _lblConfirm, _lblTbIn, _lblTbOut, _lblAlgo;
        private RadioButton _rbEncrypt, _rbDecrypt, _rbBatchEncrypt, _rbBatchDecrypt;
        private TextBox _tbInput, _tbOutput, _tbPassword, _tbConfirm;
        private Button _btnBrowseInput, _btnBrowseOutput, _btnRun;
        private CheckBox _chkShowPw, _chkDelete, _chkForce, _chkVerbose;
        private ComboBox _cmbTheme, _cmbModeAlgo;
        private ModernProgressBar _progress;

        private string _cliPath;
        private Process _proc;
        private readonly List<string> _errBuf = new List<string>();
        private List<string> _cleanupRoots = new List<string>();

        private readonly Regex _progressRe = new Regex(@"(\d+)\s*B\s*/\s*(\d+)\s*B", RegexOptions.Compiled);

        private const int CW = 640, CH = 652, M = 26; // container width, height, inner margin

        public MainForm()
        {
            ThemeManager.Load();
            Text = "FileEncryptor — 安全文件加解密";
            Font = new Font("Segoe UI", 9f);
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1180, 780);
            MinimumSize = new Size(780, 700);
            DoubleBuffered = true;

            LoadBgImages();
            _backdrop = new Backdrop(Color.FromArgb(20, 22, 30));
            BuildUi();
            _cliPath = DetectCliPath();
            ApplyTheme();
            UpdateCliStatus();
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        }

        // ---------------------------------------------------------------
        //  Background images (qs = light, ss = dark)
        // ---------------------------------------------------------------
        private void LoadBgImages()
        {
            _bgLight = BgLoader.Light();
            _bgDark = BgLoader.Dark();
        }

        // ---------------------------------------------------------------
        //  Painting (cached cover background = fast on repaint/resize)
        // ---------------------------------------------------------------
        protected override void OnPaintBackground(PaintEventArgs e)
        {
            if (_backdrop == null) { base.OnPaintBackground(e); return; }
            BuildBgCache();
            if (_bgCache != null) e.Graphics.DrawImageUnscaled(_bgCache, 0, 0);
            else
            {
                _backdrop.Configure(_bg, ClientSize.Width, ClientSize.Height);
                _backdrop.DrawFull(e.Graphics, new Rectangle(0, 0, ClientSize.Width, ClientSize.Height));
            }
        }

        private void BuildBgCache()
        {
            int w = ClientSize.Width, h = ClientSize.Height;
            if (w < 1 || h < 1) return;
            if (_bgCache != null && _bgCache.Width == w && _bgCache.Height == h) return;
            _bgCache?.Dispose();
            _bgCache = new Bitmap(w, h, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(_bgCache))
            {
                g.InterpolationMode = InterpolationMode.Low;
                g.PixelOffsetMode = PixelOffsetMode.HighSpeed;
                _backdrop.Configure(_bg, w, h);
                _backdrop.DrawFull(g, new Rectangle(0, 0, w, h));
            }
            _backdrop.Cache = _bgCache;
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (_backdrop != null) _backdrop.Configure(_bg, ClientSize.Width, ClientSize.Height);
            CenterContainer();
            Invalidate(true);
        }

        private void CenterContainer()
        {
            if (_container == null) return;
            _container.Location = new Point(
                Math.Max(0, (ClientSize.Width - _container.Width) / 2),
                Math.Max(0, (ClientSize.Height - _container.Height) / 2));
        }

        // ---------------------------------------------------------------
        //  UI construction
        // ---------------------------------------------------------------
        private void BuildUi()
        {
            _container = new GlassPanel { Size = new Size(CW, CH) };
            int IW = CW - 2 * M; // inner width (588)

            // --- Title ---
            _title = new Label
            {
                Text = "FileEncryptor", Location = new Point(M, 18), Size = new Size(IW, 34),
                Font = new Font("Segoe UI Semibold", 17f), TextAlign = ContentAlignment.MiddleLeft
            };
            _subtitle = new Label
            {
                Text = "基于 libsodium 的高强度文件加解密工具", Location = new Point(M, 54),
                Size = new Size(IW, 20), Font = new Font("Segoe UI", 9f), TextAlign = ContentAlignment.MiddleLeft
            };
            _cliStatus = new Label
            {
                Text = "...", Location = new Point(M, 76), Size = new Size(IW, 18),
                Font = new Font("Segoe UI", 8.5f), TextAlign = ContentAlignment.MiddleRight
            };

            // --- Mode radios ---
            _rbEncrypt = MakeRadio("加密单个文件", true);
            _rbDecrypt = MakeRadio("解密单个文件", false);
            _rbBatchEncrypt = MakeRadio("批量加密目录", false);
            _rbBatchDecrypt = MakeRadio("批量解密目录", false);
            _rbEncrypt.Location = new Point(M, 104);
            _rbDecrypt.Location = new Point(M + 156, 104);
            _rbBatchEncrypt.Location = new Point(M + 318, 104);
            _rbBatchDecrypt.Location = new Point(M + 480, 104);

            // --- 输入 box ---
            _inputBox = MakeBox(new Point(M, 138), IW, 88);
            _lblTbIn = new Label { Text = "输入", Location = new Point(16, 7), Size = new Size(200, 18), Font = new Font("Segoe UI Semibold", 9.5f) };
            _tbInput = new TextBox { Location = new Point(16, 30), Size = new Size(IW - 148, 24), ReadOnly = true };
            _btnBrowseInput = MakeBrowse();
            _btnBrowseInput.Location = new Point(IW - 120, 30); _btnBrowseInput.Size = new Size(92, 25);
            _lblModeLabel = new Label { Text = "请选择一个文件", Location = new Point(16, 62), Size = new Size(IW - 32, 18), Tag = "dim" };
            _inputBox.Controls.AddRange(new Control[] { _lblTbIn, _tbInput, _btnBrowseInput, _lblModeLabel });

            // --- 输出 box ---
            _outputBox = MakeBox(new Point(M, 234), IW, 68);
            _lblTbOut = new Label { Text = "输出目录（可选，默认与源文件相同）", Location = new Point(16, 7), Size = new Size(IW - 32, 18), Font = new Font("Segoe UI Semibold", 9.5f) };
            _tbOutput = new TextBox { Location = new Point(16, 30), Size = new Size(IW - 148, 24) };
            _btnBrowseOutput = MakeBrowse();
            _btnBrowseOutput.Location = new Point(IW - 120, 30); _btnBrowseOutput.Size = new Size(92, 25);
            _outputBox.Controls.AddRange(new Control[] { _lblTbOut, _tbOutput, _btnBrowseOutput });

            // --- 密钥 box ---
            _keyBox = MakeBox(new Point(M, 310), IW, 96);
            _lblPw = new Label { Text = "口令", Location = new Point(16, 10), Size = new Size(84, 20), Tag = "dim" };
            _tbPassword = new TextBox { Location = new Point(108, 7), Size = new Size(IW - 210, 24), UseSystemPasswordChar = true };
            _chkShowPw = new TransCheckBox { Text = "显示口令", Location = new Point(IW - 90, 9), AutoSize = true, Tag = "dim" };
            _lblConfirm = new Label { Text = "确认口令", Location = new Point(16, 46), Size = new Size(84, 20), Tag = "dim" };
            _tbConfirm = new TextBox { Location = new Point(108, 43), Size = new Size(IW - 210, 24), UseSystemPasswordChar = true };
            _chkShowPw.CheckedChanged += (s, e) =>
            {
                _tbPassword.UseSystemPasswordChar = !_chkShowPw.Checked;
                _tbConfirm.UseSystemPasswordChar = !_chkShowPw.Checked;
            };
            _keyBox.Controls.AddRange(new Control[] { _lblPw, _tbPassword, _chkShowPw, _lblConfirm, _tbConfirm });

            // --- 选项 box ---
            _optionBox = MakeBox(new Point(M, 414), IW, 78);
            _lblAlgo = new Label { Text = "加密算法", Location = new Point(16, 10), Size = new Size(84, 20), Tag = "dim" };
            _cmbModeAlgo = new ComboBox { Location = new Point(108, 7), Size = new Size(190, 22), DropDownStyle = ComboBoxStyle.DropDownList };
            _cmbModeAlgo.Items.AddRange(new object[] { "XChaCha20（默认）", "AEGIS-256（更快）" });
            _cmbModeAlgo.SelectedIndex = 0;
            _chkDelete = new TransCheckBox { Text = "成功后删除源文件 (-de)", Location = new Point(16, 42), AutoSize = true, Tag = "dim" };
            _chkForce = new TransCheckBox { Text = "覆盖已存在文件 (-y)", Location = new Point(230, 42), AutoSize = true, Tag = "dim" };
            _chkVerbose = new TransCheckBox { Text = "显示详细错误 (-v)", Location = new Point(400, 42), AutoSize = true, Tag = "dim" };
            _optionBox.Controls.AddRange(new Control[] { _lblAlgo, _cmbModeAlgo, _chkDelete, _chkForce, _chkVerbose });

            // --- Progress / status ---
            _progress = new ModernProgressBar { Location = new Point(M, 502), Size = new Size(IW, 14) };
            _lblStatus = new Label { Text = "就绪", Location = new Point(M, 524), Size = new Size(IW, 20), Tag = "dim" };

            // --- Footer ---
            _lblTheme = new Label { Text = "主题：", Location = new Point(M, 552), AutoSize = true, Tag = "dim" };
            _cmbTheme = new ComboBox { Location = new Point(M + 46, 549), Size = new Size(110, 22), DropDownStyle = ComboBoxStyle.DropDownList, Font = new Font("Segoe UI", 9f) };
            _cmbTheme.Items.AddRange(new object[] { "跟随系统", "浅色", "深色" });
            _cmbTheme.SelectedIndex = 0;
            int tm = (int)ThemeManager.Mode;
            _cmbTheme.SelectedIndex = (tm >= 0 && tm <= 2) ? tm : 0;
            _cmbTheme.SelectedIndexChanged += (s, e) => ApplyTheme();

            _btnRun = MakeAccent("开始");
            _btnRun.Location = new Point(M + IW - 150, 548); _btnRun.Size = new Size(150, 38);
            _lblVersion = new Label { Text = "FileEncryptor GUI v3.0.0 · 引擎 v1.7.2", Location = new Point(M, 594), Size = new Size(IW, 18), Tag = "dim" };

            _container.Controls.Add(_title);
            _container.Controls.Add(_subtitle);
            _container.Controls.Add(_cliStatus);
            _container.Controls.Add(_rbEncrypt);
            _container.Controls.Add(_rbDecrypt);
            _container.Controls.Add(_rbBatchEncrypt);
            _container.Controls.Add(_rbBatchDecrypt);
            _container.Controls.Add(_inputBox);
            _container.Controls.Add(_outputBox);
            _container.Controls.Add(_keyBox);
            _container.Controls.Add(_optionBox);
            _container.Controls.Add(_progress);
            _container.Controls.Add(_lblStatus);
            _container.Controls.Add(_lblTheme);
            _container.Controls.Add(_cmbTheme);
            _container.Controls.Add(_btnRun);
            _container.Controls.Add(_lblVersion);

            Controls.Add(_container);
            CenterContainer();

            CardsRadius();
            Ui.RoundedCorners(_tbInput, 3);
            Ui.RoundedCorners(_tbOutput, 3);
            Ui.RoundedCorners(_tbPassword, 3);
            Ui.RoundedCorners(_tbConfirm, 3);
            Ui.RoundedCorners(_cmbModeAlgo, 4);
            Ui.RoundedCorners(_cmbTheme, 4);
            Ui.RoundedCorners(_btnRun, 4);
            Ui.RoundedCorners(_btnBrowseInput, 4);
            Ui.RoundedCorners(_btnBrowseOutput, 4);

            _btnBrowseInput.Click += OnBrowseInput;
            _btnBrowseOutput.Click += OnBrowseOutput;
            _btnRun.Click += OnRunClick;
            foreach (var rb in new[] { _rbEncrypt, _rbDecrypt, _rbBatchEncrypt, _rbBatchDecrypt })
                rb.CheckedChanged += (s, e) => { if (rb.Checked) RefreshModeUi(); };
            RefreshModeUi();
        }

        private GlassPanel MakeBox(Point loc, int w, int h) => new GlassPanel { Location = loc, Size = new Size(w, h) };

        private void CardsRadius()
        {
            _container.Radius = 14;
            _inputBox.Radius = 8;
            _outputBox.Radius = 8;
            _keyBox.Radius = 8;
            _optionBox.Radius = 8;
        }

        private RadioButton MakeRadio(string text, bool check) => new TransRadioButton
        {
            Text = text, Checked = check, AutoSize = true, Margin = new Padding(0, 0, 30, 0),
            Font = new Font("Segoe UI", 9.5f)
        };

        private Button MakeBrowse() => new Button
        {
            Text = "浏览...", FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f),
            Cursor = Cursors.Hand, BackColor = Color.Transparent
        };

        private Button MakeAccent(string text)
        {
            var b = new Button
            {
                Text = text, FlatStyle = FlatStyle.Flat, ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 11f), Cursor = Cursors.Hand,
                FlatAppearance = { BorderSize = 0 }
            };
            b.MouseEnter += (s, e) => b.BackColor = ThemeManager.Effective.AccentHover;
            b.MouseLeave += (s, e) => b.BackColor = ThemeManager.Effective.Accent;
            return b;
        }

        // ---------------------------------------------------------------
        //  Theme
        // ---------------------------------------------------------------
        private void ApplyTheme()
        {
            if (_cmbTheme == null) return;
            var idx = _cmbTheme.SelectedIndex;
            ThemeManager.Mode = idx == 1 ? ThemeMode.Light : idx == 2 ? ThemeMode.Dark : ThemeMode.Auto;
            ThemeManager.Save();
            var t = ThemeManager.Effective;

            _bg = t.IsDark ? _bgDark : _bgLight;
            _bgCache?.Dispose(); _bgCache = null;
            if (_backdrop != null) _backdrop.Configure(_bg, ClientSize.Width, ClientSize.Height);
            BackColor = t.Window;

            _container.SetGlass(_backdrop, t.ContainerTint, t.ContainerBorder);
            _inputBox.SetGlass(_backdrop, t.BoxTint, t.BoxBorder);
            _outputBox.SetGlass(_backdrop, t.BoxTint, t.BoxBorder);
            _keyBox.SetGlass(_backdrop, t.BoxTint, t.BoxBorder);
            _optionBox.SetGlass(_backdrop, t.BoxTint, t.BoxBorder);

            _title.ForeColor = t.Text; _title.BackColor = Color.Transparent;
            _subtitle.ForeColor = t.TextDim; _subtitle.BackColor = Color.Transparent;
            _cliStatus.ForeColor = t.TextDim; _cliStatus.BackColor = Color.Transparent;
            _lblModeLabel.ForeColor = t.TextDim; _lblModeLabel.BackColor = Color.Transparent;
            _lblStatus.ForeColor = t.TextDim; _lblStatus.BackColor = Color.Transparent;
            _lblVersion.ForeColor = t.TextDim; _lblVersion.BackColor = Color.Transparent;
            _lblTheme.ForeColor = t.TextDim; _lblTheme.BackColor = Color.Transparent;
            _lblPw.ForeColor = t.TextDim; _lblPw.BackColor = Color.Transparent;
            _lblConfirm.ForeColor = t.TextDim; _lblConfirm.BackColor = Color.Transparent;
            _lblTbIn.ForeColor = t.Text; _lblTbIn.BackColor = Color.Transparent;
            _lblTbOut.ForeColor = t.Text; _lblTbOut.BackColor = Color.Transparent;
            _lblAlgo.ForeColor = t.TextDim; _lblAlgo.BackColor = Color.Transparent;

            foreach (var rb in new[] { _rbEncrypt, _rbDecrypt, _rbBatchEncrypt, _rbBatchDecrypt })
            { rb.ForeColor = t.Text; rb.BackColor = Color.Transparent; }
            foreach (var cb in new[] { _chkShowPw, _chkDelete, _chkForce, _chkVerbose })
            { cb.ForeColor = cb.Enabled ? t.Text : t.TextDim; cb.BackColor = Color.Transparent; }

            foreach (var tb in new[] { _tbInput, _tbOutput, _tbPassword, _tbConfirm })
            { tb.BackColor = t.FieldBg; tb.ForeColor = t.FieldText; }
            _cmbModeAlgo.BackColor = t.FieldBg; _cmbModeAlgo.ForeColor = t.FieldText;
            _cmbTheme.BackColor = t.FieldBg; _cmbTheme.ForeColor = t.FieldText;
            _btnBrowseInput.ForeColor = t.Text; _btnBrowseInput.BackColor = t.ControlBack;
            _btnBrowseOutput.ForeColor = t.Text; _btnBrowseOutput.BackColor = t.ControlBack;
            _btnBrowseInput.FlatAppearance.BorderColor = t.FieldBorder;
            _btnBrowseOutput.FlatAppearance.BorderColor = t.FieldBorder;

            _btnRun.BackColor = t.Accent;
            _progress.Theme = t;
            _progress.BackColor = t.IsDark ? Color.FromArgb(32, 35, 44) : Color.FromArgb(233, 237, 244);
            _progress.Invalidate();

            Invalidate(true);
            CenterContainer();
        }

        // ---------------------------------------------------------------
        //  Mode handling
        // ---------------------------------------------------------------
        private OpMode CurrentMode =>
            _rbBatchDecrypt.Checked ? OpMode.BatchDecrypt :
            _rbBatchEncrypt.Checked ? OpMode.BatchEncrypt :
            _rbDecrypt.Checked ? OpMode.Decrypt : OpMode.Encrypt;

        private bool IsBatch => CurrentMode == OpMode.BatchEncrypt || CurrentMode == OpMode.BatchDecrypt;

        private void RefreshModeUi()
        {
            bool enc = CurrentMode == OpMode.Encrypt || CurrentMode == OpMode.BatchEncrypt;
            _lblModeLabel.Text = IsBatch
                ? "请选择输入目录（将递归处理其中的所有文件）"
                : (enc ? "请选择一个文件" : "请选择一个 .ptd 文件");
            _lblConfirm.Visible = enc;
            _tbConfirm.Visible = enc;
            _chkDelete.Enabled = enc;
            _chkDelete.ForeColor = enc ? ThemeManager.Effective.Text : ThemeManager.Effective.TextDim;
            _btnRun.Text = enc ? "开始加密" : "开始解密";
        }

        private void OnBrowseInput(object sender, EventArgs e)
        {
            if (IsBatch)
            {
                using (var dlg = new FolderBrowserDialog { Description = "选择输入目录" })
                    if (dlg.ShowDialog(this) == DialogResult.OK) _tbInput.Text = dlg.SelectedPath;
            }
            else
            {
                using (var dlg = new OpenFileDialog { Title = "选择文件" })
                    if (dlg.ShowDialog(this) == DialogResult.OK) _tbInput.Text = dlg.FileName;
            }
        }

        private void OnBrowseOutput(object sender, EventArgs e)
        {
            using (var dlg = new FolderBrowserDialog { Description = "选择输出目录" })
                if (dlg.ShowDialog(this) == DialogResult.OK) _tbOutput.Text = dlg.SelectedPath;
        }

        // ---------------------------------------------------------------
        //  CLI discovery
        // ---------------------------------------------------------------
        private string DetectCliPath()
        {
            var exeDir = Path.GetDirectoryName(Application.ExecutablePath) ?? AppDomain.CurrentDomain.BaseDirectory;
            var candidates = new List<string>
            {
                Path.Combine(exeDir, "..", "FileEncryptor.exe"),
                Path.Combine(exeDir, "FileEncryptor.exe"),
                Environment.GetEnvironmentVariable("FILEENCRYPTOR_CLI")
            }.Where(c => !string.IsNullOrEmpty(c)).Distinct().ToList();
            foreach (var c in candidates)
            {
                var p = Path.GetFullPath(c);
                if (File.Exists(p)) return p;
            }
            return null;
        }

        private void UpdateCliStatus()
        {
            if (_cliPath != null && File.Exists(_cliPath))
                _cliStatus.Text = "CLI ✓ FileEncryptor.exe 已找到";
            else
                _cliStatus.Text = "CLI ✗ 未找到 FileEncryptor.exe，请放到程序同级或上一级目录";
        }

        // ---------------------------------------------------------------
        //  Run
        // ---------------------------------------------------------------
        private void OnRunClick(object sender, EventArgs e)
        {
            if (_proc != null && !_proc.HasExited)
            {
                MessageBox.Show(this, "已有任务正在运行，请稍候。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (_cliPath == null || !File.Exists(_cliPath))
            {
                MessageBox.Show(this, "未找到 FileEncryptor.exe。请将其放到本程序同级或上一级目录后再试。",
                    "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var mode = CurrentMode;
            var input = _tbInput.Text.Trim();
            var output = _tbOutput.Text.Trim();
            var password = _tbPassword.Text;
            bool encrypting = mode == OpMode.Encrypt || mode == OpMode.BatchEncrypt;

            if (string.IsNullOrEmpty(input))
            {
                MessageBox.Show(this, "请先选择输入" + (IsBatch ? "目录。" : "文件。"), "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (string.IsNullOrEmpty(password))
            {
                MessageBox.Show(this, "请输入口令。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (encrypting && password.Length < 6)
            {
                MessageBox.Show(this, "加密口令至少需要 6 位。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (encrypting && _tbConfirm.Text != password)
            {
                MessageBox.Show(this, "两次输入的口令不一致。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (!encrypting && !(File.Exists(input) || Directory.Exists(input)))
            {
                MessageBox.Show(this, "选择的输入不存在。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var args = new List<string>();
            if (mode == OpMode.Encrypt) args.Add("-e");
            else if (mode == OpMode.Decrypt) args.Add("-d");
            else if (mode == OpMode.BatchEncrypt) args.Add("-be");
            else args.Add("-bd");

            args.Add(Quote(input));
            if (!string.IsNullOrEmpty(output)) { args.Add("-o"); args.Add(Quote(output)); }
            if (encrypting && _chkDelete.Checked) args.Add("-de");
            if (_chkForce.Checked) args.Add("-y");
            if (_chkVerbose.Checked) args.Add("-v");
            args.Add("-m");
            args.Add(_cmbModeAlgo.SelectedIndex == 1 ? "aegis256" : "xchacha20");

            string keyFile = Path.Combine(Path.GetTempPath(), "fe_ge_" + Guid.NewGuid().ToString("N") + ".key");
            try
            {
                File.WriteAllBytes(keyFile, new UTF8Encoding(false).GetBytes(password));
                args.Add("-k"); args.Add(Quote(keyFile));
                _errBuf.Clear();
                _cleanupRoots = ComputeCleanupRoots(input, output, mode);
                StartRun(string.Join(" ", args), keyFile);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "无法创建临时密钥文件：" + ex.Message, "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static List<string> ComputeCleanupRoots(string input, string output, OpMode mode)
        {
            var roots = new List<string>();
            if (!string.IsNullOrEmpty(output)) roots.Add(output);
            else if (mode == OpMode.Encrypt || mode == OpMode.Decrypt)
            {
                var dir = Path.GetDirectoryName(input);
                if (!string.IsNullOrEmpty(dir)) roots.Add(dir);
            }
            else roots.Add(input);
            return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private void StartRun(string argLine, string keyFile)
        {
            _lblStatus.Text = "正在启动...";
            _progress.Value = 0; _progress.Running = true;
            _btnRun.Enabled = false;

            var psi = new ProcessStartInfo
            {
                FileName = _cliPath, Arguments = argLine,
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? AppDomain.CurrentDomain.BaseDirectory
            };

            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += (s, e) => AppendLine(e.Data, false);
            _proc.ErrorDataReceived += (s, e) => AppendLine(e.Data, true);
            _proc.Exited += (s, e) =>
            {
                try { if (File.Exists(keyFile)) File.Delete(keyFile); } catch { }
                var exit = _proc.ExitCode;
                var err = new List<string>(_errBuf);
                var roots = new List<string>(_cleanupRoots);
                BeginInvoke(new Action(() =>
                {
                    _btnRun.Enabled = true;
                    OkCleanup(exit == 0, roots);
                    _progress.Running = false;
                    if (exit == 0)
                    {
                        _progress.Value = 100;
                        _lblStatus.Text = "完成 ✓";
                    }
                    else
                    {
                        _lblStatus.Text = "出错（退出码 " + exit + "）";
                        if (err.Count > 0)
                            MessageBox.Show(this, string.Join(Environment.NewLine, err.TakeLast(6)),
                                "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }));
            };

            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
            _lblStatus.Text = "运行中...";
        }

        private void OkCleanup(bool ok, List<string> roots)
        {
            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
                try
                {
                    foreach (var f in SafeEnumerateFiles(root))
                    {
                        var n = Path.GetFileName(f);
                        if (IsResumeArtifact(n, ok)) { try { File.Delete(f); } catch { } }
                    }
                }
                catch { }
            }
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root)
        {
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                var dir = stack.Pop();
                string[] files, subdirs;
                try { files = Directory.GetFiles(dir); } catch { files = Array.Empty<string>(); }
                foreach (var f in files) yield return f;
                try { subdirs = Directory.GetDirectories(dir); } catch { continue; }
                foreach (var d in subdirs) stack.Push(d);
            }
        }

        private static bool IsResumeArtifact(string n, bool ok)
        {
            bool bak = n.EndsWith(".progress.bak", StringComparison.OrdinalIgnoreCase)
                    || n.EndsWith(".verify.tmp.progress.bak", StringComparison.OrdinalIgnoreCase);
            if (bak) return true;
            return ok && (n.EndsWith(".progress", StringComparison.OrdinalIgnoreCase)
                        || n.EndsWith(".verify.tmp.progress", StringComparison.OrdinalIgnoreCase));
        }

        private void AppendLine(string data, bool isError)
        {
            if (data == null) return;
            var m = _progressRe.Match(data);
            if (m.Success)
            {
                long done, total;
                if (long.TryParse(m.Groups[1].Value, out done) && long.TryParse(m.Groups[2].Value, out total) && total > 0)
                {
                    int pct = (int)Math.Min(100, Math.Round(done * 100.0 / total));
                    BeginInvoke(new Action(() => _progress.Value = pct));
                }
                return;
            }
            if (string.IsNullOrWhiteSpace(data)) return;
            var line = data.Trim();
            if (isError) { _errBuf.Add(line); return; }
            if (line.StartsWith("Encrypting:") || line.StartsWith("Decrypting:"))
            {
                int colon = line.IndexOf(':');
                int arrow = line.IndexOf(" -> ");
                var src = arrow > colon ? line.Substring(colon + 1, arrow - colon - 1).Trim() : "";
                var name = string.IsNullOrEmpty(src) ? "" : Path.GetFileName(src);
                if (!string.IsNullOrEmpty(name))
                    BeginInvoke(new Action(() =>
                        _lblStatus.Text = (line.StartsWith("Encrypting:") ? "正在加密：" : "正在解密：") + name));
            }
        }

        private static string Quote(string s) => s.Contains(' ') ? "\"" + s.Replace("\"", "\\\"") + "\"" : s;

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            try { if (_proc != null && !_proc.HasExited) _proc.Kill(); } catch { }
            base.OnFormClosing(e);
        }
    }
}
