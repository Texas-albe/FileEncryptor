// 单文件 / 整目录加
// 输出落公共 Documents
using Android.App;
using FileEncryptorMobile.Platforms.Android;
using FileEncryptorMobile.Services;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile;

public partial class CryptoPage : ContentPage
{
    private const string OutDirKey = "crypto_out_dir";

    private bool _encrypting = true;
    private bool _dirMode;
    private string _rootDir = "";
    private readonly List<string> _inputs = new();
    private readonly Dictionary<string, string> _outNames = new();
    private List<CipherModeInfo> _algos = new();
    private int _algoIndex = -1;
    private int _compressIndex;
    private string _outDir = "";
    private string _rewrapPath = "";
    private bool _asymMode;
    private bool _asymOk;
    private string _fekwPath = "";

    private static string[] CompressNames() => new[]
        { L10n.T("自动"), L10n.T("关闭"), L10n.T("极速"), L10n.T("标准"), L10n.T("最佳") };

    // 档位说明
    internal static string CompressHintText(int i) => i switch
    {
        0 => L10n.T("自动判断是否值得压缩；适合大多数文件。"),
        1 => L10n.T("不压缩，速度最快；图片、视频等已压缩文件建议选它。"),
        2 => L10n.T("速度最快，压缩比低；适合大文件。"),
        3 => L10n.T("速度与压缩比均衡；推荐日常使用。"),
        _ => L10n.T("压缩比最高，速度较慢；适合文本、代码。"),
    };
    private static readonly int[] CompressLevels =
        { FileCryptoNative.CompressAuto, 0, -3, 3, 9 };
    private static readonly string[] SplitNames =
        { L10n.T("不分卷"), "16 MiB", "64 MiB", "256 MiB", "1 GiB" };
    private static readonly ulong[] SplitBytes =
        { 0, 16UL << 20, 64UL << 20, 256UL << 20, 1UL << 30 };

    public CryptoPage()
    {
        InitializeComponent();
        ChoiceUi.BuildChips(CompressChoices, CompressNames(), 0, i =>
        {
            _compressIndex = i;
            LblCompressHint.Text = CompressHintText(i);
        });
        LblCompressHint.Text = CompressHintText(0);
        PkSplit.ItemsSource = SplitNames;
        PkSplit.SelectedIndex = 0;
        LoadAlgos();
        try { _asymOk = FileCryptoService.AsymSupported(); }
        catch { _asymOk = false; }
        BtnKeyAsym.IsEnabled = _asymOk;
        PkFekwMode.ItemsSource = new[] { L10n.T("存入"), L10n.T("取出") };
        PkFekwMode.SelectedIndex = 0;
        PkFekwAlg.ItemsSource = new[]
        {
            L10n.T("密码（更安全）"),
            L10n.T("用对方的钥匙（后量子）"),
            L10n.T("密码（兼容旧版）"),
        };
        PkFekwAlg.SelectedIndex = 0;
        RefreshMode();
        _outDir = LoadOutDir();
        LblOut.Text = _outDir;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        VaultService.LockOnLeaveVault();
        UiFx.AppearFade(this);
        ConsumeShared();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        HideAllOverlays();
    }

    // 返回键
    internal static bool HandleBack()
    {
        var p = Shell.Current?.CurrentPage as CryptoPage;
        if (p is null) return false;
        if (p.Sheet.IsOpen) { p.Sheet.Cancel(); return true; }
        if (p.InputsOverlay.IsVisible) { UiFx.Hide(p.InputsOverlay); return true; }
        if (p.InfoOverlay.IsVisible) { UiFx.Hide(p.InfoOverlay); return true; }
        if (p.OutputsOverlay.IsVisible) { UiFx.Hide(p.OutputsOverlay); return true; }
        if (p.RewrapOverlay.IsVisible) { UiFx.Hide(p.RewrapOverlay); return true; }
        if (p.FekwOverlay.IsVisible) { UiFx.Hide(p.FekwOverlay); return true; }
        return false;
    }

    private void HideAllOverlays()
    {
        UiFx.Hide(InputsOverlay);
        UiFx.Hide(InfoOverlay);
        UiFx.Hide(OutputsOverlay);
        UiFx.Hide(RewrapOverlay);
        UiFx.Hide(FekwOverlay);
    }

    private static string LoadOutDir()
    {
        string saved = Preferences.Default.Get(OutDirKey, "");
        if (!string.IsNullOrEmpty(saved) && Directory.Exists(saved)) return saved;
        return VaultStorageHelper.ExportDir();
    }

    // 外部分享入
    private void ConsumeShared()
    {
        var items = ShareInbox.Take();
        if (items.Count == 0) return;
        _dirMode = false;
        _rootDir = "";
        int added = 0;
        foreach (var s in items)
        {
            if (string.IsNullOrEmpty(s) || _inputs.Contains(s)) continue;
            _inputs.Add(s);
            added++;
        }
        if (added == 0) { RefreshInputs(); return; }
        // 全部是 .ptd 时自动切
        bool allPtd = _inputs.All(x => x.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase));
        if (allPtd && _encrypting) { _encrypting = false; RefreshMode(); }
        RefreshInputs();
        ShowMsg(L10n.F("已从外部分享加入 {0} 个文件，输入密码后开始处理。", added));
    }

    private void LoadAlgos()
    {
        try
        {
            FileCryptoService.VerifyAbi();
            // 全量列出
            var list = FileCryptoService.Modes().ToList();
            _algos = list;
            _algoIndex = list.FindIndex(m => m.Available);
            ChoiceUi.BuildModeRows(AlgoChoices, list, _algoIndex,
                i => _algoIndex = i, LblAlgoDetail);
        }
        catch (Exception ex) { ShowMsg(ex.Message); }
    }

    private void OnKeyPwd(object? sender, EventArgs e)
    {
        _asymMode = false; RefreshMode();
    }

    private void OnKeyAsym(object? sender, EventArgs e)
    {
        if (!_asymOk) { ShowMsg(L10n.T("当前版本不支持钥匙加密。")); return; }
        _asymMode = true; RefreshMode();
    }

    private void OnModeEncrypt(object? sender, EventArgs e)
    {
        _encrypting = true; RefreshMode();
    }

    private void OnModeDecrypt(object? sender, EventArgs e)
    {
        _encrypting = false; RefreshMode();
    }

    private void RefreshMode()
    {
        var res = Microsoft.Maui.Controls.Application.Current?.Resources;
        Style? on = res is not null && res.TryGetValue("SegmentSelected", out var s1) ? s1 as Style : null;
        Style? off = res is not null && res.TryGetValue("SegmentUnselected", out var s2) ? s2 as Style : null;
        if (on is not null && off is not null)
        {
            BtnEnc.Style = _encrypting ? on : off;
            BtnDec.Style = _encrypting ? off : on;
        }
        EntryPwd2.IsVisible = _encrypting;
        BoxPwd2.IsVisible = _encrypting;
        AlgoChoices.IsVisible = _encrypting;
        LblAlgoDetail.IsVisible = _encrypting;
        LblAlgoAuto.IsVisible = !_encrypting;
        GroupCompress.IsVisible = _encrypting;
        RowForce.IsVisible = !_encrypting;
        RowRestore.IsVisible = !_encrypting;
        RowSha.IsVisible = _encrypting;
        RowPack.IsVisible = _encrypting;
        RowSplit.IsVisible = _encrypting;
        BtnRun.Text = _encrypting ? L10n.T("开始加密") : L10n.T("开始解密");
        LblModeHint.Text = _encrypting
            ? L10n.T("加密后得到 .ptd 文件。")
            : L10n.T("将 .ptd 还原为原文件。");
        if (on is not null && off is not null)
        {
            BtnKeyPwd.Style = _asymMode ? off : on;
            BtnKeyAsym.Style = _asymMode ? on : off;
        }
        GroupPwd.IsVisible = !_asymMode;
        GroupAsym.IsVisible = _asymMode;
        EdtRecips.IsVisible = _asymMode && _encrypting;
        EdtIdentity.IsVisible = _asymMode && !_encrypting;
        RowRestore.IsVisible = !_encrypting && !_asymMode;
        BtnVerify.IsVisible = !_asymMode;
        LblKeyModeHint.Text = !_asymOk
            ? L10n.T("当前版本不支持钥匙加密。")
            : _encrypting
                ? L10n.T("用口令加密，解密时输入同一口令。")
                : L10n.T("加密时贴对方的钥匙，可贴多把；解密要贴对应的我的钥匙。");
        LblAsymCap.Text = _encrypting
            ? L10n.T("用钥匙加密不需要密码。")
            : L10n.T("用钥匙解密不需要密码，要贴我的钥匙。");
    }

    private void OnToggleShowPwd(object? sender, EventArgs e)
    {
        bool show = !EntryPwd.IsPassword;
        EntryPwd.IsPassword = !show;
        EntryPwd2.IsPassword = !show;
        BtnShowPwd.Text = show ? L10n.T("隐藏") : L10n.T("显示");
    }

    private async void OnChangeOutDir(object? sender, EventArgs e)
    {
        try
        {
            if (Platform.CurrentActivity is not Activity act)
            { ShowMsg(L10n.T("当前界面不可用")); return; }
            if (!VaultStorageHelper.HasAllFilesAccess())
            {
                ShowMsg(L10n.T("自定义输出目录需要「所有文件访问」权限。"));
                return;
            }
            MainActivity.NoteExternalLaunch();
            string? dir = await VaultStorageHelper.PickDirectoryAsync(act);
            if (dir is null) return;   // 取消选择
            if (dir.Length == 0) { ShowMsg(L10n.T("仅支持内部存储目录，SD 卡暂不支持。")); return; }
            Preferences.Default.Set(OutDirKey, dir);
            _outDir = dir;
            LblOut.Text = dir;
        }
        catch (Exception ex) { ShowMsg(L10n.T("更改输出目录失败：") + ex.Message); }
    }

    private void OnResetOutDir(object? sender, EventArgs e)
    {
        Preferences.Default.Remove(OutDirKey);
        _outDir = VaultStorageHelper.ExportDir();
        LblOut.Text = _outDir;
    }

    private async void OnPickFiles(object? sender, EventArgs e)
    {
        _dirMode = false;
        _rootDir = "";
        _inputs.Clear();
        _outNames.Clear();
        try
        {
            MainActivity.NoteExternalLaunch();
            var picked = await FilePicker.Default.PickMultipleAsync();
            if (picked is null || !picked.Any()) { RefreshInputs(); return; }
            foreach (var f in picked)
            {
                string p = f.FullPath ?? "";
                if (p.Length == 0) continue;
                if (p.StartsWith("content://", StringComparison.Ordinal) ||
                    FileCryptoService.CanReadDirect(p))
                {
                    _inputs.Add(p);
                    continue;
                }
                string tmp = Path.Combine(FileSystem.CacheDirectory, "cim_" + Guid.NewGuid().ToString("N"));
                await using (var s = await f.OpenReadAsync())
                await using (var fs = File.Create(tmp))
                    await s.CopyToAsync(fs);
                _inputs.Add(tmp);
                _outNames[tmp] = f.FileName ?? Path.GetFileName(p);
            }
            RefreshInputs();
        }
        catch (Exception ex) { ShowMsg(L10n.T("选择文件失败：") + ex.Message); }
    }

    private async void OnPickDir(object? sender, EventArgs e)
    {
        try
        {
            if (Platform.CurrentActivity is not Activity act)
            { ShowMsg(L10n.T("当前界面不可用")); return; }
            if (!VaultStorageHelper.HasAllFilesAccess())
            { ShowMsg(L10n.T("处理整个目录需要「所有文件访问」权限。")); return; }
            MainActivity.NoteExternalLaunch();
            string? root = await VaultStorageHelper.PickDirectoryAsync(act);
            if (root is null) return;   // 取消选择
            if (root.Length == 0) { ShowMsg(L10n.T("仅支持内部存储目录，SD 卡暂不支持。")); return; }
            var files = VaultStorageHelper.CollectFiles(root);
            files = _encrypting
                ? files.Where(x => !x.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase)).ToList()
                : files.Where(x => x.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase)).ToList();
            if (files.Count == 0)
            { ShowMsg(_encrypting ? L10n.T("目录内没有可加密的文件。") : L10n.T("目录内没有 .ptd 文件。")); return; }
            _dirMode = true;
            _rootDir = root;
            _inputs.Clear();
            _outNames.Clear();
            _inputs.AddRange(files);
            RefreshInputs();
        }
        catch (Exception ex) { ShowMsg(L10n.T("选择目录失败：") + ex.Message); }
    }

    private void RefreshInputs()
    {
        LblInputs.Text = _inputs.Count == 0
            ? L10n.T("未选择文件")
            : L10n.F("已选 {0} 个文件", _inputs.Count) + (_dirMode ? L10n.F(" · 目录：{0}", Path.GetFileName(_rootDir.TrimEnd('/'))) : "");
        BtnManageInputs.IsEnabled = _inputs.Count > 0;
        LblMsg.IsVisible = false;
    }

    private static string DisplayOf(string path)
    {
        string name = Path.GetFileName(path);
        if (path.StartsWith("content://", StringComparison.Ordinal))
        {
            try { name = global::Android.Net.Uri.Parse(path)!.LastPathSegment ?? name; }
            catch { }
            if (string.IsNullOrEmpty(name)) name = L10n.T("外部分享文件");
        }
        return name;
    }

    // 已选文件浮层
    private void OnManageInputs(object? sender, EventArgs e)
    {
        InputsList.Children.Clear();
        for (int i = 0; i < _inputs.Count; i++)
        {
            string path = _inputs[i];
            var row = new Grid { ColumnDefinitions = new ColumnDefinitionCollection(
                new ColumnDefinition(GridLength.Star), new ColumnDefinition(GridLength.Auto)),
                ColumnSpacing = 10, Padding = new Thickness(0, 6) };
            row.Children.Add(new Label { Text = DisplayOf(path), FontSize = 13,
                LineBreakMode = LineBreakMode.MiddleTruncation, VerticalOptions = LayoutOptions.Center });
            var del = new Button { Text = L10n.T("移除"), Style = Res("QuietButton") as Style,
                FontSize = 12, Padding = new Thickness(8, 2) };
            del.Clicked += (s, a) => { _inputs.Remove(path); _outNames.Remove(path); OnManageInputs(this, EventArgs.Empty); RefreshInputs(); };
            Grid.SetColumn(del, 1);
            row.Children.Add(del);
            InputsList.Children.Add(row);
            InputsList.Children.Add(new BoxView { Style = Res("Divider") as Style });
        }
        if (_inputs.Count == 0)
            InputsList.Children.Add(new Label { Text = L10n.T("未选择文件"), Style = Res("Caption") as Style });
        UiFx.Reveal(InputsOverlay);
    }

    private static object? Res(string key)
        => Microsoft.Maui.Controls.Application.Current?.Resources.TryGetValue(key, out var v) == true ? v : null;

    private void OnClearInputs(object? sender, EventArgs e)
    {
        _inputs.Clear();
        _outNames.Clear();
        _dirMode = false;
        _rootDir = "";
        OnManageInputs(this, EventArgs.Empty);
        RefreshInputs();
    }

    private void OnCloseInputs(object? sender, EventArgs e) => UiFx.Hide(InputsOverlay);
    private void OnInputsBackdropTapped(object? sender, TappedEventArgs e) => UiFx.Hide(InputsOverlay);
    private void OnCloseInfo(object? sender, EventArgs e) => UiFx.Hide(InfoOverlay);
    private void OnInfoBackdropTapped(object? sender, TappedEventArgs e) => UiFx.Hide(InfoOverlay);
    private void OnCloseOutputs(object? sender, EventArgs e) => UiFx.Hide(OutputsOverlay);
    private void OnOutputsBackdropTapped(object? sender, TappedEventArgs e) => UiFx.Hide(OutputsOverlay);

    // 工具
    private void ShowInfo(string title, string text)
    {
        InfoTitle.Text = title;
        InfoText.Text = text;
        UiFx.Reveal(InfoOverlay);
    }

    private async void OnInspect(object? sender, EventArgs e)
    {
        try
        {
            MainActivity.NoteExternalLaunch();
            var f = await FilePicker.Default.PickAsync();
            if (f is null) return;
            string p = f.FullPath ?? "";
            string local = PtdToolkit.Materialize(p);
            try
            {
                var info = await Task.Run(() => PtdToolkit.Info(local));
                string s = L10n.F("容器版本：v{0}\n", info.Version)
                    + L10n.F("载荷算法：{0}\n", info.ModeName)
                    + L10n.F("压缩：{0}\n", info.CompressName)
                    + L10n.F("原始大小：{0}\n", VaultItem.FormatSize(info.OrigSize))
                    + L10n.F("分块：{0} 块 × {1}\n", info.TotalChunks, VaultItem.FormatSize(info.ChunkSize))
                    + L10n.F("Argon2id：opslimit {0}，内存 {1} MiB\n", info.OpsLimit, info.MemLimitKb / 1024)
                    + L10n.F("盐：{0}\n", info.SaltHex)
                    + L10n.F("Nonce：{0}\n", info.IvHex)
                    + L10n.F("明文 Blake2b：{0}\n", info.PlainHashHex.Length > 0 ? info.PlainHashHex : L10n.T("无（旧格式）"))
                    + L10n.F("文件名信封：{0}\n", info.HasNameFooter ? L10n.T("有") : L10n.T("无"))
                    + L10n.F("密钥版本：{0}", info.DekWrapped ? info.KeyVersion + L10n.T("（DEK 已包裹，可改密）") : L10n.T("无（旧格式不可改密）"));
                ShowInfo(L10n.T("密文信息"), s);
            }
            finally { PtdToolkit.Delete(local); }
        }
        catch (Exception ex) { ShowMsg(L10n.T("读取密文信息失败：") + ex.Message); }
    }

    private async void OnHash(object? sender, EventArgs e)
    {
        try
        {
            MainActivity.NoteExternalLaunch();
            var f = await FilePicker.Default.PickAsync();
            if (f is null) return;
            string p = f.FullPath ?? "";
            string hex = await Task.Run(() => FileCryptoService.Hash(p));
            ShowInfo(L10n.T("明文 Blake2b-256"), L10n.F("文件：{0}\n\n{1}", DisplayOf(p), hex));
        }
        catch (Exception ex) { ShowMsg(L10n.T("计算哈希失败：") + ex.Message); }
    }

    private async void OnRewrap(object? sender, EventArgs e)
    {
        try
        {
            MainActivity.NoteExternalLaunch();
            var f = await FilePicker.Default.PickAsync();
            if (f is null) return;
            string p = f.FullPath ?? "";
            string local = PtdToolkit.Materialize(p);
            try
            {
                var info = await Task.Run(() => PtdToolkit.Info(local));
                if (!info.DekWrapped)
                { ShowMsg(L10n.F("该文件是 v{0} 旧格式，不支持改密；请重新加密。", info.Version)); return; }
            }
            finally { PtdToolkit.Delete(local); }
            _rewrapPath = p;
            RwOld.Text = ""; RwNew.Text = ""; RwNew2.Text = "";
            UiFx.Reveal(RewrapOverlay);
        }
        catch (Exception ex) { ShowMsg(L10n.T("改密失败：") + ex.Message); }
    }

    private void OnRewrapCancel(object? sender, EventArgs e) => UiFx.Hide(RewrapOverlay);
    private void OnRewrapBackdropTapped(object? sender, TappedEventArgs e) => UiFx.Hide(RewrapOverlay);

    private async void OnRewrapApply(object? sender, EventArgs e)
    {
        string oldPw = RwOld.Text ?? "", n1 = RwNew.Text ?? "", n2 = RwNew2.Text ?? "";
        if (oldPw.Length == 0) { ShowMsg(L10n.T("请输入旧密码")); return; }
        if (n1.Length == 0) { ShowMsg(L10n.T("请输入新密码")); return; }
        if (n1 != n2) { ShowMsg(L10n.T("两次输入的新密码不一致")); return; }
        if (n1 != oldPw && !PasswordPolicy.Check(n1, out string weak))
        {
            if (!await DisplayAlertAsync(L10n.T("密码强度不足"), weak + L10n.T("\n仍要使用这个密码？"), L10n.T("继续"), L10n.T("重新输入")))
                return;
        }
        UiFx.Hide(RewrapOverlay);
        string path = _rewrapPath;
        string local = "";
        byte[]? o = null, n = null;
        try
        {
            local = PtdToolkit.Materialize(path);
            o = Secret.From(oldPw);
            n = Secret.From(n1);
            await Task.Run(() => PtdToolkit.Rewrap(local, o, n));
            // content:// 无写权限
            string src = local;
            if (src != path)
            {
                string dst = Path.Combine(_outDir, Path.GetFileName(PtdToolkit.BasePtdOf(path).Length > 0
                    ? PtdToolkit.BasePtdOf(path) : DisplayOf(path)));
                string unique = Unique(dst);
                File.Copy(src, unique, true);
                ShowMsg(L10n.T("改密完成：") + unique + L10n.T("。使用后请及时清理。"));
            }
            else ShowMsg(L10n.T("改密完成，原文件已原地更新。"));
        }
        catch (Exception ex) { ShowMsg(L10n.T("改密失败：") + ex.Message); }
        finally
        {
            Secret.Wipe(o); Secret.Wipe(n);
            PtdToolkit.Delete(local);
            _rewrapPath = "";
            RwOld.Text = ""; RwNew.Text = ""; RwNew2.Text = "";
        }
    }

    private void OnManageOutputs(object? sender, EventArgs e)
    {
        try
        {
            OutputsList.Children.Clear();
            var files = ListOutputs(_outDir);
            OutputsHint.Text = files.Count == 0 ? L10n.T("暂无输出文件。")
                : L10n.F("共 {0} 个文件 · {1}", files.Count, _outDir)
                  + (IsDefaultOutDir(_outDir) ? "" : L10n.T("（仅列出本应用生成的文件）"));
            foreach (var path in files.Take(200))
            {
                var row = new Grid { ColumnDefinitions = new ColumnDefinitionCollection(
                    new ColumnDefinition(GridLength.Star), new ColumnDefinition(GridLength.Auto),
                    new ColumnDefinition(GridLength.Auto)), ColumnSpacing = 6,
                    Padding = new Thickness(0, 6) };
                row.Children.Add(new Label { Text = Path.GetFileName(path), FontSize = 13,
                    LineBreakMode = LineBreakMode.MiddleTruncation, VerticalOptions = LayoutOptions.Center });
                var share = new Button { Text = L10n.T("分享"), Style = Res("QuietButton") as Style,
                    FontSize = 12, Padding = new Thickness(6, 2) };
                share.Clicked += async (s, a) =>
                {
                    MainActivity.NoteExternalLaunch();
                    try { await Share.Default.RequestAsync(new ShareFileRequest(
                        new ShareFile(path)) { Title = Path.GetFileName(path) }); }
                    catch { }
                };
                Grid.SetColumn(share, 1);
                row.Children.Add(share);
                var del = new Button { Text = L10n.T("删除"), Style = Res("QuietButton") as Style,
                    FontSize = 12, Padding = new Thickness(6, 2) };
                del.Clicked += (s, a) =>
                {
                    try
                    {
                        DeleteOutput(path);
                        OutputRegistry.Forget(new[] { path });
                    }
                    catch { }
                    OnManageOutputs(this, EventArgs.Empty);
                };
                Grid.SetColumn(del, 2);
                row.Children.Add(del);
                OutputsList.Children.Add(row);
                OutputsList.Children.Add(new BoxView { Style = Res("Divider") as Style });
            }
            UiFx.Reveal(OutputsOverlay);
        }
        catch (Exception ex) { ShowMsg(L10n.T("读取输出目录失败：") + ex.Message); }
    }

    private async void OnDeleteAllOutputs(object? sender, EventArgs e)
    {
        if (!await DisplayAlertAsync(L10n.T("删除全部输出"),
                L10n.T("删除本应用生成的输出文件（含明文），无法恢复。继续？"), L10n.T("确认删除"), L10n.T("取消"))) return;
        try
        {
            int n = await Task.Run(() =>
            {
                var files = ListOutputs(_outDir);
                int k = 0;
                foreach (var f in files) k += DeleteOutput(f);
                OutputRegistry.Forget(files);
                return k;
            });
            UiFx.Hide(OutputsOverlay);
            ShowMsg(L10n.F("已删除 {0} 个输出文件。", n));
        }
        catch (Exception ex) { ShowMsg(L10n.T("清理失败：") + ex.Message); }
    }

    // 自定义目录可能
    private static bool IsDefaultOutDir(string dir)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(VaultStorageHelper.ExportDir()).TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private static List<string> ListOutputs(string dir)
    {
        if (IsDefaultOutDir(dir))
        {
            try { return Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).ToList(); }
            catch { return new List<string>(); }
        }
        return OutputRegistry.InDir(dir);
    }

    private static int DeleteOutput(string path)
    {
        int n = 0;
        try
        {
            if (File.Exists(path)) { File.Delete(path); return 1; }
            if (!Directory.Exists(path)) return 0;
            foreach (string f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            { try { File.Delete(f); n++; } catch { } }
            try { Directory.Delete(path, true); } catch { }
        }
        catch { }
        return n;
    }

    private static void CollectOutputs(List<string> sink, string outPath, JobOptions opt)
    {
        if (opt.Enc && opt.SplitBytes > 0)
        {
            string bp = PtdToolkit.BasePtdOf(outPath);
            if (bp.Length > 0)
            {
                for (int v = 1; v <= 999; v++)
                {
                    string vp = PtdToolkit.VolumePath(bp, v);
                    if (!File.Exists(vp)) break;
                    sink.Add(vp);
                    if (opt.Sha) sink.Add(vp + ".sha256");
                }
                return;
            }
        }
        sink.Add(outPath);
        if (opt.Enc && opt.Sha) sink.Add(outPath + ".sha256");
    }

    // 主流程
    private sealed record JobOptions(
        bool Enc, bool DelSrc, bool Force, bool Restore, bool Sha, bool Pack,
        ulong SplitBytes, string OutDir, bool DirMode, string Root,
        FeMMode Mode, int Compress, Dictionary<string, string> OutNames,
        bool Asym, byte[] AsymData);

    private async void OnRun(object? sender, EventArgs e)
    {
        string pwd = EntryPwd.Text ?? "";
        string weak = "";
        string asymText = _encrypting ? (EdtRecips.Text ?? "") : (EdtIdentity.Text ?? "");
        if (_inputs.Count == 0) { ShowMsg(L10n.T("请先选择文件或目录")); return; }
        if (_asymMode && !_asymOk)
        { ShowMsg(L10n.T("当前版本不支持钥匙加密。")); return; }
        if (_asymMode && asymText.Trim().Length == 0)
        {
            ShowMsg(_encrypting ? L10n.T("请填写对方的钥匙") : L10n.T("请填写我的钥匙"));
            return;
        }
        if (!_asymMode && pwd.Length == 0) { ShowMsg(L10n.T("请输入密码")); return; }
        if (!_asymMode && _encrypting && pwd != (EntryPwd2.Text ?? ""))
        { ShowMsg(L10n.T("两次输入的密码不一致")); return; }
        if (!_asymMode && _encrypting && !PasswordPolicy.Check(pwd, out weak))
        {
            if (!await DisplayAlertAsync(L10n.T("密码强度不足"), weak + L10n.T("\n仍要使用这个密码？"), L10n.T("继续"), L10n.T("重新输入")))
                return;
        }
        if (_algoIndex < 0 || _algoIndex >= _algos.Count) { ShowMsg(L10n.T("请选择算法")); return; }
        CipherModeInfo mode = _algos[_algoIndex];
        if (_encrypting && !mode.Available)
        { ShowMsg(L10n.F("所选算法不可用（{0}），请改用其他算法", mode.UnavailableReason)); return; }

        bool enc = _encrypting;
        bool delSrc = SwDelSrc.IsToggled;
        bool force = !enc && SwForce.IsToggled;
        if (force && !await DisplayAlertAsync(L10n.T("忽略完整性校验"),
                L10n.T("将跳过完整性校验，结果可能不完整或被改动。继续？"), L10n.T("继续"), L10n.T("取消"))) return;
        int ci = _compressIndex;
        int compressLevel = ci >= 0 && ci < CompressLevels.Length
            ? CompressLevels[ci] : FileCryptoNative.CompressAuto;
        int si = PkSplit.SelectedIndex;
        ulong splitBytes = si > 0 && si < SplitBytes.Length ? SplitBytes[si] : 0;
        bool sha = enc && SwSha.IsToggled;
        bool pack = enc && SwPack.IsToggled;
        bool restore = !enc && !_asymMode && SwRestore.IsToggled;
        if (restore && !await DisplayAlertAsync(L10n.T("恢复原始文件名"),
                L10n.T("每个文件都要额外派生密钥，批量会明显变慢。继续？"), L10n.T("继续"), L10n.T("取消"))) return;

        var inputs = _inputs.ToList();
        var outNames = new Dictionary<string, string>(_outNames);
        bool dirMode = _dirMode;
        string root = _rootDir;
        string outDir = _outDir;
        var temps = new List<string>();
        byte[]? pwBytes = null;
        BatchResult res;
        string title = enc ? L10n.T("加密中") : L10n.T("解密中");
        try
        {
            pwBytes = Secret.From(_asymMode ? asymText : pwd);
            // 解密
            if (!enc) inputs = NormalizeVolumes(inputs, temps);
            // 加密
            if (pack && inputs.Count > 1)
            {
                string arch = Path.Combine(FileSystem.CacheDirectory,
                    "fem_" + Guid.NewGuid().ToString("N") + ".arch");
                string archRoot = dirMode ? root : "";
                await Task.Run(() => PtdToolkit.WriteArchive(arch, inputs, archRoot));
                temps.Add(arch);
                string name = dirMode && root.Length > 0
                    ? Path.GetFileName(root.TrimEnd('/')) + ".ptd" : "archive.ptd";
                outNames[arch] = name;
                inputs = new List<string> { arch };
                dirMode = false;
            }
            var opt = new JobOptions(enc, delSrc, force, restore, sha, pack, splitBytes,
                outDir, dirMode, root, mode.Mode, compressLevel, outNames,
                _asymMode, pwBytes!);
            res = await ProgressPage.RunAsync(this, title, (tracker, ct) => Task.Run(
                () => Process(tracker, ct, inputs, pwBytes!, opt)));
        }
        catch (Exception ex) { ShowMsg(L10n.T("处理失败：") + ex.Message); res = new BatchResult(0, 0, 0, "", new List<string> { ex.Message }); }
        finally
        {
            foreach (var t in temps) PtdToolkit.Delete(t);
            Secret.Wipe(pwBytes);
            EntryPwd.Text = "";
            EntryPwd2.Text = "";
        }

        string msg = L10n.F("成功 {0} 个", res.Ok) + (res.Failed > 0 ? L10n.F("，失败 {0} 个", res.Failed) : "")
            + (res.Remaining > 0 ? L10n.F("，剩余 {0} 个未处理", res.Remaining) : "");
        if (res.Errors.Count > 0) msg += "\n" + string.Join("\n", res.Errors);
        if (res.LastOutput.Length > 0)
            msg += L10n.F("\n\n输出：{0}", res.LastOutput)
                + (enc ? "" : L10n.T("\n解密结果是明文，用完请删除。"))
                + (enc && !delSrc ? L10n.T("\n原始文件仍保留，请自行清理。") : "");
        if (Handler is null) return;
        try
        {
            await DisplayAlertAsync(L10n.T("完成"), msg, L10n.T("确定"));
            if (res.LastOutput.Length > 0)
            {
                string? act = await Sheet.ShowAsync(L10n.T("输出文件"), L10n.T("关闭"), null,
                    L10n.T("输出文件管理"), L10n.T("分享最后一个"), L10n.T("删除最后一个"));
                if (act == L10n.T("输出文件管理")) OnManageOutputs(this, EventArgs.Empty);
                else if (act == L10n.T("分享最后一个"))
                {
                    MainActivity.NoteExternalLaunch();
                    await Share.Default.RequestAsync(new ShareFileRequest(
                        new ShareFile(res.LastOutput)) { Title = Path.GetFileName(res.LastOutput) });
                }
                else if (act == L10n.T("删除最后一个"))
                {
                    try
                    {
                        DeleteOutput(res.LastOutput);
                        OutputRegistry.Forget(new[] { res.LastOutput });
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    // 分卷归一
    private static List<string> NormalizeVolumes(List<string> inputs, List<string> temps)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var input in inputs)
        {
            string basePtd = PtdToolkit.BasePtdOf(input);
            if (basePtd.Length == 0) { result.Add(input); continue; }
            if (!seen.Add(basePtd)) continue;
            if (File.Exists(basePtd)) { result.Add(basePtd); continue; }
            string merged = Path.Combine(FileSystem.CacheDirectory,
                "fem_" + Guid.NewGuid().ToString("N") + ".ptd");
            try
            {
                PtdToolkit.MergeVolumes(input, merged);
                temps.Add(merged);
                result.Add(merged);
            }
            catch { result.Add(input); }
        }
        return result;
    }

    private static readonly object s_pathLk = new();

    private static BatchResult Process(BatchTracker tracker, CancellationToken ct,
        List<string> inputs, byte[] password, JobOptions opt)
    {
        var errors = new List<string>();
        var produced = new List<string>();
        long totalBytes = 0;
        foreach (var f in inputs)
        {
            try { long s0 = new FileInfo(f).Length; if (s0 > 0) totalBytes += s0; } catch { }
        }
        tracker.Begin(inputs.Count, totalBytes);

        int ok = 0, failed = 0, remaining = 0;
        string last = "";
        int par = Math.Clamp(Environment.ProcessorCount, 2, 16);
        var po = new ParallelOptions { MaxDegreeOfParallelism = par, CancellationToken = ct };
        try
        {
            Parallel.For(0, inputs.Count, po, i =>
            {
                string input = inputs[i];
                string name = DisplayOf(input);
                long size = 0;
                try { size = new FileInfo(input).Length; } catch { }
                tracker.StartSlot(i, i + 1, name, (ulong)Math.Max(0, size));
                string materialized = "";
                try
                {
                    string outPath;
                    lock (s_pathLk) outPath = OutputPathOf(input, opt, password, out materialized);
                    string? dir = Path.GetDirectoryName(outPath);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    string part = outPath + ".part";
                    try
                    {
                        if (opt.Asym && opt.Enc)
                            FileCryptoService.EncryptAsym(input, part, opt.AsymData, opt.Mode, opt.Compress,
                                (d, t) => tracker.ReportSlot(i, d, t));
                        else if (opt.Asym)
                            FileCryptoService.DecryptAsym(input, part, opt.AsymData, opt.Force,
                                (d, t) => tracker.ReportSlot(i, d, t));
                        else if (opt.Enc)
                            FileCryptoService.Encrypt(input, part, password, opt.Mode, opt.Compress,
                                (d, t) => tracker.ReportSlot(i, d, t));
                        else
                            FileCryptoService.Decrypt(input, part, password, opt.Force,
                                (d, t) => tracker.ReportSlot(i, d, t));
                        File.Move(part, outPath, overwrite: true);
                    }
                    catch
                    {
                        try { if (File.Exists(part)) File.Delete(part); } catch { }
                        throw;
                    }

                    // 解密产出是 FEPK1 归档
                    if (!opt.Enc && PtdToolkit.IsArchive(outPath))
                    {
                        string dest = outPath + "_取出";
                        Directory.CreateDirectory(dest);
                        int n = PtdToolkit.ExtractArchive(outPath, dest);
                        try { File.Delete(outPath); } catch { }
                        outPath = dest;
                        lock (errors) if (errors.Count < 5) errors.Add(L10n.F("{0}：归档展开 {1} 个文件", name, n));
                    }
                    if (opt.Enc && opt.SplitBytes > 0)
                    {
                        string basePtd = outPath;
                        int vols = PtdToolkit.Split(outPath, opt.SplitBytes);
                        lock (errors) if (errors.Count < 5) errors.Add(L10n.F("{0}：已切成 {1} 卷", name, vols));
                        if (opt.Sha)
                            for (int v = 1; v <= vols; v++)
                                PtdToolkit.WriteSha256Sidecar(PtdToolkit.VolumePath(basePtd, v));
                        outPath = PtdToolkit.VolumePath(basePtd, 1);
                    }
                    else if (opt.Enc && opt.Sha)
                        PtdToolkit.WriteSha256Sidecar(outPath);
                    lock (errors) CollectOutputs(produced, outPath, opt);
                    Interlocked.Increment(ref ok);
                    lock (s_pathLk) last = outPath;
                    tracker.EndSlot(i, true);
                    if (opt.DelSrc)
                    {
                        string? delErr = SourceCleaner.Delete(input);
                        if (delErr is not null)
                            lock (errors) if (errors.Count < 5) errors.Add(L10n.F("{0}：{1}", name, delErr));
                    }
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref failed);
                    tracker.EndSlot(i, false);
                    lock (errors) if (errors.Count < 5) errors.Add(L10n.F("{0}：{1}", name, ex.Message));
                }
                finally
                {
                    PtdToolkit.Delete(materialized);
                    if (IsCimCopy(input)) CacheJanitor.DeleteCim(input);
                }
            });
        }
        catch (OperationCanceledException)
        {
            remaining = inputs.Count - ok - failed;
        }
        OutputRegistry.Track(produced);
        return new BatchResult(ok, failed, Math.Max(0, remaining), last, errors);
    }

    // 输出名
    private static string OutputPathOf(string input, JobOptions opt, byte[] password,
        out string materialized)
    {
        materialized = "";
        string baseDir = opt.OutDir;
        string filePart = opt.OutNames.TryGetValue(input, out var given) ? given : DisplayOf(input);
        string outName;
        if (opt.Enc) outName = filePart + ".ptd";
        else if (opt.Restore)
        {
            try
            {
                materialized = PtdToolkit.Materialize(input);
                if (materialized != input)
                {
                    // 物化件自己
                }
                outName = PtdToolkit.OriginalName(materialized, password);
                if (outName.Length == 0) outName = FileCryptoService.DefaultOutputName(filePart, false);
            }
            catch { outName = FileCryptoService.DefaultOutputName(filePart, false); }
        }
        else outName = FileCryptoService.DefaultOutputName(filePart, false);

        if (!opt.DirMode) return Unique(Path.Combine(baseDir, outName));
        string rel = Path.GetRelativePath(opt.Root, input).Replace('\\', '/');
        string sub = Path.GetDirectoryName(rel)?.Replace('\\', '/') ?? "";
        string top = Path.GetFileName(opt.Root.TrimEnd('/'));
        if (string.IsNullOrEmpty(top)) top = L10n.T("目录");
        return Unique(Path.Combine(baseDir, opt.Enc ? top : top + "_解密", sub, outName));
    }

    private static string Unique(string path)
    {
        if (!File.Exists(path)) return path;
        string dir = Path.GetDirectoryName(path) ?? "";
        string nm = Path.GetFileNameWithoutExtension(path);
        string ex = Path.GetExtension(path);
        for (int i = 1; i < 1000; i++)
        {
            string p = Path.Combine(dir, $"{nm}({i}){ex}");
            if (!File.Exists(p)) return p;
        }
        return path;
    }

    private static bool IsCimCopy(string path)
    {
        try
        {
            string? d = Path.GetDirectoryName(path);
            return d == FileSystem.CacheDirectory
                && Path.GetFileName(path).StartsWith("cim_", StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private async void OnVerify(object? sender, EventArgs e)
    {
        try
        {
            MainActivity.NoteExternalLaunch();
            var f = await FilePicker.Default.PickAsync();
            if (f is null) return;
            byte[] pwd = Secret.From(EntryPwd.Text ?? "");
            if (pwd.Length == 0) { Secret.Wipe(pwd); ShowMsg(L10n.T("请输入密码后校验")); return; }
            string p = f.FullPath ?? "";
            bool ok = await Task.Run(() =>
            {
                try { FileCryptoService.Verify(p, pwd); return true; }
                catch { return false; }
            });
            Secret.Wipe(pwd);
            await DisplayAlertAsync(L10n.T("校验结果"), ok ? L10n.T("完整性校验通过。") : L10n.T("校验失败：密码错误或文件已被篡改。"), L10n.T("确定"));
        }
        catch (Exception ex) { ShowMsg(L10n.T("校验失败：") + ex.Message); }
    }

    // 生成密钥
    private async void OnGenerateKeypair(object? sender, EventArgs e)
    {
        if (!_asymOk) { ShowMsg(L10n.T("当前版本不支持钥匙加密。")); return; }
        try
        {
            string? algo = await Sheet.ShowAsync(L10n.T("选择钥匙类型"), L10n.T("取消"), null,
                L10n.T("后量子混合（推荐）"),
                L10n.T("X448（常规）"), L10n.T("X25519（常规）"));
            if (string.IsNullOrEmpty(algo) || algo == L10n.T("取消")) return;
            int a = algo == L10n.T("X448（常规）") ? 2
                  : algo == L10n.T("X25519（常规）") ? 1 : 3;
            var pair = await Task.Run(() => FileCryptoService.GenerateKeypair(a));
            ShowInfo(L10n.T("钥匙已生成"),
                L10n.F("交给对方：\n{0}\n\n自己保管（请离线保存）：\n{1}", pair.Pub, pair.Priv));
        }
        catch (Exception ex) { ShowMsg(L10n.T("钥匙生成失败：") + ex.Message); }
    }

    private void OnClearAsym(object? sender, EventArgs e)
    {
        EdtRecips.Text = "";
        EdtIdentity.Text = "";
    }

    // FEKW 工具
    private void OnFekw(object? sender, EventArgs e)
    {
        if (!_asymOk) { ShowMsg(L10n.T("当前版本不支持钥匙加密。")); return; }
        _fekwPath = "";
        LblFekwPath.Text = L10n.T("还没有选择钥匙文件");
        RefreshFekw();
        UiFx.Reveal(FekwOverlay);
    }

    private void OnFekwCancel(object? sender, EventArgs e) => UiFx.Hide(FekwOverlay);
    private void OnFekwBackdropTapped(object? sender, TappedEventArgs e) => UiFx.Hide(FekwOverlay);

    private void OnFekwModeChanged(object? sender, EventArgs e) => RefreshFekw();

    private void RefreshFekw()
    {
        bool unpack = PkFekwMode.SelectedIndex == 1;
        BtnFekwPick.IsVisible = unpack;
        EdtFekwKey.IsEnabled = !unpack;
        LblFekwHint.Text = unpack
            ? L10n.T("取出需要同一密码或对应的我的钥匙。")
            : L10n.T("存入后得到一个钥匙文件；留空自动生成钥匙。");
    }

    private async void OnFekwPick(object? sender, EventArgs e)
    {
        try
        {
            MainActivity.NoteExternalLaunch();
            var f = await FilePicker.Default.PickAsync();
            if (f is null) return;
            _fekwPath = PtdToolkit.Materialize(f.FullPath ?? "");
            LblFekwPath.Text = Path.GetFileName(_fekwPath);
        }
        catch (Exception ex) { ShowMsg(ex.Message); }
    }

    private async void OnFekwApply(object? sender, EventArgs e)
    {
        bool unpack = PkFekwMode.SelectedIndex == 1;
        int alg = PkFekwAlg.SelectedIndex switch { 1 => 2, 2 => 3, _ => 1 };
        string keyHex = (EdtFekwKey.Text ?? "").Trim();
        string secret = EdtFekwSecret.Text ?? "";
        byte[]? sec = null;
        byte[]? key = null;
        try
        {
            if (secret.Trim().Length == 0)
            { ShowMsg(L10n.T("请填写密码或钥匙")); return; }
            if (unpack && !File.Exists(_fekwPath))
            { ShowMsg(L10n.T("取出前请先选择钥匙文件")); return; }
            sec = System.Text.Encoding.UTF8.GetBytes(secret);
            if (unpack)
            {
                byte[] blob = await Task.Run(() => File.ReadAllBytes(_fekwPath));
                key = await Task.Run(() => FileCryptoService.KeywrapUnpack(blob, sec));
                UiFx.Hide(FekwOverlay);
                ShowInfo(L10n.T("取出的钥匙"), Convert.ToHexStringLower(key));
                return;
            }
            if (keyHex.Length == 0)
            {
                key = new byte[32];
                System.Security.Cryptography.RandomNumberGenerator.Fill(key);
            }
            else
            {
                if (keyHex.Length != 64) { ShowMsg(L10n.T("请填写 64 位字符的钥匙")); return; }
                key = Convert.FromHexString(keyHex);
            }
            byte[] outBlob = await Task.Run(() => FileCryptoService.KeywrapPack(key, sec, alg));
            string path = Path.Combine(_outDir, "key_" + Guid.NewGuid().ToString("N")[..8] + ".fekw");
            await Task.Run(() => File.WriteAllBytes(path, outBlob));
            OutputRegistry.Track(new[] { path });
            UiFx.Hide(FekwOverlay);
            ShowInfo(L10n.T("已存入"),
                L10n.F("已写出：{0}\n\n钥匙：{1}", path, Convert.ToHexStringLower(key)));
        }
        catch (Exception ex) { ShowMsg((unpack ? L10n.T("取出失败：") : L10n.T("存入失败：")) + ex.Message); }
        finally
        {
            Secret.Wipe(sec);
            Secret.Wipe(key);
            EdtFekwSecret.Text = "";
        }
    }

    private void ShowMsg(string msg)
    {
        LblMsg.Text = msg;
        LblMsg.IsVisible = true;
    }
}

public sealed record BatchResult(int Ok, int Failed, int Remaining, string LastOutput, List<string> Errors,
    List<string>? Notes = null);
