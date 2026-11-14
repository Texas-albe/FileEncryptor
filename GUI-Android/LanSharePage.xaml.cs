// 局域网只读共享
// 共享服务独立于
// 开启前必弹安全
using System.Threading;
using FileEncryptorMobile.Services;
using FileEncryptorMobile.Views;

namespace FileEncryptorMobile;

public partial class LanSharePage : ContentPage
{
    private static readonly int[] IdleOptions = { 1, 3, 5, 10, 30, 60 };
    private static readonly int[] RateOptions = { 0, 262144, 1048576, 5242880, 20971520 };
    private static readonly int[] DevOptions = { 0, 1, 2, 3, 5 };
    private const int CooldownSeconds = 5;

    private readonly VaultService _vault = VaultService.Shared;
    private LanShareService? _svc;
    private LanShareService? _subscribed;
    private CancellationTokenSource? _cooldown;
    private bool _syncUi;
    // 开启意图
    // 保证倒计时结束
    private int _stateGen;
    private int _warnGen;   // 当前警告层对应

    public LanSharePage()
    {
        InitializeComponent();
        SyncIdle();
        SyncRate();
        SyncDev();
        _svc = LanShareService.Current;
        Subscribe();
        SyncShareUi();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        VaultService.SessionLocked -= OnVaultLocked;
        VaultService.SessionLocked += OnVaultLocked;
        _svc = LanShareService.Current;
        Subscribe();
        SyncShareUi();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        VaultService.SessionLocked -= OnVaultLocked;
        Unsubscribe();
        // 离开页面即作废
        _stateGen++;
        HideWarn();
        CancelCooldown();
        StopLogTimer();
    }

    private void OnVaultLocked()
    {
        // 库锁定
        MainThread.BeginInvokeOnMainThread(() =>
        {
            _stateGen++;
            HideWarn();
            CancelCooldown();
            _svc = LanShareService.Current;
            Subscribe();
            SyncShareUi();
        });
    }

    private void Subscribe()
    {
        if (_subscribed == _svc) return;
        if (_subscribed is not null) _subscribed.StateChanged -= OnSvcChanged;
        _subscribed = _svc;
        if (_subscribed is not null) _subscribed.StateChanged += OnSvcChanged;
    }

    private void Unsubscribe()
    {
        if (_subscribed is null) return;
        _subscribed.StateChanged -= OnSvcChanged;
        _subscribed = null;
    }

    private void OnSvcChanged()
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            _svc = LanShareService.Current;
            Subscribe();
            SyncShareUi();
        });
    }

    private void SyncIdle()
    {
        PkIdle.ItemsSource = IdleOptions.Select(m => L10n.F("{0} 分钟", m)).ToArray();
        int v = LanShareService.IdleMinutes;
        int idx = Array.IndexOf(IdleOptions, v);
        PkIdle.SelectedIndex = idx >= 0 ? idx : 0;
    }

    private void OnIdleChanged(object? sender, EventArgs e)
    {
        int idx = PkIdle.SelectedIndex;
        if (idx < 0 || idx >= IdleOptions.Length) return;
        LanShareService.IdleMinutes = IdleOptions[idx];
    }

    private void SyncRate()
    {
        PkRate.ItemsSource = RateOptions.Select(r => r == 0 ? L10n.T("不限速")
            : r >= 1048576 ? L10n.F("{0} MB/s", r / 1048576) : L10n.F("{0} KB/s", r / 1024)).ToArray();
        int v = LanShareService.RateBytesPerSec;
        int idx = Array.IndexOf(RateOptions, v);
        PkRate.SelectedIndex = idx >= 0 ? idx : 0;
    }

    private void OnRateChanged(object? sender, EventArgs e)
    {
        int idx = PkRate.SelectedIndex;
        if (idx < 0 || idx >= RateOptions.Length) return;
        LanShareService.RateBytesPerSec = RateOptions[idx];
    }

    private void SyncDev()
    {
        PkDev.ItemsSource = DevOptions.Select(d => d == 0 ? L10n.T("不限") : L10n.F("{0} 台", d)).ToArray();
        int v = LanShareService.MaxDevices;
        int idx = Array.IndexOf(DevOptions, v);
        PkDev.SelectedIndex = idx >= 0 ? idx : 0;
    }

    private void OnDevChanged(object? sender, EventArgs e)
    {
        int idx = PkDev.SelectedIndex;
        if (idx < 0 || idx >= DevOptions.Length) return;
        LanShareService.MaxDevices = DevOptions[idx];
    }

    private void SyncShareUi()
    {
        _syncUi = true;
        bool on = _svc?.Running == true && _vault.IsUnlocked;
        SwShare.IsToggled = on;
        ShareInfo.IsVisible = on;
        // 二维码
        ClearQr();
        if (on && _svc is not null)
        {
            LblUrl.Text = _svc.Url;
            LblCode.Text = _svc.PairCode;
            LblCert.Text = _svc.CertPrint;
            LblSpeed.Text = _svc.LastTransferText;
            LblSpeed.IsVisible = LblSpeed.Text.Length > 0;
            LblState.Text = L10n.T("已开启（只读）；锁定或超时自动停止。");
            ShowQr(_svc.PairCode);
        }
        else
        {
            LblUrl.Text = "";
            LblCode.Text = "";
            LblCert.Text = "";
            LblSpeed.Text = "";
            LblSpeed.IsVisible = false;
            // 倒计时期间
            if (_cooldown is null)
            {
                LblState.Text = _vault.IsUnlocked
                    ? L10n.T("开启后，同一 Wi-Fi 的设备可用浏览器访问。")
                    : L10n.T("请先解锁加密库，再开启共享。");
            }
        }
        if (LogOverlay.IsVisible) RenderLog();
        _syncUi = false;
    }

    private void OnShareToggled(object? sender, ToggledEventArgs e)
    {
        if (_syncUi) return;
        int gen = ++_stateGen;
        if (!e.Value)
        {
            // 关闭开关 = 唯一
            HideWarn();
            CancelCooldown();
            _svc?.Stop();
            _svc = LanShareService.Current;
            SyncShareUi();
            return;
        }

        if (!_vault.IsUnlocked)
        {
            SetSwitch(false);
            SyncShareUi();
            return;
        }

        int idle = LanShareService.IdleMinutes;
        LblWarnBody.Text =
            L10n.F("· 只读：对方只能浏览和下载\n") +
            L10n.F("· {0} 分钟无任何请求会自动停止共享并锁定加密库\n", idle) +
            L10n.F("· 首次访问先输入手机上的配对码\n") +
            L10n.F("· 传输经 TLS 加密；请核对浏览器证书指纹与手机一致\n") +
            L10n.F("· 「继续」{0} 秒后可用，点击立即开启\n", CooldownSeconds) +
            L10n.F("· 冷静期内取消或关掉开关即可中止");
        _warnGen = gen;
        BtnWarnGo.IsEnabled = false;
        WarnOverlay.IsVisible = true;
        _ = RunWarnCountdownAsync(gen);
    }

    private void OnWarnCardTapped(object? sender, TappedEventArgs e) { }   // 卡片吞点击

    private void OnWarnCancel(object? sender, EventArgs e)
    {
        HideWarn();
        _stateGen++;
        CancelCooldown();
        SetSwitch(false);
        SyncShareUi();
    }

    private void OnWarnContinue(object? sender, EventArgs e)
    {
        int gen = _warnGen;
        HideWarn();
        if (gen == 0 || gen != _stateGen || !SwShare.IsToggled || !_vault.IsUnlocked)
        {
            SetSwitch(false);
            SyncShareUi();
            return;
        }
        _ = StartShareAsync(gen);
    }

    private void HideWarn()
    {
        WarnOverlay.IsVisible = false;
        _warnGen = 0;
        CancelCooldown();
        BtnWarnGo.Text = L10n.T("继续");
        BtnWarnGo.IsEnabled = true;
    }

    private void SetSwitch(bool on)
    {
        _syncUi = true;
        SwShare.IsToggled = on;
        _syncUi = false;
    }

    private void CancelCooldown()
    {
        var c = _cooldown;
        _cooldown = null;
        try { c?.Cancel(); } catch { }
    }

    // 警告弹窗内
    // 期间取消警告层 /
    private async Task RunWarnCountdownAsync(int gen)
    {
        CancelCooldown();
        var cts = new CancellationTokenSource();
        _cooldown = cts;
        try
        {
            BtnWarnGo.Text = L10n.F("继续（{0}s）", CooldownSeconds);
            for (int i = CooldownSeconds - 1; i >= 0; i--)
            {
                await Task.Delay(1000, cts.Token);
                if (gen != _warnGen || !WarnOverlay.IsVisible) return;
                BtnWarnGo.Text = i > 0 ? L10n.F("继续（{0}s）", i) : L10n.T("继续");
            }
            BtnWarnGo.IsEnabled = true;
        }
        catch (OperationCanceledException)
        {
            // 冷静期内取消
        }
        finally
        {
            if (_cooldown == cts) _cooldown = null;
            cts.Dispose();
        }
    }

    // 冷静期结束
    private async Task StartShareAsync(int gen)
    {
        try
        {
            if (gen != _stateGen || !SwShare.IsToggled || !_vault.IsUnlocked) return;
            var svc = new LanShareService(_vault);
            svc.Start();
            _svc = svc;
        }
        catch (Exception ex)
        {
            _svc = null;
            SetSwitch(false);
            await DisplayAlertAsync(L10n.T("无法开启共享"), ex.Message, L10n.T("确定"));
        }
        finally
        {
            _svc = LanShareService.Current;
            Subscribe();
            SyncShareUi();
        }
    }

    private void ClearQr()
    {
        QrView.Drawable = null;
        QrView.Invalidate();
        QrBox.IsVisible = false;
    }

    private void ShowQr(string code)
    {
        if (code.Length == 0) return;
        try
        {
            QrView.Drawable = new QrDrawable(QrCode.Encode(code));
            QrView.Invalidate();
            QrBox.IsVisible = true;
        }
        catch { ClearQr(); }
    }

    private Microsoft.Maui.Dispatching.IDispatcherTimer? _logTimer;
    private string? _logSig;   // 上一帧快照签名

    private void OnLogOpen(object? sender, EventArgs e)
    {
        _logSig = null;
        RenderLog();
        LogOverlay.IsVisible = true;
        StartLogTimer();
    }

    private void OnLogRefresh(object? sender, EventArgs e) => RenderLog();

    private void OnLogClose(object? sender, EventArgs e)
    {
        LogOverlay.IsVisible = false;
        StopLogTimer();
    }

    private void OnLogCardTapped(object? sender, TappedEventArgs e) { }

    // 弹层可见期间每
    private void StartLogTimer()
    {
        StopLogTimer();
        var t = Dispatcher.CreateTimer();
        t.Interval = TimeSpan.FromMilliseconds(800);
        t.Tick += (_, _) =>
        {
            if (!LogOverlay.IsVisible) { StopLogTimer(); return; }
            RenderLog();
        };
        _logTimer = t;
        t.Start();
    }

    private void StopLogTimer()
    {
        var t = _logTimer;
        _logTimer = null;
        try { t?.Stop(); } catch { }
    }

    private void RenderLog()
    {
        var items = AccessLog.Snapshot();
        string sig = items.Length == 0 ? "0" : $"{items.Length}|{items[^1].Time.Ticks}|{(int)items[^1].Kind}";
        if (sig == _logSig) return;
        _logSig = sig;
        LogList.Children.Clear();
        LblLogCount.Text = items.Length == 0
            ? L10n.T("暂无记录。")
            : L10n.F("共 {0} 条（最多保留 200 条）。", items.Length);
        Style? rowStyle = null;
        var app = Application.Current;
        if (app is not null && app.Resources.TryGetValue("Caption", out var res))
            rowStyle = res as Style;
        foreach (var it in items)
        {
            var label = new Label
            {
                Text = $"{it.Time:HH:mm:ss}  {AccessLog.KindTextEn(it.Kind)}  {it.Tag}",
            };
            if (rowStyle is not null) label.Style = rowStyle;
            LogList.Children.Add(label);
        }
        try { _ = LogScroll.ScrollToAsync(LogScroll.Content, ScrollToPosition.End, false); } catch { }
    }

    private async void OnClose(object? sender, EventArgs e)
    {
        // 关闭页面不停止
        await Navigation.PopModalAsync();
    }
}
