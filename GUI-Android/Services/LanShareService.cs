// 局域网只读共享
// 鉴权分两段
// /api/pair
// /api/login
// 防「只知道密码
// 配对码每次启动
// 防同网段中间人
// 与手机界面显示
// 传输
// 按 512KB 随机读
// 同一浏览器
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

internal sealed class HttpReq
{
    public string Method = "";
    public string Path = "";
    public Dictionary<string, string> Query = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
    public byte[] Body = Array.Empty<byte>();
}

public sealed class LanShareService : IDisposable
{
    private const string IdleKey = "lan_idle_minutes";
    private const string RateKey = "lan_rate_bps";
    private const string DevKey = "lan_max_devices";

    // 配对码字母表
    private const string CodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    // 单次共享绝
    private const int MaxSessionMinutes = 60;

    // 空闲自动锁库
    public static int IdleMinutes
    {
        get => Math.Clamp(Preferences.Default.Get(IdleKey, 1), 1, 60);
        set => Preferences.Default.Set(IdleKey, Math.Clamp(value, 1, 60));
    }

    // 下载限速档位
    public static int RateBytesPerSec
    {
        get => Math.Clamp(Preferences.Default.Get(RateKey, 0), 0, 100 * 1024 * 1024);
        set => Preferences.Default.Set(RateKey, Math.Clamp(value, 0, 100 * 1024 * 1024));
    }

    // 持有有效
    public static int MaxDevices
    {
        get => Math.Clamp(Preferences.Default.Get(DevKey, 0), 0, 8);
        set => Preferences.Default.Set(DevKey, Math.Clamp(value, 0, 8));
    }

    public static LanShareService? Current { get; private set; }

    private readonly VaultService _vault;
    private TcpListener? _listener;
    private X509Certificate2? _cert;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<string, (DateTime Exp, string Ip)> _pairTokens = new();
    private readonly ConcurrentDictionary<string, (DateTime Exp, string Ip)> _tokens = new();
    // 活动连接
    private readonly ConcurrentDictionary<SslStream, byte> _conns = new();
    private readonly object _gate = new();
    private int _pairFailCount;
    private DateTime _pairFailSince = DateTime.MinValue;
    private int _loginFailCount;
    private DateTime _loginFailSince = DateTime.MinValue;
    private DateTime _lastReq = DateTime.UtcNow;
    private DateTime _sessionStartUtc = DateTime.UtcNow;
    private long _lastProgressTicks;
    private volatile int _active;          // 正在处理请求
    private string _pairCodeRaw = "";
    private byte[]? _page;

    public string Url { get; private set; } = "";
    public volatile string PairCode = "";        // 一次性配对码
    public volatile string CertPrint = "";       // 证书指纹
    public volatile string LastTransferText = ""; // 最近一次传输
    public bool Running => _listener is not null;

    // 配对码轮换 / 停服 /
    public event Action? StateChanged;

    public LanShareService(VaultService vault) => _vault = vault;

    private void RaiseChanged()
    {
        try { StateChanged?.Invoke(); } catch { }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_listener is not null) return;
            if (!_vault.IsUnlocked)
                throw new InvalidOperationException(L10n.T("请先解锁加密库，再开启共享。"));
            string ip = PickWifiIpv4()
                ?? throw new InvalidOperationException(L10n.T("未检测到 Wi-Fi，请先连接。"));

            _cert = CreateCert(ip);
            CertPrint = Fingerprint(_cert);
            _pairCodeRaw = NewPairCode();
            PairCode = FormatCode(_pairCodeRaw);
            LastTransferText = "";
            _page = null;
            _pairTokens.Clear();
            _conns.Clear();
            _pairFailCount = 0; _pairFailSince = DateTime.MinValue;
            _loginFailCount = 0; _loginFailSince = DateTime.MinValue;

            var listener = new TcpListener(IPAddress.Parse(ip), 0);
            listener.Start();
            _listener = listener;
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            Url = $"https://{ip}:{port}/";
            _lastReq = DateTime.UtcNow;
            _sessionStartUtc = DateTime.UtcNow;
            Volatile.Write(ref _lastProgressTicks, DateTime.UtcNow.Ticks);
            AccessLog.Clear();   // 只保留本次
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            Current = this;
            VaultService.SessionLocked += OnVaultLocked;
            _ = Task.Run(() => AcceptLoop(listener, ct));
            _ = Task.Run(() => IdleLoop(ct));
        }
        RaiseChanged();
    }

    public void Stop()
    {
        SslStream[] toClose;
        lock (_gate)
        {
            if (_listener is null && _cts is null) return;
            try { _listener?.Stop(); } catch { }
            _listener = null;
            try { _cts?.Cancel(); } catch { }
            _cts = null;
            try { _cert?.Dispose(); } catch { }
            _cert = null;
            _tokens.Clear();
            _pairTokens.Clear();
            AccessLog.Clear();   // 停服/锁库
            _pairFailCount = 0; _pairFailSince = DateTime.MinValue;
            _loginFailCount = 0; _loginFailSince = DateTime.MinValue;
            Url = "";
            PairCode = "";
            CertPrint = "";
            LastTransferText = "";
            VaultService.SessionLocked -= OnVaultLocked;
            if (Current == this) Current = null;
            // 断开全部活动连
            toClose = _conns.Keys.ToArray();
            _conns.Clear();
        }
        // 关闭放锁外
        if (toClose.Length > 0)
            _ = Task.Run(() =>
            {
                foreach (var s in toClose) { try { s.Dispose(); } catch { } }
            });
        RaiseChanged();
    }

    public void Dispose() => Stop();

    private void OnVaultLocked()
    {
        // 库一旦锁定
        Stop();
    }

    // 网络
    // 局域网
    private static string? PickWifiIpv4()
    {
        try
        {
            var fallback = new List<string>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                string lower = ni.Name.ToLowerInvariant();
                bool mobile = lower.StartsWith("rmnet") || lower.StartsWith("ccmni")
                    || lower.StartsWith("pdp") || lower.StartsWith("wwan");
                if (mobile) continue;
                bool wifi = ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
                    || lower.StartsWith("wlan");
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString();
                    if (s.StartsWith("169.254.") || IPAddress.IsLoopback(ua.Address)) continue;
                    if (wifi) return s;
                    fallback.Add(s);
                }
            }
            return fallback.Count > 0 ? fallback[0] : null;
        }
        catch { }
        return null;
    }

    private static X509Certificate2 CreateCert(string ip)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=FileEncryptor LanShare", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Parse(ip));
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-10),
            DateTimeOffset.UtcNow.AddHours(24));
        // SslStream 在部分平台要求
        try
        {
            byte[] pfx = cert.Export(X509ContentType.Pfx);
            cert.Dispose();
            return new X509Certificate2(pfx);
        }
        catch { return cert; }
    }

    // 证书指纹
    private static string Fingerprint(X509Certificate2 cert)
    {
        byte[] h = SHA256.HashData(cert.RawData);
        var sb = new StringBuilder(16);
        for (int i = 0; i < 12; i++)
        {
            int v = (h[i / 2] >> ((i % 2 == 0) ? 4 : 0)) & 0xF;
            sb.Append(CodeAlphabet[v]);
            if (i == 3 || i == 7) sb.Append('-');
        }
        return sb.ToString();
    }

    // 一次性配对码
    private static string NewPairCode()
    {
        var sb = new StringBuilder(8);
        var rnd = RandomNumberGenerator.GetBytes(8);
        foreach (byte b in rnd) sb.Append(CodeAlphabet[b & 0x1F]);
        return sb.ToString();
    }

    private static string FormatCode(string raw)
        => raw.Length >= 8 ? raw[..4] + "-" + raw[4..] : raw;

    // 归一化
    private static string NormalizeCode(string s)
    {
        var sb = new StringBuilder(12);
        foreach (char ch in s.ToUpperInvariant())
        {
            char c = ch;
            if (c == '-' || c == ' ' || c == '_') continue;
            if (c == 'O') c = '0';
            else if (c == 'I' || c == 'L') c = '1';
            if (CodeAlphabet.IndexOf(c) < 0) return "";
            sb.Append(c);
        }
        return sb.ToString();
    }

    // 常数时间比较
    private static bool FixedEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private bool Cancelled => _cts?.IsCancellationRequested == true;

    // 设备数上限
    private bool DeviceLimitReached(string ip)
    {
        int limit = MaxDevices;
        if (limit <= 0) return false;
        var now = DateTime.UtcNow;
        var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in _pairTokens.Values) if (v.Exp > now) ips.Add(v.Ip);
        foreach (var v in _tokens.Values) if (v.Exp > now) ips.Add(v.Ip);
        ips.Add(ip);
        return ips.Count > limit;
    }

    private async Task AcceptLoop(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct); }
            catch { break; }
            _ = Task.Run(() => HandleConn(client));
        }
    }

    private async Task HandleConn(TcpClient client)
    {
        SslStream? ssl = null;
        try
        {
            using (client)
            {
                client.NoDelay = true;
                client.ReceiveTimeout = 20000;   // 空闲 keep-alive 连接
                client.SendTimeout = 120000;
                var tcp = client.GetStream();
                ssl = new SslStream(tcp, false);
                var cert = _cert;
                if (cert is null) return;
                await ssl.AuthenticateAsServerAsync(cert, false,
                    SslProtocols.Tls12 | SslProtocols.Tls13, false);
                _conns[ssl] = 0;
                string ip = client.Client.RemoteEndPoint is IPEndPoint ep ? ep.Address.ToString() : "";

                // keep-alive
                while (!Cancelled && _listener is not null)
                {
                    var req = await ReadRequest(ssl);
                    if (req is null) break;
                    _lastReq = DateTime.UtcNow;
                    bool keepAlive = ShouldKeepAlive(req);
                    Interlocked.Increment(ref _active);
                    try { keepAlive = await Route(ssl, req, ip, keepAlive); }
                    finally { Interlocked.Decrement(ref _active); }
                    if (!keepAlive) break;
                }
            }
        }
        catch { /* 连接级错误不影响服务 */ }
        finally
        {
            if (ssl is not null)
            {
                _conns.TryRemove(ssl, out _);
                try { ssl.Dispose(); } catch { }
            }
        }
    }

    private static bool ShouldKeepAlive(HttpReq req)
    {
        string c = req.Headers.GetValueOrDefault("Connection", "");
        return !c.Equals("close", StringComparison.OrdinalIgnoreCase);
    }

    private async Task IdleLoop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(5000, ct);
                var now = DateTime.UtcNow;
                long prog = Volatile.Read(ref _lastProgressTicks);
                // 仅实际进度续期
                if (prog > _lastReq.Ticks) _lastReq = new DateTime(prog, DateTimeKind.Utc);
                // 会话绝对上限
                bool expired = now - _sessionStartUtc >= TimeSpan.FromMinutes(MaxSessionMinutes);
                if (!expired && now - _lastReq < TimeSpan.FromMinutes(IdleMinutes)) continue;
                // 到点先停服
                Stop();
                VaultService.NoteLockReason(expired
                    ? L10n.T("共享时长达上限，已自动锁定") : L10n.T("共享空闲超时，已自动锁定"));
                try { _vault.Lock(); } catch { }
                return;
            }
        }
        catch (OperationCanceledException) { }
        catch { }
    }

    // ---- HTTP ----
    private static async Task<HttpReq?> ReadRequest(Stream s)
    {
        var head = new StringBuilder();
        var buf = new byte[1];
        while (head.Length < 8192)
        {
            int n = await s.ReadAsync(buf.AsMemory(0, 1));
            if (n <= 0) return null;
            head.Append((char)buf[0]);
            string cur = head.ToString();
            if (cur.EndsWith("\r\n\r\n", StringComparison.Ordinal)) break;
        }
        var lines = head.ToString().Split("\r\n");
        if (lines.Length == 0) return null;
        var parts = lines[0].Split(' ');
        if (parts.Length < 2) return null;
        var req = new HttpReq { Method = parts[0].ToUpperInvariant() };
        string target = parts[1];
        int q = target.IndexOf('?');
        req.Path = q < 0 ? target : target[..q];
        if (q >= 0)
            foreach (var kv in target[(q + 1)..].Split('&'))
            {
                int e = kv.IndexOf('=');
                if (e < 0) req.Query[Uri.UnescapeDataString(kv)] = "";
                else req.Query[Uri.UnescapeDataString(kv[..e])] = Uri.UnescapeDataString(kv[(e + 1)..]);
            }
        for (int i = 1; i < lines.Length; i++)
        {
            int c = lines[i].IndexOf(':');
            if (c <= 0) continue;
            req.Headers[lines[i][..c].Trim()] = lines[i][(c + 1)..].Trim();
        }
        int len = 0;
        if (int.TryParse(req.Headers.GetValueOrDefault("Content-Length", "0"), out int cl))
            len = Math.Clamp(cl, 0, 64 * 1024);
        if (len > 0)
        {
            var body = new byte[len];
            int got = 0;
            while (got < len)
            {
                int n = await s.ReadAsync(body.AsMemory(got, len - got));
                if (n <= 0) break;
                got += n;
            }
            req.Body = got == len ? body : body[..got];
        }
        return req;
    }

    private static async Task Send(Stream s, int code, string reason, string contentType,
        byte[] body, bool headOnly = false, bool keepAlive = false, string? extraHeader = null)
    {
        var sb = new StringBuilder();
        sb.Append($"HTTP/1.1 {code} {reason}\r\n");
        sb.Append($"Content-Type: {contentType}\r\n");
        sb.Append($"Content-Length: {body.Length}\r\n");
        sb.Append("Cache-Control: no-store\r\n");
        sb.Append("X-Content-Type-Options: nosniff\r\n");
        sb.Append(keepAlive ? "Connection: keep-alive\r\n" : "Connection: close\r\n");
        if (extraHeader is not null) sb.Append(extraHeader).Append("\r\n");
        sb.Append("\r\n");
        await s.WriteAsync(Encoding.UTF8.GetBytes(sb.ToString()));
        if (!headOnly) await s.WriteAsync(body);
        await s.FlushAsync();
    }

    private async Task<bool> Route(Stream s, HttpReq req, string ip, bool keepAlive)
    {
        if (req.Method == "GET" || req.Method == "HEAD")
        {
            if (req.Path == "/" || req.Path == "/index.html")
            {
                await Send(s, 200, "OK", "text/html; charset=utf-8", PageBytes(),
                    req.Method == "HEAD", keepAlive);
                return keepAlive;
            }
            if (req.Path == "/favicon.ico")
            {
                await Send(s, 204, "No Content", "text/plain", Array.Empty<byte>(),
                    false, keepAlive);
                return keepAlive;
            }
            if (req.Path == "/api/list")
            {
                if (!Authorized(req)) { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip)); await Json(s, 401, "{\"error\":\"unauthorized\"}", keepAlive); return keepAlive; }
                await HandleList(s, req, keepAlive);
                return keepAlive;
            }
            if (req.Path == "/api/download")
            {
                if (!Authorized(req)) { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip)); await Json(s, 401, "{\"error\":\"unauthorized\"}", keepAlive); return keepAlive; }
                return await HandleDownload(s, req, req.Method == "HEAD", keepAlive);
            }
        }
        else if (req.Method == "POST" && req.Path == "/api/pair")
        {
            await HandlePair(s, req, ip, keepAlive);
            return keepAlive;
        }
        else if (req.Method == "POST" && req.Path == "/api/login")
        {
            await HandleLogin(s, req, ip, keepAlive);
            return keepAlive;
        }
        AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip));
        await Send(s, 404, "Not Found", "text/plain; charset=utf-8",
            Encoding.UTF8.GetBytes("Not found"), false, keepAlive);
        return keepAlive;
    }

    private static async Task Json(Stream s, int code, string json, bool keepAlive = false)
        => await Send(s, code, code == 200 ? "OK" : "Error", "application/json; charset=utf-8",
            Encoding.UTF8.GetBytes(json), false, keepAlive);

    private bool Authorized(HttpReq req)
    {
        string tok = req.Headers.GetValueOrDefault("Authorization", "");
        if (tok.StartsWith("Bearer ")) tok = tok[7..].Trim();
        else tok = req.Query.GetValueOrDefault("t", "");
        if (tok.Length == 0) return false;
        if (!_tokens.TryGetValue(tok, out var te)) return false;
        return te.Exp > DateTime.UtcNow;
    }

    // 第一段
    private async Task HandlePair(Stream s, HttpReq req, string ip, bool keepAlive)
    {
        string code;
        try
        {
            using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(req.Body));
            code = doc.RootElement.GetProperty("code").GetString() ?? "";
        }
        catch { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip)); await Json(s, 400, "{\"error\":\"bad request\"}", keepAlive); return; }

        var now = DateTime.UtcNow;
        if (_pairFailCount >= 5 && now - _pairFailSince < TimeSpan.FromMinutes(5))
        {
            AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip));
            await Json(s, 429, "{\"error\":\"too many attempts\"}", keepAlive);
            return;
        }

        string raw = NormalizeCode(code);
        string expect = _pairCodeRaw;
        bool ok = raw.Length > 0 && expect.Length > 0 && FixedEquals(raw, expect);
        if (!ok)
        {
            if (now - _pairFailSince >= TimeSpan.FromMinutes(5)) { _pairFailCount = 1; _pairFailSince = now; }
            else _pairFailCount++;
            AccessLog.Add(AccessEventKind.PairFail, AccessLog.Tag(ip));
            await Json(s, 401, "{\"error\":\"wrong pair code\"}", keepAlive);
            return;
        }

        if (DeviceLimitReached(ip))
        {
            AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip));
            await Json(s, 429, "{\"error\":\"device limit reached\"}", keepAlive);
            return;
        }

        // 配对成功
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _pairTokens[token] = (now.AddMinutes(10), ip);
        _pairCodeRaw = NewPairCode();
        PairCode = FormatCode(_pairCodeRaw);
        _pairFailCount = 0;
        _pairFailSince = DateTime.MinValue;
        _lastReq = now;
        AccessLog.Add(AccessEventKind.PairOk, AccessLog.Tag(ip));
        RaiseChanged();
        await Json(s, 200, "{\"pair\":\"" + token + "\"}", keepAlive);
    }

    // 第二段
    private async Task HandleLogin(Stream s, HttpReq req, string ip, bool keepAlive)
    {
        var now0 = DateTime.UtcNow;
        string ptok = req.Headers.GetValueOrDefault("X-Pair-Token", "");
        if (ptok.Length == 0) ptok = req.Query.GetValueOrDefault("pair", "");
        if (ptok.Length == 0 || !_pairTokens.TryGetValue(ptok, out var pe)
            || pe.Exp <= now0 || !pe.Ip.Equals(ip, StringComparison.OrdinalIgnoreCase))
        {
            AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip));
            await Json(s, 403, "{\"error\":\"pairing required\"}", keepAlive);
            return;
        }

        string bodyText = Encoding.UTF8.GetString(req.Body);
        string pwd;
        try
        {
            using var doc = JsonDocument.Parse(bodyText);
            pwd = doc.RootElement.GetProperty("password").GetString() ?? "";
        }
        catch { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip)); await Json(s, 400, "{\"error\":\"bad request\"}", keepAlive); return; }

        var now = DateTime.UtcNow;
        if (_loginFailCount >= 5 && now - _loginFailSince < TimeSpan.FromMinutes(5))
        {
            AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip));
            await Json(s, 429, "{\"error\":\"too many attempts\"}", keepAlive);
            return;
        }

        bool ok;
        try
        {
            // native 只读口令比
            var zbuf = Encoding.UTF8.GetBytes(pwd + "\0");
            try { ok = _vault.VerifyPassword(zbuf); }
            finally { Array.Clear(zbuf); }
        }
        catch { ok = false; }

        if (!ok)
        {
            if (now - _loginFailSince >= TimeSpan.FromMinutes(5)) { _loginFailCount = 1; _loginFailSince = now; }
            else _loginFailCount++;
            AccessLog.Add(AccessEventKind.LoginFail, AccessLog.Tag(ip));
            await Json(s, 401, "{\"error\":\"wrong password\"}", keepAlive);
            return;
        }

        _loginFailCount = 0;
        _loginFailSince = DateTime.MinValue;
        _pairTokens.TryRemove(ptok, out _);   // pair token 一次性
        if (DeviceLimitReached(ip))
        {
            AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(ip));
            await Json(s, 429, "{\"error\":\"device limit reached\"}", keepAlive);
            return;
        }
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _tokens[token] = (DateTime.UtcNow.AddHours(12), ip);
        _lastReq = DateTime.UtcNow;
        AccessLog.Add(AccessEventKind.LoginOk, AccessLog.Tag(ip));
        await Json(s, 200, "{\"token\":\"" + token + "\"}", keepAlive);
    }

    private async Task HandleList(Stream s, HttpReq req, bool keepAlive)
    {
        string path = req.Query.GetValueOrDefault("path", "");
        if (!SafeVaultPath(path)) { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(path)); await Json(s, 400, "{\"error\":\"bad path\"}", keepAlive); return; }
        try
        {
            var items = _vault.ListDir(path);
            var arr = new List<Dictionary<string, object>>();
            foreach (var it in items)
            {
                if (VaultService.IsReservedPath(it.RelPath)) continue;
                arr.Add(new Dictionary<string, object>
                {
                    ["name"] = it.Name,
                    ["path"] = it.RelPath,
                    ["dir"] = it.IsDir,
                    ["size"] = it.Size,
                    ["mtime"] = it.Mtime.ToString("yyyy-MM-dd HH:mm"),
                });
            }
            string parent = "";
            int slash = path.LastIndexOf('/');
            if (slash > 0) parent = path[..slash];
            string json = JsonSerializer.Serialize(new { path, parent, items = arr });
            await Json(s, 200, json, keepAlive);
        }
        catch (Exception ex) { await Json(s, 404, "{\"error\":\"" + JsonNest(ex.Message) + "\"}", keepAlive); }
    }

    private static string JsonNest(string s)
        => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", " ");

    // 下载
    private async Task<bool> HandleDownload(Stream s, HttpReq req, bool headOnly, bool keepAlive)
    {
        string path = req.Query.GetValueOrDefault("path", "");
        if (!SafeVaultPath(path) || path.Length == 0)
        { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(path)); await Send(s, 400, "Bad Request", "text/plain", Encoding.UTF8.GetBytes("bad path"), false, keepAlive); return keepAlive; }
        if (VaultService.IsReservedPath(path))
        { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(path)); await Send(s, 403, "Forbidden", "text/plain", Encoding.UTF8.GetBytes("forbidden"), false, keepAlive); return keepAlive; }
        if (!_vault.TryGetAttr(path, out ulong size, out bool isDir) || isDir)
        { AccessLog.Add(AccessEventKind.Denied, AccessLog.Tag(path)); await Send(s, 404, "Not Found", "text/plain", Encoding.UTF8.GetBytes("not found"), false, keepAlive); return keepAlive; }

        AccessLog.Add(AccessEventKind.Download, AccessLog.Tag(path));
        string name = path[(path.LastIndexOf('/') + 1)..];
        string disp = "attachment; filename*=UTF-8''" + Uri.EscapeDataString(name);
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 200 OK\r\n");
        sb.Append("Content-Type: application/octet-stream\r\n");
        sb.Append($"Content-Length: {size}\r\n");
        sb.Append($"Content-Disposition: {disp}\r\n");
        sb.Append("Cache-Control: no-store\r\n");
        sb.Append("X-Content-Type-Options: nosniff\r\n");
        sb.Append(keepAlive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n");
        await s.WriteAsync(Encoding.UTF8.GetBytes(sb.ToString()));
        if (headOnly) { await s.FlushAsync(); return keepAlive; }

        bool intact = await StreamExportAsync(s, path, size);
        return keepAlive && intact;   // 传输残缺时必须
    }

    // 管道桥接
    private async Task<bool> StreamExportAsync(Stream ssl, string path, ulong size)
    {
        var sw = Stopwatch.StartNew();
        // 末段窗口
        ulong winBytes = 0;
        double winT = 0;
        double lastMbps = 0;
        int rate = RateBytesPerSec;   // 单次下载取一次
        bool limited = rate > 0;      // 不限速时写循环
        Android.OS.ParcelFileDescriptor[] pipe;
        try { pipe = Android.OS.ParcelFileDescriptor.CreatePipe(); }
        catch { return false; }

        var readEnd = pipe[0];
        int writeFd = -1;
        Exception? nativeError = null;
        ulong sent = 0;
        try
        {
            writeFd = pipe[1].DetachFd();
            try { pipe[1].Dispose(); } catch { }
            int fd = writeFd;
            var task = Task.Run(() =>
            {
                try
                {
                    _vault.ExportFd(path, fd,
                    (d, t) => Volatile.Write(ref _lastProgressTicks, DateTime.UtcNow.Ticks));
                }
                catch (Exception ex) { nativeError = ex; }
                finally { try { LibcNative.close(fd); } catch { } }
            });

            var stream = new Java.IO.FileInputStream(readEnd.FileDescriptor);
            var buf = new byte[256 * 1024];
            try
            {
                while (!Cancelled && _vault.IsUnlocked)
                {
                    int n;
                    try { n = stream.Read(buf, 0, buf.Length); }
                    catch { break; }
                    if (n <= 0) break;
                    await ssl.WriteAsync(buf.AsMemory(0, n));
                    sent += (ulong)n;
                    double t = sw.Elapsed.TotalSeconds;
                    if (t - winT >= 1.0)
                    {
                        lastMbps = ((sent - winBytes) / 1048576.0) / (t - winT);
                        winBytes = sent;
                        winT = t;
                    }
                    Volatile.Write(ref _lastProgressTicks, DateTime.UtcNow.Ticks);
                    if (limited) await ThrottleAsync(sw, sent, rate);
                }
            }
            finally
            {
                // 先断开读端
                try { stream.Close(); } catch { }
            }
            try { await task; } catch { }
        }
        finally
        {
            if (writeFd >= 0) { try { LibcNative.close(writeFd); } catch { } }
            try { readEnd.Dispose(); } catch { }
        }

        double sec = sw.Elapsed.TotalSeconds;
        double tail = sec - winT;
        double mbps = tail > 0.2 ? ((sent - winBytes) / 1048576.0) / tail : lastMbps;
        LastTransferText = L10n.F("最近传输 {0} / {1:F1} 秒，末段 {2:F1} MB/s", Fmt.Bytes((long)sent), sec, mbps);
        RaiseChanged();
        return nativeError is null && sent >= size;
    }

    // 限速
    private async Task ThrottleAsync(Stopwatch sw, ulong sent, int rate)
    {
        double wait = sent / (double)rate - sw.Elapsed.TotalSeconds;
        if (wait <= 0 || Cancelled) return;
        await Task.Delay(TimeSpan.FromSeconds(wait));
    }

    // 虚拟路径校验
    private static bool SafeVaultPath(string p)
    {
        if (p.Length > 1024) return false;
        if (p.Contains('\0') || p.Contains('\\')) return false;
        foreach (var seg in p.Split('/'))
        {
            if (seg == ".." || seg == ".") return false;
            if (seg.Length > 255) return false;
        }
        return true;
    }

    // 内置页面
    // 页面内绝不包含
    private byte[] PageBytes()
    {
        if (_page is not null) return _page;
        string html = """
<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FileEncryptor 加密库 · 只读共享</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1b1f24;--muted:#5b6472;--card:#fff;--pri:#3c66b5}
@media(prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#f1f3f6;--muted:#a6aeba;--card:#1e2227;--pri:#6f94e0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:8px 0 4px}.sub{color:var(--muted);font-size:13px;margin-bottom:12px}
.card{background:var(--card);border:1px solid rgba(128,128,128,.2);border-radius:12px;padding:14px;margin-bottom:12px}
input{width:100%;padding:10px;border-radius:8px;border:1px solid rgba(128,128,128,.3);background:transparent;color:inherit;font-size:15px;letter-spacing:.06em}
button{padding:10px 16px;border:0;border-radius:8px;background:var(--pri);color:#fff;font-size:15px;width:100%;margin-top:10px}
.row{display:flex;align-items:center;gap:10px;padding:10px 4px;border-bottom:1px solid rgba(128,128,128,.15);text-decoration:none;color:inherit}
.row:last-child{border-bottom:0}.nm{flex:1;word-break:break-all}.meta{color:var(--muted);font-size:12px;white-space:nowrap}
.bc{font-size:13px;color:var(--muted);margin:8px 0}.bc a{color:var(--pri);text-decoration:none}
#msg{color:#d0453c;font-size:13px;margin-top:8px;min-height:18px}
.step{font-size:12px;color:var(--muted);margin:0 0 8px}
</style></head><body><div class="wrap">
<h1>加密库 · 只读共享</h1>
<div class="sub">仅当手机端加密库处于解锁状态时可访问；手机锁屏/离开应用/空闲超时后连接立即失效。<br>
<b>先核对证书指纹</b>：浏览器证书详情里的 SHA-256 指纹前 12 位，必须与手机界面显示的「证书指纹」完全一致，否则立即停止访问（可能有人在中间伪装）。</div>

<div class="card" id="pair">
  <div class="step">第 1 步 / 共 2 步：输入手机屏幕上显示的一次性配对码</div>
  <input id="pc" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder=L10n.T("例如 3F7K-92QT")>
  <button id="pb">验证配对码</button>
</div>

<div class="card" id="login" style="display:none">
  <div class="step">第 2 步 / 共 2 步：配对码已通过，输入加密库密码</div>
  <input id="pwd" type="password" autocomplete="current-password" placeholder=L10n.T("加密库密码")>
  <button id="btn">解锁浏览</button>
</div>

<div class="card" id="browse" style="display:none">
  <div class="bc" id="bc"></div>
  <div id="list"></div>
</div>
<div id="msg"></div>
<div class="sub">配对码一次性使用：验证成功后旧码立即失效，手机屏幕会显示新码。如浏览器提示证书不受信任，请选择「继续访问」——这是每次启动临时生成的自签名证书。</div>
</div>
<script>
const $=id=>document.getElementById(id);
let token=sessionStorage.getItem('felt')||'';
let pairTok=sessionStorage.getItem('fepair')||'';
const listEl=$('list');
function esc(s){return s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function setMsg(t){$('msg').textContent=t||''}
function showPair(){$('pair').style.display='';$('login').style.display='none';$('browse').style.display='none'}
function showLogin(){$('pair').style.display='none';$('login').style.display='';$('browse').style.display='none'}
function showBrowse(){$('pair').style.display='none';$('login').style.display='none';$('browse').style.display=''}
function clearSession(){token='';pairTok='';sessionStorage.removeItem('felt');sessionStorage.removeItem('fepair')}
async function api(path,opt){
  const r=await fetch(path,Object.assign({headers:{'Authorization':'Bearer '+token}},opt||{}));
  if(r.status===401){clearSession();if(sessionStorage.getItem('fepair'))showLogin();else showPair();setMsg('会话已失效，请重新验证配对码');throw new Error('401')}
  return r;
}
async function load(path){
  const r=await api('/api/list?path='+encodeURIComponent(path));
  const j=await r.json();
  const bc=$('bc');bc.innerHTML='';
  const segs=path.split('/').filter(Boolean);
  const mk=(t,p,cur)=>{const a=document.createElement('a');a.href='#';a.textContent=t;if(cur)a.style.color='inherit';else a.onclick=e=>{e.preventDefault();load(p)};bc.appendChild(a)};
  mk('根目录','',segs.length===0);
  let acc='';
  segs.forEach((seg,i)=>{acc=acc?acc+'/'+seg:seg;bc.appendChild(document.createTextNode(' / '));mk(seg,acc,i===segs.length-1)});
  listEl.innerHTML='';
  if(path){const a=document.createElement('a');a.className='row';a.href='#';a.innerHTML='<span class="nm">.. 上级目录</span>';a.onclick=e=>{e.preventDefault();load(j.parent)};listEl.appendChild(a)}
  if(!j.items.length){listEl.innerHTML+='<div class="sub" style="padding:10px 4px">（空目录）</div>'}
  for(const it of j.items){
    const a=document.createElement('a');a.className='row';a.href='#';
    a.innerHTML='<span class="nm">'+esc(it.name)+(it.dir?'/':'')+'</span><span class="meta">'+(it.dir?'目录':fmt(it.size))+' · '+esc(it.mtime)+'</span>';
    if(it.dir){a.onclick=e=>{e.preventDefault();load(it.path)}}
    else{a.href='/api/download?t='+encodeURIComponent(token)+'&path='+encodeURIComponent(it.path);a.download=it.name}
    listEl.appendChild(a);
  }
  showBrowse();
}
function fmt(n){if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';if(n<1073741824)return (n/1048576).toFixed(1)+' MB';return (n/1073741824).toFixed(2)+' GB'}
$('pb').onclick=async()=>{
  const code=$('pc').value.trim();if(!code){setMsg('请输入手机屏幕上的配对码');return}
  setMsg('');
  try{
    const r=await fetch('/api/pair',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
    if(!r.ok){setMsg(r.status===429?'尝试过于频繁，请稍后再试':'配对码不正确或已失效');return}
    const j=await r.json();pairTok=j.pair;sessionStorage.setItem('fepair',pairTok);
    $('pc').value='';showLogin();$('pwd').focus();
  }catch(e){setMsg('连接失败：'+e.message)}
};
$('btn').onclick=async()=>{
  const pwd=$('pwd').value;if(!pwd){setMsg('请输入加密库密码');return}
  setMsg('');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Pair-Token':pairTok},body:JSON.stringify({password:pwd})});
    if(!r.ok){
      if(r.status===403){clearSession();showPair();setMsg('配对已失效，请重新输入手机上的新配对码');return}
      setMsg(r.status===429?'尝试过于频繁，请稍后再试':'密码不正确');return;
    }
    const j=await r.json();token=j.token;sessionStorage.setItem('felt',token);
    sessionStorage.removeItem('fepair');pairTok='';
    $('pwd').value='';
    load('');
  }catch(e){setMsg('连接失败：'+e.message)}
};
if(token){load('')}else if(pairTok){showLogin()}else{showPair()}
</script></body></html>
""";
        _page = Encoding.UTF8.GetBytes(html);
        return _page;
    }
}
