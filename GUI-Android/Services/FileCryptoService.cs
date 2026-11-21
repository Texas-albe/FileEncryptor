// 单文件加解密
// native 侧为流式实现
using System.Runtime.InteropServices;
using FileEncryptorMobile.Services;
namespace FileEncryptorMobile.Services;
public sealed class FileCryptoException : Exception
{
    public FeMError Code { get; }
    public FileCryptoException(FeMError code, string message) : base(message) => Code = code;
}
public sealed record CipherModeInfo(
    FeMMode Mode, string Name, bool Available, string Note,
    int KeyBytes, int NonceBytes, int TagBytes, bool Aead)
{
    // 密钥长度
    public string ParamText =>
        L10n.F("密钥 {0} 位 · nonce {1} 字节 · 认证标签 {2} 字节 · {3}",
        KeyBytes * 8, NonceBytes, TagBytes, Aead ? "AEAD" : L10n.T("非 AEAD"));

    public string UnavailableReason => Mode switch
    {
        FeMMode.Aegis256 => L10n.T("当前设备缺少 AES-NI"),
        FeMMode.AesGcm => L10n.T("当前设备或构建不支持 AES-GCM"),
        FeMMode.Sm4 => L10n.T("当前版本未启用国密算法"),
        _ => L10n.T("当前设备不支持该算法"),
    };
}
public static unsafe class FileCryptoService
{
    // 库加载即校验 ABI
    public static void VerifyAbi()
    {
        uint v = FileCryptoNative.fe_m_abi_version();
        if (v != FileCryptoNative.ExpectedAbiVersion)
            throw new FileCryptoException(FeMError.Internal,
                L10n.F("native ABI 版本不匹配：库 0x{0:X8}，期望 0x{1:X8}", v, FileCryptoNative.ExpectedAbiVersion));
    }
    public static IReadOnlyList<CipherModeInfo> Modes()
    {
        var list = new List<CipherModeInfo>();
        // 参数取自 CLI/core
        Add(FeMMode.XChaCha20, "XChaCha20-Poly1305", L10n.T("默认算法，抗 nonce 误用"), 32, 24, 16);
        Add(FeMMode.Aegis256, "AEGIS-256", L10n.T("需 CPU 支持 AES-NI"), 32, 32, 32);
        Add(FeMMode.AesGcm, "AES-256-GCM", L10n.T("通用 AEAD；兼容旧文件"), 32, 12, 16);
        Add(FeMMode.Sm4, "SM4-GCM", L10n.T("国密算法；需额外组件"), 16, 12, 16);
        return list;
        void Add(FeMMode m, string name, string note,
            int keyBytes, int nonceBytes, int tagBytes)
        {
            bool ok = FileCryptoNative.fe_m_mode_supported((int)m) == 1;
            list.Add(new CipherModeInfo(m, name, ok, note, keyBytes, nonceBytes, tagBytes, true));
        }
    }
    public static string ErrorText(int code)
        => FileCryptoNative.fe_m_strerror(code);
    // 打开只读 fd
    public static int OpenRead(string uriOrPath)
    {
        if (uriOrPath.StartsWith("content://", StringComparison.Ordinal))
        {
            var uri = Android.Net.Uri.Parse(uriOrPath)
                ?? throw new FileCryptoException(FeMError.Io, L10n.T("无法解析所选文件"));
            var ctx = Platform.AppContext;
            var pfd = ctx.ContentResolver!.OpenFileDescriptor(uri, "r")
                ?? throw new FileCryptoException(FeMError.Io, L10n.T("无法打开所选文件"));
            return pfd.DetachFd();   // detach 后 fd 归我们
        }
        // 应用私有目录 / 导
        int fd = LibcNative.open(uriOrPath, LibcNative.O_RDONLY, 0);
        if (fd < 0) throw new FileCryptoException(FeMError.Io, L10n.F("无法打开输入：{0}", uriOrPath));
        return fd;
    }
    // 打开只写 fd
    public static int OpenWrite(string path)
    {
        int fd = LibcNative.open(path,
            LibcNative.O_WRONLY | LibcNative.O_CREAT | LibcNative.O_TRUNC, 0x180);
        if (fd < 0) throw new FileCryptoException(FeMError.Io, L10n.F("无法创建输出：{0}", path));
        return fd;
    }
    // native 进度回调 thunk：GCHandle 托管
    // 必须是静态只读
    // 原生侧周期性回
    static readonly FeMProgressNative ProgressThunk = (d, t, user) =>
    {
        var h = GCHandle.FromIntPtr(user);
        ((Action<ulong, ulong>)h.Target!)(d, t);
    };
    // 加密
    // password 为 UTF-8 byte[]；不接管所有权
    public static long Encrypt(string inUriOrPath, string outPath,
        byte[] password, FeMMode mode, int compressLevel,
        Action<ulong, ulong>? progress)
    {
        int inFd = -1, outFd = -1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            inFd = OpenRead(inUriOrPath);
            outFd = OpenWrite(outPath);
            var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
            try
            {
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
                IntPtr user = GCHandle.ToIntPtr(handle);
                fixed (byte* pp = password)
                {
                    int rc = FileCryptoNative.fe_m_encrypt_fd(
                        inFd, 0, outFd, pp, (UIntPtr)password.Length,
                        (int)mode, compressLevel,
                        (delegate* unmanaged<ulong, ulong, IntPtr, void>)fn, user);
                    Check(rc);
                }
            }
            finally { handle.Free(); }
            return sw.ElapsedMilliseconds;
        }
        finally
        {
            Close(inFd);
            Close(outFd);
        }
    }
    // 解密
    // forceOverwrite=true 跳过明文
    // 常规路径传 false
    public static long Decrypt(string inPath, string outPath,
        byte[] password, bool forceOverwrite,
        Action<ulong, ulong>? progress)
    {
        int inFd = -1, outFd = -1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            inFd = OpenRead(inPath);
            outFd = OpenWrite(outPath);
            var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
            try
            {
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
                IntPtr user = GCHandle.ToIntPtr(handle);
                fixed (byte* pp = password)
                {
                    int rc = FileCryptoNative.fe_m_decrypt_fd(
                        inFd, outFd, pp, (UIntPtr)password.Length,
                        forceOverwrite ? 1 : 0, 0,
                        (delegate* unmanaged<ulong, ulong, IntPtr, void>)fn, user);
                    Check(rc);
                }
            }
            finally { handle.Free(); }
            return sw.ElapsedMilliseconds;
        }
        finally
        {
            Close(inFd);
            Close(outFd);
        }
    }
    // 校验密文完整性
    public static void Verify(string inPath, byte[] password)
    {
        int fd = -1;
        try
        {
            fd = OpenRead(inPath);
            fixed (byte* p = password)
            {
                Check(FileCryptoNative.fe_m_verify_fd(fd, p, (UIntPtr)password.Length));
            }
        }
        finally { Close(fd); }
    }
    // 明文 Blake2b-256
    public static string Hash(string path)
    {
        int fd = -1;
        try
        {
            fd = OpenRead(path);
            byte[] out32 = new byte[32];
            fixed (byte* o = out32)
            {
                Check(FileCryptoNative.fe_m_hash_fd(fd, 0, o));
            }
            return Convert.ToHexStringLower(out32);
        }
        finally { Close(fd); }
    }
    // 默认输出名
    public static string DefaultOutputName(string fileName, bool encrypting)
    {
        if (encrypting) return fileName + ".ptd";
        if (fileName.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase))
        {
            // 文件名恰
            if (fileName.Length <= 4) return "restored";
            return fileName[..^4];
        }
        return fileName + ".decrypted";
    }
    // 路径是否
    public static bool CanReadDirect(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        int fd = LibcNative.open(path, LibcNative.O_RDONLY, 0);
        if (fd < 0) return false;
        LibcNative.close(fd);
        return true;
    }
    // 非对称 / FEKW / 库 PQC
    // 能力探测
    public static bool AsymSupported() => FileCryptoNative.fe_m_asym_supported() == 1;

    // 生成密钥对。algo
    public static (string Pub, string Priv) GenerateKeypair(int algo)
    {
        byte[] pub = new byte[16384], priv = new byte[16384];
        int rc;
        unsafe
        {
            fixed (byte* p = pub, q = priv)
                rc = FileCryptoNative.fe_m_generate_keypair(
                    algo, p, (UIntPtr)pub.Length, q, (UIntPtr)priv.Length);
        }
        Check(rc);
        return (CStr(pub), CStr(priv));
    }

    // 收件人公钥加密
    public static long EncryptAsym(string inUriOrPath, string outPath,
        byte[] recips, FeMMode mode, int compressLevel,
        Action<ulong, ulong>? progress)
    {
        int inFd = -1, outFd = -1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            inFd = OpenRead(inUriOrPath);
            outFd = OpenWrite(outPath);
            var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
            try
            {
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
                IntPtr user = GCHandle.ToIntPtr(handle);
                fixed (byte* rp = recips)
                {
                    int rc = FileCryptoNative.fe_m_encrypt_fd_asym(
                        inFd, 0, outFd, rp, (UIntPtr)recips.Length,
                        (int)mode, compressLevel,
                        (delegate* unmanaged<ulong, ulong, IntPtr, void>)fn, user);
                    Check(rc);
                }
            }
            finally { handle.Free(); }
            return sw.ElapsedMilliseconds;
        }
        finally { Close(inFd); Close(outFd); }
    }

    // 身份私钥解密
    public static long DecryptAsym(string inPath, string outPath,
        byte[] identity, bool forceOverwrite, Action<ulong, ulong>? progress)
    {
        int inFd = -1, outFd = -1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            inFd = OpenRead(inPath);
            outFd = OpenWrite(outPath);
            var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
            try
            {
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
                IntPtr user = GCHandle.ToIntPtr(handle);
                fixed (byte* ip = identity)
                {
                    int rc = FileCryptoNative.fe_m_decrypt_fd_asym(
                        inFd, outFd, ip, (UIntPtr)identity.Length,
                        forceOverwrite ? 1 : 0, 0,
                        (delegate* unmanaged<ulong, ulong, IntPtr, void>)fn, user);
                    Check(rc);
                }
            }
            finally { handle.Free(); }
            return sw.ElapsedMilliseconds;
        }
        finally { Close(inFd); Close(outFd); }
    }

    // FEKW 包装。alg
    public static byte[] KeywrapPack(byte[] key, byte[] secret, int alg)
    {
        byte[] blob = new byte[65536];
        int rc;
        UIntPtr len;
        unsafe
        {
            fixed (byte* k = key, s = secret, o = blob)
                rc = FileCryptoNative.fe_m_keywrap_pack(
                    k, (UIntPtr)key.Length, s, (UIntPtr)secret.Length, alg,
                    o, (UIntPtr)blob.Length, out len);
        }
        Check(rc);
        return blob[..(int)len];
    }

    // FEKW 解包
    public static byte[] KeywrapUnpack(byte[] blob, byte[] secret)
    {
        byte[] key = new byte[256];
        int rc;
        UIntPtr len;
        unsafe
        {
            fixed (byte* b = blob, s = secret, o = key)
                rc = FileCryptoNative.fe_m_keywrap_unpack(
                    b, (UIntPtr)blob.Length, s, (UIntPtr)secret.Length,
                    o, (UIntPtr)key.Length, out len);
        }
        Check(rc);
        return key[..(int)len];
    }

    // 库主密码 PQC 封装
    public static (byte[] Blob, byte[] Priv) PqcSeal(byte[] pass, byte[] vaultSalt)
    {
        byte[] blob = new byte[65536], priv = new byte[16384];
        int rc;
        UIntPtr len;
        unsafe
        {
            fixed (byte* p = pass, sa = vaultSalt, o = blob, pr = priv)
                rc = FileCryptoNative.fe_m_pqc_seal(
                    p, (UIntPtr)pass.Length, sa, (UIntPtr)vaultSalt.Length,
                    o, (UIntPtr)blob.Length, out len,
                    pr, (UIntPtr)priv.Length);
        }
        Check(rc);
        return (blob[..(int)len], CStrBytes(priv));
    }

    // 解封
    public static byte[] PqcOpen(byte[] blob, byte[] priv, byte[] vaultSalt)
    {
        byte[] pass = new byte[4096];
        int rc;
        UIntPtr len;
        unsafe
        {
            fixed (byte* b = blob, pr = priv, sa = vaultSalt, o = pass)
                rc = FileCryptoNative.fe_m_pqc_open(
                    b, (UIntPtr)blob.Length, pr, (UIntPtr)priv.Length,
                    sa, (UIntPtr)vaultSalt.Length,
                    o, (UIntPtr)pass.Length, out len);
        }
        Check(rc);
        return pass[..(int)len];
    }

    // 水印签名
    // 加密时附带签名水印
    public static long EncryptWm(string inUriOrPath, string outPath,
        byte[] password, FeMMode mode, int compressLevel,
        string wmPrivPem, bool wmPqc, Action<ulong, ulong>? progress)
    {
        int inFd = -1, outFd = -1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            inFd = OpenRead(inUriOrPath);
            outFd = OpenWrite(outPath);
            var handle = GCHandle.Alloc(progress ?? ((d, t) => { }));
            try
            {
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(ProgressThunk);
                IntPtr user = GCHandle.ToIntPtr(handle);
                fixed (byte* pp = password)
                {
                    int rc = FileCryptoNative.fe_m_encrypt_fd_wm(
                        inFd, 0, outFd, pp, (UIntPtr)password.Length,
                        (int)mode, compressLevel,
                        wmPrivPem, wmPqc ? 1 : 0,
                        (delegate* unmanaged<ulong, ulong, IntPtr, void>)fn, user);
                    Check(rc);
                }
            }
            finally { handle.Free(); }
            return sw.ElapsedMilliseconds;
        }
        finally { Close(inFd); Close(outFd); }
    }

    // 水印校验结果
    public sealed record WatermarkInfo(
        bool Found, bool HasSignature, bool VerifyAttempted, bool VerifyOk,
        ulong Timestamp, int Flags, string MachineIdHex, string NonceHex, string Error);

    // 校验密文水印
    // pubPem 为 null 时只展示不验签
    public static WatermarkInfo WmVerify(string ptdPath, string? pubPem, bool pqc)
    {
        byte[] buf = new byte[8192];
        int rc;
        unsafe
        {
            fixed (byte* o = buf)
                rc = FileCryptoNative.fe_m_wm_verify(
                    ptdPath, pubPem, pqc ? 1 : 0, o, (UIntPtr)buf.Length);
        }
        Check(rc);
        string json = CStr(buf);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var r = doc.RootElement;
        bool found = r.GetProperty("found").GetBoolean();
        if (!found) return new WatermarkInfo(false, false, false, false, 0, 0, "", "", "");
        bool hasSig = TryBool(r, "has_signature");
        bool attempt = TryBool(r, "verify_attempted");
        bool ok = TryBool(r, "verify_ok");
        ulong ts = TryULong(r, "timestamp");
        int flags = TryInt(r, "flags");
        string mid = TryStr(r, "machine_id_hex");
        string nonce = TryStr(r, "nonce_hex");
        string err = TryStr(r, "error");
        return new WatermarkInfo(found, hasSig, attempt, ok, ts, flags, mid, nonce, err);
    }

    static bool TryBool(System.Text.Json.JsonElement r, string k)
        => r.TryGetProperty(k, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.True;
    static ulong TryULong(System.Text.Json.JsonElement r, string k)
        => r.TryGetProperty(k, out var v) && v.TryGetUInt64(out var x) ? x : 0;
    static int TryInt(System.Text.Json.JsonElement r, string k)
        => r.TryGetProperty(k, out var v) && v.TryGetInt32(out var x) ? x : 0;
    static string TryStr(System.Text.Json.JsonElement r, string k)
        => r.TryGetProperty(k, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() ?? "" : "";

    // 生成水印签名密钥
    public static (string Pub, string Priv) WmGenerateKeypair(bool pqc)
    {
        byte[] pub = new byte[16384], priv = new byte[16384];
        int rc;
        unsafe
        {
            fixed (byte* p = pub, q = priv)
                rc = FileCryptoNative.fe_m_wm_generate_keypair(
                    pqc ? 1 : 0, p, (UIntPtr)pub.Length, q, (UIntPtr)priv.Length);
        }
        Check(rc);
        return (CStr(pub), CStr(priv));
    }

    static string CStr(byte[] b)
    {
        int n = Array.IndexOf(b, (byte)0);
        return System.Text.Encoding.UTF8.GetString(b, 0, n < 0 ? b.Length : n);
    }

    static byte[] CStrBytes(byte[] b)
    {
        int n = Array.IndexOf(b, (byte)0);
        return b[..(n < 0 ? b.Length : n)];
    }

    static void Check(int rc)
    {
        if (rc == 0) return;
        var code = (FeMError)rc;
        string msg = code switch
        {
            FeMError.Auth => L10n.T("密码错误或文件已被篡改"),
            FeMError.Hash => L10n.T("完整性校验失败"),
            FeMError.Unsup => L10n.T("当前构建不支持该算法"),
            FeMError.Io => L10n.T("读写失败"),
            _ => ErrorText(rc),
        };
        throw new FileCryptoException(code, msg);
    }
    static void Close(int fd)
    {
        if (fd < 0) return;
        LibcNative.close(fd);
    }
}