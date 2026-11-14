// .ptd 辅助工具
// 归档
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

public sealed record PtdInfo(
    int Version, int Mode, uint OpsLimit, uint MemLimitKb, string SaltHex, string IvHex,
    ulong OrigSize, uint ChunkSize, uint TotalChunks, string PlainHashHex,
    bool HasNameFooter, int Compression, int CompLevel, bool DekWrapped, uint KeyVersion)
{
    public string ModeName => Mode switch
    {
        1 => "XChaCha20-Poly1305",
        2 => "AEGIS-256",
        3 => "AES-256-GCM",
        4 => "SM4-GCM",
        _ => L10n.T("未知(") + Mode + ")",
    };
    public string CompressName => Compression == 0 ? L10n.T("未压缩") : L10n.F("zstd（级别 {0}）", CompLevel);
}

public static class PtdToolkit
{
    private const string TempPrefix = "fem_";
    private static readonly byte[] ArchiveMagic = { (byte)'F', (byte)'E', (byte)'P', (byte)'K', (byte)'1', 13, 10, 0 };
    private static readonly byte[] ArchiveTrailer = { (byte)'F', (byte)'E', (byte)'P', (byte)'K', (byte)'E', (byte)'N', (byte)'D', (byte)'!' };
    private const ulong MinVolume = 1UL << 20;

    // content
    // 本地可读路径直
    public static string Materialize(string uriOrPath, string ext = ".ptd")
    {
        if (!uriOrPath.StartsWith("content://", StringComparison.Ordinal)) return uriOrPath;
        var uri = global::Android.Net.Uri.Parse(uriOrPath)
            ?? throw new IOException(L10n.T("无法解析所选文件"));
        var ctx = Platform.AppContext;
        using var input = ctx.ContentResolver!.OpenInputStream(uri)
            ?? throw new IOException(L10n.T("无法打开所选文件"));
        string tmp = Path.Combine(FileSystem.CacheDirectory, TempPrefix + Guid.NewGuid().ToString("N") + ext);
        using (var fs = File.Create(tmp)) input.CopyTo(fs);
        return tmp;
    }

    public static void Delete(string path)
    {
        if (string.IsNullOrEmpty(path)) return;
        if (!Path.GetFileName(path).StartsWith(TempPrefix, StringComparison.Ordinal)) return;
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    // 只读头部信息
    public static unsafe PtdInfo Info(string ptdPath)
    {
        byte[] buf = new byte[4096];
        int rc;
        fixed (byte* o = buf) rc = FileCryptoNative.fe_m_info(ptdPath, o, (UIntPtr)buf.Length);
        if (rc != 0) throw new FileCryptoException((FeMError)rc, L10n.T("读取密文信息失败：") + FileCryptoService.ErrorText(rc));
        int n = Array.IndexOf(buf, (byte)0);
        string json = Encoding.UTF8.GetString(buf, 0, n < 0 ? buf.Length : n);
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        int GetI(string k) => r.GetProperty(k).GetInt32();
        uint GetU(string k) => r.GetProperty(k).GetUInt32();
        ulong GetL(string k) => r.GetProperty(k).GetUInt64();
        string GetS(string k) => r.GetProperty(k).GetString() ?? "";
        return new PtdInfo(GetI("version"), GetI("mode"), GetU("opslimit"), GetU("memlimit_kb"),
            GetS("salt_hex"), GetS("iv_hex"), GetL("orig_size"), GetU("chunk_size"), GetU("total_chunks"),
            GetS("plaintext_hash_hex"), r.GetProperty("has_name_footer").GetBoolean(),
            GetI("compression"), GetI("comp_level"), r.GetProperty("dek_wrapped").GetBoolean(),
            GetU("key_version"));
    }

    // 恢复容器内加密
    public static unsafe string OriginalName(string ptdPath, byte[] password)
    {
        byte[] buf = new byte[1024];
        fixed (byte* p = password)
        fixed (byte* o = buf)
        {
            int rc = FileCryptoNative.fe_m_original_name(ptdPath, p, (UIntPtr)password.Length,
                o, (UIntPtr)buf.Length);
            if (rc != 0) throw new FileCryptoException((FeMError)rc, L10n.T("恢复原始文件名失败：") + FileCryptoService.ErrorText(rc));
        }
        int n = Array.IndexOf(buf, (byte)0);
        return Encoding.UTF8.GetString(buf, 0, n < 0 ? buf.Length : n);
    }

    // v6 改密
    public static unsafe void Rewrap(string ptdPath, byte[] oldPassword, byte[] newPassword)
    {
        fixed (byte* o = oldPassword)
        fixed (byte* n = newPassword)
        {
            int rc = FileCryptoNative.fe_m_rewrap(ptdPath, o, (UIntPtr)oldPassword.Length,
                n, (UIntPtr)newPassword.Length);
            if (rc != 0) throw new FileCryptoException((FeMError)rc,
                rc == (int)FeMError.Auth ? L10n.T("旧密码错误，或容器不是 v6 / 头部已被篡改。") : FileCryptoService.ErrorText(rc));
        }
    }

    // 归档 FEPK1
    // root 非空
    public static void WriteArchive(string archivePath, IReadOnlyList<string> files, string root)
    {
        using var fs = File.Create(archivePath);
        byte[] head = new byte[32];
        ArchiveMagic.CopyTo(head, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(head.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(head.AsSpan(12), (uint)files.Count);
        ulong total = 0;
        foreach (var f in files) { try { total += (ulong)new FileInfo(f).Length; } catch { } }
        BinaryPrimitives.WriteUInt64LittleEndian(head.AsSpan(16), total);
        fs.Write(head);

        foreach (var f in files)
        {
            string rel = !string.IsNullOrEmpty(root)
                ? Path.GetRelativePath(root, f).Replace('\\', '/')
                : Path.GetFileName(f);
            long size = 0;
            try { size = new FileInfo(f).Length; } catch { }
            byte[] pathBytes = Encoding.UTF8.GetBytes(rel);
            byte[] rec = new byte[28];
            BinaryPrimitives.WriteUInt32LittleEndian(rec.AsSpan(0), (uint)pathBytes.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(rec.AsSpan(4), 0);
            BinaryPrimitives.WriteUInt64LittleEndian(rec.AsSpan(8), (ulong)size);
            BinaryPrimitives.WriteUInt32LittleEndian(rec.AsSpan(16), 0x1A4);
            long mt = 0;
            try { mt = new DateTimeOffset(File.GetLastWriteTimeUtc(f)).ToUnixTimeSeconds(); } catch { }
            BinaryPrimitives.WriteInt64LittleEndian(rec.AsSpan(20), mt);
            fs.Write(rec);
            fs.Write(pathBytes);
            using (var src = File.OpenRead(f))
            {
                byte[] buf = new byte[1 << 20];
                long left = size;
                while (left > 0)
                {
                    int want = (int)Math.Min(left, buf.Length);
                    int got = src.Read(buf, 0, want);
                    if (got <= 0) break;
                    fs.Write(buf, 0, got);
                    left -= got;
                }
            }
        }
        byte[] tail = new byte[16];
        ArchiveTrailer.CopyTo(tail, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(tail.AsSpan(8), total);
        fs.Write(tail);
    }

    public static bool IsArchive(string plainPath)
    {
        try
        {
            using var fs = File.OpenRead(plainPath);
            Span<byte> m = stackalloc byte[8];
            return fs.Read(m) == 8 && m.SequenceEqual(ArchiveMagic);
        }
        catch { return false; }
    }

    // 解包到 destDir
    public static int ExtractArchive(string archivePath, string destDir)
    {
        int count = 0;
        using var fs = File.OpenRead(archivePath);
        byte[] h = new byte[32];
        if (!ReadExact(fs, h)) throw new IOException(L10n.T("归档头部损坏"));
        if (!h.AsSpan(0, 8).SequenceEqual(ArchiveMagic)) throw new IOException(L10n.T("不是 FEPK1 归档"));
        uint n = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(12));
        if (n > 1000000) throw new IOException(L10n.T("归档条目数异常"));
        for (uint i = 0; i < n; i++)
        {
            byte[] rec = new byte[28];
            if (!ReadExact(fs, rec)) throw new IOException(L10n.T("归档记录损坏"));
            uint plen = BinaryPrimitives.ReadUInt32LittleEndian(rec.AsSpan(0));
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(rec.AsSpan(4));
            ulong size = BinaryPrimitives.ReadUInt64LittleEndian(rec.AsSpan(8));
            if (plen > 4096 || size > long.MaxValue) throw new IOException(L10n.T("归档条目异常"));
            byte[] pb = new byte[plen];
            if (!ReadExact(fs, pb)) throw new IOException(L10n.T("归档路径损坏"));
            string rel = Encoding.UTF8.GetString(pb).Replace('\\', '/');
            if (rel.StartsWith('/') || rel.Contains("..") || Path.IsPathRooted(rel))
                throw new IOException(L10n.T("归档含非法路径：") + rel);
            string dst = Path.Combine(destDir, rel.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            if ((flags & 1) != 0) { Directory.CreateDirectory(dst); continue; }
            using (var outFs = File.Create(dst))
            {
                byte[] buf = new byte[1 << 20];
                ulong left = size;
                while (left > 0)
                {
                    int want = (int)Math.Min(left, (ulong)buf.Length);
                    int got = fs.Read(buf, 0, want);
                    if (got <= 0) break;
                    outFs.Write(buf, 0, got);
                    left -= (ulong)got;
                }
            }
            count++;
        }
        return count;
    }

    private static bool ReadExact(Stream s, byte[] buf)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int got = s.Read(buf, off, buf.Length - off);
            if (got <= 0) return false;
            off += got;
        }
        return true;
    }

    // 分卷
    // "foo.003.ptd" ->
    public static string BasePtdOf(string file)
    {
        if (!file.EndsWith(".ptd", StringComparison.OrdinalIgnoreCase)) return "";
        string stem = file[..^4];
        int dot = stem.LastIndexOf('.');
        if (dot < 0 || dot + 1 >= stem.Length) return "";
        string digits = stem[(dot + 1)..];
        if (digits.Length < 3) return "";
        foreach (char c in digits) if (!char.IsDigit(c)) return "";
        if (digits.Length > 3 && digits[0] == '0') return "";
        return stem[..dot] + ".ptd";
    }

    public static string VolumePath(string basePtd, int index)
        => basePtd[..^4] + "." + index.ToString("D3", CultureInfo.InvariantCulture) + ".ptd";

    // 切卷后删除原 .ptd
    public static int Split(string ptdPath, ulong volumeBytes)
    {
        if (volumeBytes < MinVolume) throw new ArgumentException(L10n.T("分卷大小至少 1 MiB"));
        string basePtd = ptdPath;
        int idx = 0;
        using (var src = File.OpenRead(ptdPath))
        {
            byte[] buf = new byte[(int)Math.Min(volumeBytes, 16UL << 20)];
            for (;;)
            {
                string vp = VolumePath(basePtd, idx + 1);
                ulong written = 0;
                using (var outFs = new FileStream(vp, FileMode.CreateNew, FileAccess.Write))
                {
                    while (written < volumeBytes)
                    {
                        int want = (int)Math.Min((ulong)buf.Length, volumeBytes - written);
                        int got = src.Read(buf, 0, want);
                        if (got <= 0) break;
                        outFs.Write(buf, 0, got);
                        written += (ulong)got;
                    }
                }
                idx++;
                if (written < volumeBytes) break;
                if (idx >= 99999) throw new IOException(L10n.T("分卷数量超过上限"));
            }
        }
        if (idx == 0) throw new IOException(L10n.T("没有可切分的数据"));
        try { File.Delete(ptdPath); } catch { }
        return idx;
    }

    // 合并连续卷到 mergedPath；返
    public static int MergeVolumes(string anyVolume, string mergedPath)
    {
        string basePtd = BasePtdOf(anyVolume);
        if (basePtd.Length == 0) basePtd = anyVolume;
        if (File.Exists(basePtd)) throw new IOException(L10n.T("完整 .ptd 已存在，无需合并：") + basePtd);
        var vols = new List<string>();
        for (int i = 1; i <= 99999; i++)
        {
            string p = VolumePath(basePtd, i);
            if (!File.Exists(p)) break;
            vols.Add(p);
        }
        if (vols.Count == 0) throw new IOException(L10n.T("找不到 .001.ptd 起始卷"));
        using (var outFs = new FileStream(mergedPath, FileMode.CreateNew, FileAccess.Write))
            foreach (var v in vols)
                using (var src = File.OpenRead(v)) src.CopyTo(outFs);
        return vols.Count;
    }

    // SHA256 校验单
    public static void WriteSha256Sidecar(string ptdPath)
    {
        byte[] hash;
        using (var fs = File.OpenRead(ptdPath)) hash = SHA256.HashData(fs);
        string line = Convert.ToHexStringLower(hash) + "  " + Path.GetFileName(ptdPath) + "\n";
        File.WriteAllText(ptdPath + ".sha256", line, new UTF8Encoding(false));
    }
}
