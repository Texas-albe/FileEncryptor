using System.Text;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile.Services;

// 最小 QR 编码器
// 纯 C# 实现
public enum QrEcLevel { L, M }

public static class QrCode
{
    // 版本 1~4
    private static readonly int[] TotalCodewords = { 0, 26, 44, 70, 100 };
    // 每块纠错码字数
    private static readonly int[,] EcPerBlock = {
        { 0, 0 }, { 7, 10 }, { 10, 16 }, { 15, 26 }, { 20, 18 },
    };
    // 纠错块数
    private static readonly int[,] NumBlocks = {
        { 0, 0 }, { 1, 1 }, { 1, 1 }, { 1, 1 }, { 1, 2 },
    };

    private static readonly byte[] Exp = new byte[512];
    private static readonly byte[] Log = new byte[256];

    static QrCode()
    {
        int x = 1;
        for (int i = 0; i < 255; i++)
        {
            Exp[i] = (byte)x;
            Log[x] = (byte)i;
            x <<= 1;
            if ((x & 0x100) != 0) x ^= 0x11D;
        }
        for (int i = 255; i < 512; i++) Exp[i] = Exp[i - 255];
    }

    private static byte Mul(byte a, byte b)
        => (a == 0 || b == 0) ? (byte)0 : Exp[Log[a] + Log[b]];

    // 生成多项式
    private static byte[] GenPoly(int degree)
    {
        byte[] poly = { 1 };
        byte root = 1;
        for (int i = 0; i < degree; i++)
        {
            var nxt = new byte[poly.Length + 1];
            for (int k = 0; k < nxt.Length; k++)
            {
                byte pk = k < poly.Length ? poly[k] : (byte)0;
                byte pk1 = (k > 0 && k - 1 < poly.Length) ? poly[k - 1] : (byte)0;
                nxt[k] = (byte)(pk1 ^ Mul(root, pk));
            }
            poly = nxt;
            root = Mul(root, 2);
        }
        return poly;
    }

    // RS 纠错码字
    private static byte[] RsEc(byte[] data, int ecLen)
    {
        byte[] g = GenPoly(ecLen);
        var d = new byte[ecLen + data.Length];
        for (int i = 0; i < data.Length; i++) d[ecLen + i] = data[data.Length - 1 - i];
        byte[] rem = (byte[])d.Clone();
        for (int i = rem.Length - 1; i >= ecLen; i--)
        {
            byte f = rem[i];
            if (f != 0)
                for (int j = 0; j <= ecLen; j++)
                    rem[i - ecLen + j] ^= Mul(g[j], f);
        }
        var ec = new byte[ecLen];
        for (int k = 0; k < ecLen; k++) ec[k] = rem[ecLen - 1 - k];
        return ec;
    }

    private static void Put(List<int> bits, int val, int n)
    {
        for (int i = n - 1; i >= 0; i--) bits.Add((val >> i) & 1);
    }

    // 数据码字
    private static byte[] DataCodewords(string text, int version, int level)
    {
        byte[] b = Encoding.Latin1.GetBytes(text);
        int ec = EcPerBlock[version, level];
        int nb = NumBlocks[version, level];
        int totalData = TotalCodewords[version] - ec * nb;
        int cap = totalData * 8;
        var bits = new List<int>();
        Put(bits, 4, 4);
        Put(bits, b.Length, 8);
        foreach (byte ch in b) Put(bits, ch, 8);
        int t = Math.Min(4, cap - bits.Count);
        if (t > 0) Put(bits, 0, t);
        // 已对齐时补 0 位
        Put(bits, 0, (8 - (bits.Count % 8)) % 8);
        var cw = new List<byte>();
        for (int i = 0; i < bits.Count; i += 8)
        {
            int v = 0;
            for (int k = 0; k < 8; k++) v = (v << 1) | bits[i + k];
            cw.Add((byte)v);
        }
        byte[] pads = { 0xEC, 0x11 };
        int pi = 0;
        while (cw.Count < totalData) cw.Add(pads[pi++ % 2]);
        return cw.ToArray();
    }

    // 码字交织
    private static byte[] Interleave(byte[] data, int version, int level)
    {
        int ec = EcPerBlock[version, level];
        int nb = NumBlocks[version, level];
        int shortLen = data.Length / nb;
        int lng = data.Length % nb;
        var blocks = new List<byte[]>();
        int pos = 0;
        for (int b = 0; b < nb; b++)
        {
            int len = shortLen + (b >= nb - lng ? 1 : 0);
            var blk = new byte[len];
            Array.Copy(data, pos, blk, 0, len);
            blocks.Add(blk);
            pos += len;
        }
        var ecs = new List<byte[]>();
        foreach (var blk in blocks) ecs.Add(RsEc(blk, ec));
        var outp = new List<byte>();
        int maxLen = shortLen + (lng > 0 ? 1 : 0);
        for (int k = 0; k < maxLen; k++)
            foreach (var blk in blocks)
                if (k < blk.Length) outp.Add(blk[k]);
        for (int k = 0; k < ec; k++)
            foreach (var e in ecs) outp.Add(e[k]);
        return outp.ToArray();
    }

    private static bool[,] Build(byte[] codewords, int version, int level, int mask)
    {
        int size = 4 * version + 17;
        var mod = new bool[size, size];
        var fn = new bool[size, size];
        void SetFn(int x, int y, bool dark)
        {
            if (x >= 0 && x < size && y >= 0 && y < size)
            { mod[y, x] = dark; fn[y, x] = true; }
        }
        // 定时图形
        for (int i = 0; i < size; i++)
        {
            SetFn(6, i, i % 2 == 0);
            SetFn(i, 6, i % 2 == 0);
        }
        void Finder(int cx, int cy)
        {
            for (int dy = -4; dy <= 4; dy++)
                for (int dx = -4; dx <= 4; dx++)
                {
                    int dist = Math.Max(Math.Abs(dx), Math.Abs(dy));
                    SetFn(cx + dx, cy + dy, dist != 2 && dist != 4);
                }
        }
        Finder(3, 3); Finder(size - 4, 3); Finder(3, size - 4);
        // 校正图形
        if (version >= 2)
        {
            for (int dy = -2; dy <= 2; dy++)
                for (int dx = -2; dx <= 2; dx++)
                {
                    int d = Math.Max(Math.Abs(dx), Math.Abs(dy));
                    SetFn(size - 7 + dx, size - 7 + dy, d != 1);
                }
        }
        // 格式信息
        int ecBits = level == 0 ? 1 : 0;
        int fmt = (ecBits << 3) | mask;
        int rem = fmt;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        int bits = ((fmt << 10) | rem) ^ 0x5412;
        int Gb(int i) => (bits >> i) & 1;
        for (int i = 0; i < 6; i++) SetFn(8, i, Gb(i) == 1);
        SetFn(8, 7, Gb(6) == 1);
        SetFn(8, 8, Gb(7) == 1);
        SetFn(7, 8, Gb(8) == 1);
        for (int i = 9; i < 15; i++) SetFn(14 - i, 8, Gb(i) == 1);
        for (int i = 0; i < 8; i++) SetFn(size - 1 - i, 8, Gb(i) == 1);
        for (int i = 8; i < 15; i++) SetFn(8, size - 15 + i, Gb(i) == 1);
        SetFn(8, size - 8, true);

        // 数据锯齿填充
        int bi = 0;
        int right = size - 1;
        while (right >= 1)
        {
            if (right == 6) right = 5;
            for (int vert = 0; vert < size; vert++)
                for (int j = 0; j < 2; j++)
                {
                    int x = right - j;
                    bool upward = ((right + 1) & 2) == 0;
                    int y = upward ? size - 1 - vert : vert;
                    if (!fn[y, x] && bi < codewords.Length * 8)
                    {
                        int b = codewords[bi >> 3];
                        mod[y, x] = ((b >> (7 - (bi & 7))) & 1) == 1;
                        bi++;
                    }
                }
            right -= 2;
        }
        // 掩码
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
            {
                if (fn[y, x]) continue;
                bool inv = mask switch
                {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => (x * y) % 2 + (x * y) % 3 == 0,
                    6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                    _ => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
                };
                if (inv) mod[y, x] = !mod[y, x];
            }
        return mod;
    }

    // 自动挑
    public static bool[,] Encode(string text, QrEcLevel level = QrEcLevel.M)
    {
        int lv = level == QrEcLevel.L ? 0 : 1;
        for (int v = 1; v <= 4; v++)
        {
            int ec = EcPerBlock[v, lv];
            int nb = NumBlocks[v, lv];
            int dataCw = TotalCodewords[v] - ec * nb;
            byte[] dc = DataCodewords(text, v, lv);
            if (dc.Length > dataCw) continue;
            return Build(Interleave(dc, v, lv), v, lv, 0);
        }
        throw new ArgumentException(L10n.T("内容过长，超出版本 1~4 容量。"), nameof(text));
    }
}
