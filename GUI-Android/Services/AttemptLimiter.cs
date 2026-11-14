// 解锁失败限次
// 计数放 Preferences
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile.Services;

public static class AttemptLimiter
{
    private const string KeyCount = "unlock_fail_count";
    private const string KeyUntil = "unlock_block_until";

    // 当前冷却剩余
    public static TimeSpan Remaining()
    {
        long until = Preferences.Default.Get(KeyUntil, 0L);
        var left = DateTimeOffset.FromUnixTimeSeconds(until) - DateTimeOffset.UtcNow;
        return left > TimeSpan.Zero ? left : TimeSpan.Zero;
    }

    // 5 次
    public static void OnFailure()
    {
        int n = Preferences.Default.Get(KeyCount, 0) + 1;
        Preferences.Default.Set(KeyCount, n);
        if (n < 5) return;
        double sec = Math.Min(30 * Math.Pow(2, n - 5), 1800);
        Preferences.Default.Set(KeyUntil,
            DateTimeOffset.UtcNow.AddSeconds(sec).ToUnixTimeSeconds());
    }

    public static void OnSuccess()
    {
        Preferences.Default.Set(KeyCount, 0);
        Preferences.Default.Set(KeyUntil, 0L);
    }
}
