// 空闲锁档位
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile.Services;

public static class VaultIdle
{
    private const string Key = "vault_idle_minutes";
    public static readonly int[] Minutes = { 1, 5, 15, 30 };

    public static int CurrentMinutes
    {
        get
        {
            int v = Preferences.Default.Get(Key, 5);
            return System.Array.IndexOf(Minutes, v) >= 0 ? v : 5;
        }
        set => Preferences.Default.Set(Key, value);
    }

    public static uint Seconds => (uint)(CurrentMinutes * 60);
}
