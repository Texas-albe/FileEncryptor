// Android 存储适配
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Provider;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile.Platforms.Android;

public static class VaultStorageHelper
{
    // 用户自选目录持
    // 默认走外部 Documents
    public const string VaultDirKey = "vault_dir";
    public const int PickDirRequestCode = 7301;
    public const int PickCryptoDirRequestCode = 7303;

    // 目录选择进行
    public static bool PickInProgress;

    // SAF 选目录结果事件
    public static event Action<string?>? DirectoryPicked;

    // 文件加密页
    private static TaskCompletionSource<string?>? s_cryptoDirTcs;

    // 启动 SAF 目录选择
    public static Task<string?> PickDirectoryAsync(Activity act)
    {
        s_cryptoDirTcs?.TrySetCanceled();   // 上一次未决先作
        var tcs = new TaskCompletionSource<string?>();
        s_cryptoDirTcs = tcs;
        MainActivity.NoteExternalLaunch();  // 选目录期间不锁
        try
        {
            var intent = new Intent(Intent.ActionOpenDocumentTree);
            intent.AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
            PickInProgress = true;
            act.StartActivityForResult(intent, PickCryptoDirRequestCode);
        }
        catch
        {
            s_cryptoDirTcs = null;
            PickInProgress = false;
            tcs.TrySetResult(null);
        }
        return tcs.Task;
    }

    // MainActivity.OnActivityResult 转发：兑现或作废
    public static void CompleteCryptoDirPick(Result resultCode, global::Android.Net.Uri? uri)
    {
        var tcs = s_cryptoDirTcs;
        s_cryptoDirTcs = null;
        PickInProgress = false;
        if (tcs is null) return;
        MainActivity.ReleaseExternalLaunch();
        if (resultCode != Result.Ok || uri is null) { tcs.TrySetResult(null); return; }
        // 空串表示非主存储
        tcs.TrySetResult(ResolveTreePath(uri) ?? "");
    }

    public static void RaiseDirectoryPicked(string? path)
    {
        PickInProgress = false;
        MainActivity.ReleaseExternalLaunch();
        DirectoryPicked?.Invoke(path);
    }

    // 默认库目录
    public static string DefaultVaultDir()
    {
        var docs = global::Android.OS.Environment.GetExternalStoragePublicDirectory(global::Android.OS.Environment.DirectoryDocuments);
        return Path.Combine(docs!.AbsolutePath, "FileEncryptor");
    }

    // 当前生效
    public static string CurrentVaultDir()
    {
        var saved = Preferences.Default.Get(VaultDirKey, "");
        return string.IsNullOrEmpty(saved) ? DefaultVaultDir() : saved;
    }

    // 主存储卷根
    private static string PrimaryRoot()
    {
        try
        {
            var docs = global::Android.OS.Environment.GetExternalStoragePublicDirectory(global::Android.OS.Environment.DirectoryDocuments);
            return Path.GetDirectoryName(docs?.AbsolutePath ?? "") ?? "/storage/emulated/0";
        }
        catch { return "/storage/emulated/0"; }
    }

    // 是否可读写外部
    public static bool HasAllFilesAccess()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.R) return HasLegacyWrite();
#pragma warning disable CA1416 // 仅在 Android 30+ 支持，调用点
        return global::Android.OS.Environment.IsExternalStorageManager;
#pragma warning restore CA1416
    }

    // 旧版
    private static bool HasLegacyWrite()
    {
        try
        {
            var ctx = Platform.AppContext;
            if ((int)ctx.ApplicationInfo!.TargetSdkVersion < 23) return true;
            return ctx.CheckSelfPermission(global::Android.Manifest.Permission.WriteExternalStorage)
                == global::Android.Content.PM.Permission.Granted;
        }
        catch { return false; }
    }

    // 引导授权
    public static void RequestAllFilesAccess(Context ctx)
    {
        try
        {
            if (Build.VERSION.SdkInt >= BuildVersionCodes.R)
            {
                var uri = global::Android.Net.Uri.FromParts("package", ctx.PackageName, null);
                // 精确页
                try
                {
                    var precise = new Intent("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION", uri);
                    precise.AddFlags(ActivityFlags.NewTask);
                    ctx.StartActivity(precise);
                    return;
                }
                catch (ActivityNotFoundException) { }
#pragma warning disable CA1416 // 仅在 Android 30+ 支持，调用点
                var intent = new Intent(Settings.ActionManageAllFilesAccessPermission, uri);
#pragma warning restore CA1416
                intent.AddFlags(ActivityFlags.NewTask);
                try { ctx.StartActivity(intent); return; }
                catch (ActivityNotFoundException) { }
                var details = new Intent(Settings.ActionApplicationDetailsSettings, uri);
                details.AddFlags(ActivityFlags.NewTask);
                ctx.StartActivity(details);
                return;
            }
            if (ctx is Activity act)
                // 旧版共享存储
                act.RequestPermissions(new[]
                {
                    global::Android.Manifest.Permission.WriteExternalStorage,
                    global::Android.Manifest.Permission.ReadExternalStorage,
                }, 1001);
        }
        catch { /* 引导失败不阻断页面 */ }
    }

    // 将 SAF 返回
    // 仅支持主存储卷
    public static string? ResolveTreePath(global::Android.Net.Uri? treeUri)
    {
        try
        {
            if (treeUri is null) return null;
            string? docId = DocumentsContract.GetTreeDocumentId(treeUri);
            if (string.IsNullOrEmpty(docId)) return null;
            if (docId.StartsWith("raw:")) return docId.Substring(4);
            if (docId.StartsWith("primary:"))
            {
                string rel = docId.Substring("primary:".Length);
                return Path.Combine(PrimaryRoot(), rel);
            }
            return null;
        }
        catch { return null; }
    }

    // 导出目录
    // 不得放
    public static string ExportDir()
    {
        string root;
        if (HasAllFilesAccess())
        {
            var docs = global::Android.OS.Environment.GetExternalStoragePublicDirectory(global::Android.OS.Environment.DirectoryDocuments);
            root = Path.Combine(docs!.AbsolutePath, "FileEncryptorExport");
        }
        else
        {
            root = Path.Combine(Platform.AppContext.GetExternalFilesDir(null)!.AbsolutePath, "export");
        }
        Directory.CreateDirectory(root);
        return root;
    }

    // 递归收集常规文
    public static List<string> CollectFiles(string root)
    {
        var result = new List<string>();
        string exportDir = ExportDir();
        string exportPrefix = exportDir + Path.DirectorySeparatorChar;
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            string dir = stack.Pop();
            // 导出目录可能
            if (dir.Equals(exportDir, StringComparison.Ordinal)
                || dir.StartsWith(exportPrefix, StringComparison.Ordinal)) continue;
            try { result.AddRange(Directory.GetFiles(dir)); }
            catch { continue; }   // 无权限/IO 异常
            try
            {
                foreach (var sub in Directory.GetDirectories(dir))
                {
                    if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                    stack.Push(sub);
                }
            }
            catch { /* 子目录列举失败不影响已收文件 */ }
        }
        return result;
    }

    // 自底向上删空目
    public static void PruneEmptyDirs(string root)
    {
        try
        {
            foreach (var d in Directory.GetDirectories(root, "*", SearchOption.AllDirectories)
                         .OrderByDescending(x => x.Length))
            {
                try { if (!Directory.EnumerateFileSystemEntries(d).Any()) Directory.Delete(d); }
                catch { }
            }
            if (!Directory.EnumerateFileSystemEntries(root).Any()) Directory.Delete(root);
        }
        catch { }
    }
}
