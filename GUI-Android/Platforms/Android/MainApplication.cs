// 应用入口
using Android.App;
using Android.Runtime;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;

namespace FileEncryptorMobile;

[Application]
public class MainApplication : MauiApplication
{
	public MainApplication(IntPtr handle, JniHandleOwnership ownership)
		: base(handle, ownership)
	{
	}

	protected override MauiApp CreateMauiApp()
	{
		LogI(TagCore, "startup: CreateMauiApp begin");
		var app = MauiProgram.CreateMauiApp();
		LogI(TagCore, "startup: CreateMauiApp end");
		return app;
	}

	public override void OnCreate()
	{
		// 放在 base
		LogI(TagCore, "startup: Application.OnCreate begin");
		base.OnCreate();
		LogI(TagCore, "startup: Application.OnCreate end (MauiApp built)");
		InstallCrashLog();
		LogI(TagCore, "startup: crash handlers installed");
	}

	// Java 侧与托管侧未处
	static void InstallCrashLog()
	{
		AndroidEnvironment.UnhandledExceptionRaiser += (s, e) => LogCaught("java", e.Exception);
		AppDomain.CurrentDomain.UnhandledException += (s, e) => LogCaught("managed", e.ExceptionObject as Exception);
	}

	// logcat 统一 tag
	internal const string TagCore = "FE-Core";
	internal const string TagMusic = "FE-Music";
	internal const string TagVideo = "FE-Video";

	// 正常流程 Info / 可疑 Warn / 异
	internal static void LogI(string tag, string message) => Emit(Android.Util.LogPriority.Info, tag, message);

	// 诊断开关
	internal const string DiagLogKey = "diag_log";
	internal static bool DiagnosticLogging
	{
		get { try { return Preferences.Default.Get(DiagLogKey, false); } catch { return false; } }
	}

	// 过程细节
	internal static void LogD(string tag, string message)
	{
		if (DiagnosticLogging) Emit(Android.Util.LogPriority.Info, tag, message ?? "");
	}

	internal static void LogW(string tag, string message) => Emit(Android.Util.LogPriority.Warn, tag, message);
	internal static void LogE(string tag, string message) => Emit(Android.Util.LogPriority.Error, tag, message);

	static void Emit(Android.Util.LogPriority level, string tag, string message)
	{
		try { Android.Util.Log.WriteLine(level, tag, message ?? ""); } catch { }
	}

	// 已捕获但需要留
	internal static void LogCaught(string kind, Exception? ex)
	{
		if (ex is null) return;
		AppendCrash(kind, ex.ToString());
		Emit(Android.Util.LogPriority.Error, TagOf(kind),
			$"{kind}: {ex.GetType().Name}: {ex.Message}");
	}

	// 非异常但需要留
	internal static void LogNote(string kind, string message)
	{
		AppendCrash(kind, message);
		Emit(Android.Util.LogPriority.Info, TagOf(kind), $"{kind}: {message}");
	}

	static string TagOf(string kind) =>
		kind.StartsWith("music", StringComparison.Ordinal) ? TagMusic
		: kind.StartsWith("video", StringComparison.Ordinal) ? TagVideo
		: TagCore;

	static readonly object s_logLock = new();
	const long MaxLogBytes = 1L << 20;   // 1MB

	static void AppendCrash(string kind, string text)
	{
		try
		{
			lock (s_logLock)
			{
				// 私有目录
				string path = Path.Combine(CrashLogPath(), "fe_crash.log");
				if (File.Exists(path) && new FileInfo(path).Length > MaxLogBytes)
					File.Move(path, path + ".1", overwrite: true);   // 只留 1 份旧
				File.AppendAllText(path,
					$"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {kind}: {Sanitize(text)}\n\n");
				// 外部镜像
				string? ext = Platform.AppContext.GetExternalFilesDir(null)?.AbsolutePath;
				if (ext is not null)
				{
					string extPath = Path.Combine(ext, "fe_diag.log");
					if (File.Exists(extPath) && new FileInfo(extPath).Length > MaxLogBytes)
						File.Move(extPath, extPath + ".1", overwrite: true);
					File.AppendAllText(extPath,
						$"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {kind}: {Sanitize(text)}\n\n");
				}
			}
		}
		catch { /* 日志失败不递归 */ }
	}

	static string CrashLogPath() => Platform.AppContext.FilesDir?.AbsolutePath ?? "";

	// 脱敏
	static string Sanitize(string s)
	{
		try
		{
			string files = CrashLogPath();
			s = s.Replace(files, "<app>");
			string parent = Path.GetDirectoryName(files) ?? "";
			if (parent.Length > 0) s = s.Replace(parent, "<data>");
		}
		catch { }
		return s;
	}
}
