using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Storage;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class App : Application
{
	// 成就通知覆盖层
	internal static VerticalStackLayout? ToastStack =>
		(Current?.Windows.FirstOrDefault()?.Page as AchievementHostPage)?.ToastStack;

	public App()
	{
		MainApplication.LogI(MainApplication.TagCore, "startup: App ctor begin");
		InitializeComponent();
		// 应用上次保存
		SettingsPage.ApplyTheme(Preferences.Default.Get("app_theme", "system"));
		// 应用上次保存
		L10n.Init();
		// 成就加载与解锁弹窗
		AchievementService.Load();
		AchievementService.Unlocked += def =>
		{
			var lang = L10n.Lang == 2 ? "ru" : (L10n.Lang == 1 ? "en" : "zh");
			AchievementToastManager.Show(def, lang);
		};
		MainApplication.LogI(MainApplication.TagCore, "startup: App ctor end");
	}

	protected override Window CreateWindow(IActivationState? activationState)
	{
		MainApplication.LogI(MainApplication.TagCore, "startup: CreateWindow begin");
		var window = new Window(new AchievementHostPage(new AppShell()));
		MainApplication.LogI(MainApplication.TagCore, "startup: CreateWindow end (AppShell ready)");
		return window;
	}
}