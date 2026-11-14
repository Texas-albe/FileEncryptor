using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Storage;
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class App : Application
{
	public App()
	{
		MainApplication.LogI(MainApplication.TagCore, "startup: App ctor begin");
		InitializeComponent();
		// 应用上次保存
		SettingsPage.ApplyTheme(Preferences.Default.Get("app_theme", "system"));
		// 应用上次保存
		L10n.Init();
		MainApplication.LogI(MainApplication.TagCore, "startup: App ctor end");
	}

	protected override Window CreateWindow(IActivationState? activationState)
	{
		MainApplication.LogI(MainApplication.TagCore, "startup: CreateWindow begin");
		var window = new Window(new AppShell());
		MainApplication.LogI(MainApplication.TagCore, "startup: CreateWindow end (AppShell ready)");
		return window;
	}
}