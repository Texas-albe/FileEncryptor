using Microsoft.Maui.Hosting;
using Microsoft.Maui.Handlers;

namespace FileEncryptorMobile;

using FileEncryptorMobile.Platforms.Android;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		MainApplication.LogI(MainApplication.TagCore, "startup: builder begin");
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
				fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
			});

		// 画廊用原生 ImageView 宿主
		builder.ConfigureMauiHandlers(handlers =>
			handlers.AddHandler<NativeImageHost, NativeImageHostHandler>());

#if ANDROID
		// Entry 的底色和描边
		EntryHandler.Mapper.AppendToMapping("FieldBorder", (handler, view) =>
		{
			handler.PlatformView.BackgroundTintList =
				Android.Content.Res.ColorStateList.ValueOf(Android.Graphics.Color.Transparent);
			handler.PlatformView.SetBackgroundColor(Android.Graphics.Color.Transparent);
		});
#endif

		MainApplication.LogI(MainApplication.TagCore, "startup: builder build");
		var app = builder.Build();
		MainApplication.LogI(MainApplication.TagCore, "startup: builder done");
		return app;
	}
}
