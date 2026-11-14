// 外壳
// 返回键策略集
// 进度浮层
//   鸣谢模态页     → 关闭
// 加密库子目录         → 返
// 加密库根             → 锁定加
// 其他非主页 Tab           → 回主
// 主页                     →
// 冷启动
using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

public partial class AppShell : Shell
{
	public AppShell()
	{
		InitializeComponent();
		// 回前台
		// 模态页不随 Activity 重建
		FileEncryptorMobile.MainActivity.Resumed += () => BatchRuns.ShowProgress();
		// 切 Tab / 页面导航即收
		Navigated += (s, e) => ProgressPage.Hide();
		// 冷启动 / 系统恢复
		// （Activity
		Loaded += OnShellLoaded;
	}

	// Shell 就绪后拉回主页
	private void OnShellLoaded(object? sender, EventArgs e)
	{
		Loaded -= OnShellLoaded;
		Dispatcher.Dispatch(() =>
		{
			if (Services.ShareInbox.HasPending)
			{ _ = GoToAsync($"//{nameof(CryptoPage)}", true); return; }
			BackPolicy.GoHome(this);
		});
	}

	protected override bool OnBackButtonPressed() => BackPolicy.Handle();
}
