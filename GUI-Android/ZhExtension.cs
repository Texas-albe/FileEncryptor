// XAML 标记扩展：Text="{local:Zh 中文}"

using FileEncryptorMobile.Services;

namespace FileEncryptorMobile;

[ContentProperty(nameof(Zh))]
public class ZhExtension : IMarkupExtension<string>
{
    public string Zh { get; set; } = "";

    public ZhExtension() { }

    // 支持位置参数 {local:Zh 继续}
    public ZhExtension(string zh) { Zh = zh; }

    public string ProvideValue(IServiceProvider serviceProvider) => L10n.T(Zh);

    object IMarkupExtension.ProvideValue(IServiceProvider serviceProvider)
        => ProvideValue(serviceProvider);
}
