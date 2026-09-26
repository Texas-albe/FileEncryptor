// 内置 CJK 兜底字体
// ---------------------------------------------------------------------------
// 字体：Noto Sans SC（思源黑体简体子集）
// 来源：https://github.com/notofonts/noto-cjk  （Sans/SubsetOTF/SC/NotoSansSC-Regular.otf）
// 许可：SIL Open Font License 1.1（OFL-1.1），允许随软件再分发，见：
//       https://scripts.sil.org/OFL
// 用途：Linux 目标机未安装中文字体（或静态 Qt 未启用 fontconfig、拿不到系统字体）时，
//       由 src/FontBootstrap.cpp 在启动期从 Qt 资源 :/fonts/ 加载并设为界面默认字体，
//       避免中文渲染成“豆腐块”。
// 取舍：8.3MB。若不需要可删除本目录（CMake 检测不到 fonts/*.ttf|otf 即不会嵌入）。
// ---------------------------------------------------------------------------
