// progress_frame - 批量模式的「帧式」进度显示（CLI v2.3.0）
//
// 设计要点：
//   1) 帧刷新：批量模式按帧原地刷新（不换行堆叠），避免刷屏。帧内布局固定为
//       第 1 行   汇总行：总大小 | 已处理大小 | 总速率 | ETA
//       第 2..n+1 行：文件路径 | 进度条 | 速率 | ETA   （n = 并发线程数）
//   2) 自适应：体积/速率按 B/KB/MB/GB… 自适应单位 + 自适应精度；
//      进度条宽度随终端宽度伸缩；空闲线程行按同样列宽渲染占位，布局不跳动。
//   3) 双通道：
//        - 终端（tty）：用 ANSI 光标上移 + \r 原地重绘（Windows 自动开启 VT）。
//        - 非 tty 且宿主显式开启（环境变量 FILEENCRYPTOR_PROGRESS_FRAME=1）：
//          每帧以哨兵行包裹，供 GUI 等宿主整帧解析后自己原地渲染（见 GUI BatchProgressPanel）。
//        - 其它（重定向到文件等）：回退旧的「单行 \r 进度条」，不产生任何帧/哨兵。
//      这样 GUI 与 CLI 看到的是同一份文本（字段顺序、分隔符、单位格式完全一致）。
//
// 本文件只负责「显示」，不参与任何加密逻辑；列宽策略集中在此，便于 GUI 侧对齐。
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>

// 帧哨兵（非 tty 帧模式专用）。宿主按行解析：BEGIN 与 END 之间的行即本帧内容。
// 使用 ESC 前缀使其与正常业务输出天然区分，且不含可打印文本，旧宿主直接忽略即可。
extern const char* const FE_FRAME_BEGIN;   // "\x1b[FEPRG+"
extern const char* const FE_FRAME_END;     // "\x1b[FEPRG-"

// 开启帧模式的环境变量（GUI 批量模式注入）：非零即开启。
extern const char* const FE_FRAME_ENV;     // "FILEENCRYPTOR_PROGRESS_FRAME"

namespace feui {

// ---------- 格式化（与 GUI BatchProgressPanel 内的同名实现保持一致）----------
// 自适应单位：B / KB / MB / GB / TB（1024 进制）；数值 <10 保留 2 位，<100 保留 1 位，其余取整。
std::string fmt_bytes(uint64_t bytes);
// 速率：同上单位 + "/s"；0 或非法值返回 "-"。
std::string fmt_rate(double bytes_per_sec);
// 时长：MM:SS，超过 1 小时为 H:MM:SS；负数/无穷返回 "--:--"。
std::string fmt_eta(double seconds);

// 终端宽度（列数）：Windows 取控制台窗口宽度，POSIX 取 TIOCGWINSZ，
// 失败时回退 COLUMNS 环境变量，最后回退 80。宿主（GUI）可注入 COLUMNS 指定宽度。
int  terminal_width();

// 帧模式是否开启：宿主强制开启（环境变量）→ 是；否则仅当 stdout 是终端且支持光标控制。
bool frame_mode_enabled();

// 单个工作线程的进度槽位（由 worker 线程更新，显示线程读取）
struct ProgressSlot {
    std::string path;                                  // 当前文件路径（UTF-8）
    uint64_t    done  = 0;                             // 当前文件已处理字节
    uint64_t    total = 0;                             // 当前文件总字节
    bool        active = false;                        // false = 空闲（占位渲染）
    std::chrono::steady_clock::time_point started{};   // 当前文件起始时刻
};

// 批量进度帧显示器（线程安全：worker 调 setSlot，显示线程调 render）
class BatchProgress {
public:
    // 初始化；返回是否真正进入帧模式（false 时调用方应回退旧的单行进度条）。
    bool begin(int threads, uint64_t total_bytes);

    bool enabled() const { return m_enabled; }
    int  rows() const { return m_rows; }               // 帧行数 = 线程数 + 1

    // 更新第 slot 个线程的状态（slot 越界时忽略）
    void setSlot(int slot, const std::string& path, uint64_t done, uint64_t total, bool active);
    // 更新全局已处理字节数（汇总行用）
    void setProcessed(uint64_t bytes) { m_processed = bytes; }

    // 渲染一帧（内部按 80ms 节流，避免高频回调刷爆终端）
    void render();
    // 渲染最后一帧并收尾（帧后补换行，保证后续输出另起一行）
    void finish();

private:
    std::vector<std::string> build_lines(int width) const;
    void emit_frame(const std::vector<std::string>& lines, bool final_frame);

    mutable std::mutex       m_mutex;
    std::vector<ProgressSlot> m_slots;
    uint64_t                 m_total = 0;
    std::atomic<uint64_t>    m_processed{0};
    int                      m_rows = 0;
    bool                     m_enabled = false;
    bool                     m_tty = false;            // true=ANSI 原地重绘；false=哨兵整帧
    int                      m_written = 0;            // 已写出的帧行数（用于光标上移）
    std::chrono::steady_clock::time_point m_started{};
    std::chrono::steady_clock::time_point m_last_render{};
};

} // namespace feui
