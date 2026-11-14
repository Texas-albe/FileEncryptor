// 批量模式帧式进
// （路径|进度条|速率|ETA）。tty
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>
#include <deque>
#include <utility>

// 帧哨兵
// 使用 ESC 前缀
extern const char* const FE_FRAME_BEGIN;   // "\x1b[FEPRG+"
extern const char* const FE_FRAME_END;     // "\x1b[FEPRG-"

// 开启帧模式
extern const char* const FE_FRAME_ENV;     // "FILEENCRYPTOR_PROGRESS_FRAME"

namespace feui {

// 格式化
// B / KB / MB / GB /
std::string fmt_bytes(uint64_t bytes);
// 速率
std::string fmt_rate(double bytes_per_sec);
// 时长
std::string fmt_eta(double seconds);

// 终端宽度
// 失败时回退 COLUMNS 环境
int  terminal_width();

// 帧模式是否开启
bool frame_mode_enabled();

// 单个工作线程
struct ProgressSlot {
    std::string path;                                  // 当前文件路径
    uint64_t    done  = 0;                             // 当前文件已处理
    uint64_t    total = 0;                             // 当前文件总字节
    bool        active = false;                        // false = 空闲
    std::chrono::steady_clock::time_point started{};   // 当前文件起始
    // 速率窗口
    std::deque<std::pair<double, uint64_t>> rate_win;
    // 路径截断缓存
    std::string cache_path;                            // 上次截断
    std::string cache_trunc;                           // 截断结果
    int         cache_w = 0;                           // 截断
};

// 批量进度帧显示
class BatchProgress {
public:
    // 初始化
    bool begin(int threads, uint64_t total_bytes);

    bool enabled() const { return m_enabled; }
    int  rows() const { return m_rows; }               // 帧行数 = 线程数 + 1

    // 更新第 slot 个线程
    void setSlot(int slot, const std::string& path, uint64_t done, uint64_t total, bool active);
    // 更新全局已处理
    void setProcessed(uint64_t bytes) { m_processed = bytes; }

    // 文件级计数
    // （已完成/非 .ptd），failed
    void setFileStats(uint64_t done,uint64_t failed,uint64_t skipped,uint64_t total);

    // 渲染一帧
    void render(bool force = false);
    // 渲染
    void finish();

private:
    std::vector<std::string> build_lines(int width);
    void emit_frame(const std::vector<std::string>& lines, bool final_frame);

    mutable std::mutex       m_mutex;
    std::vector<ProgressSlot> m_slots;
    uint64_t                 m_total = 0;
    std::atomic<uint64_t>    m_processed{0};
    uint64_t                 m_fileDone = 0;
    uint64_t                 m_fileFailed = 0;
    uint64_t                 m_fileSkipped = 0;
    uint64_t                 m_fileTotal = 0;
    int                      m_rows = 0;
    bool                     m_enabled = false;
    bool                     m_tty = false;            // true=ANSI 原
    int                      m_written = 0;            // 已写出
    bool                     m_saved = false;          // 是否已保存帧首
    std::vector<std::string> m_prev;                   // 上一帧各行内容
    std::chrono::steady_clock::time_point m_started{};
    // 全局速率窗口
    std::deque<std::pair<double, uint64_t>> m_rateWin;
    std::chrono::steady_clock::time_point m_last_render{};
    uint64_t                 m_last_proc = 0;          // 上次渲染
};

} // namespace feui
