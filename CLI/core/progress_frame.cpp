// progress_frame 实现（CLI v2.3.0）—— 批量模式帧式进度显示
// 详见 progress_frame.hpp 顶部设计说明。
#include "progress_frame.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#endif

const char* const FE_FRAME_BEGIN = "\x1b[FEPRG+";
const char* const FE_FRAME_END   = "\x1b[FEPRG-";
const char* const FE_FRAME_ENV   = "FILEENCRYPTOR_PROGRESS_FRAME";

namespace feui {

// ---------- 环境探测 ----------
static bool stdout_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

// Windows 需显式开启虚拟终端处理，ANSI 光标指令才会被解释（Win10 1511+）。
static bool enable_vt() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return false;
    if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) return true;
    return SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    return true;
#endif
}

int terminal_width() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &csbi)) {
        int w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        if (w > 0) return w;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return (int)ws.ws_col;
#endif
    const char* cols = std::getenv("COLUMNS");
    if (cols && *cols) {
        int v = std::atoi(cols);
        if (v > 0) return v;
    }
    return 80;
}

bool frame_mode_enabled() {
    static int cached = -1;
    if (cached < 0) {
        bool forced = false;
        const char* e = std::getenv(FE_FRAME_ENV);
        if (e && *e && std::strcmp(e, "0") != 0) forced = true;
        cached = (forced || (stdout_is_tty() && enable_vt())) ? 1 : 0;
    }
    return cached == 1;
}

// ---------- 格式化 ----------
// 数值精度自适应：<10 两位小数、<100 一位、其余取整；单位按 1024 进制递进。
static std::string fmt_value(double v, const char* unit) {
    char buf[64];
    if (v < 10.0)         std::snprintf(buf, sizeof(buf), "%.2f %s", v, unit);
    else if (v < 100.0)   std::snprintf(buf, sizeof(buf), "%.1f %s", v, unit);
    else                  std::snprintf(buf, sizeof(buf), "%.0f %s", v, unit);
    return std::string(buf);
}

std::string fmt_bytes(uint64_t bytes) {
    const double KB = 1024.0, MB = 1024.0 * 1024.0, GB = 1024.0 * 1024.0 * 1024.0;
    const double TB = GB * 1024.0;
    double v = (double)bytes;
    if (v >= TB)      return fmt_value(v / TB, "TB");
    else if (v >= GB) return fmt_value(v / GB, "GB");
    else if (v >= MB) return fmt_value(v / MB, "MB");
    else if (v >= KB) return fmt_value(v / KB, "KB");
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return std::string(buf);
}

std::string fmt_rate(double bytes_per_sec) {
    if (!(bytes_per_sec > 0.0) || std::isinf(bytes_per_sec) || std::isnan(bytes_per_sec))
        return "-";
    const double KB = 1024.0, MB = 1024.0 * 1024.0, GB = 1024.0 * 1024.0 * 1024.0;
    double v = bytes_per_sec;
    if (v >= GB)      return fmt_value(v / GB, "GB/s");
    else if (v >= MB) return fmt_value(v / MB, "MB/s");
    else if (v >= KB) return fmt_value(v / KB, "KB/s");
    return fmt_value(v, "B/s");
}

std::string fmt_eta(double seconds) {
    if (!(seconds >= 0.0) || std::isinf(seconds) || std::isnan(seconds)) return "--:--";
    unsigned long long total_s = (unsigned long long)(seconds + 0.5);
    unsigned long long h = total_s / 3600;
    unsigned long long m = (total_s % 3600) / 60;
    unsigned long long s = total_s % 60;
    char buf[32];
    if (h > 0) std::snprintf(buf, sizeof(buf), "%llu:%02llu:%02llu", h, m, s);
    else       std::snprintf(buf, sizeof(buf), "%02llu:%02llu", m, s);
    return std::string(buf);
}

// 宽字符（中日韩）占两列：粗略按码点 + 高位字节估算，够用于对齐
static size_t display_width(const std::string& s) {
    size_t w = 0;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        size_t seq = 1;
        if      ((c & 0xE0) == 0xC0) seq = 2;
        else if ((c & 0xF0) == 0xE0) seq = 3;
        else if ((c & 0xF8) == 0xF0) seq = 4;
        if (i + seq > s.size()) break;
        // CJK 统一表意文字（U+4E00-U+9FFF）等宽字符按 2 列计
        bool wide = false;
        if (seq == 3) {
            unsigned int cp = ((unsigned int)(s[i] & 0x0F) << 12)
                            | ((unsigned int)(s[i + 1] & 0x3F) << 6)
                            |  (unsigned int)(s[i + 2] & 0x3F);
            wide = (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3)
                || (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE4F)
                || (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6);
        }
        w += wide ? 2 : 1;
        i += seq;
    }
    return w;
}

// 取显示宽度不超过 keep 列的最长前缀（多字节/宽字符感知，不截半个字符）
static std::string head_by_width(const std::string& s, size_t keep) {
    std::string out;
    size_t w = 0;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        size_t seq = 1;
        if      ((c & 0xE0) == 0xC0) seq = 2;
        else if ((c & 0xF0) == 0xE0) seq = 3;
        else if ((c & 0xF8) == 0xF0) seq = 4;
        if (i + seq > s.size()) break;
        std::string one = s.substr(i, seq);
        size_t ow = display_width(one);
        if (w + ow > keep) break;
        out += one;
        w += ow;
        i += seq;
    }
    return out;
}

// 按显示宽度缩写路径：能放下原样返回；超宽先缩目录部分（"...\"+文件名），文件名仍放不下
// 则缩主部保留扩展名；连扩展名方案都放不下就整体头部截断加 "..."。
static std::string truncate_path(const std::string& s, size_t max_w) {
    if (display_width(s) <= max_w) return s;
    if (max_w <= 3) return std::string(max_w, '.');
    const size_t base_pos = s.find_last_of("/\\");
    if (base_pos != std::string::npos && base_pos + 1 < s.size()) {
        const std::string base = s.substr(base_pos + 1);
        const std::string prefix = "...\\";
        const size_t avail = max_w - prefix.size();
        if (display_width(base) <= avail)
            return prefix + base;   // pad_right 负责补齐剩余空格
        const size_t dot = base.find_last_of('.');
        if (dot != std::string::npos && dot + 1 < base.size()) {
            const std::string ext = base.substr(dot);
            const size_t ew = display_width(ext);
            if (ew + 3 < avail) {
                const std::string head = head_by_width(base.substr(0, dot), avail - ew - 3);
                if (!head.empty())
                    return prefix + head + "..." + ext;
            }
        }
    }
    return head_by_width(s, max_w - 3) + "...";
}

static std::string pad_right(const std::string& s, size_t w) {
    size_t cur = display_width(s);
    if (cur >= w) return s;
    return s + std::string(w - cur, ' ');
}

static std::string pad_left(const std::string& s, size_t w) {
    size_t cur = display_width(s);
    if (cur >= w) return s;
    return std::string(w - cur, ' ') + s;
}

// ---------- 帧布局 ----------
// 四列：路径 | 进度条 | 速率 | ETA。路径/进度条按终端宽度分配（进度条约 40%），
// 速率/ETA 固定宽，保证各行列对齐不跳动。
namespace {
constexpr int kRateW = 12;   // "123.45 MB/s"
constexpr int kEtaW  = 11;   // "ETA 1:02:03"
constexpr int kSepW  = 3;    // " | "
}

bool BatchProgress::begin(int threads, uint64_t total_bytes) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_total = total_bytes;
    m_processed = 0;
    m_written = 0;
    m_rows = (threads > 0 ? threads : 1) + 1;
    m_slots.assign(threads > 0 ? threads : 1, ProgressSlot());
    m_started = std::chrono::steady_clock::now();
    m_last_render = std::chrono::steady_clock::time_point();
    m_tty = stdout_is_tty();
    m_enabled = frame_mode_enabled() && threads > 0;
    return m_enabled;
}

void BatchProgress::setSlot(int slot, const std::string& path, uint64_t done, uint64_t total,
                            bool active) {
    std::lock_guard<std::mutex> lk(m_mutex);
    if (slot < 0 || slot >= (int)m_slots.size()) return;
    ProgressSlot& s = m_slots[slot];
    if (active && !s.active) s.started = std::chrono::steady_clock::now();   // 新文件开始计时
    s.path = path;
    s.done = done;
    s.total = total;
    s.active = active;
}

void BatchProgress::setFileStats(uint64_t done,uint64_t failed,uint64_t skipped,uint64_t total) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_fileDone=done; m_fileFailed=failed; m_fileSkipped=skipped; m_fileTotal=total;
}

std::vector<std::string> BatchProgress::build_lines(int width) const {
    // ---- 列宽 ----
    int avail = width - kRateW - kEtaW - 3 * kSepW;
    if (avail < 30) avail = 30;
    int bar_w = avail * 40 / 100;
    if (bar_w < 16) bar_w = 16;
    if (bar_w > 42) bar_w = 42;
    int path_w = avail - bar_w;
    if (path_w < 12) path_w = 12;
    int inner = bar_w - 2 - 1 - 4;      // 方括号 2 + 空格 1 + "100%" 4
    if (inner < 6) inner = 6;

    const auto now = std::chrono::steady_clock::now();
    const double elapsed = std::chrono::duration<double>(now - m_started).count();

    // ---- 第 1 行：汇总（总大小 | 已处理大小 | 总速率 | ETA）----
    const uint64_t done_bytes = m_processed.load();
    const uint64_t total_bytes = m_total;
    const double overall_rate = (elapsed > 0.0) ? (double)done_bytes / elapsed : 0.0;
    double remain_s = -1.0;
    if (overall_rate > 0.0 && total_bytes > done_bytes)
        remain_s = (double)(total_bytes - done_bytes) / overall_rate;
    else if (total_bytes <= done_bytes) remain_s = 0.0;

    std::string pct_total = "  0%";
    if (total_bytes > 0) {
        int p = (int)((double)done_bytes * 100.0 / (double)total_bytes);
        if (p > 100) p = 100;
        char pb[8];
        std::snprintf(pb, sizeof(pb), "%3d%%", p);
        pct_total = pb;
    }
    std::string line1 = pad_right("TOTAL " + fmt_bytes(total_bytes), (size_t)path_w) + " | "
                      + pad_right("DONE " + fmt_bytes(done_bytes) + " " + pct_total, (size_t)bar_w) + " | "
                      + pad_left(fmt_rate(overall_rate), (size_t)kRateW) + " | "
                      + pad_left(std::string("ETA ") + fmt_eta(remain_s), (size_t)kEtaW);

    std::vector<std::string> lines;
    lines.push_back(line1);

    // ---- 第 2..n+1 行：每线程一行（文件路径 | 进度条 | 速率 | ETA）----
    for (const ProgressSlot& s : m_slots) {
        std::string col1, col2, col3, col4;
        if (s.active && s.total > 0) {
            col1 = truncate_path(s.path, (size_t)path_w);

            double frac = (double)s.done / (double)s.total;
            if (frac < 0.0) frac = 0.0;
            if (frac > 1.0) frac = 1.0;
            size_t pos = (size_t)(frac * (double)inner + 0.5);
            if (pos > (size_t)inner) pos = (size_t)inner;
            std::string bar;
            bar.reserve((size_t)inner + 2);
            bar += '[';
            for (size_t i = 0; i < (size_t)inner; ++i) {
                // 100% 时铺满 '='，不再画 '>' 头部（否则满格仍像"未完成"）
                if (frac >= 1.0)                     bar += '=';
                else if (i + 1 < pos)                bar += '=';
                else if (i + 1 == pos)               bar += '>';
                else                                 bar += ' ';
            }
            bar += ']';
            int p = (int)(frac * 100.0 + 0.5);
            if (p > 100) p = 100;
            char pb[8];
            std::snprintf(pb, sizeof(pb), "%3d%%", p);
            col2 = bar + " " + pb;

            const double file_elapsed = std::chrono::duration<double>(now - s.started).count();
            const double rate = (file_elapsed > 0.0) ? (double)s.done / file_elapsed : 0.0;
            col3 = fmt_rate(rate);
            double eta = -1.0;
            if (rate > 0.0 && s.total > s.done) eta = (double)(s.total - s.done) / rate;
            else if (s.total <= s.done) eta = 0.0;
            col4 = std::string("ETA ") + fmt_eta(eta);
        } else {
            // 空闲线程：保持完全相同的列宽与占位符，避免整帧布局跳动
            col1 = "-";
            col2 = std::string("[") + std::string((size_t)inner, ' ') + "]  --%";
            col3 = "-";
            col4 = "ETA --:--";
        }
        lines.push_back(pad_right(col1, (size_t)path_w) + " | "
                      + pad_right(col2, (size_t)bar_w) + " | "
                      + pad_left(col3, (size_t)kRateW) + " | "
                      + pad_left(col4, (size_t)kEtaW));
    }

    // 末行 FILES 给出文件级计数，宿主按帧解析即可，避免每文件多打一行刷屏
    if(m_fileTotal>0||m_fileDone>0||m_fileFailed>0||m_fileSkipped>0) {
        char st[128];
        std::snprintf(st,sizeof(st),"FILES %llu/%llu   SKIP %llu   FAIL %llu",
            (unsigned long long)m_fileDone,(unsigned long long)m_fileTotal,
            (unsigned long long)m_fileSkipped,(unsigned long long)m_fileFailed);
        lines.push_back(head_by_width(st,(size_t)(width>0?width:80)));
    }
    return lines;
}

void BatchProgress::emit_frame(const std::vector<std::string>& lines, bool final_frame) {
    if (m_tty) {
        // 上一次渲染后光标停在帧的最后一行 → 上移 (行数-1) 行回到帧首行
        if (m_written > 1) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "\x1b[%dA", m_written - 1);
            std::fputs(buf, stdout);
        }
        for (size_t i = 0; i < lines.size(); ++i) {
            std::fputs("\r", stdout);
            std::fputs(lines[i].c_str(), stdout);
            std::fputs("\x1b[K", stdout);       // 清除行尾残留
            if (i + 1 < lines.size()) std::fputc('\n', stdout);
        }
        m_written = (int)lines.size();
        if (final_frame) {
            std::fputc('\n', stdout);           // 帧后换行，后续输出另起一行
            m_written = 0;
        }
    } else {
        // 非 tty（宿主解析模式）：整帧以哨兵行包裹
        std::fputs(FE_FRAME_BEGIN, stdout);
        std::fputc('\n', stdout);
        for (const std::string& l : lines) {
            std::fputs(l.c_str(), stdout);
            std::fputc('\n', stdout);
        }
        std::fputs(FE_FRAME_END, stdout);
        std::fputc('\n', stdout);
    }
    std::fflush(stdout);
}

void BatchProgress::render() {
    if (!m_enabled) return;
    const auto now = std::chrono::steady_clock::now();
    bool due;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        // 节流：80ms 一帧（首次立即渲染）
        due = m_last_render.time_since_epoch().count() == 0
            || std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last_render).count() >= 80;
        if (!due) return;
        m_last_render = now;
    }
    std::vector<std::string> lines;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        lines = build_lines(terminal_width());
    }
    emit_frame(lines, false);
}

void BatchProgress::finish() {
    if (!m_enabled) return;
    std::vector<std::string> lines;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        // 收尾帧：所有槽位置空闲，汇总行保留最终吞吐与 ETA
        for (ProgressSlot& s : m_slots) { s.active = false; s.done = 0; s.total = 0; s.path.clear(); }
        lines = build_lines(terminal_width());
    }
    emit_frame(lines, true);
}

} // namespace feui
