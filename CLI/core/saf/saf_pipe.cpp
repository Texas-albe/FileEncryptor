// SAF 管道传输原语：stdio 流 / 内存流 / 通用分块泵送 saf_pump。
// 管道是「流」而非「后端」（无路径语义），故此处只提供 Stream 工厂 + 搬运原语。
#include "saf.hpp"
#include "saf_secure.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#include <csignal>
#endif

#ifndef _WIN32
namespace {
// M30：忽略 SIGPIPE（仅 POSIX）。stdout 数据通道对端提前退出（如 fe --stdout 管道被 head 关闭）时
// 进程不再被 SIGPIPE 击杀，写失败以短写/EPIPE 形式上报，由 StdioStream::write 映射 SAF_E_IO。
// SAF 无统一初始化入口，故用文件级静态对象在本 TU 加载时完成注册。
struct SigpipeIgnorer {
    SigpipeIgnorer() { std::signal(SIGPIPE, SIG_IGN); }
};
SigpipeIgnorer s_sigpipe_ignorer;
}  // namespace
#endif

namespace {

// M28：内存写流容量绝对上限（1GiB）。seek/write 均以此设界，既防 pos_+len 回绕越界写，也防故障调用方撑爆进程内存
constexpr uint64_t kMaxMemWrite = 1ull << 30;

// ---- stdio 流：stdin('r') / stdout('w')；非 seek，二进制模式 ----
class StdioStream final : public Stream {
public:
    explicit StdioStream(bool reading) : reading_(reading) {
#ifdef _WIN32
        // 二进制模式：禁 CRLF 转换与 Ctrl-Z EOF，密文/管道字节原样透传
        _setmode(reading_ ? _fileno(stdin) : _fileno(stdout), _O_BINARY);
#endif
    }
    SafStatus read(uint8_t* out, uint64_t* len) override {
        if (!reading_ || !out || !len) return SAF_E_BADARG;
        if (*len == 0) return SAF_OK;
        size_t n = 0;
        for (;;) {
            n = std::fread(out, 1, (size_t)*len, stdin);
            if (n != 0 || !std::ferror(stdin)) break;
            if (errno != EINTR) break;   // M30：EINTR 清错误标志后重试；其余错误按真错处理
            std::clearerr(stdin);
        }
        pos_ += n;
        *len = (uint64_t)n;
        if (n == 0 && std::ferror(stdin)) return SAF_E_IO;   // 真错；n==0 无错 = EOF
        return SAF_OK;
    }
    SafStatus write(const uint8_t* in, uint64_t len) override {
        if (reading_ || !in) return SAF_E_BADARG;
        if (len == 0) return SAF_OK;
        size_t n = std::fwrite(in, 1, (size_t)len, stdout);
        pos_ += n;
        if (n != (size_t)len) return SAF_E_IO;  // 部分写出=失败（含 EPIPE：对端已退出。SIGPIPE 已被本 TU 静态初始化忽略，否则进程先被信号击杀，走不到这里）
        return SAF_OK;
    }
    SafStatus seek(uint64_t) override { return SAF_E_NOTIMPL; }   // 管道不可寻址
    SafStatus tell(uint64_t* out_pos) override {
        if (!out_pos) return SAF_E_BADARG;
        *out_pos = pos_;
        return SAF_OK;
    }
    SafStatus flush() override {
        if (reading_) return SAF_OK;
        return std::fflush(stdout) == 0 ? SAF_OK : SAF_E_IO;
    }
    SafStatus close() override {
        if (!reading_) return std::fflush(stdout) == 0 ? SAF_OK : SAF_E_IO;   // M31：刷盘失败（ENOSPC/EPIPE）必须上报，不能恒返 OK
        return SAF_OK;
    }
private:
    bool     reading_;
    uint64_t pos_ = 0;
};

// ---- 内存读流：随机访问给定缓冲（调用方保活）----
class MemReadStream final : public Stream {
public:
    MemReadStream(const uint8_t* data, uint64_t n) : d_(data), n_(n) {}
    SafStatus read(uint8_t* out, uint64_t* len) override {
        if (!out || !len) return SAF_E_BADARG;
        if (*len == 0) return SAF_OK;
        if (pos_ >= n_) { *len = 0; return SAF_OK; }          // EOF
        uint64_t avail = n_ - pos_;
        uint64_t take = (*len < avail) ? *len : avail;
        std::memcpy(out, d_ + pos_, (size_t)take);
        pos_ += take;
        *len = take;
        return SAF_OK;
    }
    SafStatus write(const uint8_t*, uint64_t) override { return SAF_E_RO; }
    SafStatus seek(uint64_t off) override { pos_ = off; return SAF_OK; }
    SafStatus tell(uint64_t* p) override { if (!p) return SAF_E_BADARG; *p = pos_; return SAF_OK; }
    SafStatus flush() override { return SAF_OK; }
    SafStatus close() override { return SAF_OK; }
private:
    const uint8_t* d_;
    uint64_t       n_;
    uint64_t       pos_ = 0;
};

// ---- 内存写流：写进 vector，可 seek 覆盖/稀疏 ----
class MemWriteStream final : public Stream {
public:
    explicit MemWriteStream(std::vector<uint8_t>& sink) : s_(sink) { s_.clear(); }
    SafStatus read(uint8_t*, uint64_t*) override { return SAF_E_RO; }
    SafStatus write(const uint8_t* in, uint64_t len) override {
        if (len == 0) return SAF_OK;
        if (!in) return SAF_E_BADARG;
        // M28：pos_+len 回绕会把 resize 目标变小、memcpy 以回绕索引越界写；先做加法回绕校验
        if (len > SIZE_MAX - pos_) return SAF_E_BADARG;
        uint64_t end = pos_ + len;
        if (end > kMaxMemWrite) return SAF_E_NOMEM;   // vector 总容量绝对上限
        if (end > s_.size()) s_.resize((size_t)end);   // 增长段补零
        std::memcpy(&s_[(size_t)pos_], in, (size_t)len);
        pos_ += len;
        return SAF_OK;
    }
    SafStatus seek(uint64_t off) override {
        if (off > kMaxMemWrite) return SAF_E_BADARG;   // M28：seek 上界校验，杜绝 pos_ 被置到约 2^64 后回绕
        pos_ = off;
        return SAF_OK;
    }
    SafStatus tell(uint64_t* p) override { if (!p) return SAF_E_BADARG; *p = pos_; return SAF_OK; }
    SafStatus flush() override { return SAF_OK; }
    SafStatus close() override { return SAF_OK; }
private:
    std::vector<uint8_t>& s_;
    uint64_t              pos_ = 0;
};

}  // namespace

SafStatus saf_open_stdio(char mode, std::shared_ptr<Stream>& out) {
    out.reset();
    if (mode == 'r') { out = std::make_shared<StdioStream>(true);  return SAF_OK; }
    if (mode == 'w' || mode == 'a') { out = std::make_shared<StdioStream>(false); return SAF_OK; }
    return SAF_E_BADARG;
}

SafStatus saf_open_memory_read(const uint8_t* data, uint64_t n, std::shared_ptr<Stream>& out) {
    out.reset();
    if (n && !data) return SAF_E_BADARG;
    out = std::make_shared<MemReadStream>(data, n);
    return SAF_OK;
}

SafStatus saf_open_memory_write(std::vector<uint8_t>& sink, std::shared_ptr<Stream>& out) {
    out.reset();
    out = std::make_shared<MemWriteStream>(sink);
    return SAF_OK;
}

SafStatus saf_pump(Stream& src, Stream& dst, uint64_t src_skip,
                   const SafPumpProgress& prog, uint64_t* out_copied) {
    uint64_t chunk = prog.chunk ? prog.chunk : (1u << 20);
    // M29：chunk 钳制到 [4KiB, 1GiB]——过小无谓增加系统调用，过大则 SecureBuf 直接 OOM/抛异常穿出 SafStatus 接口；越界按调用方参数错误/资源不足拒绝
    constexpr uint64_t kPumpMinChunk = 4ull << 10;
    constexpr uint64_t kPumpMaxChunk = 1ull << 30;
    if (chunk < kPumpMinChunk) return SAF_E_BADARG;
    if (chunk > kPumpMaxChunk) return SAF_E_NOMEM;
    SecureBuf buf(chunk);
    uint64_t copied = 0;
    uint64_t skip_left = src_skip;
    SafStatus rc = SAF_OK;
    for (;;) {
        if (prog.cancelled && prog.cancelled()) { rc = SAF_E_BADARG; break; }
        uint64_t want = chunk;
        SafStatus st = src.read(buf.data(), &want);
        if (st != SAF_OK) { rc = st; break; }
        if (want == 0) break;                                   // EOF
        const uint8_t* p = buf.data();
        uint64_t n = want;
        if (skip_left > 0) {                                    // 续传：跳过已搬运前缀
            if (skip_left >= n) { skip_left -= n; continue; }
            p += skip_left;
            n -= skip_left;
            skip_left = 0;
        }
        st = dst.write(p, n);
        buf.zero();                                             // 明文块用完即擦
        if (st != SAF_OK) { rc = st; break; }
        copied += n;
        // 契约：on_bytes 只允许用于进度展示（stderr/日志/GUI），严禁写 stdout 数据通道——dst 可能恰为 stdout，进度帧混入会污染密文流
        if (prog.on_bytes) prog.on_bytes(n);
    }
    buf.zero();
    if (out_copied) *out_copied = copied;
    return rc;
}
