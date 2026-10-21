// SAF 通用批量层：遍历 / 搬运 / 续传 / 审计，全部基于逻辑路径
#pragma once

#include "saf.hpp"

#include <functional>
#include <string>
#include <vector>

// 遍历结果项
struct SafWalkItem {
    std::string path;            // 相对 root 的逻辑路径，目录不带尾斜杠
    bool        is_dir = false;
    uint64_t    size   = 0;
    uint64_t    mtime  = 0;
};

// 递归枚举 root 下全部条目（含 root 自身为文件的情况）
// 后端不支持列目录时返回 SAF_E_NOTIMPL
SafStatus saf_walk(StorageBackend& be, const std::string& root,
                   std::vector<SafWalkItem>& out);

// 进度与中止：on_bytes 每次搬运后回调增量字节数
struct SafTransferProgress {
    std::function<void(uint64_t bytes)> on_bytes;
    std::function<bool()>               cancelled;   // 返回 true 立即中止
    uint64_t                             chunk = 1u << 20;
};

// 单文件流式搬运：src_path → dst_path
// skip_bytes > 0 时 dst 以追加方式续写（源从该偏移读起）
// out_copied 回填本次实际搬运字节数；中止返回 SAF_E_BADARG
SafStatus saf_transfer_file(StorageBackend& src, const std::string& src_path,
                            StorageBackend& dst, const std::string& dst_path,
                            uint64_t skip_bytes,
                            const SafTransferProgress& prog,
                            uint64_t* out_copied);

// 续传簿记：key 由调用方给定，形如 "<scheme>|<root>|<logical path>"
struct SafResumeEntry {
    bool     done  = false;
    uint64_t bytes = 0;          // 半完成时的已搬运字节数
};

class SafResumeBook {
public:
    void mark_done(const std::string& key);
    void set_bytes(const std::string& key, uint64_t n);
    const SafResumeEntry* find(const std::string& key) const;
    size_t size() const;
    void clear();

    // 行格式：v1 <esc-key> <0|1> <bytes>，可存任意 Stream（本地 / 盘内 / 归档）
    std::string serialize() const;
    bool deserialize(const std::string& text);

    static std::string escape(const std::string& s);
    static bool unescape(const std::string& s, std::string& out);

private:
    std::vector<std::pair<std::string, SafResumeEntry>> items_;
};

// 整树搬运结果
struct SafTransferStats {
    uint64_t files_done  = 0;
    uint64_t files_skip  = 0;    // 簿记里已完成，直接跳过
    uint64_t files_fail  = 0;
    uint64_t bytes       = 0;
};

// 按 walk 结果批量搬运，逐条更新簿记；dst 支持时自动建目录
// name_map 可为空（原名搬运），否则把源逻辑路径映射成目标逻辑路径
SafStatus saf_transfer_tree(StorageBackend& src, const std::string& src_root,
                            StorageBackend& dst, const std::string& dst_root,
                            const std::function<std::string(const std::string&)>& name_map,
                            SafResumeBook& book, const std::string& key_prefix,
                            const SafTransferProgress& prog,
                            SafTransferStats& out_stats);

// 审计事件：只记逻辑路径，不含任何本地路径假设
struct SafAuditEvent {
    std::string op;              // encrypt / decrypt / delete / ...
    std::string key;             // 逻辑路径（后端无关）
    SafStatus   status = SAF_OK;
    uint64_t    bytes  = 0;
    uint64_t    ts     = 0;      // Unix 秒
};

class SafAuditLog {
public:
    void append(const SafAuditEvent& ev);
    const std::vector<SafAuditEvent>& events() const;
    size_t size() const;
    void clear();

    std::string serialize() const;
    bool deserialize(const std::string& text);

private:
    std::vector<SafAuditEvent> evs_;
};
