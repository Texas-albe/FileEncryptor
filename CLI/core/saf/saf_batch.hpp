// SAF 通用批量层
#pragma once

#include "saf.hpp"

#include <functional>
#include <string>
#include <vector>

// 遍历结果项
struct SafWalkItem {
    std::string path;            // 相对 root
    bool        is_dir = false;
    uint64_t    size   = 0;
    uint64_t    mtime  = 0;
};

// 递归枚举 root 下全部
// 后端不支持列目
SafStatus saf_walk(StorageBackend& be, const std::string& root,
                   std::vector<SafWalkItem>& out);

// 进度
struct SafTransferProgress {
    std::function<void(uint64_t bytes)> on_bytes;
    std::function<bool()>               cancelled;   // 返回 true 立即中止
    uint64_t                             chunk = 1u << 20;
};

// 单文件流式搬运
// skip_bytes > 0 时 dst
// out_copied 回填本次实际搬
SafStatus saf_transfer_file(StorageBackend& src, const std::string& src_path,
                            StorageBackend& dst, const std::string& dst_path,
                            uint64_t skip_bytes,
                            const SafTransferProgress& prog,
                            uint64_t* out_copied);

// 续传簿记
struct SafResumeEntry {
    bool     done  = false;
    uint64_t bytes = 0;          // 半完成
};

class SafResumeBook {
public:
    void mark_done(const std::string& key);
    void set_bytes(const std::string& key, uint64_t n);
    const SafResumeEntry* find(const std::string& key) const;
    size_t size() const;
    void clear();

    // 行格式
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
    uint64_t files_skip  = 0;    // 簿记里已完成
    uint64_t files_fail  = 0;
    uint64_t bytes       = 0;
};

// 按 walk 结果批量搬运
// name_map 可为空
SafStatus saf_transfer_tree(StorageBackend& src, const std::string& src_root,
                            StorageBackend& dst, const std::string& dst_root,
                            const std::function<std::string(const std::string&)>& name_map,
                            SafResumeBook& book, const std::string& key_prefix,
                            const SafTransferProgress& prog,
                            SafTransferStats& out_stats);

// 审计事件
struct SafAuditEvent {
    std::string op;              // encrypt / decrypt / delete / ...
    std::string key;             // 逻辑路径
    SafStatus   status = SAF_OK;
    uint64_t    bytes  = 0;
    uint64_t    ts     = 0;      // Unix 秒
    std::string device_id;       // 设备标识
    int         error_code = 0;  // 底层错误码
    uint64_t    elapsed_ms = 0;  
};

class SafAuditLog {
public:
    void append(const SafAuditEvent& ev);
    const std::vector<SafAuditEvent>& events() const;
    size_t size() const;
    void clear();

    std::string serialize() const;
    std::string to_jsonl() const;
    bool deserialize(const std::string& text);

private:
    std::vector<SafAuditEvent> evs_;
};

// 审计上报钩子
using SafAuditHook = std::function<void(const SafAuditEvent&)>;
void saf_set_audit_hook(SafAuditHook hook);
SafAuditLog& saf_audit_log();
