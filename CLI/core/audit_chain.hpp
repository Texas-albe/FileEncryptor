#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fe {

struct AuditEvent {
    std::string op;
    std::string key;
    std::string device_id;
    int         status = 0;
    int         error_code = 0;
    std::uint64_t bytes = 0;
    std::uint64_t elapsed_ms = 0;
    std::uint64_t ts = 0;
};

struct AuditVerifyResult {
    bool          ok = false;
    bool          has_head = false;
    std::uint64_t head_seq = 0;
    std::string   head_mac;
    std::string   kid;
    std::uint64_t first_bad_seq = 0;
    std::uint64_t legacy_lines = 0;
    std::uint64_t checked_lines = 0;
    std::uint64_t schema3_lines = 0;
    std::vector<std::string> paths;
    std::string   err;
};

class AuditWriter {
public:
    AuditWriter() = default;
    AuditWriter(const AuditWriter&) = delete;
    AuditWriter& operator=(const AuditWriter&) = delete;
    ~AuditWriter();

    bool init(const std::string& log_path, const std::string& key_spec,
              bool strict, bool sync_each, bool keep_path, std::string& err);
    bool append(const AuditEvent& ev, std::string& err);
    void flush();

    bool protected_mode() const { return protected_; }
    const std::string& mode() const { return mode_; }
    const std::string& head_mac() const { return head_mac_; }
    std::uint64_t head_seq() const { return head_seq_; }
    const std::string& kid() const { return kid_; }

private:
    std::string path_;
    std::string kid_;
    std::string head_mac_;
    std::string boot_id_;
    std::string session_id_;
    std::string mode_ = "off";
    std::uint64_t head_seq_ = 0;
    std::uint64_t pending_ = 0;
    bool inited_ = false;
    bool protected_ = false;
    bool strict_ = false;
    bool sync_each_ = false;
    bool keep_path_ = false;
    unsigned char key_[32] = {0};
    std::intptr_t fd_ = 0;
};

AuditWriter& audit_writer();

bool audit_keygen(const std::string& path, std::string& err);
bool audit_verify(const std::string& path, const std::string& key_spec,
                  const std::string& anchor_path, AuditVerifyResult& out,
                  bool decrypt_path = false);
bool audit_write_anchor(const std::string& log_path, const std::string& key_spec,
                        const std::string& anchor_path, std::string& err);

} // namespace fe
