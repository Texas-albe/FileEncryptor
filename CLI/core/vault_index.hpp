// 加密盘索引模块（M1）：库元数据 + 加密索引 .feindex + 增量入盘。
// 全局命名空间（core/ 下约定不加 namespace，避免 main.cpp/FileEncryptor.cpp 编译失败）。
#pragma once
#include <string>
#include <vector>
#include "secure_buffer.hpp"
#include "FileEncryptor.hpp"   // CryptoMode


// 库元数据（明文存于 <vault>/vault.meta）：只含盐/版本/根路径，不含任何密钥。
struct VaultMeta {
    uint32_t format = 1;
    std::vector<unsigned char> salt;   // 16 字节（crypto_pwhash_SALTBYTES）
    std::string root;                  // 库根绝对路径
    uint64_t created = 0;              // 创建时间（unix 秒）
    unsigned int opslimit = 4;         // Argon2id 参数（与索引密钥派生一致）
    uint32_t memlimit_kb = 65536;      // 64 MB
    std::string mount_point;           // 期望挂载点（盘符 "V:" 或 Linux 挂载目录）；空=未记录
};

// 索引条目：设计文档 §5 的 rel_path/orig_abs/size/mtime/enc_ts/算法参数。
struct VaultEntry {
    std::string rel_path;   // 相对库根（如 gts/Alpha/photos/2025/a.jpg），逻辑名
    std::string store;      // 实际 .ptd 文件名（不含目录与 .ptd 后缀）；空=沿用 rel_path 基名（旧盘兼容）
    std::string orig_abs;   // 挂载时由库根拼接的绝对原路径
    uint64_t size = 0;      // 明文原始大小
    int64_t mtime = 0;      // 明文修改时间
    uint64_t enc_ts = 0;    // 加密时间戳（预热排序用）
    std::string algo;       // 算法（XChaCha20 / AEGIS-256 / SM4-GCM ...）
    std::string kdf;        // 密钥派生（argon2id）
    VaultEntry() = default;
};

// 实际 .ptd 路径：目录结构沿用 rel_path，基名优先用 store（随机 16hex 命名）；
// store 为空（旧盘）则取 rel_path 基名。CLI 入盘/recrypt 与 vdisk 挂载共用此规则。
std::string vault_ptd_path(const std::string& dir, const std::string& rel, const std::string& store);

// 生成随机 16 位 hex 存储名（8 字节 → 16 hex）。
std::string vault_random_store_name();

// 初始化库：vault.meta 不存在则创建（随机盐），存在则载入校验。
// 清空进程内缓存的索引密钥（Argon2id 派生结果）——锁定/休眠时调用，
// 否则索引密钥会在内存中长期驻留，与 §4.1 密钥生命周期冲突。
// 注册索引密钥缓存实现（批量写优化，H5）。holder 在 open 时注册、lock 时调 drop。
void set_index_key_cache_hook(
    bool (*fn)(const SecureBuffer&, const VaultMeta&, std::vector<unsigned char>&, std::string&),
    void (*drop)());
void forget_cached_index_keys();
// 从密码+库盐派生索引密钥（Argon2id）。holder 的缓存 hook 需调用它做未命中路径。
bool derive_index_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key, std::string& err);
// 索引内存镜像（批量写优化）：把待落盘改动立即写入 .feindex。
// 进程退出/锁定/卸载前应调用，否则最后一批改动会丢。
bool vault_flush_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, std::string& err);
// 丢弃内存镜像（换库/锁定），下次写重新从盘面读。
void vault_drop_index_mirror();
bool vault_meta_init(const std::string& dir, const std::string& root,
                     VaultMeta& out, std::string& err);

// 仅载入已有 vault.meta（不存在返回 false）。
bool vault_meta_load(const std::string& dir, VaultMeta& out, std::string& err);

// 回写 vault.meta（保留原有盐与 KDF 参数，仅更新挂载点等可变字段）。
bool vault_meta_save(const std::string& dir, const VaultMeta& m, std::string& err);

// 由密码 + 库盐派生 32 字节索引密钥（Argon2id）。
bool vault_derive_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key32, std::string& err);

// 解密读取全部索引条目；.feindex 缺失视为空索引（ok=true）。密码错误返回 false。
bool vault_read_index(const std::string& dir, const VaultMeta& meta,
                      const SecureBuffer& password, std::vector<VaultEntry>& out,
                      std::string& err);

// 增量追加一条索引条目（载入现有、压入、重加密、原子写回）。
bool vault_append_entry(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const VaultEntry& e,
                        std::string& err);

// 重扫库目录：按 .ptd 头部重抽元数据重建索引（best-effort，覆盖式写入）。
bool vault_reindex(const std::string& dir, const VaultMeta& meta,
                   const SecureBuffer& password, std::string& err);

// 整体覆写索引（改密换盐重封 / recrypt 后重建用）。
bool vault_write_index(const std::string& dir, const VaultMeta& meta,
                      const SecureBuffer& password, const std::string& json,
                      std::string& err);

// 索引原子 upsert/remove（M6 写支持）：读全量 → 改 → 整体写回；内部走 write_file_atomic。
bool vault_upsert_entry(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const VaultEntry& e, std::string& err);
bool vault_remove_entry(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& rel_path, std::string& err);

// 条目序列化（紧凑 JSON，供 vault-list 输出与调试）。
// ---- §4.4 恢复密钥（BitLocker 语义，可轮换）----
// 保险文件 <vault>/.fevault：库盐 + Argon2id(恢复密钥) 加密的**主密码副本**。
// 恢复密钥 = 48 位十进制（≈159 bit）。泄露恢复密钥即泄露盘访问权。
std::string vault_recovery_gen_code();                       // 生成 48 位十进制恢复密钥
bool vault_recovery_exists(const std::string& dir);
bool vault_recovery_create(const std::string& dir, const SecureBuffer& passphrase,
                           const std::string& code, std::string& err);
bool vault_recovery_load(const std::string& dir, const std::string& code,
                         SecureBuffer& out_passphrase, std::string& err);
bool vault_recovery_remove(const std::string& dir, std::string& err);

std::string vault_entries_to_json(const std::vector<VaultEntry>& entries);

// 算法枚举 → 人类可读串（与 CLI 主程序口径一致）。
std::string vault_mode_str(CryptoMode m);
