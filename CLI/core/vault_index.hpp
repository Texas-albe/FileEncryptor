// 加密盘索引模块
// 全局命名空间
#pragma once
#include <string>
#include <vector>
#include "vdisk.h"             // VDiskProgressFn / VDiskCancelFn 回调类型
#include "secure_buffer.hpp"
#include "FileEncryptor.hpp"   // CryptoMode


// 库元数据
// 明文前导
// 私钥派生
// 挂载命令需
// 隐私字段 root/created
// 解密需密码满足「vault.meta
struct VaultMeta {
    uint32_t format = 1;
    std::vector<unsigned char> salt;   // 16 字节
    std::string root;                  // 库根绝对路径
    uint64_t created = 0;              // 创建时间
    unsigned int opslimit = 4;         // Argon2id 参数
    uint32_t memlimit_kb = 65536;      // 64 MB
    std::string mount_point;           // 期望挂载点
    bool encrypted = false;                                  
    std::vector<unsigned char> meta_nonce;                   // crypto_secretbox_NONCEBYTES
    std::vector<unsigned char> meta_enc;                     // secretbox 密文
    // 新写入默认算法/
    int default_mode = 1;        // FE_M_MODE_*（1=XChaCha20）
    int compress_policy = 100;   
};

// 索引条目
struct VaultEntry {
    std::string rel_path;   // 相对库根
    std::string store;      // 实际 .ptd 文件名
    std::string orig_abs;   // 挂载
    uint64_t size = 0;      // 明文原始大小
    int64_t mtime = 0;      // 明文修改时间
    uint64_t enc_ts = 0;    // 加密时间戳
    std::string algo;       // 算法
    std::string kdf;        // 密钥派生
    bool is_dir = false;    // 显式目录条目
    VaultEntry() = default;
};

// 实际 .ptd 路径
// store 为空
std::string vault_ptd_path(const std::string& dir, const std::string& rel, const std::string& store);

// 生成随机 16 位 hex 存储
std::string vault_random_store_name();

// 保留路径判定
bool rel_first_reserved(const std::string& rel);

// 初始化库
// 清空进程内缓存
// 索引密钥
// 注册索引密钥缓
void set_index_key_cache_hook(
    bool (*fn)(const SecureBuffer&, const VaultMeta&, std::vector<unsigned char>&, std::string&),
    void (*drop)());
void forget_cached_index_keys();
// 从密码+库盐派生
bool derive_index_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key, std::string& err);
// 索引内存镜像
// 进程退出/锁定/卸
bool vault_flush_index(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, std::string& err);
// 丢弃内存镜像
void vault_drop_index_mirror();
// 索引盘面版本戳
// 未变
uint64_t vault_index_stamp(const std::string& dir);
bool vault_meta_init(const std::string& dir, const std::string& root,
                     VaultMeta& out, std::string& err);

// 仅载入已有 vault.meta
// 需 vault_meta_decrypt 用密码
bool vault_meta_load(const std::string& dir, VaultMeta& out, std::string& err);

// 回写 vault.meta
// 若 meta.encrypted
// 仅更新明文可写
bool vault_meta_save(const std::string& dir, const VaultMeta& m, std::string& err);

// 用索引密钥
// 仅在已持有密码
bool vault_meta_save_encrypted(const std::string& dir, const VaultMeta& m,
                               const std::vector<unsigned char>& kek, std::string& err);

bool vault_meta_decrypt(VaultMeta& m, const SecureBuffer& password, std::string& err);

// 由密码 + 库盐派生
bool vault_derive_key(const SecureBuffer& password, const VaultMeta& meta,
                      std::vector<unsigned char>& key32, std::string& err);

// 解密读取全部索
bool vault_read_index(const std::string& dir, const VaultMeta& meta,
                      const SecureBuffer& password, std::vector<VaultEntry>& out,
                      std::string& err);

// 增量追加一条索
// flush=false 时只
bool vault_append_entry(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const VaultEntry& e,
                        std::string& err, bool flush = true);

// 重扫库目录
// old_hint
// 故盘面旧索引
// progress 收
bool vault_reindex(const std::string& dir, const VaultMeta& meta,
                   const SecureBuffer& password, std::string& err,
                   const std::vector<VaultEntry>* old_hint = nullptr,
                   VDiskProgressFn progress = nullptr, void* user = nullptr,
                   VDiskCancelFn cancel = nullptr, void* cancel_user = nullptr,
                   bool* cancelled = nullptr);

// 覆写索引
bool vault_write_index(const std::string& dir, const VaultMeta& meta,
                      const SecureBuffer& password, const std::string& json,
                      std::string& err);

// 只写受影响分片
bool vault_write_index_folders(const std::string& dir, const VaultMeta& meta,
                               const SecureBuffer& password,
                               const std::vector<std::string>& folders,
                               const std::vector<VaultEntry>& entries,
                               std::string& err);

// 索引原子 upsert/remove：读全量 →
bool vault_upsert_entry(const std::string& dir, const VaultMeta& meta,
                        const SecureBuffer& password, const VaultEntry& e, std::string& err);
bool vault_remove_entry(const std::string& dir, const VaultMeta& meta,
                       const SecureBuffer& password, const std::string& rel_path, std::string& err);

// 批量删除
// 逐个调 vault_remove_entry 删
bool vault_remove_entries(const std::string& dir, const VaultMeta& meta,
                          const SecureBuffer& password,
                          const std::vector<std::string>& rel_paths, std::string& err);

// 条目序列化
// §4.4 恢复密钥
// 保险文件 <vault>/.fevault：库盐
// 恢复密钥 = 48 位十进
std::string vault_recovery_gen_code();                       // 生成 48 位十进制恢
bool vault_recovery_exists(const std::string& dir);
bool vault_recovery_create(const std::string& dir, const SecureBuffer& passphrase,
                           const std::string& code, std::string& err);
bool vault_recovery_load(const std::string& dir, const std::string& code,
                         SecureBuffer& out_passphrase, std::string& err);
bool vault_recovery_remove(const std::string& dir, std::string& err);

std::string vault_entries_to_json(const std::vector<VaultEntry>& entries);

// 算法枚举 → 人类
std::string vault_mode_str(CryptoMode m);
