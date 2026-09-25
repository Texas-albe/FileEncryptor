#pragma once
#include <string>
#include <vector>

// ---------- 密钥库（功能1） ----------
// 本机 age 身份与收件人公钥的统一管理：
//   <用户配置目录>/keys/library.yaml   索引（元数据：名称/类型/别名/备注/创建时间/缓存公钥）
//   <用户配置目录>/keys/<name>.key     密钥材料文件（索引只存文件名，不存材料本身）
//
// GUI 与 CLI 共用同一目录与索引格式，任一端导入的密钥对另一端立即可见。
// 索引文件由本模块生成，格式为扁平 YAML（每键一行标量），便于两端以简单解析器读写。

struct KeyLibEntry {
    std::string name;        // 唯一名称，[A-Za-z0-9._-]，1..64 字符（同时用作 .key 文件名）
    std::string kind;        // "identity"（AGE-SECRET-KEY-...）| "recipient"（age1...）
    std::string file;        // 密钥材料文件名，相对 keylib_dir()
    std::string alias;       // 可选别名（展示用）
    std::string notes;       // 可选备注（单行）
    std::string created;     // 本地时间 "YYYY-MM-DD HH:MM:SS"
    std::string public_key;  // identity：导入时派生并缓存的收件人公钥（age1...）；recipient：空
};

// 密钥库目录（无用户目录可用时返回空串）
std::string keylib_dir();

// 索引文件完整路径
std::string keylib_index_path();

// 名称合法性：1..64 字节，仅 [A-Za-z0-9._-]，不允许 "." / ".."（防路径穿越）
bool keylib_valid_name(const std::string& name);

// 读取索引。文件不存在视为空库（返回 true、空列表）；解析失败返回 false 并写 err。
bool keylib_load(std::vector<KeyLibEntry>& out, std::string& err);

// 写回索引（先写临时文件再原子替换）。entries 为空时写空索引。
bool keylib_save(const std::vector<KeyLibEntry>& entries, std::string& err);

// 在条目列表中按名称查找；命中返回 true（out 可空）。
bool keylib_find(const std::vector<KeyLibEntry>& entries,
                 const std::string& name, KeyLibEntry* out);

// 导入密钥文件：复制材料到 <库目录>/<name>.key（权限收紧），检测类型，
// identity 类型同时派生并缓存公钥。重名、材料为空或无法识别时返回 false。
bool keylib_add(const std::string& key_path, const std::string& name,
                const std::string& alias, const std::string& notes, std::string& err);

// 移除条目并删除对应 .key 文件（文件缺失仅告警，不视为失败）。
bool keylib_remove(const std::string& name, std::string& err);

// 更新条目缓存公钥（-L pub 导出后回写索引）。
bool keylib_set_public(const std::string& name, const std::string& pub, std::string& err);

// 解析条目对应的密钥材料文件完整路径（文件必须存在）。
bool keylib_key_path(const std::string& name, std::string& path, std::string& err);

// 把一批库名解析为收件人公钥列表（用于 -K 加密）：
//   recipient 条目 -> 读 .key 文件内容（一行 age1...）
//   identity  条目 -> 使用缓存公钥；缓存为空则报错（先 -L pub <name> 生成）
bool keylib_recipients(const std::vector<std::string>& names,
                       std::vector<std::string>& pubs, std::string& err);

// 导出密钥材料到 dest_dir（缺省为当前目录），目标名为 <原文件名>。
bool keylib_export(const std::string& name, const std::string& dest_dir, std::string& err);
