#pragma once
#include <string>
#include <vector>

// 密钥库
// 存元数据

struct KeyLibEntry {
    std::string name;        // 唯一名称
    std::string kind;        
    std::string file;        // 密钥材料文件名
    std::string alias;       // 可选别名
    std::string notes;       // 可选备注
    std::string created;     // 本地时间 "YYYY-MM-DD
    std::string public_key;  // identity
};

// 密钥库目录
std::string keylib_dir();

// 索引文件完整路
std::string keylib_index_path();

// 名称合法性
bool keylib_valid_name(const std::string& name);

// 读取索引
bool keylib_load(std::vector<KeyLibEntry>& out, std::string& err);

// 写回索引
bool keylib_save(const std::vector<KeyLibEntry>& entries, std::string& err);

// 在条目列表
bool keylib_find(const std::vector<KeyLibEntry>& entries,
                 const std::string& name, KeyLibEntry* out);

// 导入密钥文件
// identity 类型同时派生并
bool keylib_add(const std::string& key_path, const std::string& name,
                const std::string& alias, const std::string& notes, std::string& err);

// 移除条目并删除
bool keylib_remove(const std::string& name, std::string& err);

// 更新条目缓存公
bool keylib_set_public(const std::string& name, const std::string& pub, std::string& err);

// 解析条目对应
bool keylib_key_path(const std::string& name, std::string& path, std::string& err);

// 把一批库名解析
// identity 用缓存公钥
bool keylib_recipients(const std::vector<std::string>& names,
                       std::vector<std::string>& pubs, std::string& err);

// 导出密钥材料到 dest_dir
bool keylib_export(const std::string& name, const std::string& dest_dir, std::string& err);
