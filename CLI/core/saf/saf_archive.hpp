// 归档后端：目录树 ⇄ 单字节流（明文域），只读访问归档内文件树
#pragma once

#include "saf.hpp"

// 打包：递归 src 整棵树写入 out（FEPK1 布局，与既有归档格式一致）
SafStatus saf_archive_pack(StorageBackend& src, Stream& out);

// 解包：把归档条目还原到 dst 后端
SafStatus saf_archive_unpack(StorageBackend& arc, StorageBackend& dst);

// 打开本地归档文件作为只读后端
SafStatus saf_open_archive_file(const std::string& path, std::shared_ptr<StorageBackend>& out);

// 用已打开的归档流构造只读后端（流需可读可定位）
SafStatus saf_open_archive_stream(std::shared_ptr<Stream> raw,
                                  std::shared_ptr<StorageBackend>& out);
