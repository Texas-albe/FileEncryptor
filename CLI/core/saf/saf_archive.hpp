// 归档后端
#pragma once

#include "saf.hpp"

// 打包
SafStatus saf_archive_pack(StorageBackend& src, Stream& out);

// 解包
SafStatus saf_archive_unpack(StorageBackend& arc, StorageBackend& dst);

// 打开本
SafStatus saf_open_archive_file(const std::string& path, std::shared_ptr<StorageBackend>& out);

// 用已打开
SafStatus saf_open_archive_stream(std::shared_ptr<Stream> raw,
                                  std::shared_ptr<StorageBackend>& out);
