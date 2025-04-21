// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <map>
#include <string>
#include <base/filesystem/path.h>

namespace tx::network {
class ZAsyncTransportLayer;

class ZFileTransporter {
 public:
  ZFileTransporter(ZAsyncTransportLayer&);
  ~ZFileTransporter();

  bool SendFile(const base::Path&);

  bool AssembleFileFromChunks(
      const base::Path& output_path,
      const std::map<u32, std::string>& chunks,
      u32 total_chunks);

 private:
  ZAsyncTransportLayer& transport_layer_;
};
}  // namespace tx::network