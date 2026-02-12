// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_file_transporter.h"
#include "z_transport.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/filesystem/file.h>
#include <base/logging.h>
#include <base/containers/vector.h>
#include <base/filesystem/memory_mapped_file.h>
#endif

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-file-transporter";
constexpr size_t kChunkSize = 1024;

size_t CalculateTotalChunks(int64_t file_size, size_t chunk_size) {
  return (file_size + chunk_size - 1) / chunk_size;
}

struct FileTransferHeader {
  u32 file_size;
  u32 chunk_size;
  u32 total_chunks;
  u32 name_length;
  u32 path_hint_length;
};
}  // namespace

ZFileTransporter::ZFileTransporter(ZAsyncTransportLayer& tp)
    : transport_layer_(tp) {}
ZFileTransporter::~ZFileTransporter() {}

bool ZFileTransporter::SendFile(const base::Path& path) {
  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    BASE_LOGE(kLogTag, "Failed to open file: {}", path.ToAsciiString());
    return false;
  }

  base::Vector<char> buffer(kChunkSize);
  int64_t file_size = file.GetLength();
  size_t total_chunks = CalculateTotalChunks(file_size, kChunkSize);
  BASE_LOGI(kLogTag, "File size: {} bytes, total chunks: {}", file_size,
            total_chunks);

  int64_t offset = 0;
  int bytes_read;
  while ((bytes_read = file.Read(offset, buffer.data(), kChunkSize)) > 0) {
    offset += bytes_read;

    base::Vector<byte> file_data(bytes_read);
    memcpy(file_data.data(), buffer.data(), bytes_read);
    PackageFlags flags{.reliable = 1,
                       .encrypted = 0,
                       .compressed = 1,
                       .priority = static_cast<u8>(PacketPriority::Low),
                       .acknowledged = 0,
                       .awaiting_ack = 1,
                       .reserved = 0};

    OutgoingPacket packet(ZPeerId::to_all, PacketType::FileTransfer,
                          PacketChannelType::Data, flags, file_data);
  }

  return true;
}

bool ZFileTransporter::AssembleFileFromChunks(
    const base::Path& output_path,
    const std::map<u32, std::string>& chunks,
    u32 total_chunks) {
  base::File output_file(
      output_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!output_file.IsValid()) {
    BASE_LOGE(kLogTag, "Failed to create file: {}", output_path.ToAsciiString());
    return false;
  }

  for (u32 i = 0; i < total_chunks; ++i) {
    auto it = chunks.find(i);
    if (it == chunks.end()) {
      BASE_LOGE(kLogTag, "Missing chunk: {}", i);
      return false;
    }

    const std::string& chunk_data = it->second;
    if (output_file.WriteAtCurrentPos(
            chunk_data.data(), static_cast<int>(chunk_data.size())) == -1) {
      BASE_LOGE(kLogTag, "Failed to write chunk: {}", i);
      return false;
    }
  }

  return true;
}
}  // namespace tx::network
