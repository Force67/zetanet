// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_file_transporter.h"
#include "z_crypto_backend.h"
#include "z_file_write_interface.h"
#include "z_transport.h"
#include "z_wire_le.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <limits>
#include <thread>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/vector.h>
#include <base/filesystem/file.h>
#include <base/logging.h>
#endif

#include "z_network_allocator.h"

#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
#include <mbedtls/md.h>
#elif defined(ZNET_USE_STL)
#include <openssl/hmac.h>
#include <openssl/sha.h>
#else
#include <base/crypto/hmac.h>
#include <base/crypto/sha.h>
#endif

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-file-transporter";
constexpr u32 kWireMagic = 0x5A465452u;  // "ZFTR"
constexpr u8 kWireVersion = 1;
constexpr u8 kFlagHasFileName = 1u << 0u;
constexpr u8 kFlagLastChunk = 1u << 1u;
constexpr u8 kFlagHasHmac = 1u << 2u;

constexpr u32 kFnv1aOffset = 2166136261u;
constexpr u32 kFnv1aPrime = 16777619u;

constexpr mem_size kDispatchBatchSize = 64;
constexpr mem_size kFixedHeaderSize = 48;
constexpr mem_size kHmacSize = 32;

constexpr char kFileHmacKeyEnv[] = "ZNET_FILE_HMAC_KEY";

bool ComputeHmacSha256(const byte* data, mem_size size, const byte* key, mem_size key_size, byte* out_hmac) {
#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info != nullptr &&
         mbedtls_md_hmac(info, key, key_size, data, size, out_hmac) == 0;
#elif defined(ZNET_USE_STL)
  unsigned int hmac_len = 0;
  return HMAC(EVP_sha256(), key, static_cast<int>(key_size), data, size, out_hmac, &hmac_len) != nullptr && hmac_len == kHmacSize;
#else
  return base::HmacSha256(key, key_size, data, size, out_hmac, kHmacSize);
#endif
}

bool ContainsPathTraversal(const base::String& path) {
  if (path.empty()) {
    return true;
  }
  // Reject absolute paths
  if (path[0] == '/' || path[0] == '\\') {
    return true;
  }
  // Reject Windows drive letter paths (e.g. "C:")
  if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':') {
    return true;
  }
  for (mem_size i = 0; i < path.size(); ++i) {
    if (path[i] == '.' && i + 1 < path.size() && path[i + 1] == '.') {
      if (i + 2 >= path.size() || path[i + 2] == '/' || path[i + 2] == '\\') {
        return true;
      }
    }
    if (path[i] == '/' || path[i] == '\\') {
      if (i + 1 < path.size() && path[i + 1] == '.' && i + 2 < path.size() && path[i + 2] == '.') {
        return true;
      }
    }
  }
  return false;
}

u32 UpdateChecksum(const byte* data, mem_size size, u32 seed) {
  u32 hash = seed;
  for (mem_size i = 0; i < size; ++i) {
    hash ^= static_cast<u32>(data[i]);
    hash *= kFnv1aPrime;
  }
  return hash;
}

u32 ComputeChecksum(const byte* data, mem_size size) {
  return UpdateChecksum(data, size, kFnv1aOffset);
}

mem_size CalculateTotalChunks(const u64 file_size, const u32 chunk_size) {
  if (chunk_size == 0) {
    return 0;
  }
  if (file_size == 0) {
    return 1;
  }
  return static_cast<mem_size>((file_size + chunk_size - 1u) / chunk_size);
}

u64 SafeReadChunk(base::File& file,
                  const u64 offset,
                  char* output,
                  const u32 target_size) {
  u64 total_read = 0;
  while (total_read < target_size) {
    const int read = file.Read(static_cast<int64_t>(offset + total_read),
                               output + total_read,
                               static_cast<int>(target_size - total_read));
    if (read <= 0) {
      break;
    }
    total_read += static_cast<u64>(read);
  }
  return total_read;
}

u64 GenerateTransferId() {
  static base::Atomic<u64> counter{1};
  return counter.fetch_add(1u, std::memory_order_relaxed);
}
}  // namespace

ZFileTransporter::ZFileTransporter(ZAsyncTransportLayer& tp,
                                   IFileWriteFactory* file_write_factory)
    : transport_layer_(tp),
      file_write_factory_(file_write_factory ? file_write_factory
                                             : &GetDefaultFileWriteFactory()) {}
ZFileTransporter::~ZFileTransporter() {}

void ZFileTransporter::SetFileWriteFactory(
    IFileWriteFactory* file_write_factory) {
  std::lock_guard<base::Mutex> lock(stream_mutex_);
  file_write_factory_ = file_write_factory ? file_write_factory
                                           : &GetDefaultFileWriteFactory();
}

bool ZFileTransporter::SendFile(const base::Path& path) {
  return SendFile(path, ZPeerId(ZPeerId::to_all), TransferTuning{});
}

bool ZFileTransporter::SendFile(const base::Path& path, ZPeerId destination) {
  return SendFile(path, destination, TransferTuning{});
}

bool ZFileTransporter::SendFile(const base::Path& path,
                                ZPeerId destination,
                                const TransferTuning& tuning) {
  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    BASE_LOGE(kLogTag, "Failed to open file: {}", path.ToAsciiString());
    return false;
  }

  const int64_t signed_file_size = file.GetLength();
  if (signed_file_size < 0) {
    BASE_LOGE(kLogTag, "Failed to obtain file size: {}", path.ToAsciiString());
    return false;
  }
  const u64 file_size = static_cast<u64>(signed_file_size);
  if (tuning.chunk_size == 0 ||
      tuning.chunk_size > static_cast<mem_size>(std::numeric_limits<u32>::max())) {
    BASE_LOGE(kLogTag, "Invalid chunk_size in transfer tuning");
    return false;
  }
  const u32 chunk_size = static_cast<u32>(tuning.chunk_size);
  const mem_size total_chunks_64 = CalculateTotalChunks(file_size, chunk_size);
  if (total_chunks_64 == 0 ||
      total_chunks_64 > static_cast<mem_size>(std::numeric_limits<u32>::max())) {
    BASE_LOGE(kLogTag, "Unsupported chunk count for file {}", path.ToAsciiString());
    return false;
  }

  const base::String file_name = path.BaseName().ToAsciiString();
  if (file_name.empty() || file_name.size() > std::numeric_limits<u16>::max()) {
    BASE_LOGE(kLogTag, "Unsupported file name for transfer");
    return false;
  }

  const u32 total_chunks = static_cast<u32>(total_chunks_64);
  const u64 transfer_id = GenerateTransferId();
  base::Vector<char> read_buffer(chunk_size);
  base::Vector<byte> payload;
  payload.reserve(kFixedHeaderSize + file_name.size() + chunk_size);

  u64 file_offset = 0;
  u32 file_checksum = kFnv1aOffset;

  PacketBufferPool::Instance().BoostClassCacheForSize(
      payload.capacity(), tuning.allocator_min_cached_blocks);

  BASE_LOGI(kLogTag,
            "Sending file '{}' ({} bytes) in {} chunks with transfer_id={}",
            path.ToAsciiString(), file_size, total_chunks, transfer_id);

  for (u32 chunk_index = 0; chunk_index < total_chunks; ++chunk_index) {
    const u64 remaining = (file_size > file_offset) ? (file_size - file_offset) : 0;
    const u32 target_chunk_bytes =
        static_cast<u32>(std::min<u64>(remaining, static_cast<u64>(chunk_size)));
    const u64 bytes_read_u64 =
        SafeReadChunk(file, file_offset, read_buffer.data(), target_chunk_bytes);
    if (bytes_read_u64 > std::numeric_limits<u32>::max()) {
      BASE_LOGE(kLogTag, "Read size overflow while sending file chunk");
      return false;
    }
    const u32 bytes_read = static_cast<u32>(bytes_read_u64);

    if (target_chunk_bytes != bytes_read) {
      // A short read before EOF implies local file mutation or IO issues.
      if (file_offset + bytes_read < file_size) {
        BASE_LOGE(kLogTag,
                  "Unexpected short read for chunk {} (got {} expected {})",
                  chunk_index, bytes_read, target_chunk_bytes);
        return false;
      }
    }

    file_offset += bytes_read;
    file_checksum =
        UpdateChecksum(reinterpret_cast<const byte*>(read_buffer.data()), bytes_read,
                       file_checksum);

    payload.clear();
    payload.reserve(kFixedHeaderSize + file_name.size() + bytes_read);
    wire_le::AppendU32(payload, kWireMagic);
    payload.push_back(kWireVersion);
    u8 wire_flags = 0;
    if (chunk_index == 0) {
      wire_flags |= kFlagHasFileName;
    }
    const bool is_last_chunk = (chunk_index == (total_chunks - 1));
    if (is_last_chunk) {
      wire_flags |= kFlagLastChunk;
    }
    payload.push_back(wire_flags);
    wire_le::AppendU64(payload, transfer_id);
    wire_le::AppendU64(payload, file_size);
    wire_le::AppendU32(payload, chunk_size);
    wire_le::AppendU32(payload, chunk_index);
    wire_le::AppendU32(payload, total_chunks);
    wire_le::AppendU32(payload, bytes_read);
    wire_le::AppendU32(payload,
              ComputeChecksum(reinterpret_cast<const byte*>(read_buffer.data()),
                              bytes_read));
    wire_le::AppendU32(payload, is_last_chunk ? file_checksum : 0);
    if (chunk_index == 0) {
      wire_le::AppendU16(payload, static_cast<u16>(file_name.size()));
      const auto* file_name_bytes =
          reinterpret_cast<const byte*>(file_name.data());
      payload.insert(payload.end(), file_name_bytes,
                     file_name_bytes + file_name.size());
    } else {
      wire_le::AppendU16(payload, 0);
    }
    const auto* chunk_bytes = reinterpret_cast<const byte*>(read_buffer.data());
    payload.insert(payload.end(), chunk_bytes, chunk_bytes + bytes_read);

    if (!WaitForSendWindow(tuning)) {
      BASE_LOGE(kLogTag, "Backpressure timeout while sending transfer {}", transfer_id);
      return false;
    }

    const PackageFlags flags{
        .reliable = 1,
        .encrypted = static_cast<u8>(transport_layer_.encryption_enabled() ? 1 : 0),
        .compressed = 0,
        .priority = static_cast<u8>(PacketPriority::High),
        .acknowledged = 0,
        .awaiting_ack = 1,
        .reserved = 0};
    OutgoingPacket packet(destination.id, PacketType::FileTransfer,
                          PacketChannelType::Control, flags,
                          base::Span<byte>(payload.data(), payload.size()));
    if (!transport_layer_.EnqueuePacket(std::move(packet))) {
      BASE_LOGE(kLogTag, "Failed to enqueue file transfer chunk {}", chunk_index);
      return false;
    }

    if (((chunk_index + 1) % kDispatchBatchSize) == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  if (file_offset != file_size) {
    BASE_LOGE(kLogTag, "File size changed during transfer");
    return false;
  }

  BASE_LOGI(kLogTag, "Completed enqueue of transfer_id={} ({})", transfer_id,
            path.ToAsciiString());
  return true;
}

bool ZFileTransporter::AssembleFileFromChunks(
    const base::Path& output_path,
    const base::Map<u32, base::String>& chunks,
    u32 total_chunks) {
  return AssembleFileFromChunks(output_path, chunks, total_chunks,
                                std::numeric_limits<u64>::max(), 0);
}

bool ZFileTransporter::AssembleFileFromChunks(
    const base::Path& output_path,
    const base::Map<u32, base::String>& chunks,
    u32 total_chunks,
    u64 expected_file_size,
    u32 expected_file_checksum) {
  if (total_chunks == 0) {
    BASE_LOGE(kLogTag, "Cannot assemble transfer with zero chunks");
    return false;
  }

  const base::String output_path_str = output_path.ToAsciiString();
  if (IsPathTraversal(output_path_str)) {
    BASE_LOGE(kLogTag, "Path traversal attempt detected in output path");
    return false;
  }

  base::File output_file(
      output_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!output_file.IsValid()) {
    BASE_LOGE(kLogTag, "Failed to create file: {}", output_path.ToAsciiString());
    return false;
  }

  u64 bytes_written = 0;
  u32 file_checksum = kFnv1aOffset;
  for (u32 i = 0; i < total_chunks; ++i) {
    auto it = chunks.find(i);
    if (it == chunks.end()) {
      BASE_LOGE(kLogTag, "Missing chunk: {}", i);
      return false;
    }

    const base::String& chunk_data = it->second;
    mem_size chunk_offset = 0;
    while (chunk_offset < chunk_data.size()) {
      const int wrote = output_file.WriteAtCurrentPos(
          chunk_data.data() + chunk_offset,
          static_cast<int>(chunk_data.size() - chunk_offset));
      if (wrote <= 0) {
        BASE_LOGE(kLogTag, "Failed to write chunk: {}", i);
        return false;
      }
      chunk_offset += static_cast<mem_size>(wrote);
      bytes_written += static_cast<u64>(wrote);
    }
    file_checksum =
        UpdateChecksum(reinterpret_cast<const byte*>(chunk_data.data()),
                       chunk_data.size(), file_checksum);
  }

  if (expected_file_size != std::numeric_limits<u64>::max() &&
      bytes_written != expected_file_size) {
    BASE_LOGE(kLogTag, "Reassembled size mismatch: got {} expected {}",
              bytes_written, expected_file_size);
    return false;
  }
  if (expected_file_checksum != 0 && file_checksum != expected_file_checksum) {
    BASE_LOGE(kLogTag, "Reassembled checksum mismatch");
    return false;
  }

  return true;
}

bool ZFileTransporter::BuildTransferChunkPayload(
    const TransferChunk& chunk,
    base::Vector<byte>& payload) const {
  if (chunk.transfer_id == 0 || chunk.chunk_size == 0 || chunk.total_chunks == 0 ||
      chunk.chunk_index >= chunk.total_chunks) {
    return false;
  }
  if (chunk.data.size() > chunk.chunk_size) {
    return false;
  }
  if (chunk.has_file_name != (chunk.chunk_index == 0)) {
    return false;
  }
  if (chunk.has_file_name && chunk.file_name.empty()) {
    return false;
  }
  if (chunk.file_name.size() > std::numeric_limits<u16>::max()) {
    return false;
  }
  if (!chunk.has_file_name && !chunk.file_name.empty()) {
    return false;
  }
  if (chunk.is_last_chunk && chunk.chunk_index != (chunk.total_chunks - 1)) {
    return false;
  }
  if (!chunk.is_last_chunk && chunk.file_checksum != 0) {
    return false;
  }

  const u64 expected_total_chunks =
      CalculateTotalChunks(chunk.file_size, chunk.chunk_size);
  if (expected_total_chunks != chunk.total_chunks) {
    return false;
  }

  const u64 chunk_start = static_cast<u64>(chunk.chunk_index) * chunk.chunk_size;
  if (chunk_start > chunk.file_size) {
    return false;
  }
  const u64 remaining = chunk.file_size - chunk_start;
  const u64 expected_chunk_bytes = std::min<u64>(remaining, chunk.chunk_size);
  if (chunk.file_size == 0 && chunk.chunk_index == 0 && chunk.total_chunks == 1) {
    if (!chunk.data.empty()) {
      return false;
    }
  } else if (chunk.data.size() != expected_chunk_bytes) {
    return false;
  }

  payload.clear();
  payload.reserve(kFixedHeaderSize + chunk.file_name.size() + chunk.data.size());
  wire_le::AppendU32(payload, kWireMagic);
  payload.push_back(kWireVersion);
  u8 flags = 0;
  if (chunk.has_file_name) {
    flags |= kFlagHasFileName;
  }
  if (chunk.is_last_chunk) {
    flags |= kFlagLastChunk;
  }
  payload.push_back(flags);
  wire_le::AppendU64(payload, chunk.transfer_id);
  wire_le::AppendU64(payload, chunk.file_size);
  wire_le::AppendU32(payload, chunk.chunk_size);
  wire_le::AppendU32(payload, chunk.chunk_index);
  wire_le::AppendU32(payload, chunk.total_chunks);
  wire_le::AppendU32(payload, static_cast<u32>(chunk.data.size()));
  wire_le::AppendU32(payload, chunk.chunk_checksum);
  wire_le::AppendU32(payload, chunk.file_checksum);
  wire_le::AppendU16(payload, static_cast<u16>(chunk.file_name.size()));

  if (!chunk.file_name.empty()) {
    const auto* bytes = reinterpret_cast<const byte*>(chunk.file_name.data());
    payload.insert(payload.end(), bytes, bytes + chunk.file_name.size());
  }
  if (!chunk.data.empty()) {
    const auto* bytes = reinterpret_cast<const byte*>(chunk.data.data());
    payload.insert(payload.end(), bytes, bytes + chunk.data.size());
  }
  return true;
}

bool ZFileTransporter::ParseTransferChunkPayload(const base::Span<byte>& payload,
                                                 TransferChunk& chunk) const {
  if (payload.size() < kFixedHeaderSize) {
    return false;
  }

  chunk = TransferChunk{};
  mem_size cursor = 0;
  u32 magic = 0;
  u8 version = 0;
  u8 flags = 0;
  u16 file_name_size = 0;
  u32 chunk_data_size = 0;

  if (!wire_le::ReadU32(payload, cursor, magic)) {
    return false;
  }
  if (magic != kWireMagic || cursor >= payload.size()) {
    return false;
  }
  version = payload[cursor++];
  if (version != kWireVersion || cursor >= payload.size()) {
    return false;
  }
  flags = payload[cursor++];
  if ((flags & ~(kFlagHasFileName | kFlagLastChunk)) != 0) {
    return false;
  }
  if (!wire_le::ReadU64(payload, cursor, chunk.transfer_id)) {
    return false;
  }
  if (!wire_le::ReadU64(payload, cursor, chunk.file_size)) {
    return false;
  }
  if (!wire_le::ReadU32(payload, cursor, chunk.chunk_size) ||
      !wire_le::ReadU32(payload, cursor, chunk.chunk_index) ||
      !wire_le::ReadU32(payload, cursor, chunk.total_chunks) ||
      !wire_le::ReadU32(payload, cursor, chunk_data_size) ||
      !wire_le::ReadU32(payload, cursor, chunk.chunk_checksum) ||
      !wire_le::ReadU32(payload, cursor, chunk.file_checksum) ||
      !wire_le::ReadU16(payload, cursor, file_name_size)) {
    return false;
  }

  chunk.has_file_name = (flags & kFlagHasFileName) != 0;
  chunk.is_last_chunk = (flags & kFlagLastChunk) != 0;

  if (chunk.transfer_id == 0 || chunk.chunk_size == 0 || chunk.total_chunks == 0 ||
      chunk.chunk_index >= chunk.total_chunks) {
    return false;
  }
  if (chunk.has_file_name != (chunk.chunk_index == 0)) {
    return false;
  }
  if (!chunk.has_file_name && file_name_size != 0) {
    return false;
  }
  if (chunk.has_file_name && file_name_size == 0) {
    return false;
  }
  if (!chunk.is_last_chunk && chunk.file_checksum != 0) {
    return false;
  }
  if (chunk.is_last_chunk && chunk.chunk_index != (chunk.total_chunks - 1)) {
    return false;
  }

  const u64 expected_total_chunks =
      CalculateTotalChunks(chunk.file_size, chunk.chunk_size);
  if (expected_total_chunks != chunk.total_chunks) {
    return false;
  }

  if (cursor + file_name_size > payload.size()) {
    return false;
  }
  chunk.file_name.assign(
      reinterpret_cast<const char*>(payload.data() + cursor), file_name_size);
  cursor += file_name_size;
  
  if (IsPathTraversal(chunk.file_name)) {
    BASE_LOGE(kLogTag, "Path traversal attempt detected in filename");
    return false;
  }

  if (cursor + chunk_data_size != payload.size()) {
    return false;
  }
  if (chunk_data_size > chunk.chunk_size) {
    return false;
  }

  const u64 chunk_start = static_cast<u64>(chunk.chunk_index) * chunk.chunk_size;
  if (chunk_start > chunk.file_size) {
    return false;
  }
  const u64 remaining = chunk.file_size - chunk_start;
  const u64 expected_chunk_bytes = std::min<u64>(remaining, chunk.chunk_size);
  if (chunk.file_size == 0 && chunk.chunk_index == 0 && chunk.total_chunks == 1) {
    if (chunk_data_size != 0 || !chunk.is_last_chunk) {
      return false;
    }
  } else if (chunk_data_size != expected_chunk_bytes) {
    return false;
  }

  const u32 computed_checksum =
      ComputeChecksum(payload.data() + cursor, chunk_data_size);
  if (computed_checksum != chunk.chunk_checksum) {
    return false;
  }

  chunk.data.assign(reinterpret_cast<const char*>(payload.data() + cursor),
                    chunk_data_size);
  return true;
}

bool ZFileTransporter::ParseTransferChunkPacket(const IncomingPacket& packet,
                                                TransferChunk& chunk) const {
  if (packet.type != PacketType::FileTransfer ||
      packet.channel != PacketChannelType::Control) {
    return false;
  }
  return ParseTransferChunkPayload(
      base::Span<byte>(reinterpret_cast<const byte*>(packet.data.data()),
                       packet.data.size()),
      chunk);
}

bool ZFileTransporter::WaitForSendWindow(const TransferTuning& tuning) const {
  if (tuning.max_inflight_chunks == 0 && tuning.max_inflight_bytes == 0) {
    return true;
  }

  const auto start = std::chrono::steady_clock::now();
  const auto sleep_duration = std::chrono::milliseconds(
      std::max<u32>(1, tuning.backpressure_sleep_ms));
  while (true) {
    if (transport_layer_.state() != ZAsyncTransportLayer::State::kConnected) {
      return false;
    }
    const auto pressure = transport_layer_.GetOutboundPressure();
    const mem_size inflight_chunks = pressure.control_queued_packets;
    const mem_size inflight_bytes = pressure.control_queued_bytes;

    const bool chunks_ok =
        (tuning.max_inflight_chunks == 0) ||
        (inflight_chunks < tuning.max_inflight_chunks);
    const bool bytes_ok =
        (tuning.max_inflight_bytes == 0) ||
        (inflight_bytes < tuning.max_inflight_bytes);
    if (chunks_ok && bytes_ok) {
      return true;
    }

    if (tuning.backpressure_timeout_ms > 0) {
      const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - start);
      if (waited.count() >= tuning.backpressure_timeout_ms) {
        return false;
      }
    }
    std::this_thread::sleep_for(sleep_duration);
  }
}

bool ZFileTransporter::ComputeFileChecksum(const base::Path& path,
                                           u32& out_checksum) const {
  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    return false;
  }

  base::Vector<char> buffer(64 * 1024);
  u64 offset = 0;
  u32 checksum = kFnv1aOffset;
  while (true) {
    const int read = file.Read(static_cast<int64_t>(offset), buffer.data(),
                               static_cast<int>(buffer.size()));
    if (read < 0) {
      return false;
    }
    if (read == 0) {
      break;
    }
    checksum = UpdateChecksum(reinterpret_cast<const byte*>(buffer.data()),
                              static_cast<mem_size>(read), checksum);
    offset += static_cast<u64>(read);
  }
  out_checksum = checksum;
  return true;
}

bool ZFileTransporter::EnsureStreamSession(const TransferChunk& chunk,
                                           const base::Path& temp_directory,
                                           StreamReceiveSession*& out_session) {
  auto it = active_streams_.find(chunk.transfer_id);
  if (it != active_streams_.end()) {
    StreamReceiveSession& session = it->second;
    if (session.file_size != chunk.file_size || session.chunk_size != chunk.chunk_size ||
        session.total_chunks != chunk.total_chunks) {
      return false;
    }
    out_session = &session;
    return true;
  }

  if (chunk.has_file_name == false) {
    return false;
  }

  base::String temp_dir = temp_directory.ToAsciiString();
  if (!temp_dir.empty() && temp_dir.back() != '/' && temp_dir.back() != '\\') {
    temp_dir.push_back('/');
  }
  base::String temp_name = "znet-transfer-" + std::to_string(chunk.transfer_id) + ".part";
  const base::Path temp_path(temp_dir + temp_name);

  StreamReceiveSession session;
  session.transfer_id = chunk.transfer_id;
  session.file_size = chunk.file_size;
  session.chunk_size = chunk.chunk_size;
  session.total_chunks = chunk.total_chunks;
  session.temp_path = temp_path;
  if (!file_write_factory_) {
    return false;
  }
  session.temp_file = file_write_factory_->Open(temp_path, chunk.file_size);
  if (!session.temp_file) {
    return false;
  }
  session.received_chunks.resize(chunk.total_chunks, 0);

  auto [inserted, ok] =
      active_streams_.emplace(chunk.transfer_id, std::move(session));
  if (!ok) {
    return false;
  }
  out_session = &inserted->second;
  return true;
}

bool ZFileTransporter::StreamChunkToFile(const TransferChunk& chunk,
                                         const base::Path& temp_directory,
                                         bool* out_completed) {
  if (out_completed) {
    *out_completed = false;
  }

  std::lock_guard<base::Mutex> lock(stream_mutex_);
  StreamReceiveSession* session = nullptr;
  if (!EnsureStreamSession(chunk, temp_directory, session) || !session ||
      !session->temp_file) {
    return false;
  }

  if (session->received_chunks[chunk.chunk_index] != 0) {
    if (out_completed) {
      *out_completed = session->received_chunk_count == session->total_chunks &&
                       session->has_expected_file_checksum;
    }
    return true;
  }

  const u64 write_offset =
      static_cast<u64>(chunk.chunk_index) * static_cast<u64>(chunk.chunk_size);
  if (!session->temp_file.Get_UseOnlyIfYouKnowWhatYouareDoing()->WriteAt(
          write_offset, chunk.data.data(), chunk.data.size())) {
    return false;
  }

  session->received_chunks[chunk.chunk_index] = 1;
  session->received_chunk_count++;
  if (chunk.is_last_chunk) {
    session->expected_file_checksum = chunk.file_checksum;
    session->has_expected_file_checksum = true;
  }

  if (out_completed) {
    *out_completed = session->received_chunk_count == session->total_chunks &&
                     session->has_expected_file_checksum;
  }
  return true;
}

bool ZFileTransporter::FinalizeStreamedFile(u64 transfer_id,
                                            const base::Path& output_path) {
  base::Path temp_path;
  u32 expected_checksum = 0;
  {
    std::lock_guard<base::Mutex> lock(stream_mutex_);
    const auto it = active_streams_.find(transfer_id);
    if (it == active_streams_.end()) {
      return false;
    }
    StreamReceiveSession& session = it->second;
    if (session.received_chunk_count != session.total_chunks ||
        !session.has_expected_file_checksum) {
      return false;
    }
    if (!session.temp_file) {
      return false;
    }
    if (!session.temp_file.Get_UseOnlyIfYouKnowWhatYouareDoing()->FlushAndClose()) {
      return false;
    }
    session.temp_file.Reset();
    temp_path = session.temp_path;
    expected_checksum = session.expected_file_checksum;
  }

  u32 computed_checksum = 0;
  if (!ComputeFileChecksum(temp_path, computed_checksum)) {
    return false;
  }
  if (computed_checksum != expected_checksum) {
    return false;
  }

  const base::String out_path = output_path.ToAsciiString();
  const base::String tmp_path = temp_path.ToAsciiString();
  std::remove(out_path.c_str());
  if (std::rename(tmp_path.c_str(), out_path.c_str()) != 0) {
    return false;
  }

  std::lock_guard<base::Mutex> lock(stream_mutex_);
  active_streams_.erase(transfer_id);
  return true;
}

void ZFileTransporter::AbortStreamedFile(u64 transfer_id) {
  base::String temp_path;
  {
    std::lock_guard<base::Mutex> lock(stream_mutex_);
    const auto it = active_streams_.find(transfer_id);
    if (it == active_streams_.end()) {
      return;
    }
    if (it->second.temp_file) {
      it->second.temp_file.Get_UseOnlyIfYouKnowWhatYouareDoing()->Close();
      it->second.temp_file.Reset();
    }
    temp_path = it->second.temp_path.ToAsciiString();
    active_streams_.erase(it);
  }
  if (!temp_path.empty()) {
    std::remove(temp_path.c_str());
  }
}

bool ZFileTransporter::ValidatePath(const base::Path& base_dir,
                                     const base::Path& file_path) const {
  const base::String base_str = base_dir.ToAsciiString();
  const base::String file_str = file_path.ToAsciiString();
  if (ContainsPathTraversal(file_str)) {
    return false;
  }
  // Ensure the file path starts with the base directory prefix
  if (base_str.empty()) {
    return true;
  }
  base::String base_prefix = base_str;
  if (base_prefix.back() != '/' && base_prefix.back() != '\\') {
    base_prefix.push_back('/');
  }
  if (file_str.size() < base_prefix.size()) {
    return false;
  }
  return file_str.compare(0, base_prefix.size(), base_prefix) == 0;
}

bool ZFileTransporter::IsPathTraversal(const base::String& path) {
  return ContainsPathTraversal(path);
}

}  // namespace tx::network
