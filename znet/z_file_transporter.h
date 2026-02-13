// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_peer.h>
#include <znet/z_packets.h>
#include <znet/z_file_write_interface.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/span.h>
#include <base/containers/vector.h>
#include <base/filesystem/file.h>
#include <base/filesystem/path.h>
#include <base/memory/unique_pointer.h>
#endif

namespace tx::network {
class ZAsyncTransportLayer;

class ZFileTransporter {
 public:
  struct TransferChunk {
    u64 transfer_id{0};
    u64 file_size{0};
    u32 chunk_size{0};
    u32 chunk_index{0};
    u32 total_chunks{0};
    u32 chunk_checksum{0};
    u32 file_checksum{0};
    bool has_file_name{false};
    bool is_last_chunk{false};
    base::String file_name;
    base::String data;
  };

  static constexpr size_t kDefaultChunkSize = 1024;

  struct TransferTuning {
    size_t chunk_size{kDefaultChunkSize};
    size_t max_inflight_chunks{2048};
    size_t max_inflight_bytes{64 * 1024 * 1024};
    size_t allocator_min_cached_blocks{128};
    u32 backpressure_sleep_ms{1};
    u32 backpressure_timeout_ms{120000};
  };

  ZFileTransporter(ZAsyncTransportLayer&,
                   IFileWriteFactory* file_write_factory = nullptr);
  ~ZFileTransporter();

  void SetFileWriteFactory(IFileWriteFactory* file_write_factory);

  bool SendFile(const base::Path&);
  bool SendFile(const base::Path&, ZPeerId destination);
  bool SendFile(const base::Path&,
                ZPeerId destination,
                const TransferTuning& tuning);

  bool BuildTransferChunkPayload(const TransferChunk& chunk,
                                 base::Vector<byte>& payload) const;
  bool ParseTransferChunkPayload(const base::Span<byte>& payload,
                                 TransferChunk& chunk) const;
  bool ParseTransferChunkPacket(const IncomingPacket& packet,
                                TransferChunk& chunk) const;

  bool AssembleFileFromChunks(
      const base::Path& output_path,
      const base::Map<u32, base::String>& chunks,
      u32 total_chunks);
  bool AssembleFileFromChunks(
      const base::Path& output_path,
      const base::Map<u32, base::String>& chunks,
      u32 total_chunks,
      u64 expected_file_size,
      u32 expected_file_checksum);

  bool StreamChunkToFile(const TransferChunk& chunk,
                         const base::Path& temp_directory,
                         bool* out_completed);
  bool FinalizeStreamedFile(u64 transfer_id, const base::Path& output_path);
  void AbortStreamedFile(u64 transfer_id);

 private:
  struct StreamReceiveSession {
    u64 transfer_id{0};
    u64 file_size{0};
    u32 chunk_size{0};
    u32 total_chunks{0};
    u32 expected_file_checksum{0};
    bool has_expected_file_checksum{false};
    base::Path temp_path;
    base::UniquePointer<IFileWriteHandle> temp_file;
    base::Vector<u8> received_chunks;
    u32 received_chunk_count{0};
  };

  bool WaitForSendWindow(const TransferTuning& tuning) const;
  bool ComputeFileChecksum(const base::Path& path, u32& out_checksum) const;
  bool EnsureStreamSession(const TransferChunk& chunk,
                           const base::Path& temp_directory,
                           StreamReceiveSession*& out_session);
  bool ValidatePath(const base::Path& base_dir, const base::Path& file_path) const;

  static bool IsPathTraversal(const base::String& path);

  ZAsyncTransportLayer& transport_layer_;
  IFileWriteFactory* file_write_factory_{nullptr};
  mutable base::Mutex stream_mutex_;
  base::Map<u64, StreamReceiveSession> active_streams_;
};
}  // namespace tx::network
