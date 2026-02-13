// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <cstddef>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/atomic.h>
#include <base/memory/unique_pointer.h>
#endif

#include <znet/z_crypto_wrapper.h>
#include <znet/z_packet_queues.h>
#include <znet/z_task_executor.h>
#include <znet/z_socket.h>
#include <znet/z_peer_mapping.h>

namespace tx::network {

class ZAsyncTransportLayer {
 public:
  ZAsyncTransportLayer();
  ~ZAsyncTransportLayer();

  enum class State { kDisconnected, kConnecting, kConnected, kDisconnecting };
  enum class ConnectionType { kClient, kServer, kP2PNode };

  struct InitOptions {
    const base::StringRef ip;
    u16 port;
    u16 local_bind_port;
    ConnectionType setup_type;
    bool use_encryption;
    bool use_compression;
    bool allow_ipv6;
  };

  struct OutboundPressure {
    mem_size control_queued_packets{0};
    mem_size control_queued_bytes{0};
    mem_size data_queued_packets{0};
    mem_size data_queued_bytes{0};
    mem_size awaiting_ack_packets{0};
    mem_size awaiting_ack_bytes{0};
  };
  bool Init(const InitOptions&);

  void Deinit();

  // Set a custom executor before Init/Connect/Begin to integrate zetanet with
  // an existing job system. Ownership stays with the caller.
  void SetTaskExecutor(ITaskExecutor* executor);

  // Configure the built-in executor used when no custom executor is set.
  // worker_count = 0 picks a sensible default based on hardware concurrency.
  void SetBuiltInTaskExecutorConfig(mem_size worker_count,
                                    mem_size max_queued_tasks = 0);

  bool EnqueuePacket(OutgoingPacket&& packet);
  OutboundPressure GetOutboundPressure() const;
  bool encryption_enabled() const {
    return crypto_context_.Get_UseOnlyIfYouKnowWhatYouareDoing() != nullptr;
  }

  State state() const { return state_; }

  bool compression_enabled() const { return use_compression_; }

 private:
  tx::network::ZSocket socket_;
  base::Atomic<bool> stop_threads{false};

 protected:
  State state_{State::kDisconnected};
  bool use_compression_{false};
  base::UniquePointer<ZCryptoContext> crypto_context_;
  ZPacketQueue packet_queue_;
  ZPeerMapping peer_mapping_;
  ITaskExecutor* task_executor_override_{nullptr};
  mem_size built_in_executor_worker_count_{0};
  mem_size built_in_executor_max_queued_tasks_{0};
};
}  // namespace tx::network
