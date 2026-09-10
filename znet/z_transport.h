// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <cstddef>
#include <chrono>

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
#include <znet/z_clock.h>
#include <znet/z_synchronized_clock.h>

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
    base::StringRef pre_shared_key{};
    bool use_compression;
    bool allow_ipv6;
    bool start_threads = true;  // false = synchronous mode
    ZSocket::ChaosOptions chaos{};
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

  // Integrates zetanet with an existing job system; ownership stays with the
  // caller. Set before Init/Connect/Begin.
  void SetTaskExecutor(ITaskExecutor* executor);

  // Configures the built-in executor; worker_count 0 picks a default from
  // hardware concurrency.
  void SetBuiltInTaskExecutorConfig(mem_size worker_count,
                                    mem_size max_queued_tasks = 0);

  bool EnqueuePacket(OutgoingPacket&& packet);
  OutboundPressure GetOutboundPressure() const;

  void SetRateLimitConfig(const ZPacketQueue::RateLimitConfig& config) {
    packet_queue_.SetRateLimitConfig(config);
  }
  void SetCongestionControlConfig(
      const ZPacketQueue::CongestionControlConfig& config) {
    packet_queue_.SetCongestionControlConfig(config);
  }
  mem_size GetCongestionScalePerMille() const {
    return packet_queue_.GetCongestionScalePerMille();
  }
  bool encryption_enabled() const {
    return crypto_context_.Get_UseOnlyIfYouKnowWhatYouareDoing() != nullptr;
  }

  State state() const { return state_; }

  bool compression_enabled() const { return use_compression_; }
  u64 GetLocalClockTickMs() const;
  u64 GetSynchronizedClockTickMs() const;
  bool IsClockSynchronized() const;
  void SetClockAsymmetryCompensationMs(i32 compensation_ms);
  i32 GetClockAsymmetryCompensationMs() const;

  // At each peer_count threshold, the dispatch pool is reconfigured with the
  // given worker count; the first tier also starts the outgoing thread.
  // DisableAdaptiveThreading() switches to full direct mode.
  struct ThreadScalingTier {
    size_t peer_count;
    size_t dispatch_workers;
  };

  void SetThreadScaling(const ThreadScalingTier* tiers, size_t count) {
    scaling_tier_count_ = count < kMaxScalingTiers ? count : kMaxScalingTiers;
    for (size_t i = 0; i < scaling_tier_count_; ++i)
      scaling_tiers_[i] = tiers[i];
  }

  void DisableAdaptiveThreading() {
    scaling_tier_count_ = 0;
  }

  // Starts the incoming thread immediately.
  bool WarmIncomingThread() {
    return packet_queue_.StartIncomingThread();
  }

 private:
  tx::network::ZSocket socket_;
  base::Atomic<bool> stop_threads{false};

 protected:
  State state_{State::kDisconnected};
  bool use_compression_{false};

  static constexpr size_t kMaxScalingTiers = 4;
  ThreadScalingTier scaling_tiers_[kMaxScalingTiers] = {
      {32, 1},
      {64, 2},
      {128, 4},
  };
  size_t scaling_tier_count_{3};
  size_t current_scaling_tier_{0};
  base::UniquePointer<ZCryptoContext> crypto_context_;
  ZPacketQueue packet_queue_;
  ZPeerMapping peer_mapping_;
  ITaskExecutor* task_executor_override_{nullptr};
  mem_size built_in_executor_worker_count_{0};
  mem_size built_in_executor_max_queued_tasks_{0};
  base::Clock::time_point local_clock_epoch_{
      base::Clock::now()};
  ZSynchronizedClock synchronized_clock_{};

 protected:
  void ResetSynchronizedClock();
  void SynchronizeClockSample(u64 client_send_tick_ms,
                              u64 client_receive_tick_ms,
                              u64 server_receive_tick_ms,
                              u64 server_send_tick_ms);
  void UpdateSynchronizedClock();
};
}  // namespace tx::network
