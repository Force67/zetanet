// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <array>
#include <map>
#include <znet/z_packets.h>
#include <znet/z_task_executor.h>
#include <znet/z_clock.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/memory/unique_pointer.h>
#include <base/containers/mpsc_queue.h>
#include <base/containers/lock_free_ordered_map.h>
#endif

#include <znet/z_crypto_wrapper.h>
#include <znet/z_socket.h>
#include <znet/z_peer_mapping.h>

#include <znet/z_packet_dispatcher.h>
#include <znet/z_packet_receiver.h>
#include <znet/z_packet_priority_queue.h>

#include <thread>
#include <condition_variable>
#include <mutex>

namespace tx::network {

class ZCryptoContext;
class ZPeerMapping;

class ZPacketQueue {
 public:
  static constexpr mem_size kChannelCount = 2;

  struct RateLimitConfig {
    mem_size max_packets_per_second = 500000;
    mem_size max_bytes_per_second = 1024 * 1024 * 1024;
    mem_size burst_allowance = 100000;
  };

  struct CongestionControlConfig {
    bool enabled = true;
    mem_size min_scale_per_mille = 300;
    mem_size max_scale_per_mille = 1600;
    mem_size additive_increase_per_window = 25;
    mem_size ack_events_per_window = 64;
    mem_size retransmit_backoff_per_mille = 900;
    mem_size drop_backoff_per_mille = 700;
    mem_size min_data_dispatch_per_tick = 64;
  };

  ZPacketQueue(ZSocket&, ZPeerMapping&, base::Atomic<bool>& stop_token);

  bool StartThreads();
  bool StartIncomingThread();
  bool StartOutgoingThread();
  void StopThreads();

  // Stops the outgoing thread, swaps the dispatch executor, restarts.
  // No-op when an external executor is set.
  void ReconfigureDispatchWorkers(mem_size new_worker_count);

  void ConfigureDispatchExecutor(ITaskExecutor* executor,
                                 mem_size built_in_worker_count = 0,
                                 mem_size built_in_max_queued_tasks = 0);

  void SetRateLimitConfig(const RateLimitConfig& config) {
    rate_limit_config_ = config;
  }
  void SetCongestionControlConfig(const CongestionControlConfig& config) {
    congestion_control_config_ = config;
  }
  mem_size GetCongestionScalePerMille() const {
    return congestion_scale_per_mille_.load(std::memory_order_relaxed);
  }

  // Atomics rather than thread_.joinable(): those are read from the receive
  // thread while another thread may be assigning or joining the std::thread
  // object, which would race on its handle.
  bool incoming_thread_running() const {
    return incoming_thread_active_.load(std::memory_order_acquire);
  }

  bool outgoing_thread_running() const {
    return outgoing_thread_active_.load(std::memory_order_acquire);
  }

  void Push(OutgoingPacket&& package_move_in) {
    if (!outgoing_thread_running()) {
      PushDirect(std::move(package_move_in));
      return;
    }
    if (!CheckRateLimit(package_move_in.heap_data_size)) {
      return;
    }
    const PacketChannelType channel = package_move_in.channel;
    const mem_size payload_bytes = package_move_in.heap_data_size;
    auto& queue = GetChannelQueue(package_move_in.channel);
    PacketPriority priority = (PacketPriority)package_move_in.flags.priority;
    queue.enqueue(std::move(package_move_in), priority);
    const mem_size channel_index = static_cast<mem_size>(channel);
    if (channel_index < channel_outgoing_bytes_.size()) {
      channel_outgoing_bytes_[channel_index].fetch_add(payload_bytes,
                                                       std::memory_order_relaxed);
    }
    // Notify only while the outgoing thread is sleeping. Taking the mutex
    // closes the window between the consumer's last emptiness re-check and
    // its cv wait, so the wakeup cannot be lost.
    if (outgoing_thread_sleeping_.load(std::memory_order_seq_cst)) {
      std::lock_guard<std::mutex> lock(outgoing_wakeup_mutex_);
      outgoing_wakeup_cv_.notify_one();
    }
  }

  // Dispatch directly from the calling thread, bypassing the outgoing queue.
  void PushDirect(OutgoingPacket&& packet) {
    dispatcher_.DispatchPacket(crypto_context_, packet, awaiting_ack_packets_);
  }
  
  bool CheckRateLimit(mem_size payload_bytes);

  // Synchronous single recvfrom(); for threadless mode.
  bool ReceiveOne();

  bool Pop(PacketChannelType channel_type, IncomingPacket& p) {
    if (!incoming_thread_running()) {
      ReceiveOne();
    }
    const mem_size index = static_cast<mem_size>(channel_type);
    if (index >= kChannelCount) {
      return false;
    }
    return channel_incoming_queues_[index].dequeue(p);
  }

  PriorityMPSCQueue<OutgoingPacket>& GetChannelQueue(
      PacketChannelType channel) {
    return channel_outgoing_queues_[static_cast<mem_size>(channel)];
  }

  void SetCryptoProvider(ZCryptoContext* crypto) { crypto_context_ = crypto; }

  mem_size GetApproxOutgoingPacketCount(PacketChannelType channel) const {
    const mem_size index = static_cast<mem_size>(channel);
    if (index >= kChannelCount) {
      return 0;
    }
    return channel_outgoing_queues_[index].size_approx();
  }

  mem_size GetApproxOutgoingBytes(PacketChannelType channel) const {
    const mem_size channel_index = static_cast<mem_size>(channel);
    if (channel_index >= channel_outgoing_bytes_.size()) {
      return 0;
    }
    return channel_outgoing_bytes_[channel_index].load(std::memory_order_relaxed);
  }

  mem_size GetApproxAwaitingAckPacketCount() const {
    return awaiting_ack_packet_count_.load(std::memory_order_relaxed);
  }

  mem_size GetApproxAwaitingAckBytes() const {
    return awaiting_ack_bytes_.load(std::memory_order_relaxed);
  }

 private:
  void ProcessOutgoingPackets();
  mem_size ProcessChannel(PacketChannelType, mem_size max_packets);
  mem_size GetDataDispatchBudget() const;
  void OnReliablePacketAcknowledged();
  void OnReliablePacketRetransmit();
  void OnReliablePacketDrop();
  void MaybeApplyCongestionRecovery(base::Clock::time_point now_tp);
  void EnsureDispatchExecutor();
  void WaitForPendingDispatchTasks();
  void TrackDispatchTaskCompletion();

  void ProcessReceiving();
  void AddAwaitingAckPacket(ZPeerId return_address,
                            u32 sequence_number,
                            u32 ack_number);
  // Removes the packet if it was destined for source_peer; counters drop
  // only when this remove() wins, so duplicate ACKs cannot double-decrement.
  void TryAcknowledgePacket(u32 acked_seq, u32 source_peer);
  bool HasPendingOutgoing() const {
    for (const auto& queue : channel_outgoing_queues_) {
      if (queue.size_approx() != 0) {
        return true;
      }
    }
    return false;
  }

 private:
  tx::network::ZSocket& socket_;
  tx::network::ZPeerMapping& peer_list_;
  ZCryptoContext* crypto_context_{nullptr};

  std::thread outgoing_thread_;
  std::thread incoming_thread_;

  // Indexed by PacketChannelType.
  base::Array<PriorityMPSCQueue<OutgoingPacket>, kChannelCount>
      channel_outgoing_queues_;
  base::Array<PriorityMPSCQueue<IncomingPacket>, kChannelCount>
      channel_incoming_queues_;

  base::LockFreeOrderedHashMap<u32, OutgoingPacket> awaiting_ack_packets_;

  PacketDispatcher dispatcher_;
  PacketReceiver receiver_;

  base::UniquePointer<ITaskExecutor> owned_dispatch_executor_;
  ITaskExecutor* dispatch_executor_{nullptr};
  ITaskExecutor* external_dispatch_executor_{nullptr};
  mem_size built_in_dispatch_worker_count_{0};
  mem_size built_in_dispatch_max_queued_tasks_{0};

  base::Atomic<mem_size> pending_dispatch_tasks_{0};
  std::mutex dispatch_wait_mutex_;
  std::condition_variable dispatch_wait_cv_;

  std::mutex outgoing_wakeup_mutex_;
  std::condition_variable outgoing_wakeup_cv_;

  base::Array<base::Atomic<mem_size>, 2> channel_outgoing_bytes_{};
  base::Atomic<mem_size> awaiting_ack_packet_count_{0};
  base::Atomic<mem_size> awaiting_ack_bytes_{0};

  base::Atomic<bool>& stop_threads_;
  base::Atomic<bool> incoming_thread_active_{false};
  base::Atomic<bool> outgoing_thread_active_{false};
  base::Atomic<bool> outgoing_thread_sleeping_{false};

  RateLimitConfig rate_limit_config_;
  // Guards rate_limit_window_start_, shared by all producer threads.
  std::mutex rate_limit_window_mutex_;
  base::Atomic<mem_size> packets_sent_this_second_{0};
  base::Atomic<mem_size> bytes_sent_this_second_{0};
  base::Atomic<mem_size> burst_tokens_{0};
  CongestionControlConfig congestion_control_config_;
  base::Atomic<mem_size> congestion_scale_per_mille_{1000};
  base::Atomic<mem_size> ack_events_since_adjust_{0};
  base::Clock::time_point next_congestion_recovery_time_{};
  base::Clock::time_point rate_limit_window_start_;
  u32 gc_counter_{0};
};
}  // namespace tx::network
