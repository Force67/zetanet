// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <array>
#include <map>
#include <znet/z_packets.h>
#include <znet/z_task_executor.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/memory/unique_pointer.h>
#include <base/containers/mpsc_queue.h>
#include <base/containers/lock_free_ordered_concurrent_hashmap.h>
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
  struct RateLimitConfig {
    mem_size max_packets_per_second = 1000;
    mem_size max_bytes_per_second = 10 * 1024 * 1024;
    mem_size burst_allowance = 2000;
  };

  ZPacketQueue(ZSocket&, ZPeerMapping&, base::Atomic<bool>& stop_token);

  bool StartThreads();
  void StopThreads();

  void ConfigureDispatchExecutor(ITaskExecutor* executor,
                                 mem_size built_in_worker_count = 0,
                                 mem_size built_in_max_queued_tasks = 0);

  void SetRateLimitConfig(const RateLimitConfig& config) {
    rate_limit_config_ = config;
  }

  void Push(OutgoingPacket&& package_move_in) {
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
  }
  
  bool CheckRateLimit(mem_size payload_bytes);
  bool Pop(PacketChannelType channel_type, IncomingPacket& p) {
    auto& queue = channel_incoming_queues_[channel_type];
    if (!queue.empty()) {
      queue.dequeue(p);
      return true;
    }
    return false;
  }

  PriorityMPSCQueue<OutgoingPacket>& GetChannelQueue(
      PacketChannelType channel) {
    return channel_outgoing_queues_[channel];
  }

  void SetCryptoProvider(ZCryptoContext* crypto) { crypto_context_ = crypto; }

  mem_size GetApproxOutgoingPacketCount(PacketChannelType channel) const {
    return channel_outgoing_queues_.at(channel).size_approx();
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
  void EnsureDispatchExecutor();
  void WaitForPendingDispatchTasks();
  void TrackDispatchTaskCompletion();

  void ProcessReceiving();
  void AddAwaitingAckPacket(ZPeerId return_address,
                            u32 sequence_number,
                            u32 ack_number);

 private:
  tx::network::ZSocket& socket_;
  tx::network::ZPeerMapping& peer_list_;
  ZCryptoContext* crypto_context_{nullptr};

  std::thread outgoing_thread_;
  std::thread incoming_thread_;

  base::Map<PacketChannelType, PriorityMPSCQueue<OutgoingPacket>>
      channel_outgoing_queues_;
  base::Map<PacketChannelType, PriorityMPSCQueue<IncomingPacket>>
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

  base::Array<base::Atomic<mem_size>, 2> channel_outgoing_bytes_{};
  base::Atomic<mem_size> awaiting_ack_packet_count_{0};
  base::Atomic<mem_size> awaiting_ack_bytes_{0};

  base::Atomic<bool>& stop_threads_;

  RateLimitConfig rate_limit_config_;
  base::Atomic<mem_size> packets_sent_this_second_{0};
  base::Atomic<mem_size> bytes_sent_this_second_{0};
  base::Atomic<mem_size> burst_tokens_{0};
  std::chrono::steady_clock::time_point rate_limit_window_start_;
  u32 gc_counter_{0};
};
}  // namespace tx::network
