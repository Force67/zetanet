// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_queues.h"
#include "z_packet_serdes.h"
#include "z_wire_le.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#include <unordered_set>
#include <unordered_map>
#else
#include <base/time/time.h>
#endif

#include "z_socket.h"

namespace tx::network {
static constexpr char kLogTag[] = "z-packet-queue";
static constexpr u32 kResendIntervalSeconds = 1;
static constexpr u32 kDropAfterSeconds = 5;
static constexpr mem_size kMaxDispatchPerChannelPerTick = 4096;
static constexpr auto kIdleSleepDuration = std::chrono::microseconds(10);
static constexpr auto kRetryScanInterval = std::chrono::milliseconds(10);
namespace {
void SaturatingSub(base::Atomic<mem_size>& value, mem_size delta) {
  mem_size current = value.load(std::memory_order_relaxed);
  while (true) {
    const mem_size next = (current > delta) ? (current - delta) : 0;
    if (value.compare_exchange_weak(current, next, std::memory_order_relaxed)) {
      return;
    }
  }
}
}  // namespace

ZPacketQueue::ZPacketQueue(ZSocket& socket,
                           ZPeerMapping& peer_list,
                           base::Atomic<bool>& stop_token)
    : socket_(socket),
      peer_list_(peer_list),
      awaiting_ack_packets_(200),
      dispatcher_(socket, peer_list),
      receiver_(socket, peer_list),
      stop_threads_(stop_token),
      rate_limit_config_({}),
      rate_limit_window_start_(std::chrono::steady_clock::now()) {
    // Default-construct queues via operator[] (PriorityMPSCQueue is not moveable due to mutex)
    channel_outgoing_queues_[PacketChannelType::Control];
    channel_outgoing_queues_[PacketChannelType::Data];
    channel_outgoing_bytes_[0].store(0, std::memory_order_relaxed);
    channel_outgoing_bytes_[1].store(0, std::memory_order_relaxed);
    awaiting_ack_packet_count_.store(0, std::memory_order_relaxed);
    awaiting_ack_bytes_.store(0, std::memory_order_relaxed);
    packets_sent_this_second_.store(0, std::memory_order_relaxed);
    bytes_sent_this_second_.store(0, std::memory_order_relaxed);
    burst_tokens_.store(rate_limit_config_.burst_allowance, std::memory_order_relaxed);
    pending_dispatch_tasks_.store(0, std::memory_order_relaxed);
    dispatcher_.SetAwaitingAckCounters(&awaiting_ack_packet_count_, &awaiting_ack_bytes_);
}

void ZPacketQueue::ConfigureDispatchExecutor(ITaskExecutor* executor,
                                             mem_size built_in_worker_count,
                                             mem_size built_in_max_queued_tasks) {
  if (outgoing_thread_.joinable() || incoming_thread_.joinable()) {
    BASE_LOGW(kLogTag, "Cannot reconfigure dispatch executor while threads are running");
    return;
  }

  external_dispatch_executor_ = executor;
  built_in_dispatch_worker_count_ = built_in_worker_count;
  built_in_dispatch_max_queued_tasks_ = built_in_max_queued_tasks;

  owned_dispatch_executor_.Reset();
  dispatch_executor_ = external_dispatch_executor_;
}

bool ZPacketQueue::CheckRateLimit(mem_size payload_bytes) {
  // Fast path: skip rate limit checks if limits are at defaults (very high).
  // The default is 500K pkts/s and 1 GB/s — for benchmarks this never triggers.
  mem_size current_packets = packets_sent_this_second_.fetch_add(1, std::memory_order_relaxed);
  mem_size current_bytes = bytes_sent_this_second_.fetch_add(payload_bytes, std::memory_order_relaxed);

  // Only check clock when approaching the limit (99% of packets skip this).
  if (current_packets < rate_limit_config_.max_packets_per_second &&
      current_bytes + payload_bytes <= rate_limit_config_.max_bytes_per_second) {
    return true;
  }

  // Slow path: check if the window has elapsed.
  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      now - rate_limit_window_start_);

  if (elapsed.count() >= 1) {
    packets_sent_this_second_.store(1, std::memory_order_relaxed);
    bytes_sent_this_second_.store(payload_bytes, std::memory_order_relaxed);
    burst_tokens_.store(rate_limit_config_.burst_allowance, std::memory_order_relaxed);
    rate_limit_window_start_ = now;
    return true;
  }

  if (current_bytes + payload_bytes > rate_limit_config_.max_bytes_per_second) {
    SaturatingSub(packets_sent_this_second_, 1);
    SaturatingSub(bytes_sent_this_second_, payload_bytes);
    return false;
  }

  if (current_packets >= rate_limit_config_.max_packets_per_second) {
    mem_size current_burst = burst_tokens_.load(std::memory_order_relaxed);
    while (true) {
      if (current_burst == 0) {
        SaturatingSub(packets_sent_this_second_, 1);
        SaturatingSub(bytes_sent_this_second_, payload_bytes);
        return false;
      }
      if (burst_tokens_.compare_exchange_weak(current_burst, current_burst - 1,
                                               std::memory_order_relaxed)) {
        break;
      }
    }
  }

  return true;
}

bool ZPacketQueue::StartIncomingThread() {
  if (incoming_thread_.joinable()) return true;
  stop_threads_.store(false);
  incoming_thread_ = std::thread(&ZPacketQueue::ProcessReceiving, this);
  return true;
}

bool ZPacketQueue::StartOutgoingThread() {
  if (outgoing_thread_.joinable()) return true;
  EnsureDispatchExecutor();
  stop_threads_.store(false);
  outgoing_thread_ = std::thread(&ZPacketQueue::ProcessOutgoingPackets, this);
  return true;
}

bool ZPacketQueue::StartThreads() {
  if (outgoing_thread_.joinable() && incoming_thread_.joinable()) return true;
  StartIncomingThread();
  StartOutgoingThread();
  return true;
}

void ZPacketQueue::ReconfigureDispatchWorkers(mem_size new_worker_count) {
  if (external_dispatch_executor_) return;

  if (outgoing_thread_.joinable()) {
    // Upgrade: stop all threads, recreate executor, restart.
    bool had_incoming = incoming_thread_.joinable();
    StopThreads();
    owned_dispatch_executor_.Reset();
    dispatch_executor_ = nullptr;
    built_in_dispatch_worker_count_ = new_worker_count;
    if (had_incoming) StartIncomingThread();
    StartOutgoingThread();
  } else {
    // First start: set worker count, then launch outgoing thread.
    built_in_dispatch_worker_count_ = new_worker_count;
    StartOutgoingThread();
  }
}

void ZPacketQueue::StopThreads() {
  stop_threads_.store(true);
  outgoing_wakeup_cv_.notify_all();
  const auto current_thread_id = std::this_thread::get_id();
  if (outgoing_thread_.joinable() &&
      outgoing_thread_.get_id() != current_thread_id) {
    outgoing_thread_.join();
  }
  if (incoming_thread_.joinable() &&
      incoming_thread_.get_id() != current_thread_id) {
    incoming_thread_.join();
  }
  WaitForPendingDispatchTasks();
}

void ZPacketQueue::EnsureDispatchExecutor() {
  if (dispatch_executor_) {
    return;
  }
  ZThreadPoolTaskExecutor::Options options;
  options.worker_count = built_in_dispatch_worker_count_;
  options.max_queued_tasks = built_in_dispatch_max_queued_tasks_;
  owned_dispatch_executor_ = base::MakeUnique<ZThreadPoolTaskExecutor>(options);
  dispatch_executor_ = owned_dispatch_executor_.Get_UseOnlyIfYouKnowWhatYouareDoing();
}

void ZPacketQueue::WaitForPendingDispatchTasks() {
  std::unique_lock<std::mutex> lock(dispatch_wait_mutex_);
  dispatch_wait_cv_.wait(lock, [this] {
    return pending_dispatch_tasks_.load(std::memory_order_acquire) == 0;
  });
}

void ZPacketQueue::TrackDispatchTaskCompletion() {
  const mem_size remaining =
      pending_dispatch_tasks_.fetch_sub(1, std::memory_order_acq_rel) - 1;
  if (remaining == 0) {
    dispatch_wait_cv_.notify_all();
  }
}

void ZPacketQueue::ProcessOutgoingPackets() {
  auto next_retry_scan = std::chrono::steady_clock::now();
  while (!stop_threads_.load()) {
    mem_size dispatched = 0;
    dispatched += ProcessChannel(PacketChannelType::Control,
                                 kMaxDispatchPerChannelPerTick);
    dispatched += ProcessChannel(PacketChannelType::Data,
                                 kMaxDispatchPerChannelPerTick);

    // Periodically collect garbage from the ack tracking map
    if ((gc_counter_++ % 1000) == 0) {
      awaiting_ack_packets_.collect_garbage();
    }

    const auto now_tp = std::chrono::steady_clock::now();
    if (now_tp >= next_retry_scan) {
      const auto now = static_cast<u32>(base::GetUnixTimeStamp());
      for (auto& [seqNum, packet] : awaiting_ack_packets_) {
        const u32 packet_age = now - packet.last_send_time;
        // Drop packets that have exceeded retry budget to cap memory growth.
        if (packet_age > kDropAfterSeconds) {
          const mem_size dropped_bytes = packet.heap_data_size;
          awaiting_ack_packets_.remove(seqNum);
          SaturatingSub(awaiting_ack_packet_count_, 1);
          SaturatingSub(awaiting_ack_bytes_, dropped_bytes);
          continue;
        }
        if (packet_age > kResendIntervalSeconds) {
          dispatcher_.RetransmitPacket(crypto_context_, packet, seqNum);
          packet.last_send_time = now;
        }
      }
      next_retry_scan = now_tp + kRetryScanInterval;
    }

    if (dispatched == 0) {
      // Wait on condvar — Push() calls notify_one() so we wake immediately
      // when a packet is enqueued.  Falls back to periodic wake for retry scans.
      outgoing_thread_sleeping_.store(true, std::memory_order_release);
      std::unique_lock<std::mutex> lock(outgoing_wakeup_mutex_);
      outgoing_wakeup_cv_.wait_for(lock, kRetryScanInterval);
      outgoing_thread_sleeping_.store(false, std::memory_order_release);
    }
  }
}

mem_size ZPacketQueue::ProcessChannel(PacketChannelType channel,
                                      mem_size max_packets) {
  mem_size processed = 0;
  auto& queue = channel_outgoing_queues_[channel];

  // Fast path: dispatch directly without lambda/executor overhead.
  if (!dispatch_executor_) {
    while (processed < max_packets) {
      OutgoingPacket packet;
      if (!queue.dequeue(packet)) break;
      const mem_size channel_index = static_cast<mem_size>(channel);
      if (channel_index < channel_outgoing_bytes_.size()) {
        SaturatingSub(channel_outgoing_bytes_[channel_index], packet.heap_data_size);
      }
      dispatcher_.DispatchPacket(crypto_context_, packet, awaiting_ack_packets_);
      ++processed;
    }
    return processed;
  }

  while (processed < max_packets) {
    OutgoingPacket packet;
    if (!queue.dequeue(packet)) {
      break;
    }
    const mem_size channel_index = static_cast<mem_size>(channel);
    if (channel_index < channel_outgoing_bytes_.size()) {
      SaturatingSub(channel_outgoing_bytes_[channel_index], packet.heap_data_size);
    }
    pending_dispatch_tasks_.fetch_add(1, std::memory_order_acq_rel);
    ITaskExecutor::Task task = [this, packet = std::move(packet)]() mutable {
      try {
        dispatcher_.DispatchPacket(crypto_context_, packet, awaiting_ack_packets_);
      } catch (...) {
      }
      TrackDispatchTaskCompletion();
    };
    dispatch_executor_->Submit(std::move(task));
    ++processed;
  }
  return processed;
}

bool ZPacketQueue::ReceiveOne() {
  IncomingPacket pack;
  const auto result = receiver_.ReceivePackets(crypto_context_, pack);
  if (result == PacketReceiver::ReceiveResult::Success) {
    if (pack.flags.reliable) {
      AddAwaitingAckPacket(pack.source_peer_id, pack.sequence_number,
                           pack.acknowledgement_number);
    }
    auto prio = (PacketPriority)pack.flags.priority;
    channel_incoming_queues_[pack.channel].enqueue(std::move(pack), prio);
    return true;
  } else if (result == PacketReceiver::ReceiveResult::Acknowledgement) {
    if (pack.data.size() >= 4) {
      const byte* d = reinterpret_cast<const byte*>(pack.data.data());
      const u32 acked_seq = wire_le::LoadU32(d);
      bool destination_matches = false;
      const bool has_packet = awaiting_ack_packets_.with_value(
          acked_seq, [&](const OutgoingPacket& packet) {
            destination_matches =
                (packet.destination_peer_id == pack.source_peer_id) ||
                (packet.destination_peer_id == ZPeerId::to_server) ||
                (packet.destination_peer_id == ZPeerId::to_all);
            if (destination_matches) {
              SaturatingSub(awaiting_ack_bytes_, packet.heap_data_size);
            }
          });
      if (has_packet && destination_matches) {
        awaiting_ack_packets_.remove(acked_seq);
        SaturatingSub(awaiting_ack_packet_count_, 1);
      }
    }
    return true;
  }
  return false;
}

void ZPacketQueue::ProcessReceiving() {
  // Per-peer dedup sets live here (not in the class) to avoid changing the
  // header/ABI.  Sequence numbers are only unique within a single peer's
  // dispatcher, so dedup must be scoped per source_peer_id.
  // ProcessReceiving runs on a single dedicated thread per ZPacketQueue instance.
  std::unordered_map<u32, std::unordered_set<u32>> received_reliable_seqs;

  IncomingPacket pack;
  while (!stop_threads_.load()) {
    const auto result = receiver_.ReceivePackets(crypto_context_, pack);
    if (result == PacketReceiver::ReceiveResult::Success) {
      // record the new packet on the proper channel queue.
      auto prio = (PacketPriority)pack.flags.priority;

      if (pack.flags.reliable) {
        // Always ACK so the sender stops retransmitting.
        AddAwaitingAckPacket(pack.source_peer_id, pack.sequence_number,
                             pack.acknowledgement_number);
        // But only deliver once — drop duplicate sequence numbers per peer.
        if (!received_reliable_seqs[pack.source_peer_id]
                 .insert(pack.sequence_number)
                 .second) {
          continue;
        }
      }
      channel_incoming_queues_[pack.channel].enqueue(std::move(pack), prio);
    } else if (result == PacketReceiver::ReceiveResult::Acknowledgement) {
      // Parse the 4-byte LE payload to get the acked sequence number
      if (pack.data.size() >= 4) {
        const byte* d = reinterpret_cast<const byte*>(pack.data.data());
        const u32 acked_seq = wire_le::LoadU32(d);
        bool destination_matches = false;
        const bool has_packet = awaiting_ack_packets_.with_value(
            acked_seq, [&](const OutgoingPacket& packet) {
              destination_matches =
                  (packet.destination_peer_id == pack.source_peer_id) ||
                  (packet.destination_peer_id == ZPeerId::to_server) ||
                  (packet.destination_peer_id == ZPeerId::to_all);
              if (destination_matches) {
                SaturatingSub(awaiting_ack_bytes_, packet.heap_data_size);
              }
            });
        if (has_packet && destination_matches) {
          awaiting_ack_packets_.remove(acked_seq);
          SaturatingSub(awaiting_ack_packet_count_, 1);
        }
      }
    } else if (result == PacketReceiver::ReceiveResult::Goodbye) {
      stop_threads_.store(true);
      BASE_LOGI(kLogTag, "Goodbye packet received, stopping threads");
      break;
    }
  };
}

void ZPacketQueue::AddAwaitingAckPacket(ZPeerId return_address,
                                        u32 sequence_number,
                                        u32 ack_number) {
  const u8 use_encryption = crypto_context_ ? 1 : 0;
  const PackageFlags flags{.reliable = 0,
                           .encrypted = use_encryption,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::High,
                           .acknowledged = 1,
                           .awaiting_ack = 0,
                           .reserved = 0};
  // Serialize the acknowledged sequence number as a 4-byte LE payload
  byte ack_payload[4];
  wire_le::StoreU32(ack_payload, sequence_number);
  OutgoingPacket out(return_address.id, PacketType::Acknowledgement,
                     PacketChannelType::Control, flags,
                     base::Span<byte>(ack_payload, sizeof(ack_payload)));
  if (!outgoing_thread_running()) {
    dispatcher_.DispatchPacket(crypto_context_, out, awaiting_ack_packets_);
  } else {
    auto& queue = channel_outgoing_queues_[PacketChannelType::Control];
    queue.enqueue(std::move(out), PacketPriority::High);
  }
  if (ack_number == 0) {
    return;
  }

  bool destination_matches = false;
  const bool has_acknowledged_packet = awaiting_ack_packets_.with_value(
      ack_number, [&](const OutgoingPacket& packet) {
        destination_matches =
            (packet.destination_peer_id == return_address.id) ||
            (packet.destination_peer_id == ZPeerId::to_server) ||
            (packet.destination_peer_id == ZPeerId::to_all);
        if (destination_matches) {
          SaturatingSub(awaiting_ack_bytes_, packet.heap_data_size);
        }
      });
  if (has_acknowledged_packet && destination_matches) {
    awaiting_ack_packets_.remove(ack_number);
    SaturatingSub(awaiting_ack_packet_count_, 1);
  }
}

}  // namespace tx::network
