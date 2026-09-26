// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_queues.h"
#include "z_packet_serdes.h"
#include "z_wire_le.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/threading/lock_guard.h>
#include <base/threading/mutex.h>
#include <base/atomic.h>
#include <base/memory/move.h>
#include <base/containers/unordered_map.h>
#include <base/time/time.h>
#endif

#include "z_socket.h"

namespace tx::network {
static constexpr char kLogTag[] = "z-packet-queue";
static constexpr u32 kResendIntervalSeconds = 1;
static constexpr u32 kDropAfterSeconds = 5;
static constexpr mem_size kMaxDispatchPerChannelPerTick = 4096;
static constexpr auto kIdleSleepDuration = base::Microseconds(10);
static constexpr auto kRetryScanInterval = base::Milliseconds(10);
static constexpr auto kCongestionRecoveryInterval = base::Milliseconds(100);
namespace {
// The queue whose outgoing / incoming thread is the calling thread, so that
// StopThreads() called from inside one of them does not join itself.
thread_local const ZPacketQueue* tl_outgoing_thread_of = nullptr;
thread_local const ZPacketQueue* tl_incoming_thread_of = nullptr;

void SaturatingSub(base::Atomic<mem_size>& value, mem_size delta) {
  mem_size current = value.load(base::memory_order_relaxed);
  while (true) {
    const mem_size next = (current > delta) ? (current - delta) : 0;
    if (value.compare_exchange_weak(current, next, base::memory_order_relaxed)) {
      return;
    }
  }
}

// Sliding bitmap window per peer. Reliable sequence numbers rise per sender,
// so duplicates and replays are dropped relative to the highest seen value
// without unbounded per-peer state.
class ReplayWindow {
 public:
  // True if seq was not seen before.
  bool Observe(u32 seq) {
    if (!initialized_) {
      initialized_ = true;
      highest_ = seq;
      bits_.fill(0);
      Set(seq);
      return true;
    }
    if (seq == highest_) {
      return false;
    }
    if (static_cast<i32>(seq - highest_) > 0) {
      const u32 advance = seq - highest_;
      if (advance >= kWindow) {
        bits_.fill(0);
      } else {
        for (u32 i = 1; i <= advance; ++i) {
          Clear(highest_ + i);
        }
      }
      highest_ = seq;
      Set(seq);
      return true;
    }
    const u32 behind = highest_ - seq;
    if (behind >= kWindow) {
      return false;
    }
    if (Test(seq)) {
      return false;
    }
    Set(seq);
    return true;
  }

 private:
  static constexpr u32 kWindow = 8192;
  void Set(u32 seq) { bits_[(seq % kWindow) / 64] |= (u64{1} << (seq % 64)); }
  void Clear(u32 seq) { bits_[(seq % kWindow) / 64] &= ~(u64{1} << (seq % 64)); }
  bool Test(u32 seq) const {
    return (bits_[(seq % kWindow) / 64] >> (seq % 64)) & 1u;
  }
  base::Array<u64, kWindow / 64> bits_{};
  u32 highest_{0};
  bool initialized_{false};
};

mem_size ScaleLimitByPerMille(mem_size base_limit, mem_size per_mille) {
  if (base_limit == 0) {
    return 0;
  }
  const u64 scaled =
      (static_cast<u64>(base_limit) * static_cast<u64>(per_mille)) / 1000u;
  if (scaled == 0) {
    return 1;
  }
  const u64 max_mem_size = static_cast<u64>(static_cast<mem_size>(-1));
  return static_cast<mem_size>(scaled > max_mem_size ? max_mem_size : scaled);
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
      congestion_control_config_({}),
      next_congestion_recovery_time_(base::TimeTicks::Now() + kCongestionRecoveryInterval),
      rate_limit_window_start_(base::TimeTicks::Now()) {
    channel_outgoing_bytes_[0].store(0, base::memory_order_relaxed);
    channel_outgoing_bytes_[1].store(0, base::memory_order_relaxed);
    awaiting_ack_packet_count_.store(0, base::memory_order_relaxed);
    awaiting_ack_bytes_.store(0, base::memory_order_relaxed);
    packets_sent_this_second_.store(0, base::memory_order_relaxed);
    bytes_sent_this_second_.store(0, base::memory_order_relaxed);
    burst_tokens_.store(rate_limit_config_.burst_allowance, base::memory_order_relaxed);
    congestion_scale_per_mille_.store(1000, base::memory_order_relaxed);
    ack_events_since_adjust_.store(0, base::memory_order_relaxed);
    pending_dispatch_tasks_.store(0, base::memory_order_relaxed);
    dispatcher_.SetAwaitingAckCounters(&awaiting_ack_packet_count_, &awaiting_ack_bytes_);
}

void ZPacketQueue::ConfigureDispatchExecutor(ITaskExecutor* executor,
                                             mem_size built_in_worker_count,
                                             mem_size built_in_max_queued_tasks) {
  if (outgoing_thread_ || incoming_thread_) {
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
  const mem_size congestion_scale =
      congestion_control_config_.enabled
          ? congestion_scale_per_mille_.load(base::memory_order_relaxed)
          : 1000;
  const mem_size max_packets_per_second =
      ScaleLimitByPerMille(rate_limit_config_.max_packets_per_second,
                           congestion_scale);
  const mem_size max_bytes_per_second =
      ScaleLimitByPerMille(rate_limit_config_.max_bytes_per_second,
                           congestion_scale);
  const mem_size burst_allowance =
      ScaleLimitByPerMille(rate_limit_config_.burst_allowance, congestion_scale);

  mem_size current_packets = packets_sent_this_second_.fetch_add(1, base::memory_order_relaxed);
  mem_size current_bytes = bytes_sent_this_second_.fetch_add(payload_bytes, base::memory_order_relaxed);

  if (current_packets < max_packets_per_second &&
      current_bytes + payload_bytes <= max_bytes_per_second) {
    return true;
  }

  {
    base::LockGuard<base::Mutex> lock(rate_limit_window_mutex_);
    const auto now = base::TimeTicks::Now();
    if ((now - rate_limit_window_start_).InSeconds() >= 1) {
      packets_sent_this_second_.store(1, base::memory_order_relaxed);
      bytes_sent_this_second_.store(payload_bytes, base::memory_order_relaxed);
      burst_tokens_.store(burst_allowance, base::memory_order_relaxed);
      rate_limit_window_start_ = now;
      return true;
    }
  }

  if (current_bytes + payload_bytes > max_bytes_per_second) {
    SaturatingSub(packets_sent_this_second_, 1);
    SaturatingSub(bytes_sent_this_second_, payload_bytes);
    return false;
  }

  if (current_packets >= max_packets_per_second) {
    mem_size current_burst = burst_tokens_.load(base::memory_order_relaxed);
    while (true) {
      if (current_burst == 0) {
        SaturatingSub(packets_sent_this_second_, 1);
        SaturatingSub(bytes_sent_this_second_, payload_bytes);
        return false;
      }
      if (burst_tokens_.compare_exchange_weak(current_burst, current_burst - 1,
                                               base::memory_order_relaxed)) {
        break;
      }
    }
  }

  return true;
}

bool ZPacketQueue::StartIncomingThread() {
  if (incoming_thread_) return true;
  stop_threads_.store(false);
  incoming_thread_active_.store(true, base::memory_order_release);
  incoming_thread_ = base::MakeUnique<base::Thread>(
      "znet-incoming", [this] { ProcessReceiving(); }, /*start_now=*/true);
  return true;
}

bool ZPacketQueue::StartOutgoingThread() {
  if (outgoing_thread_) return true;
  EnsureDispatchExecutor();
  stop_threads_.store(false);
  outgoing_thread_active_.store(true, base::memory_order_release);
  outgoing_thread_ = base::MakeUnique<base::Thread>(
      "znet-outgoing", [this] { ProcessOutgoingPackets(); }, /*start_now=*/true);
  return true;
}

bool ZPacketQueue::StartThreads() {
  if (outgoing_thread_ && incoming_thread_) return true;
  StartIncomingThread();
  StartOutgoingThread();
  return true;
}

void ZPacketQueue::ReconfigureDispatchWorkers(mem_size new_worker_count) {
  if (external_dispatch_executor_) return;

  if (outgoing_thread_) {
    bool had_incoming = static_cast<bool>(incoming_thread_);
    StopThreads();
    owned_dispatch_executor_.Reset();
    dispatch_executor_ = nullptr;
    built_in_dispatch_worker_count_ = new_worker_count;
    if (had_incoming) StartIncomingThread();
    StartOutgoingThread();
  } else {
    built_in_dispatch_worker_count_ = new_worker_count;
    StartOutgoingThread();
  }
}

void ZPacketQueue::StopThreads() {
  stop_threads_.store(true);
  outgoing_thread_active_.store(false, base::memory_order_release);
  incoming_thread_active_.store(false, base::memory_order_release);
  outgoing_wakeup_cv_.NotifyAll();
  if (outgoing_thread_ && tl_outgoing_thread_of != this) {
    outgoing_thread_->Join();
    outgoing_thread_.Reset();
  }
  if (incoming_thread_ && tl_incoming_thread_of != this) {
    incoming_thread_->Join();
    incoming_thread_.Reset();
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
  base::UniqueLock<base::Mutex> lock(dispatch_wait_mutex_);
  dispatch_wait_cv_.Wait(lock, [this] {
    return pending_dispatch_tasks_.load(base::memory_order_acquire) == 0;
  });
}

void ZPacketQueue::TrackDispatchTaskCompletion() {
  // Notify under the mutex: a spurious wake outside it could observe zero
  // and let the owner destroy this object while we touch the condvar.
  base::LockGuard<base::Mutex> lock(dispatch_wait_mutex_);
  const mem_size remaining =
      pending_dispatch_tasks_.fetch_sub(1, base::memory_order_acq_rel) - 1;
  if (remaining == 0) {
    dispatch_wait_cv_.NotifyAll();
  }
}

void ZPacketQueue::ProcessOutgoingPackets() {
  tl_outgoing_thread_of = this;
  auto next_retry_scan = base::TimeTicks::Now();
  while (!stop_threads_.load()) {
    mem_size dispatched = 0;
    dispatched += ProcessChannel(PacketChannelType::Control,
                                 kMaxDispatchPerChannelPerTick);
    dispatched +=
        ProcessChannel(PacketChannelType::Data, GetDataDispatchBudget());

    if ((gc_counter_++ % 1000) == 0) {
      awaiting_ack_packets_.collect_garbage();
    }

    const auto now_tp = base::TimeTicks::Now();
    if (now_tp >= next_retry_scan) {
      const auto now = static_cast<u32>(base::GetUnixTimeStamp());
      for (auto& [seqNum, packet] : awaiting_ack_packets_) {
        // Signed difference: last_send_time can lie slightly in the future
        // and must then read as age <= 0 rather than wrap.
        const i32 packet_age = static_cast<i32>(now - packet.last_send_time);
        if (packet_age > static_cast<i32>(kDropAfterSeconds)) {
          const mem_size dropped_bytes = packet.heap_data_size;
          // Counter adjustments only when this remove() wins; a concurrent
          // ACK may have already removed and accounted for the packet.
          if (awaiting_ack_packets_.remove(seqNum)) {
            OnReliablePacketDrop();
            SaturatingSub(awaiting_ack_packet_count_, 1);
            SaturatingSub(awaiting_ack_bytes_, dropped_bytes);
          }
          continue;
        }
        if (packet_age > static_cast<i32>(kResendIntervalSeconds)) {
          OnReliablePacketRetransmit();
          dispatcher_.RetransmitPacket(crypto_context_, packet, seqNum);
          packet.last_send_time = now;
        }
      }
      next_retry_scan = now_tp + kRetryScanInterval;
    }

    MaybeApplyCongestionRecovery(now_tp);

    if (dispatched == 0) {
      // Publish the sleeping flag, then re-check under the wakeup mutex so a
      // producer enqueuing in between cannot lose the wakeup.
      base::UniqueLock<base::Mutex> lock(outgoing_wakeup_mutex_);
      outgoing_thread_sleeping_.store(true, base::memory_order_seq_cst);
      if (!HasPendingOutgoing()) {
        outgoing_wakeup_cv_.WaitFor(lock, kRetryScanInterval);
      }
      outgoing_thread_sleeping_.store(false, base::memory_order_release);
    }
  }
}

mem_size ZPacketQueue::ProcessChannel(PacketChannelType channel,
                                      mem_size max_packets) {
  mem_size processed = 0;
  auto& queue = channel_outgoing_queues_[static_cast<mem_size>(channel)];

  // No executor: dispatch inline.
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
    pending_dispatch_tasks_.fetch_add(1, base::memory_order_acq_rel);
    ITaskExecutor::Task task = [this, packet = base::move(packet)]() mutable {
      dispatcher_.DispatchPacket(crypto_context_, packet, awaiting_ack_packets_);
      TrackDispatchTaskCompletion();
    };
    dispatch_executor_->Submit(base::move(task));
    ++processed;
  }
  return processed;
}

mem_size ZPacketQueue::GetDataDispatchBudget() const {
  if (!congestion_control_config_.enabled) {
    return kMaxDispatchPerChannelPerTick;
  }
  const mem_size scale =
      congestion_scale_per_mille_.load(base::memory_order_relaxed);
  const u64 scaled =
      (static_cast<u64>(kMaxDispatchPerChannelPerTick) * static_cast<u64>(scale)) / 1000u;
  mem_size budget = static_cast<mem_size>(scaled == 0 ? 1 : scaled);
  if (budget < congestion_control_config_.min_data_dispatch_per_tick) {
    budget = congestion_control_config_.min_data_dispatch_per_tick;
  }
  if (budget > kMaxDispatchPerChannelPerTick) {
    budget = kMaxDispatchPerChannelPerTick;
  }
  return budget;
}

void ZPacketQueue::OnReliablePacketAcknowledged() {
  if (!congestion_control_config_.enabled) {
    return;
  }
  ack_events_since_adjust_.fetch_add(1, base::memory_order_relaxed);
}

void ZPacketQueue::OnReliablePacketRetransmit() {
  if (!congestion_control_config_.enabled) {
    return;
  }
  mem_size current = congestion_scale_per_mille_.load(base::memory_order_relaxed);
  while (true) {
    const mem_size reduced =
        (current * congestion_control_config_.retransmit_backoff_per_mille) / 1000;
    const mem_size clamped =
        reduced < congestion_control_config_.min_scale_per_mille
            ? congestion_control_config_.min_scale_per_mille
            : reduced;
    if (congestion_scale_per_mille_.compare_exchange_weak(
            current, clamped, base::memory_order_relaxed)) {
      break;
    }
  }
}

void ZPacketQueue::OnReliablePacketDrop() {
  if (!congestion_control_config_.enabled) {
    return;
  }
  mem_size current = congestion_scale_per_mille_.load(base::memory_order_relaxed);
  while (true) {
    const mem_size reduced =
        (current * congestion_control_config_.drop_backoff_per_mille) / 1000;
    const mem_size clamped =
        reduced < congestion_control_config_.min_scale_per_mille
            ? congestion_control_config_.min_scale_per_mille
            : reduced;
    if (congestion_scale_per_mille_.compare_exchange_weak(
            current, clamped, base::memory_order_relaxed)) {
      break;
    }
  }
}

void ZPacketQueue::MaybeApplyCongestionRecovery(base::TimeTicks now_tp) {
  if (!congestion_control_config_.enabled) {
    return;
  }
  if (now_tp < next_congestion_recovery_time_) {
    return;
  }
  const mem_size ack_events =
      ack_events_since_adjust_.exchange(0, base::memory_order_relaxed);
  if (ack_events < congestion_control_config_.ack_events_per_window) {
    next_congestion_recovery_time_ = now_tp + kCongestionRecoveryInterval;
    return;
  }
  mem_size current = congestion_scale_per_mille_.load(base::memory_order_relaxed);
  while (true) {
    mem_size raised =
        current + congestion_control_config_.additive_increase_per_window;
    if (raised > congestion_control_config_.max_scale_per_mille) {
      raised = congestion_control_config_.max_scale_per_mille;
    }
    if (congestion_scale_per_mille_.compare_exchange_weak(
            current, raised, base::memory_order_relaxed)) {
      break;
    }
  }
  next_congestion_recovery_time_ = now_tp + kCongestionRecoveryInterval;
}

void ZPacketQueue::TryAcknowledgePacket(u32 acked_seq, u32 source_peer) {
  bool destination_matches = false;
  mem_size acked_bytes = 0;
  const bool has_packet = awaiting_ack_packets_.with_value(
      acked_seq, [&](const OutgoingPacket& packet) {
        destination_matches =
            (packet.destination_peer_id == source_peer) ||
            (packet.destination_peer_id == ZPeerId::to_server) ||
            (packet.destination_peer_id == ZPeerId::to_all);
        acked_bytes = packet.heap_data_size;
      });
  if (has_packet && destination_matches &&
      awaiting_ack_packets_.remove(acked_seq)) {
    SaturatingSub(awaiting_ack_packet_count_, 1);
    SaturatingSub(awaiting_ack_bytes_, acked_bytes);
    OnReliablePacketAcknowledged();
  }
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
    const mem_size channel_index = static_cast<mem_size>(pack.channel);
    if (channel_index < kChannelCount) {
      channel_incoming_queues_[channel_index].enqueue(base::move(pack), prio);
    }
    return true;
  } else if (result == PacketReceiver::ReceiveResult::Acknowledgement) {
    if (pack.data.size() >= 4) {
      const u32 acked_seq = wire_le::LoadU32(
          reinterpret_cast<const byte*>(pack.data.data()));
      TryAcknowledgePacket(acked_seq, pack.source_peer_id);
    }
    return true;
  }
  return false;
}

void ZPacketQueue::ProcessReceiving() {
  tl_incoming_thread_of = this;
  // Per-peer dedup state, scoped per source_peer_id because sequence numbers
  // are only unique within one peer's dispatcher. Bounded by the per-peer
  // window and kMaxPeers. Runs on a single dedicated thread per instance.
  base::UnorderedMap<u32, ReplayWindow> received_reliable_seqs;

  IncomingPacket pack;
  while (!stop_threads_.load()) {
    const auto result = receiver_.ReceivePackets(crypto_context_, pack);
    if (result == PacketReceiver::ReceiveResult::Success) {
      auto prio = (PacketPriority)pack.flags.priority;

      if (pack.flags.reliable) {
        // Always ACK so the sender stops retransmitting, but deliver once.
        AddAwaitingAckPacket(pack.source_peer_id, pack.sequence_number,
                             pack.acknowledgement_number);
        if (!received_reliable_seqs[pack.source_peer_id].Observe(
                pack.sequence_number)) {
          continue;
        }
      }
      const mem_size channel_index = static_cast<mem_size>(pack.channel);
      if (channel_index < kChannelCount) {
        channel_incoming_queues_[channel_index].enqueue(base::move(pack), prio);
      }
    } else if (result == PacketReceiver::ReceiveResult::Acknowledgement) {
      if (pack.data.size() >= 4) {
        const u32 acked_seq = wire_le::LoadU32(
            reinterpret_cast<const byte*>(pack.data.data()));
        TryAcknowledgePacket(acked_seq, pack.source_peer_id);
      }
    } else if (result == PacketReceiver::ReceiveResult::Goodbye) {
      stop_threads_.store(true);
      BASE_LOGI(kLogTag, "Goodbye packet received, stopping threads");
      break;
    } else {
      // Nothing readable: park in poll() until data arrives. The interval
      // bounds how long StopThreads() waits for this thread.
      socket_.WaitReadable(/*timeout_ms=*/10);
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
  byte ack_payload[4];
  wire_le::StoreU32(ack_payload, sequence_number);
  OutgoingPacket out(return_address.id, PacketType::Acknowledgement,
                     PacketChannelType::Control, flags,
                     base::Span<byte>(ack_payload, sizeof(ack_payload)));
  if (!outgoing_thread_running()) {
    dispatcher_.DispatchPacket(crypto_context_, out, awaiting_ack_packets_);
  } else {
    auto& queue = GetChannelQueue(PacketChannelType::Control);
    queue.enqueue(base::move(out), PacketPriority::High);
  }
  if (ack_number == 0) {
    return;
  }
  TryAcknowledgePacket(ack_number, return_address.id);
}

}  // namespace tx::network
