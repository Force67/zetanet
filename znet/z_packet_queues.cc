// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_queues.h"
#include "z_packet_serdes.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/time/time.h>
#endif

#include "z_socket.h"
#include "z_packet_serdes.h"

namespace tx::network {
static constexpr char kLogTag[] = "z-packet-queue";
static constexpr u32 kResendIntervalSeconds = 1;
static constexpr u32 kDropAfterSeconds = 5;
namespace {
void SaturatingSub(base::Atomic<size_t>& value, size_t delta) {
  size_t current = value.load(std::memory_order_relaxed);
  while (true) {
    const size_t next = (current > delta) ? (current - delta) : 0;
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
    dispatcher_.SetAwaitingAckCounters(&awaiting_ack_packet_count_, &awaiting_ack_bytes_);
}

bool ZPacketQueue::CheckRateLimit(size_t payload_bytes) {
  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      now - rate_limit_window_start_);
  
  if (elapsed.count() >= 1) {
    packets_sent_this_second_.store(0, std::memory_order_relaxed);
    bytes_sent_this_second_.store(0, std::memory_order_relaxed);
    burst_tokens_.store(rate_limit_config_.burst_allowance, std::memory_order_relaxed);
    rate_limit_window_start_ = now;
  }
  
  size_t current_packets = packets_sent_this_second_.load(std::memory_order_relaxed);
  size_t current_bytes = bytes_sent_this_second_.load(std::memory_order_relaxed);
  size_t burst = burst_tokens_.load(std::memory_order_relaxed);
  
  if (current_packets >= rate_limit_config_.max_packets_per_second) {
    size_t current_burst = burst_tokens_.load(std::memory_order_relaxed);
    while (true) {
      if (current_burst == 0) {
        return false;
      }
      if (burst_tokens_.compare_exchange_weak(current_burst, current_burst - 1,
                                               std::memory_order_relaxed)) {
        break;
      }
    }
  }
  
  if (current_bytes + payload_bytes > rate_limit_config_.max_bytes_per_second) {
    return false;
  }
  
  packets_sent_this_second_.fetch_add(1, std::memory_order_relaxed);
  bytes_sent_this_second_.fetch_add(payload_bytes, std::memory_order_relaxed);
  return true;
}

bool ZPacketQueue::StartThreads() {
  stop_threads_.store(false);
  outgoing_thread_ = std::thread(&ZPacketQueue::ProcessOutgoingPackets, this);
  incoming_thread_ = std::thread(&ZPacketQueue::ProcessReceiving, this);
  return true;
}

void ZPacketQueue::ProcessOutgoingPackets() {
  while (!stop_threads_.load()) {
    ProcessChannel(PacketChannelType::Control);
    ProcessChannel(PacketChannelType::Data);

    // Periodically collect garbage from the ack tracking map
    if ((gc_counter_++ % 1000) == 0) {
      awaiting_ack_packets_.collect_garbage();
    }

    auto now = static_cast<u32>(base::GetUnixTimeStamp());
    for (auto& [seqNum, packet] : awaiting_ack_packets_) {
      const u32 packet_age = now - packet.last_send_time;
      // Drop packets that have exceeded retry budget to cap memory growth.
      if (packet_age > kDropAfterSeconds) {
        const size_t dropped_bytes = packet.heap_data_size;
        awaiting_ack_packets_.remove(seqNum);
        SaturatingSub(awaiting_ack_packet_count_, 1);
        SaturatingSub(awaiting_ack_bytes_, dropped_bytes);
        continue;
      }
      if (packet_age > kResendIntervalSeconds) {
        dispatcher_.DispatchPacket(crypto_context_, packet,
                                   awaiting_ack_packets_);
        packet.last_send_time = now;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

void ZPacketQueue::ProcessChannel(PacketChannelType channel) {
  auto& queue = channel_outgoing_queues_[channel];
  if (!queue.empty()) {
    OutgoingPacket packet;
    queue.dequeue(packet);
    const size_t channel_index = static_cast<size_t>(channel);
    if (channel_index < channel_outgoing_bytes_.size()) {
      SaturatingSub(channel_outgoing_bytes_[channel_index], packet.heap_data_size);
    }
    dispatcher_.DispatchPacket(crypto_context_, packet, awaiting_ack_packets_);
  }
}

void ZPacketQueue::ProcessReceiving() {
  IncomingPacket pack;
  while (!stop_threads_.load()) {
    const auto result = receiver_.ReceivePackets(crypto_context_, pack);
    if (result == PacketReceiver::ReceiveResult::Success) {
      // record the new packet on the proper channel queue.
      auto prio = (PacketPriority)pack.flags.priority;

      if (pack.flags.reliable) {
        AddAwaitingAckPacket(pack.source_peer_id, pack.sequence_number,
                             pack.acknowledgement_number);
      }
      channel_incoming_queues_[pack.channel].enqueue(std::move(pack), prio);
    } else if (result == PacketReceiver::ReceiveResult::Acknowledgement) {
      // Parse the 4-byte LE payload to get the acked sequence number
      if (pack.data.size() >= 4) {
        const byte* d = reinterpret_cast<const byte*>(pack.data.data());
        const u32 acked_seq = static_cast<u32>(d[0]) |
                              (static_cast<u32>(d[1]) << 8) |
                              (static_cast<u32>(d[2]) << 16) |
                              (static_cast<u32>(d[3]) << 24);
        bool destination_matches = false;
        const bool has_packet = awaiting_ack_packets_.with_value(
            acked_seq, [&](const OutgoingPacket& packet) {
              destination_matches =
                  (packet.destination_peer_id == pack.source_peer_id);
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
  ack_payload[0] = static_cast<byte>(sequence_number & 0xFF);
  ack_payload[1] = static_cast<byte>((sequence_number >> 8) & 0xFF);
  ack_payload[2] = static_cast<byte>((sequence_number >> 16) & 0xFF);
  ack_payload[3] = static_cast<byte>((sequence_number >> 24) & 0xFF);
  OutgoingPacket out(return_address.id, PacketType::Acknowledgement,
                     PacketChannelType::Control, flags,
                     base::Span<byte>(ack_payload, sizeof(ack_payload)));
  auto& queue = channel_outgoing_queues_[PacketChannelType::Control];
  queue.enqueue(std::move(out), PacketPriority::High);
  if (ack_number == 0) {
    return;
  }

  bool destination_matches = false;
  const bool has_acknowledged_packet = awaiting_ack_packets_.with_value(
      ack_number, [&](const OutgoingPacket& packet) {
        destination_matches = (packet.destination_peer_id == return_address.id);
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
