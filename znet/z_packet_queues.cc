// Copyright (C) 2023-2025 Vincent Hengel
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
      stop_threads_(stop_token) {
    // Default-construct queues via operator[] (PriorityMPSCQueue is not moveable due to mutex)
    channel_outgoing_queues_[PacketChannelType::Control];
    channel_outgoing_queues_[PacketChannelType::Data];
    channel_outgoing_bytes_[0].store(0, std::memory_order_relaxed);
    channel_outgoing_bytes_[1].store(0, std::memory_order_relaxed);
    awaiting_ack_packet_count_.store(0, std::memory_order_relaxed);
    awaiting_ack_bytes_.store(0, std::memory_order_relaxed);
    dispatcher_.SetAwaitingAckCounters(&awaiting_ack_packet_count_, &awaiting_ack_bytes_);
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
  OutgoingPacket out(return_address.id, PacketType::Acknowledgement,
                     PacketChannelType::Control, flags);
  // stash the number
  out.payload.scalar = sequence_number;
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
