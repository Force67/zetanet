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
      if ((now - packet.last_send_time) > 1000) {
        dispatcher_.DispatchPacket(crypto_context_, packet,
                                   awaiting_ack_packets_);
        packet.last_send_time = now;
      }
      // we waited too long, drop the packet to avoid flooding
      if ((now - packet.last_send_time) > 5000) {
        awaiting_ack_packets_.remove(seqNum);
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

  OutgoingPacket acknowledged_packet;
  if (awaiting_ack_packets_.find(ack_number, acknowledged_packet) &&
      acknowledged_packet.destination_peer_id == return_address.id) {
    awaiting_ack_packets_.remove(ack_number);
  }
}

}  // namespace tx::network
