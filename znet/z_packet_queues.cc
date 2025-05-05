// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_queues.h"
#include "z_packet_serdes.h"

#include <base/time/time.h>

#include "z_socket.h"
#include "z_packet_serdes.h"

namespace tx::network {
static constexpr char kLogTag[] = "z-packet-queue";
static constexpr char kOutoingThreadName[] =
    "tx::network::OutgoingPacketQueueThread";
static constexpr char kIncomingThreadName[] =
    "tx::network::IncomingPacketQueueThread";

ZPacketQueue::ZPacketQueue(ZSocket& socket,
                           ZPeerMapping& peer_list,
                           bool& stop_token)
    : awaiting_ack_packets_(200),
#if defined(USE_BASE_THREADS)
      outgoing_thread_(kOutoingThreadName,
                       {this, &ZPacketQueue::ProcessOutgoingPackets}),
      incoming_thread_(kIncomingThreadName,
                       {this, &ZPacketQueue::ProcessReceiving}),
#else
      outgoing_thread_(
          std::thread(&ZPacketQueue::ProcessOutgoingPackets, this)),
      incoming_thread_(
          std::thread(&ZPacketQueue::ProcessReceiving, this)),
#endif
      socket_(socket),
      peer_list_(peer_list),
      stop_threads_(stop_token),
      dispatcher_(socket, peer_list),
      receiver_(socket, peer_list) {
    channel_outgoing_queues_.emplace(PacketChannelType::Control,
                               PriorityMPSCQueue<OutgoingPacket>());
    channel_outgoing_queues_.emplace(PacketChannelType::Data, PriorityMPSCQueue<OutgoingPacket>());
}

bool ZPacketQueue::StartThreads() {
#if defined(USE_BASE_THREADS)
  return outgoing_thread_.Start(base::Thread::Priority::kNormal) &&
         incoming_thread_.Start(base::Thread::Priority::kNormal);
#else
  outgoing_thread_.detach();
  incoming_thread_.detach();

  return true;
#endif
}

void ZPacketQueue::ProcessOutgoingPackets() {
  while (!stop_threads_) {
    while (true) {
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
#ifndef USE_BASE_THREADS
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
#endif
    }
  }
}

void ZPacketQueue::ProcessChannel(PacketChannelType channel) {
  auto& queue = channel_outgoing_queues_[channel];
  OutgoingPacket packet;
  if (!queue.empty()) {
    OutgoingPacket packet;
    queue.dequeue(packet);
    dispatcher_.DispatchPacket(crypto_context_, packet, awaiting_ack_packets_);
  }
}

void ZPacketQueue::ProcessReceiving() {
  IncomingPacket pack;
  while (!stop_threads_) {
    const auto result = receiver_.ReceivePackets(crypto_context_, pack);
    if (result == PacketReceiver::ReceiveResult::Success) {
      // record the new packet on the proper channel queue.
      auto prio = (PacketPriority)pack.flags.priority;

      if (pack.flags.reliable) {
        AddAwaitingAckPacket(pack.source_peer_id, pack.sequence_number,
                             pack.acknowledgement_number);
      }
      channel_incoming_queues_[pack.channel].enqueue(base::move(pack), prio);
    } else if (result == PacketReceiver::ReceiveResult::Goodbye) {
      StopThreads();
      BASE_LOGI(kLogTag, "Goodbye packet received, stopping threads");
    }
  };
}

void ZPacketQueue::AddAwaitingAckPacket(ZPeerId return_address,
                                        u32 sequence_number,
                                        u32 ack_number) {
  const PackageFlags flags{.reliable = 0,
                           .encrypted = 0,
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
  queue.enqueue(base::move(out), PacketPriority::High);
  // safe to do. concurrent hash map.
  awaiting_ack_packets_.remove(ack_number);
}

}  // namespace tx::network