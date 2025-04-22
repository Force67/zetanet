// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <map>
#include <znet/z_packets.h>

#include <base/memory/unique_pointer.h>
#include <znet/z_crypto_wrapper.h>
#include <znet/z_socket.h>
#include <znet/z_peer_mapping.h>
#include <base/containers/mpsc_queue.h>
#include <base/containers/lock_free_ordered_concurrent_hashmap.h>
#include <base/threading/thread.h>

#include <znet/z_packet_dispatcher.h>
#include <znet/z_packet_receiver.h>
#include <znet/z_packet_priority_queue.h>

namespace tx::network {

class ZCryptoContext;
class ZPeerMapping;

class ZPacketQueue {
 public:
  ZPacketQueue(ZSocket&, ZPeerMapping&, bool& stop_token);

  bool StartThreads();
  void StopThreads() {
	stop_threads_ = true;
  }

  void Push(OutgoingPacket&& package_move_in) {
    auto& queue = GetChannelQueue(package_move_in.channel);
    PacketPriority priority = (PacketPriority)package_move_in.flags.priority;
    queue.enqueue(std::move(package_move_in), priority);
  }
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

 private:
  void ProcessOutgoingPackets();
  void ProcessChannel(PacketChannelType);

  void ProcessReceiving();
  void AddAwaitingAckPacket(ZPeerId return_address,
                            u32 sequence_number,
                            u32 ack_number);

 private:
  tx::network::ZSocket& socket_;
  tx::network::ZPeerMapping& peer_list_;
  ZCryptoContext* crypto_context_{nullptr};

  base::Thread outgoing_thread_;
  base::Thread incoming_thread_;

  std::map<PacketChannelType, PriorityMPSCQueue<OutgoingPacket>>
      channel_outgoing_queues_;
  std::map<PacketChannelType, PriorityMPSCQueue<IncomingPacket>>
      channel_incoming_queues_;

  base::LockFreeOrderedHashMap<u32, OutgoingPacket> awaiting_ack_packets_;

  PacketDispatcher dispatcher_;
  PacketReceiver receiver_;

  bool& stop_threads_;

  byte incomingbuffer[4096]{};
};
}  // namespace tx::network