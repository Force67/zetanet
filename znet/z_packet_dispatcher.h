// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_socket.h>
#include <znet/z_packets.h>
#include <znet/z_peer_mapping.h>
#include <znet/z_packet_serdes.h>
#include <znet/fancy_queue.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/atomic.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/containers/vector.h>
#endif

namespace tx::network {

class PacketDispatcher {
 public:
  static constexpr char kLogTag[] = "packet-dispatcher";

  PacketDispatcher(ZSocket& socket, ZPeerMapping& peer_list)
      : socket_(socket), peer_list_(peer_list) {}

  void DispatchPacket(
      ZCryptoContext* crypto,
      OutgoingPacket& packet,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue) {
    tx::network::PacketBuilder builder(crypto);

    if (packet.destination_peer_id == ZPeerId::to_server) {
      DispatchToServer(packet, builder, receipt_queue);
    } else if (packet.destination_peer_id == ZPeerId::to_all) {
      for (auto& peer : peer_list_.GetPeerList()) {
        DispatchToOne(peer, packet, builder, receipt_queue);
      }
    } else {
      ZPeer* peer = peer_list_.GetPeer(packet.destination_peer_id);
      if (peer) {
        DispatchToOne(*peer, packet, builder, receipt_queue);
      } else {
        BASE_LOGE(kLogTag,
                  "PacketDispatcher::DispatchPacket(): Failed to find peer {}",
                  packet.destination_peer_id);
      }
    }
  }

 private:
  void DispatchToOne(
      ZPeer& peer,
      OutgoingPacket& packet,
      PacketBuilder& builder,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue) {
    auto bytes = builder.BuildPacket(packet, next_outgoing_sequence_number_);
    if (bytes.empty()) {
      BASE_LOGE(kLogTag, "Failed to build outgoing packet");
      return;
    }
    if (socket_.Send(peer.address, bytes) <= 0) {
      BASE_LOGE(kLogTag, "Failed to send packet to peer {}", peer.identifier.id);
      return;
    }
    AddReceiptIfNeeded(packet, receipt_queue);
    next_outgoing_sequence_number_++;
  }

  void DispatchToServer(
      OutgoingPacket& packet,
      PacketBuilder& builder,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue) {
    auto bytes = builder.BuildPacket(packet, next_outgoing_sequence_number_);
    if (bytes.empty()) {
      BASE_LOGE(kLogTag, "Failed to build outgoing packet");
      return;
    }
    if (socket_.SendtoServer(bytes) <= 0) {
      BASE_LOGE(kLogTag, "Failed to send packet to server");
      return;
    }
    AddReceiptIfNeeded(packet, receipt_queue);
    next_outgoing_sequence_number_++;
  }

  void AddReceiptIfNeeded(
      OutgoingPacket& packet,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue) {
    if (packet.flags.reliable && packet.type != PacketType::Acknowledgement) {
      packet.flags.awaiting_ack = true;
      packet.last_send_time = static_cast<u32>(base::GetUnixTimeStamp());
      receipt_queue.insert(next_outgoing_sequence_number_, std::move(packet));
    }
  }

  ZSocket& socket_;
  ZPeerMapping& peer_list_;
  base::Atomic<u32> next_outgoing_sequence_number_{0};
};

}  // namespace tx::network
