// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <cstddef>

#include <znet/z_socket.h>
#include <znet/z_packets.h>
#include <znet/z_peer_mapping.h>
#include <znet/z_packet_serdes.h>
#include <znet/z_clock.h>
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

  void SetAwaitingAckCounters(base::Atomic<mem_size>* packet_count,
                              base::Atomic<mem_size>* bytes) {
    awaiting_ack_packet_count_ = packet_count;
    awaiting_ack_bytes_ = bytes;
  }

  // Retransmit a packet using its original sequence number.
  // Does NOT allocate a new sequence number or touch the receipt queue.
  void RetransmitPacket(ZCryptoContext* crypto,
                        OutgoingPacket& packet,
                        u32 original_sequence_number) {
    tx::network::PacketBuilder builder(crypto);

    if (packet.destination_peer_id == ZPeerId::to_server) {
      auto bytes =
          builder.BuildPacket(packet, original_sequence_number);
      if (!bytes.empty()) {
        socket_.SendtoServer(bytes);
      }
    } else if (packet.destination_peer_id == ZPeerId::to_all) {
      for (auto& peer : peer_list_.GetPeerList()) {
        auto bytes =
            builder.BuildPacket(packet, original_sequence_number);
        if (!bytes.empty()) {
          socket_.Send(peer.address, bytes);
        }
      }
    } else {
      ZSocket::Address address;
      if (peer_list_.ResolvePeerAddress(packet.destination_peer_id, address)) {
        auto bytes =
            builder.BuildPacket(packet, original_sequence_number);
        if (!bytes.empty()) {
          socket_.Send(address, bytes);
        }
      }
    }
  }

  void DispatchPacket(
      ZCryptoContext* crypto,
      OutgoingPacket& packet,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue) {
    tx::network::PacketBuilder builder(crypto);

    if (packet.destination_peer_id == ZPeerId::to_server) {
      const u32 sequence_number =
          next_outgoing_sequence_number_.fetch_add(1, std::memory_order_relaxed);
      DispatchToServer(packet, builder, receipt_queue, sequence_number);
    } else if (packet.destination_peer_id == ZPeerId::to_all) {
      for (auto& peer : peer_list_.GetPeerList()) {
        OutgoingPacket fanout_packet = packet;
        const u32 sequence_number = next_outgoing_sequence_number_.fetch_add(
            1, std::memory_order_relaxed);
        DispatchToOne(peer.address, peer.identifier.id, fanout_packet, builder,
                      receipt_queue, sequence_number);
      }
    } else {
      ZSocket::Address address;
      if (peer_list_.ResolvePeerAddress(packet.destination_peer_id, address)) {
        const u32 sequence_number = next_outgoing_sequence_number_.fetch_add(
            1, std::memory_order_relaxed);
        DispatchToOne(address, packet.destination_peer_id, packet, builder,
                      receipt_queue, sequence_number);
      } else {
        BASE_LOGE(kLogTag,
                  "PacketDispatcher::DispatchPacket(): Failed to find peer {}",
                  packet.destination_peer_id);
      }
    }
  }

 private:
  void DispatchToOne(
      const ZSocket::Address& address,
      u32 peer_id,
      OutgoingPacket& packet,
      PacketBuilder& builder,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue,
      u32 sequence_number) {
    auto bytes = builder.BuildPacket(packet, sequence_number);
    if (bytes.empty()) {
      BASE_LOGE(kLogTag, "Failed to build outgoing packet");
      return;
    }
    if (socket_.Send(address, bytes) <= 0) {
      BASE_LOGE(kLogTag, "Failed to send packet to peer {}", peer_id);
      return;
    }
    AddReceiptIfNeeded(packet, receipt_queue, sequence_number);
  }

  void DispatchToServer(
      OutgoingPacket& packet,
      PacketBuilder& builder,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue,
      u32 sequence_number) {
    auto bytes = builder.BuildPacket(packet, sequence_number);
    if (bytes.empty()) {
      BASE_LOGE(kLogTag, "Failed to build outgoing packet");
      return;
    }
    if (socket_.SendtoServer(bytes) <= 0) {
      BASE_LOGE(kLogTag, "Failed to send packet to server");
      return;
    }
    AddReceiptIfNeeded(packet, receipt_queue, sequence_number);
  }

  void AddReceiptIfNeeded(
      OutgoingPacket& packet,
      base::LockFreeOrderedHashMap<u32, OutgoingPacket>& receipt_queue,
      u32 sequence_number) {
    if (packet.flags.reliable && packet.type != PacketType::Acknowledgement &&
        packet.last_send_time == 0) {
      const mem_size payload_bytes = packet.heap_data_size;
      packet.flags.awaiting_ack = true;
      // Use coarse timestamp to avoid per-packet syscall.  The retry
      // scan interval (10 ms) is far larger than any cache staleness.
      {
        static thread_local u32 tl_cached_ts = 0;
        static thread_local base::Clock::time_point tl_ts_refresh{};
        auto now_tp = base::Clock::now();
        if (now_tp - tl_ts_refresh > std::chrono::milliseconds(100)) {
          tl_cached_ts = static_cast<u32>(base::GetUnixTimeStamp());
          tl_ts_refresh = now_tp;
        }
        packet.last_send_time = tl_cached_ts;
      }
      if (receipt_queue.insert(sequence_number, std::move(packet))) {
        if (awaiting_ack_packet_count_) {
          awaiting_ack_packet_count_->fetch_add(1, std::memory_order_relaxed);
        }
        if (awaiting_ack_bytes_) {
          awaiting_ack_bytes_->fetch_add(payload_bytes, std::memory_order_relaxed);
        }
      }
    }
  }

  ZSocket& socket_;
  ZPeerMapping& peer_list_;
  base::Atomic<u32> next_outgoing_sequence_number_{0};
  base::Atomic<mem_size>* awaiting_ack_packet_count_{nullptr};
  base::Atomic<mem_size>* awaiting_ack_bytes_{nullptr};
};

}  // namespace tx::network
