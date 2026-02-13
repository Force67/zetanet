// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_socket.h>
#include <znet/z_packets.h>
#include <znet/z_peer_mapping.h>
#include <znet/z_packet_serdes.h>
#include <znet/z_packet_priority_queue.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/atomic.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/containers/vector.h>
#include <base/optional.h>
#include <base/containers/lock_free_ordered_concurrent_hashmap.h>
#endif

namespace tx::network {
class PacketReceiver {
 public:
  static constexpr char kLogTag[] = "packet-receiver";

  static constexpr const mem_size InitialBufferSize = 65507;
  static constexpr const mem_size MaxBufferSize =
      65507;  // Maximum UDP payload size
  static constexpr const mem_size MinimumBufferSize = 512;  // Min buffer size
  static constexpr float ResizeDownThreshold = 0.5f;  // Threshold for downsizing
  static constexpr float Alpha = 0.1f;  // Smoothing factor for moving average

  explicit PacketReceiver(ZSocket& socket, ZPeerMapping& peer_list)
      : socket_(socket),
        peer_list_(peer_list),
        incoming_buffer_(InitialBufferSize),
        average_packet_size_(InitialBufferSize) {
    memset(incoming_buffer_.data(), 0, incoming_buffer_.size());
  }

  enum class ReceiveResult { Success, Acknowledgement, Goodbye, Error, Timeout };

  ReceiveResult ReceivePackets(ZCryptoContext* crypto,
                               IncomingPacket& incoming) {
    // UDP is datagram-based: receive the entire packet in one call.
    // The buffer must be large enough for the largest expected datagram.
    i32 recvResult =
        socket_.Receive(address, (char*)incoming_buffer_.data(),
                        static_cast<i32>(incoming_buffer_.size()));

    if (recvResult <= 0) {
      return HandleReceiveError(recvResult);
    }

    if (static_cast<size_t>(recvResult) < sizeof(PacketHeader)) {
      BASE_LOGE(kLogTag, "Received packet too small for header");
      return ReceiveResult::Error;
    }

    PacketHeader header{};
    std::memcpy(&header, incoming_buffer_.data(), sizeof(PacketHeader));
    const u32 packet_size = header.total_packet_data_size;
    if (packet_size > MaxBufferSize || packet_size < sizeof(PacketHeader)) {
      BASE_LOGE(kLogTag, "Invalid packet size");
      return ReceiveResult::Error;
    }

    if (static_cast<u32>(recvResult) < packet_size) {
      BASE_LOGE(kLogTag, "Incomplete datagram: got {} expected {}",
                recvResult, packet_size);
      return ReceiveResult::Error;
    }

    if (!IngestPacket(crypto, incoming, address, incoming_buffer_.data(),
                      packet_size)) {
      return ReceiveResult::Error;
    }
    if (incoming.type == PacketType::Acknowledgement) {
      return ReceiveResult::Acknowledgement;
    }
    return ReceiveResult::Success;
  }

  bool IngestPacket(ZCryptoContext* crypto,
                    IncomingPacket& incoming,
                    const ZSocket::Address& address,
                    byte* buffer,
                    size_t size) {
    PacketUnpacker unpacker(crypto);
    if (!unpacker.UnpackPacket(buffer, size, incoming)) {
      BASE_LOGE(kLogTag, "Failed to unpack packet");
      return false;
    }

    // find the peer associated with this address
    ZPeer* peer = peer_list_.GetOrCreatePeer(address);
    if (!peer) {
      BASE_LOGE(
          kLogTag,
          "Dropped packet: peer table full or peer allocation failed for type {}",
          (u16)incoming.type);
      return false;
    }
    // the peer list manages the peers unique identifier, so we apply it here to
    // the data packet
    incoming.source_peer_id = peer->identifier.id;

    return true;
  }

 private:
  ReceiveResult HandleReceiveError(i32 result) {
    if (result == 0) {
      BASE_LOGE(kLogTag, "Connection closed");
      return ReceiveResult::Goodbye;
    } else {
      const ZSocket::Error error = ZSocket::GetLastError();
      if (error == ZSocket::Error::ConnectionReset) {
        BASE_LOGW(kLogTag, "Received a force reset");
        return ReceiveResult::Goodbye;
      }
      if (error == ZSocket::Error::NotConnected) {
        return ReceiveResult::Goodbye;
      }
      // For non-blocking sockets, EAGAIN/EWOULDBLOCK is normal
      if (error == ZSocket::Error::Success) {
        return ReceiveResult::Timeout;
      }
      BASE_LOGE(kLogTag, "Socket error: {}", ZSocket::GetErrorString(error));
      return ReceiveResult::Error;
    }
  }

  void ResizeBufferIfNeeded(mem_size packet_size) {
    UpdateAveragePacketSize(packet_size);

    // Resize up if needed
    if (packet_size > incoming_buffer_.size()) {
      incoming_buffer_.resize(std::min(packet_size, MaxBufferSize));
      memset(incoming_buffer_.data(), 0, incoming_buffer_.size());  // re-zero
    }
    // Resize down if conditions are met
    else if (average_packet_size_ <
                 incoming_buffer_.size() * ResizeDownThreshold &&
             incoming_buffer_.size() > MinimumBufferSize) {
      incoming_buffer_.resize(std::max(
          static_cast<mem_size>(average_packet_size_), MinimumBufferSize));
      memset(incoming_buffer_.data(), 0, incoming_buffer_.size());  // re-zero
    }
  }

  void UpdateAveragePacketSize(mem_size packet_size) {
    average_packet_size_ =
        (Alpha * packet_size) + ((1 - Alpha) * average_packet_size_);
  }

 private:
  ZSocket& socket_;
  ZPeerMapping& peer_list_;
  ZSocket::Address address{};
  base::Vector<byte> incoming_buffer_;
  f32 average_packet_size_;  // Average size of recent packets
};
}  // namespace tx::network
