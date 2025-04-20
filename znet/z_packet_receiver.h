#pragma once

#include <network/zeta/z_socket.h>
#include <network/zeta/z_packets.h>
#include <network/zeta/z_peer_mapping.h>
#include <network/zeta/z_packet_serdes.h>
#include <network/zeta/z_packet_priority_queue.h>

#include <base/atomic.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/containers/vector.h>
#include <base/optional.h>
#include <base/containers/lock_free_ordered_concurrent_hashmap.h>

namespace tx::network {
class PacketReceiver {
 public:
  static constexpr char kLogTag[] = "packet-receiver";

  static constexpr const mem_size InitialBufferSize = 1024;
  static constexpr const mem_size MaxBufferSize =
      0xffffffff;  // Set a reasonable max buffer size
  static constexpr const mem_size MinimumBufferSize = 512;  // Min buffer size
  static constexpr float ResizeDownThreshold = 0.5f;  // Threshold for downsizing
  static constexpr float Alpha = 0.1f;  // Smoothing factor for moving average

  explicit PacketReceiver(ZSocket& socket, ZPeerMapping& peer_list)
      : socket_(socket),
        peer_list_(peer_list),
        incoming_buffer_(InitialBufferSize,
                         base::VectorReservePolicy::kForData),
        average_packet_size_(InitialBufferSize) {
    memset(incoming_buffer_.data(), 0, incoming_buffer_.size());
  }

  enum class ReceiveResult { Success, Goodbye, Error, Timeout };

  ReceiveResult ReceivePackets(ZCryptoContext* crypto,
                               IncomingPacket& incoming) {
    // First, receive the fixed-size header
    byte headerBuffer[sizeof(PacketHeader)];
    i32 headerResult =
        socket_.Receive(address, (char*)headerBuffer, sizeof(PacketHeader));

    if (headerResult <= 0) {
      return HandleReceiveError(headerResult);
    }

    const auto* header = reinterpret_cast<const PacketHeader*>(headerBuffer);
    const u32 packet_size = header->total_packet_data_size;
    if (packet_size > MaxBufferSize || packet_size < sizeof(PacketHeader)) {
      BASE_LOGE(kLogTag, "Invalid packet size");
      return ReceiveResult::Error;
    }

    // Resize buffer for the remaining packet content
    ResizeBufferIfNeeded(packet_size);

    // Then, receive the remaining packet based on the size from the header
    i32 contentResult = socket_.Receive(address, (char*)incoming_buffer_.data(),
                                        packet_size - sizeof(PacketHeader));
    if (contentResult <= 0) {
      return HandleReceiveError(contentResult);
    }

    // Combine header and content for further processing
    memcpy(incoming_buffer_.data(), headerBuffer, sizeof(PacketHeader));

    return IngestPacket(crypto, incoming, address, incoming_buffer_.data(),
                        packet_size)
               ? ReceiveResult::Success
               : ReceiveResult::Error;
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
      BASE_LOGE(kLogTag, "ZPacketQueue::IngestPacket(): Dropped unknown packet : {}",
                (u16)incoming.type);
      return false;
    }
    // the peer list manages the peers unique identifier, so we apply it here to
    // the data packet
    incoming.source_peer_id = peer->identifier.id;

    // dont shove acks into the queue.. we know it succeeded.
    // TODO: this is a bit hacky, we should probably have a separate queue for
    // receipt tickets
    PacketHeader* header = reinterpret_cast<PacketHeader*>(buffer);
    if ((PacketType)header->type == PacketType::Acknowledgement) {
      return false;  // construct empty optional
    }

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