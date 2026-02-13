// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/strings/xstring.h>
#include <base/compiler.h>
#include <base/containers/span.h>
#endif
#include <znet/z_network_allocator.h>

namespace tx::network {

// the priority of packets determindes the order they are dispatched in
// be careful of spamming the criticl priority, as it will block other packets
// indefinitely
// regular packets should be sent with medium priority
enum class PacketPriority : u8 { Low = 0, Medium, High, Critical };

// the encryption algorithm used for the data channel
enum class EncryptionAlgorithm : u8 {
  None = 0,
  AESCBC128,
  ChaCha20,
  AES256,
  RSA4096,
  Count
};
enum class CompressionAlgorithm : u8 { None = 0, LZ4, ZLIB, Brotli, Count };

enum class PacketType : u16 {
  Invalid = 0,  // null is reserved
  // +++++++++++ from here, message ids are reserved (those are sent on the
  // + Control channel)

  // special message for reliable packets, contains no payload in response
  Acknowledgement = 1,

  // This is the first message sent from the client to the server, it contains
  // a list of supported encryption algorithms
  ClientHello = 10,

  // this is sent from the server to the client in response to a ClientHello
  // it includes the servers public key and the selected encryption algorithm
  // as well as general info about the server (name, version, etc.)
  ServerHello,

  // sent from the server to the client to indicate that the server is
  // shutting down
  ServerGoodbye,

  // periodic wellness check, sent if no other messages are sent within a fixed
  // time frame
  Heartbeat,

  // notification of a network event, such as a new peer connecting or a peer
  // disconnecting or some status change
  Notification,

  // changes to the (public) network configuration, such as Flow control,
  // synchronization, etc.
  ConfigurationUpdate,

  // routing info for the network
  RoutingInfo,

  // reserved for future use
  NetworkControl,

  // client sends proof of identity after receiving ServerHello
  ClientAuthProof,

  // used to request a file transfer (native feature of this library)
  FileTransfer,
  StreamingData,

  // from here, message ids can be defined (those are sent on the Data channel)
  // message is a generic type, but you can define your own types starting from
  // 101
  Message = 100,
};

inline bool IsSystemMessage(const PacketType type) {
  return type < PacketType::Message;
}

enum class PacketChannelType : u8 {
  Control,  // system messages
  Data,     // user messages
};

struct PackageFlags {
  u8 reliable : 1;      // 1 bit
  u8 encrypted : 1;     // 1 bit
  u8 compressed : 1;    // 1 bit
  u8 priority : 2;      // 2 bits
  u8 acknowledged : 1;  // 1 bit
  u8 awaiting_ack : 1;  // 1 bit
  u8 reserved : 1;      // 1 bits
};                      // 1 byte

struct IncomingPacket {
  PacketChannelType channel;   // 1 byte
  PackageFlags flags;          // 1 byte
  PacketType type;             // 2 bytes
  u32 source_peer_id;          // 4 bytes
  u32 acknowledgement_number;  // 4 bytes
  u32 sequence_number;         // 4 bytes
  std::string data;
};

class OutgoingPacket {
 public:
  PacketChannelType channel;  // 1 byte
  PackageFlags flags;         // 1 byte
  PacketType type;            // 2 bytes
  u32 heap_data_size;         // 4 bytes
  u32 last_send_time;         // 4 bytes
  u32 destination_peer_id;    // 4 bytes
  union {
    byte* data;  // 8 bytes
    u64 scalar;  // 8 bytes
  } payload;

 public:
  OutgoingPacket()
      : channel(PacketChannelType::Data),
        flags{},
        type(PacketType::Invalid),
        heap_data_size(0),
        last_send_time(0),
        destination_peer_id(0) {
    payload.scalar = 0;
  }

  STRONG_INLINE OutgoingPacket(const OutgoingPacket& other)
      : channel(other.channel),
        flags(other.flags),
        type(other.type),
        heap_data_size(0),
        last_send_time(other.last_send_time),
        destination_peer_id(other.destination_peer_id) {
    CopyPayloadFrom(other);
  }

  STRONG_INLINE OutgoingPacket(OutgoingPacket&& other) noexcept
      : channel(other.channel),
        flags(other.flags),
        type(other.type),
        heap_data_size(other.heap_data_size),
        last_send_time(other.last_send_time),
        destination_peer_id(other.destination_peer_id),
        payload(other.payload) {
    other.payload.scalar = 0;
    other.heap_data_size = 0;
  }
  // with data
  STRONG_INLINE OutgoingPacket(const u32 peer_id,
                               const PacketType type,
                               const PacketChannelType channel,
                               const PackageFlags flags,
                               const base::Span<byte> data)
      : channel(channel),
        flags(flags),
        type(type),
        heap_data_size(static_cast<u32>(data.size())),
        last_send_time(0),
        destination_peer_id(peer_id) {
    payload.data = nullptr;
    if (heap_data_size > 0) {
      payload.data = reinterpret_cast<byte*>(
          PacketBufferPool::Instance().Allocate(data.size()));
      memcpy(payload.data, data.data(), data.size());
    }
  }
  // without data
  STRONG_INLINE OutgoingPacket(const u32 peer_id,
                               const PacketType type,
                               const PacketChannelType channel,
                               const PackageFlags flags)
      : channel(channel),
        flags(flags),
        type(type),
        heap_data_size(0),
        last_send_time(0),
        destination_peer_id(peer_id) {
    payload.scalar = 0;
  }
  STRONG_INLINE ~OutgoingPacket() { ReleasePayload(); }
  // copy operator
  STRONG_INLINE OutgoingPacket& operator=(const OutgoingPacket& other) {
    if (this == &other)
      return *this;
    ReleasePayload();
    type = other.type;
    flags = other.flags;
    channel = other.channel;
    last_send_time = other.last_send_time;
    destination_peer_id = other.destination_peer_id;
    CopyPayloadFrom(other);
    return *this;
  }

  STRONG_INLINE OutgoingPacket& operator=(OutgoingPacket&& other) noexcept {
    if (this == &other)
      return *this;
    ReleasePayload();
    type = other.type;
    flags = other.flags;
    channel = other.channel;
    heap_data_size = other.heap_data_size;
    last_send_time = other.last_send_time;
    destination_peer_id = other.destination_peer_id;
    payload = other.payload;
    other.payload.scalar = 0;
    other.heap_data_size = 0;
    return *this;
  }

 private:
  STRONG_INLINE void ReleasePayload() {
    if (heap_data_size > 0 && payload.data) {
      PacketBufferPool::Instance().Release(
          reinterpret_cast<unsigned char*>(payload.data));
    }
    heap_data_size = 0;
    payload.scalar = 0;
  }

  STRONG_INLINE void CopyPayloadFrom(const OutgoingPacket& other) {
    if (other.heap_data_size > 0 && other.payload.data) {
      heap_data_size = other.heap_data_size;
      payload.data = other.payload.data;
      PacketBufferPool::Instance().Retain(
          reinterpret_cast<unsigned char*>(payload.data));
      return;
    }
    heap_data_size = 0;
    payload.scalar = other.payload.scalar;
  }
};
static_assert(sizeof(OutgoingPacket) == 24, "OutgoingPacket is not 24 bytes");
}  // namespace tx::network
