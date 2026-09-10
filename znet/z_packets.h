// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <limits>

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

// Higher priority dispatches first. Regular traffic should use Medium; avoid
// spamming Critical, it blocks other packets.
enum class PacketPriority : u8 { Low = 0, Medium, High, Critical };

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
  Invalid = 0,

  // ---- system message ids, sent on the Control channel ----

  // response to a reliable packet, carries no payload
  Acknowledgement = 1,

  // first client message; lists supported encryption algorithms
  ClientHello = 10,

  // server response; carries the selected algorithm, server info, and the
  // key exchange material
  ServerHello,

  // server is shutting down
  ServerGoodbye,

  // sent when no other message went out within the keepalive window
  Heartbeat,

  // peer connect/disconnect and other network events
  Notification,

  // changes to the public network configuration
  ConfigurationUpdate,

  // routing info for the network
  RoutingInfo,

  NetworkControl,

  // proof of identity sent after ServerHello
  ClientAuthProof,

  // native file transfer
  FileTransfer,
  StreamingData,
  ClockSyncRequest,
  ClockSyncResponse,

  // ---- user message ids start here, sent on the Data channel; custom
  // types may start at 101 ----
  Message = 100,
};

inline bool IsSystemMessage(const PacketType type) {
  return type < PacketType::Message;
}

enum class PacketChannelType : u8 {
  Control,
  Data,
};

struct PackageFlags {
  u8 reliable : 1;
  u8 encrypted : 1;
  u8 compressed : 1;
  u8 priority : 2;
  u8 acknowledged : 1;
  u8 awaiting_ack : 1;
  u8 reserved : 1;
};

struct IncomingPacket {
  PacketChannelType channel;
  PackageFlags flags;
  PacketType type;
  u32 source_peer_id;
  u32 acknowledgement_number;
  u32 sequence_number;
  base::String data;
};

class OutgoingPacket {
 public:
  PacketChannelType channel;
  PackageFlags flags;
  PacketType type;
  u32 heap_data_size;
  u32 last_send_time;
  u32 destination_peer_id;
  union {
    byte* data;
    u64 scalar;
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
  STRONG_INLINE OutgoingPacket(const u32 peer_id,
                               const PacketType type,
                               const PacketChannelType channel,
                               const PackageFlags flags,
                               const base::Span<byte> data)
      : channel(channel),
        flags(flags),
        type(type),
        heap_data_size(0),
        last_send_time(0),
        destination_peer_id(peer_id) {
    payload.data = nullptr;
    if (data.size() > std::numeric_limits<u32>::max()) {
      payload.scalar = 0;
      return;
    }
    heap_data_size = static_cast<u32>(data.size());
    if (heap_data_size > 0) {
      payload.data = reinterpret_cast<byte*>(
          PacketBufferPool::Instance().Allocate(data.size()));
      if (!payload.data) {
        heap_data_size = 0;
        payload.scalar = 0;
        return;
      }
      memcpy(payload.data, data.data(), data.size());
    }
  }
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

  // Tag for the reserve-capacity ctor below.
  struct ReserveBufferTag {};

  // Allocates a pooled payload buffer of `reserve_bytes`; heap_data_size
  // tracks the reserved size until SetHeapDataSize() reports the real count.
  STRONG_INLINE OutgoingPacket(ReserveBufferTag,
                               const u32 peer_id,
                               const PacketType type,
                               const PacketChannelType channel,
                               const PackageFlags flags,
                               const mem_size reserve_bytes)
      : channel(channel),
        flags(flags),
        type(type),
        heap_data_size(0),
        last_send_time(0),
        destination_peer_id(peer_id) {
    payload.data = nullptr;
    if (reserve_bytes > std::numeric_limits<u32>::max()) {
      payload.scalar = 0;
    } else if (reserve_bytes > 0) {
      payload.data = reinterpret_cast<byte*>(
          PacketBufferPool::Instance().Allocate(reserve_bytes));
      if (payload.data) {
        heap_data_size = static_cast<u32>(reserve_bytes);
      } else {
        payload.scalar = 0;
      }
    } else {
      payload.scalar = 0;
    }
  }

  STRONG_INLINE void SetHeapDataSize(u32 size) { heap_data_size = size; }
  STRONG_INLINE byte* HeapDataPtr() const { return payload.data; }
  STRONG_INLINE mem_size HeapDataCapacity() const {
    if (!payload.data) return 0;
    return PacketBufferPool::Instance().GetCapacity(
        reinterpret_cast<const unsigned char*>(payload.data));
  }
  // Releases ownership of the pooled buffer without freeing it.
  STRONG_INLINE byte* DetachHeapBuffer() {
    byte* old = payload.data;
    payload.data = nullptr;
    heap_data_size = 0;
    return old;
  }
  // Adopts a buffer obtained from PacketBufferPool::Allocate().
  STRONG_INLINE void AttachHeapBuffer(byte* buffer, u32 reserved_size) {
    payload.data = buffer;
    heap_data_size = reserved_size;
  }
  STRONG_INLINE ~OutgoingPacket() { ReleasePayload(); }
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
