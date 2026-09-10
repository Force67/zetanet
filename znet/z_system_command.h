// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once
#include <cstring>

#include <limits>
#include <new>
#include <type_traits>

#include "z_wire_le.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/span.h>
#include <base/containers/vector.h>
#endif

namespace tx::network {
namespace detail {
template <typename T, bool IsEnum = std::is_enum<T>::value>
struct WireRawType {
  using type = T;
};

template <typename T>
struct WireRawType<T, true> {
  using type = typename std::underlying_type<T>::type;
};
}  // namespace detail

class PacketWriter {
 public:
  explicit PacketWriter(mem_size initial_size = 1024)
      : buffer_(new byte[initial_size]), capacity_(initial_size), offset_(0) {}

  ~PacketWriter() { delete[] buffer_; }

  bool EnsureCapacity(mem_size required) {
    if (required <= capacity_) {
      return true;
    }
    mem_size new_capacity = capacity_ == 0 ? 1 : capacity_;
    while (new_capacity < required) {
      if (new_capacity > std::numeric_limits<mem_size>::max() / 2) {
        new_capacity = required;
        break;
      }
      new_capacity *= 2;
    }
    if (new_capacity < required) {
      return false;
    }
    byte* new_buffer = new (std::nothrow) byte[new_capacity];
    if (!new_buffer) {
      return false;
    }
    std::memcpy(new_buffer, buffer_, offset_);
    delete[] buffer_;
    buffer_ = new_buffer;
    capacity_ = new_capacity;
    return true;
  }

  // Writes scalar values in little-endian byte order.
  template <typename T>
  typename std::enable_if<std::is_scalar<T>::value, bool>::type Put(
      const T value) {
    if (sizeof(T) > std::numeric_limits<mem_size>::max() - offset_ ||
        !EnsureCapacity(offset_ + sizeof(T))) {
      return false;
    }
    if constexpr (std::is_integral<T>::value || std::is_enum<T>::value) {
      using RawT = typename detail::WireRawType<T>::type;
      using UnsignedRawT = typename std::make_unsigned<RawT>::type;
      UnsignedRawT bits = 0;
      const RawT raw_value = static_cast<RawT>(value);
      std::memcpy(&bits, &raw_value, sizeof(bits));
      if constexpr (sizeof(UnsignedRawT) == 1) {
        buffer_[offset_] = static_cast<byte>(bits);
      } else if constexpr (sizeof(UnsignedRawT) == 2) {
        wire_le::StoreU16(buffer_ + offset_, static_cast<u16>(bits));
      } else if constexpr (sizeof(UnsignedRawT) == 4) {
        wire_le::StoreU32(buffer_ + offset_, static_cast<u32>(bits));
      } else if constexpr (sizeof(UnsignedRawT) == 8) {
        wire_le::StoreU64(buffer_ + offset_, static_cast<u64>(bits));
      } else {
        std::memcpy(buffer_ + offset_, &value, sizeof(T));
      }
    } else {
      std::memcpy(buffer_ + offset_, &value, sizeof(T));
    }
    offset_ += sizeof(T);
    return true;
  }

  template <typename T>
  typename std::enable_if<!std::is_scalar<T>::value &&
                              std::is_trivially_copyable<T>::value,
                          bool>::type
  Put(const T& type) {
    if (sizeof(T) > std::numeric_limits<mem_size>::max() - offset_ ||
        !EnsureCapacity(offset_ + sizeof(T))) {
      return false;
    }
    std::memcpy(buffer_ + offset_, &type, sizeof(T));
    offset_ += sizeof(T);
    return true;
  }

  bool PutS(const base::Span<byte>& data) {
    if (data.size() > std::numeric_limits<mem_size>::max() - offset_ ||
        !EnsureCapacity(offset_ + data.size())) {
      return false;
    }
    std::memcpy(buffer_ + offset_, data.data(), data.size());
    offset_ += data.size();
    return true;
  }

  bool PutList(const base::Span<byte>& data) {
    if (data.size() > std::numeric_limits<u16>::max()) {
      return false;
    }
    if (sizeof(u16) > std::numeric_limits<mem_size>::max() - offset_ ||
        data.size() > std::numeric_limits<mem_size>::max() - offset_ - sizeof(u16) ||
        !EnsureCapacity(offset_ + sizeof(u16) + data.size())) {
      return false;
    }
    wire_le::StoreU16(buffer_ + offset_, static_cast<u16>(data.size()));
    offset_ += sizeof(u16);
    return PutS(data);
  }

  const base::Span<byte> data() const {
    return base::Span<byte>(buffer_, offset_);
  }

 private:
  byte* buffer_;
  mem_size capacity_;
  mem_size offset_;

  PacketWriter(const PacketWriter&) = delete;
  PacketWriter& operator=(const PacketWriter&) = delete;
};

class PacketReader {
 public:
  PacketReader(const byte* buffer, mem_size size)
      : buffer_(buffer), capacity_(size), offset_(0) {}

  template <typename T>
  typename std::enable_if<std::is_scalar<T>::value, bool>::type Read(T& value) {
    if (sizeof(T) > capacity_ - offset_) {
      return false;
    }
    if constexpr (std::is_integral<T>::value || std::is_enum<T>::value) {
      using RawT = typename detail::WireRawType<T>::type;
      using UnsignedRawT = typename std::make_unsigned<RawT>::type;
      UnsignedRawT bits = 0;
      if constexpr (sizeof(UnsignedRawT) == 1) {
        bits = static_cast<UnsignedRawT>(buffer_[offset_]);
      } else if constexpr (sizeof(UnsignedRawT) == 2) {
        bits = static_cast<UnsignedRawT>(wire_le::LoadU16(buffer_ + offset_));
      } else if constexpr (sizeof(UnsignedRawT) == 4) {
        bits = static_cast<UnsignedRawT>(wire_le::LoadU32(buffer_ + offset_));
      } else if constexpr (sizeof(UnsignedRawT) == 8) {
        bits = static_cast<UnsignedRawT>(wire_le::LoadU64(buffer_ + offset_));
      } else {
        std::memcpy(&value, buffer_ + offset_, sizeof(T));
        offset_ += sizeof(T);
        return true;
      }
      RawT raw_value{};
      std::memcpy(&raw_value, &bits, sizeof(raw_value));
      value = static_cast<T>(raw_value);
    } else {
      std::memcpy(&value, buffer_ + offset_, sizeof(T));
    }
    offset_ += sizeof(T);
    return true;
  }

  template <typename T>
  typename std::enable_if<!std::is_scalar<T>::value &&
                              std::is_trivially_copyable<T>::value,
                          bool>::type
  Read(T& type) {
    if (sizeof(T) > capacity_ - offset_) {
      return false;
    }

    std::memcpy(&type, buffer_ + offset_, sizeof(T));
    offset_ += sizeof(T);
    return true;
  }

  bool ReadS(base::Vector<byte>& data) {
    if (data.size() > capacity_ - offset_) {
      return false;
    }

    std::memcpy((void*)data.data(), buffer_ + offset_, data.size());
    offset_ += data.size();
    return true;
  }

  bool ReadList(base::Vector<byte>& data) {
    if (sizeof(u16) > capacity_ - offset_) {
      return false;
    }
    const u16 size = wire_le::LoadU16(buffer_ + offset_);
    offset_ += sizeof(u16);
    if (size > capacity_ - offset_) {
      return false;
    }
    data.resize(size);
    return ReadS(data);
  }

  mem_size position() const { return offset_; }
  mem_size remaining() const { return capacity_ - offset_; }

 private:
  const byte* buffer_;
  mem_size capacity_;
  mem_size offset_;

  PacketReader(const PacketReader&) = delete;
  PacketReader& operator=(const PacketReader&) = delete;
};

namespace system_commands {

static constexpr u16 kProtocolVersionCurrent = 1;
static constexpr u16 kProtocolVersionMinSupported = 1;

enum FeatureFlag : u32 {
  kFeatureClockSync = 1u << 0,
  kFeatureCompression = 1u << 1,
  kFeatureEncryption = 1u << 2,
  kFeatureAdaptiveCongestion = 1u << 3,
};

enum class HandshakeRejectReason : u8 {
  None = 0,
  Timeout = 1,
  ProtocolVersionMismatch = 2,
  FeatureMismatch = 3,
  MalformedPacket = 4,
  AuthenticationFailed = 5,
};

struct ClientHello {
  u16 protocol_version;
  u32 feature_flags;
  u8 encryption_algo_list_len;
  u8 compression_algo_list_len;
  u8 pub_key_list_len;
  u8 challenge_len;

  static void Build(PacketWriter& builder, ClientHello& packet) {
    builder.Put<u16>(packet.protocol_version);
    builder.Put<u32>(packet.feature_flags);
    builder.Put<u8>(packet.encryption_algo_list_len);
    builder.Put<u8>(packet.compression_algo_list_len);
    builder.Put<u8>(packet.pub_key_list_len);
    builder.Put<u8>(packet.challenge_len);
  }
};

struct ServerHello {
  u16 protocol_version;
  u32 feature_flags;
  u8 encryption_algo_list_len;
  u8 compression_algo_list_len;
  u8 pub_key_list_len;
  u8 challenge_len;
  u8 proof_len;

  static void Build(PacketWriter& builder, ServerHello& packet) {
    builder.Put<u16>(packet.protocol_version);
    builder.Put<u32>(packet.feature_flags);
    builder.Put<u8>(packet.encryption_algo_list_len);
    builder.Put<u8>(packet.compression_algo_list_len);
    builder.Put<u8>(packet.pub_key_list_len);
    builder.Put<u8>(packet.challenge_len);
    builder.Put<u8>(packet.proof_len);
  }
};

struct ServerAuthProof {
  u8 proof_len;

  static void Build(PacketWriter& builder, ServerAuthProof& packet) {
    builder.Put<u8>(packet.proof_len);
  }
};

struct ClientAuthProof {
  u8 proof_len;

  static void Build(PacketWriter& builder, ClientAuthProof& packet) {
    builder.Put<u8>(packet.proof_len);
  }
};

struct ClockSyncRequest {
  u64 client_tick_ms;

  static void Build(PacketWriter& builder, const ClockSyncRequest& packet) {
    builder.Put(packet.client_tick_ms);
  }
};

struct ClockSyncResponse {
  u64 echoed_client_tick_ms;
  u64 server_receive_tick_ms;
  u64 server_send_tick_ms;

  static void Build(PacketWriter& builder, const ClockSyncResponse& packet) {
    builder.Put(packet.echoed_client_tick_ms);
    builder.Put(packet.server_receive_tick_ms);
    builder.Put(packet.server_send_tick_ms);
  }
};

struct ServerGoodbye {
  HandshakeRejectReason reason;

  static void Build(PacketWriter& builder, ServerGoodbye& packet) {
    builder.Put(packet.reason);
  }
};
}  // namespace system_commands

}  // namespace tx::network
