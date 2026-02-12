// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <limits>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/vector.h>
#endif

namespace tx::network {
class PacketWriter {
 public:
  explicit PacketWriter(size_t initial_size = 1024)
      : buffer_(new byte[initial_size]), capacity_(initial_size), offset_(0) {}

  ~PacketWriter() { delete[] buffer_; }

  // Put method for scalar types
  template <typename T>
  typename std::enable_if<std::is_scalar<T>::value, bool>::type Put(
      const T value) {
    if (offset_ + sizeof(T) > capacity_) {
      return false;
    }

    std::memcpy(buffer_ + offset_, &value, sizeof(T));
    offset_ += sizeof(T);
    return true;
  }

  // Put method for other trivially copyable types
  template <typename T>
  typename std::enable_if<!std::is_scalar<T>::value &&
                              std::is_trivially_copyable<T>::value,
                          bool>::type
  Put(const T& type) {
    if (offset_ + sizeof(T) > capacity_) {
      return false;
    }

    std::memcpy(buffer_ + offset_, &type, sizeof(T));
    offset_ += sizeof(T);
    return true;
  }

  bool PutS(const base::Span<byte>& data) {
    if (offset_ + data.size() > capacity_) {
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
    if (!Put<u16>(static_cast<u16>(data.size()))) {
      return false;
    }
    return PutS(data);
  }

  const base::Span<byte> data() const {
    return base::Span<byte>(buffer_, offset_);
  }

 private:
  byte* buffer_;
  size_t capacity_;
  size_t offset_;

  // Prevent copying and assignment
  PacketWriter(const PacketWriter&) = delete;
  PacketWriter& operator=(const PacketWriter&) = delete;
};

class PacketReader {
 public:
  // Constructor takes a pointer to a buffer and its size
  PacketReader(const byte* buffer, size_t size)
      : buffer_(buffer), capacity_(size), offset_(0) {}

  // Read method for scalar types
  template <typename T>
  typename std::enable_if<std::is_scalar<T>::value, bool>::type Read(T& value) {
    if (offset_ + sizeof(T) > capacity_) {
      return false;
    }

    std::memcpy(&value, buffer_ + offset_, sizeof(T));
    offset_ += sizeof(T);
    return true;
  }

  // Read method for other trivially copyable types
  template <typename T>
  typename std::enable_if<!std::is_scalar<T>::value &&
                              std::is_trivially_copyable<T>::value,
                          bool>::type
  Read(T& type) {
    if (offset_ + sizeof(T) > capacity_) {
      return false;
    }

    std::memcpy(&type, buffer_ + offset_, sizeof(T));
    offset_ += sizeof(T);
    return true;
  }

  bool ReadS(base::Vector<byte>& data) {
    if (offset_ + data.size() > capacity_) {
      return false;
    }

    std::memcpy((void*)data.data(), buffer_ + offset_, data.size());
    offset_ += data.size();
    return true;
  }

  bool ReadList(base::Vector<byte>& data) {
    u16 size;
    if (!Read<u16>(size)) {
      return false;
    }
    if (offset_ + size > capacity_) {
      return false;
    }
    data.resize(size);
    return ReadS(data);
  }

  // Return the current position in the buffer
  size_t position() const { return offset_; }

 private:
  const byte* buffer_;
  size_t capacity_;
  size_t offset_;

  // Prevent copying and assignment
  PacketReader(const PacketReader&) = delete;
  PacketReader& operator=(const PacketReader&) = delete;
};

namespace system_commands {

struct ClientHello {
  u8 encryption_algo_list_len;
  u8 compression_algo_list_len;
  u8 challenge_len;

  static void Build(PacketWriter& builder, ClientHello& packet) {
    builder.Put<u8>(packet.encryption_algo_list_len);
    builder.Put<u8>(packet.compression_algo_list_len);
    builder.Put<u8>(packet.challenge_len);
  }
};

struct ServerHello {
  u8 encryption_algo_list_len;
  u8 compression_algo_list_len;
  u8 pub_key_list_len;
  u8 challenge_len;
  u8 proof_len;

  static void Build(PacketWriter& builder, ServerHello& packet) {
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

struct ServerGoodbye {
  u8 reason;

  static void Build(PacketWriter& builder, ServerGoodbye& packet) {
    builder.Put<u8>(packet.reason);
  }
};
}  // namespace system_commands

}  // namespace tx::network
