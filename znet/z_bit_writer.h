// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

// 64-bit LSB-first bit writer. Flushes whole bytes once at least 56 bits
// are queued. Targets game-state payloads: quantized ints, floats, unit
// quaternions, packed booleans.

#include <bit>
#include <cstring>
#include <limits>
#include <utility>

#include <znet/z_network_allocator.h>
#include <znet/z_packets.h>
#include <znet/z_wire_le.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/span.h>
#include <base/logging.h>
#endif

namespace tx::network {

class BitWriter {
 public:
  static constexpr mem_size kFlushThresholdBits = 56;
  static constexpr mem_size kDefaultReserveBytes = 256;

  BitWriter(OutgoingPacket& packet, mem_size reserve_bytes)
      : packet_(&packet) {
    if (reserve_bytes == 0) {
      reserve_bytes = kDefaultReserveBytes;
    }
    buffer_ = PacketBufferPool::Instance().Allocate(reserve_bytes);
    if (!buffer_) {
      ok_ = false;
      return;
    }
    capacity_ = PacketBufferPool::Instance().GetCapacity(buffer_);
    packet_->AttachHeapBuffer(reinterpret_cast<byte*>(buffer_),
                              static_cast<u32>(capacity_));
  }

  explicit BitWriter(mem_size reserve_bytes) {
    if (reserve_bytes == 0) {
      reserve_bytes = kDefaultReserveBytes;
    }
    buffer_ = PacketBufferPool::Instance().Allocate(reserve_bytes);
    if (!buffer_) {
      ok_ = false;
      return;
    }
    capacity_ = PacketBufferPool::Instance().GetCapacity(buffer_);
    owns_buffer_ = true;
  }

  explicit BitWriter(base::Span<byte> external)
      : buffer_(reinterpret_cast<unsigned char*>(
            const_cast<byte*>(external.data()))),
        capacity_(external.size()),
        external_buffer_(true) {}

  ~BitWriter() {
    if (!finalized_) {
      Finalize();
    }
    if (owns_buffer_ && buffer_) {
      PacketBufferPool::Instance().Release(buffer_);
    }
  }

  BitWriter(const BitWriter&) = delete;
  BitWriter& operator=(const BitWriter&) = delete;
  BitWriter(BitWriter&&) = delete;
  BitWriter& operator=(BitWriter&&) = delete;

  bool ok() const { return ok_; }
  mem_size bits_written() const { return byte_offset_ * 8 + scratch_bits_; }
  mem_size bytes_written() const { return byte_offset_ + (scratch_bits_ + 7) / 8; }

  // Append `bits` low-order bits of `value` to the stream.
  void WriteBits(u64 value, u32 bits) {
    if (!ok_) return;
    if (bits == 0) return;
    if (bits > 64) {
      ok_ = false;
      return;
    }
    if (bits < 64) {
      value &= (u64{1} << bits) - 1;
    }
    const u32 room = 64 - scratch_bits_;
    if (bits <= room) {
      scratch_ |= value << scratch_bits_;
      scratch_bits_ += bits;
    } else {
      if (room > 0) {
        scratch_ |= value << scratch_bits_;
      }
      scratch_bits_ = 64;
      FlushScratchBytes();
      scratch_ = value >> room;
      scratch_bits_ = bits - room;
    }
    if (scratch_bits_ >= kFlushThresholdBits) {
      FlushScratchBytes();
    }
  }

  void WriteBool(bool v) { WriteBits(v ? 1u : 0u, 1); }

  void WriteUint(u32 value, u32 max_inclusive) {
    if (max_inclusive == 0) {
      return;
    }
    if (value > max_inclusive) {
      ok_ = false;
      return;
    }
    const u32 bits = BitsRequired(max_inclusive);
    WriteBits(value, bits);
  }

  void WriteInt(i32 value, i32 min, i32 max) {
    if (max < min || value < min || value > max) {
      ok_ = false;
      return;
    }
    const u32 range = static_cast<u32>(max - min);
    const u32 biased = static_cast<u32>(value - min);
    if (range == 0) {
      return;
    }
    WriteBits(biased, BitsRequired(range));
  }

  void WriteFloat(f32 value, f32 min, f32 max, u32 bits) {
    if (bits == 0 || bits > 32 || max <= min) {
      ok_ = false;
      return;
    }
    if (value < min) value = min;
    if (value > max) value = max;
    const u32 levels = (bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    const f32 normalized = (value - min) / (max - min);
    u64 quantized = static_cast<u64>(
        static_cast<f64>(normalized) * static_cast<f64>(levels) + 0.5);
    if (quantized > levels) {
      quantized = levels;
    }
    WriteBits(quantized, bits);
  }

  // Unit quaternion as smallest-three: 2 bits for the index of the largest
  // absolute component, then `per_component_bits` per remaining component.
  void WriteUnitQuat(f32 x, f32 y, f32 z, f32 w, u32 per_component_bits = 9) {
    f32 c[4] = {x, y, z, w};
    u32 largest = 0;
    f32 largest_abs = -1.0f;
    for (u32 i = 0; i < 4; ++i) {
      const f32 a = c[i] < 0 ? -c[i] : c[i];
      if (a > largest_abs) {
        largest_abs = a;
        largest = i;
      }
    }
    if (c[largest] < 0) {
      for (auto& v : c) v = -v;
    }
    WriteBits(largest, 2);
    constexpr f32 kRange = 0.7071068f;  // sqrt(0.5)
    for (u32 i = 0; i < 4; ++i) {
      if (i == largest) continue;
      WriteFloat(c[i], -kRange, kRange, per_component_bits);
    }
  }

  void WriteBytes(const byte* data, mem_size n) {
    if (!ok_ || n == 0) return;
    AlignToByte();
    if (!ok_) return;
    if (!Reserve(byte_offset_ + n)) {
      return;
    }
    std::memcpy(buffer_ + byte_offset_, data, n);
    byte_offset_ += n;
  }

  void AlignToByte() {
    if (scratch_bits_ % 8 != 0) {
      const u32 pad = 8 - (scratch_bits_ % 8);
      WriteBits(0, pad);
    }
    if (scratch_bits_ > 0) {
      FlushScratchBytes();
    }
  }

  template <typename T>
  void Push(const T& value);

  void Finalize() {
    if (finalized_) return;
    finalized_ = true;
    if (!ok_) return;
    while (scratch_bits_ > 0) {
      if (!Reserve(byte_offset_ + 1)) {
        return;
      }
      buffer_[byte_offset_++] = static_cast<unsigned char>(scratch_ & 0xFFu);
      scratch_ >>= 8;
      scratch_bits_ = scratch_bits_ > 8 ? scratch_bits_ - 8 : 0;
    }
    if (packet_) {
      packet_->SetHeapDataSize(static_cast<u32>(byte_offset_));
    }
  }

  // Must call Finalize() first.
  base::Span<byte> data() const {
    return base::Span<byte>(reinterpret_cast<const byte*>(buffer_),
                            byte_offset_);
  }

  // Hands the pool-owned buffer to the caller, who must Release it.
  unsigned char* Detach(mem_size& size_out) {
    Finalize();
    size_out = byte_offset_;
    unsigned char* result = buffer_;
    buffer_ = nullptr;
    owns_buffer_ = false;
    capacity_ = 0;
    return result;
  }

 private:
  static u32 BitsRequired(u32 max_value) {
    return static_cast<u32>(std::bit_width(max_value));
  }

  void FlushScratchBytes() {
    if (scratch_bits_ < 8) {
      return;
    }
    // Store the whole accumulator as one little-endian word and advance over
    // the complete bytes only. The over-written tail bytes are scratch space
    // within capacity, rewritten by later flushes.
    if (Reserve(byte_offset_ + 8)) {
      const u32 bytes = scratch_bits_ >> 3;
      wire_le::StoreU64(reinterpret_cast<byte*>(buffer_ + byte_offset_),
                        scratch_);
      byte_offset_ += bytes;
      scratch_ = (bytes == 8) ? 0 : (scratch_ >> (bytes * 8));
      scratch_bits_ -= bytes * 8;
      return;
    }
    // External buffer with fewer than 8 bytes left: Reserve() set ok_ =
    // false; retry byte-wise so a buffer that exactly fits still succeeds.
    if (!external_buffer_) {
      return;
    }
    ok_ = true;
    while (scratch_bits_ >= 8) {
      if (!Reserve(byte_offset_ + 1)) {
        return;
      }
      buffer_[byte_offset_++] = static_cast<unsigned char>(scratch_ & 0xFFu);
      scratch_ >>= 8;
      scratch_bits_ -= 8;
    }
  }

  // Grow capacity for pool-backed buffers; external buffers fail instead.
  bool Reserve(mem_size needed) {
    if (needed <= capacity_) return true;
    if (external_buffer_) {
      ok_ = false;
      return false;
    }
    if (needed > std::numeric_limits<u32>::max()) {
      ok_ = false;
      return false;
    }
    mem_size new_capacity = capacity_ ? capacity_ : kDefaultReserveBytes;
    while (new_capacity < needed) {
      if (new_capacity > std::numeric_limits<mem_size>::max() / 2) {
        new_capacity = needed;
        break;
      }
      new_capacity *= 2;
    }
    unsigned char* new_buf =
        PacketBufferPool::Instance().Allocate(new_capacity);
    if (!new_buf) {
      ok_ = false;
      return false;
    }
    const mem_size new_cap_actual =
        PacketBufferPool::Instance().GetCapacity(new_buf);
    if (buffer_ && byte_offset_ > 0) {
      std::memcpy(new_buf, buffer_, byte_offset_);
    }
    if (packet_) {
      unsigned char* old = reinterpret_cast<unsigned char*>(
          packet_->DetachHeapBuffer());
      packet_->AttachHeapBuffer(reinterpret_cast<byte*>(new_buf),
                                static_cast<u32>(new_cap_actual));
      if (old) {
        PacketBufferPool::Instance().Release(old);
      }
    } else {
      if (buffer_ && owns_buffer_) {
        PacketBufferPool::Instance().Release(buffer_);
      }
      owns_buffer_ = true;
    }
    buffer_ = new_buf;
    capacity_ = new_cap_actual;
    return true;
  }

  OutgoingPacket* packet_{nullptr};
  unsigned char* buffer_{nullptr};
  mem_size capacity_{0};
  mem_size byte_offset_{0};
  u64 scratch_{0};
  u32 scratch_bits_{0};
  bool ok_{true};
  bool finalized_{false};
  bool owns_buffer_{false};
  bool external_buffer_{false};
};

}  // namespace tx::network
