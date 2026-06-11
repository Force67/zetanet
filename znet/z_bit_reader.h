// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

// Mirror of BitWriter; see z_bit_writer.h for the wire format.
// LSB-first within each byte. Helpers return false on overflow or
// out-of-range values.

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>

#include <znet/z_wire_le.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/span.h>
#endif

namespace tx::network {

class BitReader {
 public:
  BitReader(const byte* data, mem_size size)
      : buffer_(reinterpret_cast<const unsigned char*>(data)),
        capacity_bits_(size * 8) {}

  explicit BitReader(base::Span<byte> data)
      : BitReader(data.data(), data.size()) {}

  bool ok() const { return ok_; }
  mem_size bits_consumed() const { return bit_offset_; }
  mem_size bits_remaining() const {
    return bit_offset_ <= capacity_bits_ ? capacity_bits_ - bit_offset_ : 0;
  }

  bool ReadBits(u64& value_out, u32 bits) {
    value_out = 0;
    if (!ok_ || bits == 0) {
      return bits == 0;
    }
    if (bits > 64 || bit_offset_ + bits > capacity_bits_) {
      ok_ = false;
      return false;
    }
    const mem_size byte_capacity = capacity_bits_ / 8;
    u64 acc = 0;
    u32 acc_bits = 0;
    while (acc_bits < bits) {
      const mem_size byte_index = bit_offset_ / 8;
      const u32 bit_in_byte = static_cast<u32>(bit_offset_ % 8);
      if (byte_index + 8 <= byte_capacity) {
        // Word path: one unaligned little-endian load yields up to
        // 64 - bit_in_byte (>= 57) bits, so any read of <= 57 bits
        // completes in a single iteration.
        const u64 window = wire_le::LoadU64(buffer_ + byte_index) >> bit_in_byte;
        const u32 take = std::min<u32>(bits - acc_bits, 64u - bit_in_byte);
        const u64 mask =
            (take == 64) ? ~u64{0} : ((u64{1} << take) - 1);
        acc |= (window & mask) << acc_bits;
        acc_bits += take;
        bit_offset_ += take;
      } else {
        // Tail path: fewer than 8 readable bytes remain.
        const u32 take = std::min<u32>(bits - acc_bits, 8u - bit_in_byte);
        const u8 mask = static_cast<u8>((1u << take) - 1);
        const u8 chunk = (buffer_[byte_index] >> bit_in_byte) & mask;
        acc |= static_cast<u64>(chunk) << acc_bits;
        acc_bits += take;
        bit_offset_ += take;
      }
    }
    value_out = acc;
    return true;
  }

  bool ReadBool(bool& v) {
    u64 raw = 0;
    if (!ReadBits(raw, 1)) return false;
    v = (raw != 0);
    return true;
  }

  bool ReadUint(u32& value_out, u32 max_inclusive) {
    if (max_inclusive == 0) {
      value_out = 0;
      return true;
    }
    const u32 bits = BitsRequired(max_inclusive);
    u64 raw = 0;
    if (!ReadBits(raw, bits)) return false;
    if (raw > max_inclusive) {
      ok_ = false;
      return false;
    }
    value_out = static_cast<u32>(raw);
    return true;
  }

  bool ReadInt(i32& value_out, i32 min, i32 max) {
    if (max < min) {
      ok_ = false;
      return false;
    }
    const u32 range = static_cast<u32>(max - min);
    if (range == 0) {
      value_out = min;
      return true;
    }
    const u32 bits = BitsRequired(range);
    u64 raw = 0;
    if (!ReadBits(raw, bits)) return false;
    if (raw > range) {
      ok_ = false;
      return false;
    }
    value_out = static_cast<i32>(raw) + min;
    return true;
  }

  bool ReadFloat(f32& value_out, f32 min, f32 max, u32 bits) {
    if (bits == 0 || bits > 32 || max <= min) {
      ok_ = false;
      return false;
    }
    u64 raw = 0;
    if (!ReadBits(raw, bits)) return false;
    const u32 levels = (bits == 32) ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    const f32 normalized =
        static_cast<f32>(static_cast<f64>(raw) / static_cast<f64>(levels));
    value_out = min + normalized * (max - min);
    return true;
  }

  bool ReadUnitQuat(f32& x, f32& y, f32& z, f32& w,
                    u32 per_component_bits = 9) {
    u64 raw_largest = 0;
    if (!ReadBits(raw_largest, 2)) return false;
    const u32 largest = static_cast<u32>(raw_largest);
    f32 c[4] = {0, 0, 0, 0};
    constexpr f32 kRange = 0.7071068f;
    f32 sum_sq = 0.0f;
    for (u32 i = 0; i < 4; ++i) {
      if (i == largest) continue;
      if (!ReadFloat(c[i], -kRange, kRange, per_component_bits)) return false;
      sum_sq += c[i] * c[i];
    }
    const f32 missing = 1.0f - sum_sq;
    c[largest] = missing > 0.0f ? std::sqrt(missing) : 0.0f;
    x = c[0]; y = c[1]; z = c[2]; w = c[3];
    return true;
  }

  bool ReadBytes(byte* dst, mem_size n) {
    if (!ok_) return false;
    if (n == 0) return true;
    if (!AlignToByte()) return false;
    const mem_size byte_index = bit_offset_ / 8;
    // Subtract instead of add: byte_index + n could wrap for a hostile n.
    if (n > capacity_bits_ / 8 - byte_index) {
      ok_ = false;
      return false;
    }
    std::memcpy(dst, buffer_ + byte_index, n);
    bit_offset_ += n * 8;
    return true;
  }

  bool AlignToByte() {
    const u32 mod = static_cast<u32>(bit_offset_ % 8);
    if (mod == 0) return true;
    const u32 pad = 8 - mod;
    if (bit_offset_ + pad > capacity_bits_) {
      ok_ = false;
      return false;
    }
    bit_offset_ += pad;
    return true;
  }

  template <typename T>
  bool Pop(T& out);

 private:
  static u32 BitsRequired(u32 max_value) {
    return static_cast<u32>(std::bit_width(max_value));
  }

  const unsigned char* buffer_{nullptr};
  mem_size capacity_bits_{0};
  mem_size bit_offset_{0};
  bool ok_{true};
};

}  // namespace tx::network
