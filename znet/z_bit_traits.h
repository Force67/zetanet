// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

// Trait-based dispatch for BitWriter::Push / BitReader::Pop.
//
// User types opt in by specializing BitTraits<T>:
//
//   template <>
//   struct tx::network::BitTraits<MyStruct> {
//     static void Write(BitWriter& w, const MyStruct& v) { ... }
//     static bool Read(BitReader& r, MyStruct& v) { ... }
//   };
//
// Per-field users can wrap members in ZBitField<T, Spec>; the matching
// trait is provided automatically. A Spec is a struct with static
// Write(BitWriter&, T) / Read(BitReader&, T&) methods. Built-in specs:
//
//   ZIntRange<Min, Max>      i32 in [Min, Max]
//   ZUintMax<Max>            u32 in [0, Max]
//   ZBoolBit                 single-bit bool
//   ZFloatRange<RangeSpec>   float quantized to RangeSpec::kBits

#include <znet/z_bit_reader.h>
#include <znet/z_bit_writer.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#endif

namespace tx::network {

template <typename T>
struct BitTraits;

// ---------- primitives ----------

template <>
struct BitTraits<bool> {
  static void Write(BitWriter& w, bool v) { w.WriteBool(v); }
  static bool Read(BitReader& r, bool& v) { return r.ReadBool(v); }
};

template <>
struct BitTraits<u8> {
  static void Write(BitWriter& w, u8 v) { w.WriteBits(v, 8); }
  static bool Read(BitReader& r, u8& v) {
    u64 raw = 0;
    if (!r.ReadBits(raw, 8)) return false;
    v = static_cast<u8>(raw);
    return true;
  }
};

template <>
struct BitTraits<u16> {
  static void Write(BitWriter& w, u16 v) { w.WriteBits(v, 16); }
  static bool Read(BitReader& r, u16& v) {
    u64 raw = 0;
    if (!r.ReadBits(raw, 16)) return false;
    v = static_cast<u16>(raw);
    return true;
  }
};

template <>
struct BitTraits<u32> {
  static void Write(BitWriter& w, u32 v) { w.WriteBits(v, 32); }
  static bool Read(BitReader& r, u32& v) {
    u64 raw = 0;
    if (!r.ReadBits(raw, 32)) return false;
    v = static_cast<u32>(raw);
    return true;
  }
};

template <>
struct BitTraits<u64> {
  static void Write(BitWriter& w, u64 v) { w.WriteBits(v, 64); }
  static bool Read(BitReader& r, u64& v) { return r.ReadBits(v, 64); }
};

template <>
struct BitTraits<i32> {
  static void Write(BitWriter& w, i32 v) {
    u32 raw;
    std::memcpy(&raw, &v, 4);
    w.WriteBits(raw, 32);
  }
  static bool Read(BitReader& r, i32& v) {
    u64 raw = 0;
    if (!r.ReadBits(raw, 32)) return false;
    const u32 truncated = static_cast<u32>(raw);
    std::memcpy(&v, &truncated, 4);
    return true;
  }
};

template <>
struct BitTraits<f32> {
  static void Write(BitWriter& w, f32 v) {
    u32 raw;
    std::memcpy(&raw, &v, 4);
    w.WriteBits(raw, 32);
  }
  static bool Read(BitReader& r, f32& v) {
    u64 raw = 0;
    if (!r.ReadBits(raw, 32)) return false;
    const u32 truncated = static_cast<u32>(raw);
    std::memcpy(&v, &truncated, 4);
    return true;
  }
};

// ---------- ZBitField + Specs ----------

template <typename T, typename Spec>
struct ZBitField {
  T value{};

  ZBitField() = default;
  ZBitField(const T& v) : value(v) {}

  operator T&() { return value; }
  operator const T&() const { return value; }

  ZBitField& operator=(const T& v) {
    value = v;
    return *this;
  }
};

template <typename T, typename Spec>
struct BitTraits<ZBitField<T, Spec>> {
  static void Write(BitWriter& w, const ZBitField<T, Spec>& f) {
    Spec::Write(w, f.value);
  }
  static bool Read(BitReader& r, ZBitField<T, Spec>& f) {
    return Spec::Read(r, f.value);
  }
};

// Integer range spec: i32 in [Min, Max] inclusive.
template <i32 Min, i32 Max>
struct ZIntRange {
  static_assert(Max >= Min, "ZIntRange: Max must be >= Min");
  static void Write(BitWriter& w, i32 v) { w.WriteInt(v, Min, Max); }
  static bool Read(BitReader& r, i32& v) { return r.ReadInt(v, Min, Max); }
};

// Unsigned-with-max spec: u32 in [0, Max].
template <u32 Max>
struct ZUintMax {
  static void Write(BitWriter& w, u32 v) { w.WriteUint(v, Max); }
  static bool Read(BitReader& r, u32& v) { return r.ReadUint(v, Max); }
};

// Single-bit bool.
struct ZBoolBit {
  static void Write(BitWriter& w, bool v) { w.WriteBool(v); }
  static bool Read(BitReader& r, bool& v) { return r.ReadBool(v); }
};

// Float quantization spec. RangeSpec must define static constexpr members
//   f32 kMin, kMax;  u32 kBits;
template <typename RangeSpec>
struct ZFloatRange {
  static void Write(BitWriter& w, f32 v) {
    w.WriteFloat(v, RangeSpec::kMin, RangeSpec::kMax, RangeSpec::kBits);
  }
  static bool Read(BitReader& r, f32& v) {
    return r.ReadFloat(v, RangeSpec::kMin, RangeSpec::kMax, RangeSpec::kBits);
  }
};

// ---------- Push / Pop dispatch ----------

template <typename T>
inline void BitWriter::Push(const T& value) {
  BitTraits<T>::Write(*this, value);
}

template <typename T>
inline bool BitReader::Pop(T& out) {
  return BitTraits<T>::Read(*this, out);
}

}  // namespace tx::network
