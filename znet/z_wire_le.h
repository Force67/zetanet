// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <cstddef>
#include <cstring>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/vector.h>
#endif

namespace tx::network::wire_le {

#if defined(_WIN32) || \
    (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN)
#define ZNET_WIRE_LE_NATIVE 1
#elif (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
    defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN)
#define ZNET_WIRE_LE_NATIVE 0
#else
#define ZNET_WIRE_LE_NATIVE -1
#endif

inline u16 ByteSwap16(const u16 value) {
#if defined(_MSC_VER)
  return static_cast<u16>(_byteswap_ushort(value));
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap16(value);
#else
  return static_cast<u16>((value << 8u) | (value >> 8u));
#endif
}

inline u32 ByteSwap32(const u32 value) {
#if defined(_MSC_VER)
  return static_cast<u32>(_byteswap_ulong(value));
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap32(value);
#else
  return ((value & 0x000000FFu) << 24u) |
         ((value & 0x0000FF00u) << 8u) |
         ((value & 0x00FF0000u) >> 8u) |
         ((value & 0xFF000000u) >> 24u);
#endif
}

inline u64 ByteSwap64(const u64 value) {
#if defined(_MSC_VER)
  return static_cast<u64>(_byteswap_uint64(value));
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(value);
#else
  return ((value & 0x00000000000000FFull) << 56u) |
         ((value & 0x000000000000FF00ull) << 40u) |
         ((value & 0x0000000000FF0000ull) << 24u) |
         ((value & 0x00000000FF000000ull) << 8u) |
         ((value & 0x000000FF00000000ull) >> 8u) |
         ((value & 0x0000FF0000000000ull) >> 24u) |
         ((value & 0x00FF000000000000ull) >> 40u) |
         ((value & 0xFF00000000000000ull) >> 56u);
#endif
}

inline bool NativeLittleEndianFallback() {
  const u16 one = 1;
  return *(reinterpret_cast<const byte*>(&one)) == static_cast<byte>(1);
}

inline u16 HostToLe16(const u16 value) {
#if ZNET_WIRE_LE_NATIVE == 1
  return value;
#elif ZNET_WIRE_LE_NATIVE == 0
  return ByteSwap16(value);
#else
  return NativeLittleEndianFallback() ? value : ByteSwap16(value);
#endif
}

inline u32 HostToLe32(const u32 value) {
#if ZNET_WIRE_LE_NATIVE == 1
  return value;
#elif ZNET_WIRE_LE_NATIVE == 0
  return ByteSwap32(value);
#else
  return NativeLittleEndianFallback() ? value : ByteSwap32(value);
#endif
}

inline u64 HostToLe64(const u64 value) {
#if ZNET_WIRE_LE_NATIVE == 1
  return value;
#elif ZNET_WIRE_LE_NATIVE == 0
  return ByteSwap64(value);
#else
  return NativeLittleEndianFallback() ? value : ByteSwap64(value);
#endif
}

inline u16 LeToHost16(const u16 value) { return HostToLe16(value); }
inline u32 LeToHost32(const u32 value) { return HostToLe32(value); }
inline u64 LeToHost64(const u64 value) { return HostToLe64(value); }

inline void StoreU16(byte* out, const u16 value) {
  const u16 encoded = HostToLe16(value);
  std::memcpy(out, &encoded, sizeof(encoded));
}

inline void StoreU32(byte* out, const u32 value) {
  const u32 encoded = HostToLe32(value);
  std::memcpy(out, &encoded, sizeof(encoded));
}

inline void StoreU64(byte* out, const u64 value) {
  const u64 encoded = HostToLe64(value);
  std::memcpy(out, &encoded, sizeof(encoded));
}

inline u16 LoadU16(const byte* data) {
  u16 encoded = 0;
  std::memcpy(&encoded, data, sizeof(encoded));
  return LeToHost16(encoded);
}

inline u32 LoadU32(const byte* data) {
  u32 encoded = 0;
  std::memcpy(&encoded, data, sizeof(encoded));
  return LeToHost32(encoded);
}

inline u64 LoadU64(const byte* data) {
  u64 encoded = 0;
  std::memcpy(&encoded, data, sizeof(encoded));
  return LeToHost64(encoded);
}

inline void AppendU16(base::Vector<byte>& out, const u16 value) {
  const mem_size start = out.size();
  out.resize(start + sizeof(u16));
  StoreU16(out.data() + start, value);
}

inline void AppendU32(base::Vector<byte>& out, const u32 value) {
  const mem_size start = out.size();
  out.resize(start + sizeof(u32));
  StoreU32(out.data() + start, value);
}

inline void AppendU64(base::Vector<byte>& out, const u64 value) {
  const mem_size start = out.size();
  out.resize(start + sizeof(u64));
  StoreU64(out.data() + start, value);
}

inline bool ReadU16(const byte* data,
                    const mem_size data_size,
                    mem_size& cursor,
                    u16& out) {
  if (cursor + sizeof(u16) > data_size) {
    return false;
  }
  out = LoadU16(data + cursor);
  cursor += sizeof(u16);
  return true;
}

inline bool ReadU32(const byte* data,
                    const mem_size data_size,
                    mem_size& cursor,
                    u32& out) {
  if (cursor + sizeof(u32) > data_size) {
    return false;
  }
  out = LoadU32(data + cursor);
  cursor += sizeof(u32);
  return true;
}

inline bool ReadU64(const byte* data,
                    const mem_size data_size,
                    mem_size& cursor,
                    u64& out) {
  if (cursor + sizeof(u64) > data_size) {
    return false;
  }
  out = LoadU64(data + cursor);
  cursor += sizeof(u64);
  return true;
}

template <typename Input>
inline bool ReadU16(const Input& input, mem_size& cursor, u16& out) {
inline bool ReadU32(const Input& input, mem_size& cursor, u32& out) {
inline bool ReadU64(const Input& input, mem_size& cursor, u64& out) {
  return ReadU64(input.data(), input.size(), cursor, out);
}

#undef ZNET_WIRE_LE_NATIVE

}  // namespace tx::network::wire_le
