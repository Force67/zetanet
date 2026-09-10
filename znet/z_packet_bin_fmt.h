// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#endif

namespace tx::network {
constexpr u8 kProtocolVersion = 1;

struct PacketHeader {
  static constexpr u16 kMagic = 0x1337;
  u16 magic;
  u16 header_checksum;
  u32 total_packet_data_size;  // headers + payload, after compression/encryption
  u8 version;

  // Optional headers follow in the order of these flag bits.
  struct {
    u8 is_reliable : 1;    // ReliableHeader follows
    u8 is_encrypted : 1;   // see z_crypto_wrapper.h
    u8 is_compressed : 1;  // CompressedPayloadHeader follows
    u8 is_fragmented : 1;
    u8 priority : 2;
    u8 reserved : 2;
  } flags;
  u16 type;
  u16 alignment;      // power of two, applies to headers + payload
  u8 padding_number;  // fill byte for padding
  u8 channel_id;
  u32 timestamp;  // unix time minus program start
};
static_assert(sizeof(PacketHeader) == 20);

// Follows the header when the packet is reliable.
struct ReliableHeader {
  u32 sequence_number;
  u32 acknowledgment_number;
};
static_assert(sizeof(ReliableHeader) == 8);

// Follows next when the payload is uncompressed.
struct UncompressedPayloadHeader {
  u32 checksum;
};
static_assert(sizeof(UncompressedPayloadHeader) == 4);

// Follows next when the payload is compressed.
struct CompressedPayloadHeader {
  u32 compressed_size;
  u32 original_size;
  u32 checksum;
  struct {
    u8 is_little_endian : 1;
    u8 reserved : 7;
  } flags;
  u8 padding[3];
};
static_assert(sizeof(CompressedPayloadHeader) == 16);
}  // namespace tx::network
