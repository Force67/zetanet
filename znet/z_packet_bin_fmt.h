// Copyright (C) 2023-2025 Vincent Hengel
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
  // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  u16 magic;                   // 2 bytes
  u16 header_checksum;         // 2 bytes
  u32 total_packet_data_size;  // 4 bytes, total size of the packet, including
                               // all headers and payload, after
                               // compression/encryption
  // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  u8 version;  // 1 byte for the protocol/header version

  // NOTE: headers follow in the order of these flag bits.
  struct {
    u8 is_reliable : 1;    // if the ReliableHeader follows after the header
    u8 is_encrypted : 1;   // see z_crypto_wrapper.h
    u8 is_compressed : 1;  // if the CompressedPayloadHeader follows after the
                           // header
    u8 is_fragmented : 1;  // if the payload is fragmented
    u8 priority : 2;       // 2 bits for priority (4 levels), see Priority enum
    u8 reserved : 2;       // reserved for future use
  } flags;                 // 1 byte for flags
  // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  u16 type;  // 2 bytes for type (allows up to 65536 types)
  // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  u16 alignment;      // 1 byte, for alignment - exponential of 2, affects that
                      // total data hunk, meaning header(s) + payload
  u8 padding_number;  // 1 byte, what to fill the padding with
  u8 channel_id;      // Channel the data was sent on (See Channel enum)
  u32 timestamp;  // 4 bytes, timestamp of the packet, custom representation,
                  // current unix timestamp minus unix from program start
};
static_assert(sizeof(PacketHeader) == 20);

// 1. follows after the header of a packet if the packet is reliable
struct ReliableHeader {
  u32 sequence_number;  // 4 bytes, sequence number of the packet always going
                        // up
  u32 acknowledgment_number;  // 4 bytes, sequence number of the last packet
                              // acknowledged
};
static_assert(sizeof(ReliableHeader) == 8);

// 2. follows next if the packet is uncompressed
struct UncompressedPayloadHeader {
  u32 checksum;   // 4 bytes
};
static_assert(sizeof(UncompressedPayloadHeader) == 4);

// 2. follows next if the packet is compressed
struct CompressedPayloadHeader {
  u32 compressed_size;    // 4 bytes
  u32 checksum;           // 4 bytes
  struct {
    u8 is_little_endian : 1;  // if the payload is little endian
    u8 reserved : 7;          // reserved for future use
  } flags;                    // 1 byte for flags
  u8 padding[3];              // 3 byte
};
static_assert(sizeof(CompressedPayloadHeader) == 12);
}  // namespace tx::network
