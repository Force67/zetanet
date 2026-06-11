// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_crypto_wrapper.h>
#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/vector.h>
#include <base/time/time.h>
#include <base/logging.h>
#endif

#include <znet/z_packets.h>
#include <znet/z_packet_bin_fmt.h>
#include <znet/z_wire_le.h>

namespace tx::network {

class PacketBuilder {
 public:
  PacketBuilder(ZCryptoContext* crypto_context)
      : crypto_context_(crypto_context) {}

  base::Vector<byte> BuildPacket(OutgoingPacket& packet_info,
                                 const u32 next_sequence_number);

  // Builds into `out`, reusing its capacity (resize + overwrite). Returns
  // false on failure; `out` contents are unspecified then. Preferred on the
  // per-packet hot path to avoid an allocation per send.
  bool BuildPacketInto(OutgoingPacket& packet_info,
                       u32 next_sequence_number,
                       base::Vector<byte>& out);

 private:
  ZCryptoContext* crypto_context_;

  void FillPacketHeader(const base::Span<byte> outgoing_data,
                        const OutgoingPacket& packet_info,
                        u32 payload_size,
                        u32 original_payload_size,
                        u32 next_sequence_number);

  bool EncryptPayloadIfNeeded(const OutgoingPacket& packet_info,
                              u32 next_sequence_number,
                              u32 wire_payload_size,
                              u32 original_payload_size,
                              base::Vector<byte>& payload) {
    if (!packet_info.flags.encrypted) {
      return true;
    }
    if (!crypto_context_) {
      return false;
    }
    // Stack-allocated AAD avoids per-packet heap allocation.
    byte aad[20];
    const u8 flags =
        (packet_info.flags.reliable ? 1 : 0) |
        (packet_info.flags.encrypted ? (1 << 1) : 0) |
        (packet_info.flags.compressed ? (1 << 2) : 0) |
        ((packet_info.flags.priority & 0x3) << 4);
    const u32 sequence = packet_info.flags.reliable ? next_sequence_number : 0;
    const u32 acknowledgement =
        (packet_info.flags.reliable && packet_info.type == PacketType::Acknowledgement)
            ? static_cast<u32>(packet_info.payload.scalar)
            : 0;
    wire_le::StoreU16(aad, static_cast<u16>(packet_info.type));
    aad[2] = static_cast<u8>(packet_info.channel);
    aad[3] = flags;
    wire_le::StoreU32(aad + 4, sequence);
    wire_le::StoreU32(aad + 8, acknowledgement);
    wire_le::StoreU32(aad + 12, wire_payload_size);
    wire_le::StoreU32(aad + 16, original_payload_size);

    base::Vector<byte> encrypted_payload;
    if (!crypto_context_->EncryptPayload(
            base::Span<byte>(payload.data(), payload.size()),
            base::Span<byte>(aad, sizeof(aad)),
            encrypted_payload)) {
      return false;
    }
    payload = std::move(encrypted_payload);
    return true;
  }
};

class PacketUnpacker {
 public:
  PacketUnpacker(ZCryptoContext* crypto_context)
      : crypto_context_(crypto_context) {}

  bool UnpackPacket(const byte* in_buffer, mem_size in_size, IncomingPacket& out);

 private:
  ZCryptoContext* crypto_context_;

  bool ValidatePacketHeader(const PacketHeader& header, mem_size size) const {
    if (size < sizeof(PacketHeader)) {
      return false;
    }
    if (header.magic != PacketHeader::kMagic) {
      return false;
    }
    if (header.version != kProtocolVersion) {
      return false;
    }
    if (header.total_packet_data_size != size) {
      return false;
    }
    if (header.flags.reserved != 0 || header.flags.is_fragmented) {
      return false;
    }
    if (header.channel_id > static_cast<u8>(PacketChannelType::Data)) {
      return false;
    }
    if (header.flags.priority > static_cast<u8>(PacketPriority::Critical)) {
      return false;
    }
    return header.type != static_cast<u16>(PacketType::Invalid);
  }

  bool DecryptPayloadIfNeeded(base::Vector<byte>& payload,
                              u32 sequence_number,
                              u32 acknowledgement_number,
                              const PacketHeader& header,
                              u32 original_payload_size) {
    if (!header.flags.is_encrypted) {
      return true;
    }
    if (!crypto_context_) {
      return false;
    }
    // Stack-allocated AAD avoids per-packet heap allocation.
    byte aad[20];
    const u8 flags =
        (header.flags.is_reliable ? 1 : 0) |
        (header.flags.is_encrypted ? (1 << 1) : 0) |
        (header.flags.is_compressed ? (1 << 2) : 0) |
        ((header.flags.priority & 0x3) << 4);
    wire_le::StoreU16(aad, header.type);
    aad[2] = header.channel_id;
    aad[3] = flags;
    wire_le::StoreU32(aad + 4, sequence_number);
    wire_le::StoreU32(aad + 8, acknowledgement_number);
    wire_le::StoreU32(aad + 12, static_cast<u32>(payload.size()));
    wire_le::StoreU32(aad + 16, original_payload_size);

    base::Vector<byte> plaintext;
    if (!crypto_context_->DecryptPayload(
            base::Span<byte>(payload.data(), payload.size()),
            base::Span<byte>(aad, sizeof(aad)), plaintext)) {
      return false;
    }
    payload = std::move(plaintext);
    return true;
  }
};
}  // namespace tx::network
