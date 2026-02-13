// Copyright (C) 2023-2025 Vincent Hengel
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

namespace tx::network {

class PacketBuilder {
 public:
  PacketBuilder(ZCryptoContext* crypto_context)
      : crypto_context_(crypto_context) {}

  base::Vector<byte> BuildPacket(OutgoingPacket& packet_info,
                                 const u32 next_sequence_number);

 private:
  ZCryptoContext* crypto_context_;

  void FillPacketHeader(const base::Span<byte> outgoing_data,
                        const OutgoingPacket& packet_info,
                        u32 payload_size,
                        u32 original_payload_size,
                        u32 next_sequence_number);

  bool EncryptPayloadIfNeeded(const OutgoingPacket& packet_info,
                              u32 next_sequence_number,
                              base::Vector<byte>& payload) {
    if (!packet_info.flags.encrypted) {
      return true;
    }
    if (!crypto_context_) {
      return false;
    }
    base::Vector<byte> aad(12);
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
    aad[0] = static_cast<u8>(static_cast<u16>(packet_info.type) & 0xFFu);
    aad[1] = static_cast<u8>((static_cast<u16>(packet_info.type) >> 8) & 0xFFu);
    aad[2] = static_cast<u8>(packet_info.channel);
    aad[3] = flags;
    aad[4] = static_cast<u8>(sequence & 0xFFu);
    aad[5] = static_cast<u8>((sequence >> 8) & 0xFFu);
    aad[6] = static_cast<u8>((sequence >> 16) & 0xFFu);
    aad[7] = static_cast<u8>((sequence >> 24) & 0xFFu);
    aad[8] = static_cast<u8>(acknowledgement & 0xFFu);
    aad[9] = static_cast<u8>((acknowledgement >> 8) & 0xFFu);
    aad[10] = static_cast<u8>((acknowledgement >> 16) & 0xFFu);
    aad[11] = static_cast<u8>((acknowledgement >> 24) & 0xFFu);

    base::Vector<byte> encrypted_payload;
    if (!crypto_context_->EncryptPayload(
            base::Span<byte>(payload.data(), payload.size()),
            base::Span<byte>(aad.data(), aad.size()),
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

  bool UnpackPacket(const byte* in_buffer, size_t in_size, IncomingPacket& out);

 private:
  ZCryptoContext* crypto_context_;

  bool ValidatePacketHeader(const PacketHeader& header, size_t size) const {
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
                              const PacketHeader& header) {
    if (!header.flags.is_encrypted) {
      return true;
    }
    if (!crypto_context_) {
      return false;
    }
    base::Vector<byte> aad(12);
    const u8 flags =
        (header.flags.is_reliable ? 1 : 0) |
        (header.flags.is_encrypted ? (1 << 1) : 0) |
        (header.flags.is_compressed ? (1 << 2) : 0) |
        ((header.flags.priority & 0x3) << 4);
    aad[0] = static_cast<u8>(header.type & 0xFFu);
    aad[1] = static_cast<u8>((header.type >> 8) & 0xFFu);
    aad[2] = header.channel_id;
    aad[3] = flags;
    aad[4] = static_cast<u8>(sequence_number & 0xFFu);
    aad[5] = static_cast<u8>((sequence_number >> 8) & 0xFFu);
    aad[6] = static_cast<u8>((sequence_number >> 16) & 0xFFu);
    aad[7] = static_cast<u8>((sequence_number >> 24) & 0xFFu);
    aad[8] = static_cast<u8>(acknowledgement_number & 0xFFu);
    aad[9] = static_cast<u8>((acknowledgement_number >> 8) & 0xFFu);
    aad[10] = static_cast<u8>((acknowledgement_number >> 16) & 0xFFu);
    aad[11] = static_cast<u8>((acknowledgement_number >> 24) & 0xFFu);

    base::Vector<byte> plaintext;
    if (!crypto_context_->DecryptPayload(
            base::Span<byte>(payload.data(), payload.size()),
            base::Span<byte>(aad.data(), aad.size()), plaintext)) {
      return false;
    }
    payload = std::move(plaintext);
    return true;
  }
};
}  // namespace tx::network
