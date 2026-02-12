// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_serdes.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {

static constexpr char kLogTag[] = "z-packet-serdes";
static constexpr u32 kTimeshift =
    1701290985;

base::Vector<byte> PacketBuilder::BuildPacket(OutgoingPacket& packet_info,
                                              const u32 next_sequence_number) {
  auto unix_timestamp = base::GetUnixTimeStamp();

  u32 payload_size = packet_info.heap_data_size;
  u32 size_of_headers =
      sizeof(PacketHeader) +
      (packet_info.flags.reliable * sizeof(ReliableHeader)) +
      (packet_info.flags.compressed * sizeof(CompressedPayloadHeader)) +
      ((!packet_info.flags.compressed) * sizeof(UncompressedPayloadHeader));

  base::Vector<byte> packet(size_of_headers + payload_size);

  base::Vector<char> compressed_data;
  CompressPayloadIfNeeded(packet_info, compressed_data);
  EncryptPayloadIfNeeded(packet_info);
  FillPacketHeader(packet, packet_info, next_sequence_number);

  // and we copy the payload to its appropriate place
  if (payload_size > 0) {
    memcpy(packet.data() + size_of_headers, packet_info.payload.data,
           payload_size);
  }

  return packet;
}

void PacketBuilder::FillPacketHeader(const base::Span<byte> outgoing_data,
                                     const OutgoingPacket& packet_info,
                                     u32 next_sequence_number) {
  byte* readptr = const_cast<byte*>(outgoing_data.data());
  PacketHeader* header = reinterpret_cast<PacketHeader*>(readptr);
  // build core header.
  header->magic = PacketHeader::kMagic;
  header->header_checksum = 0;
  header->total_packet_data_size = outgoing_data.size();
  header->version = 1;
  header->flags = {.is_reliable = packet_info.flags.reliable,
                   .is_encrypted = packet_info.flags.encrypted,
                   .is_compressed = packet_info.flags.compressed,
                   .is_fragmented = 0,
                   .priority = packet_info.flags.priority,
                   .reserved = 0};
  header->type = (u16)packet_info.type;
  header->alignment = 0;
  header->padding_number = 0;
  header->channel_id = (u8)packet_info.channel;
  header->timestamp = static_cast<u32>(base::GetUnixTimeStamp() - kTimeshift);
  readptr += sizeof(PacketHeader);

  if (packet_info.flags.reliable) {
    ReliableHeader* reliable_header =
        reinterpret_cast<ReliableHeader*>(readptr);
    reliable_header->sequence_number = next_sequence_number;

    if (packet_info.type == PacketType::Acknowledgement) {
      reliable_header->acknowledgment_number =
          static_cast<u32>(packet_info.payload.scalar);
    } else {
      reliable_header->acknowledgment_number = 0;
    }
    readptr += sizeof(ReliableHeader);
  }

  if (packet_info.flags.compressed) {
    CompressedPayloadHeader* compressed_header =
        reinterpret_cast<CompressedPayloadHeader*>(readptr);
    compressed_header->compressed_size = 0;
    compressed_header->checksum = 0;
    compressed_header->flags = {.is_little_endian = 1, .reserved = 0};
    compressed_header->padding[0] = 0;
    compressed_header->padding[1] = 0;
    compressed_header->padding[2] = 0;
    readptr += sizeof(CompressedPayloadHeader);
  } else {
    UncompressedPayloadHeader* uncompressed_header =
        reinterpret_cast<UncompressedPayloadHeader*>(readptr);
    uncompressed_header->checksum = 0;
    readptr += sizeof(UncompressedPayloadHeader);
  }
}

bool PacketUnpacker::UnpackPacket(const byte* in_buffer,
                                  size_t in_size,
                                  IncomingPacket& out) {
  const auto* header = reinterpret_cast<const PacketHeader*>(in_buffer);
  if (!ValidatePacketHeader(header, in_size)) {
    BASE_LOGE(kLogTag, "Invalid packet header");
    return false;
  }
  mem_size offset = sizeof(PacketHeader);

  if (header->flags.is_reliable) {
    const auto* reliable_header =
        reinterpret_cast<const ReliableHeader*>(&in_buffer[offset]);
    out.sequence_number = reliable_header->sequence_number;
    out.acknowledgement_number = reliable_header->acknowledgment_number;
    offset += sizeof(ReliableHeader);
  }

  if (header->flags.is_compressed) {
    offset += sizeof(CompressedPayloadHeader);
  } else {
    offset += sizeof(UncompressedPayloadHeader);
  }

  size_t payload_size = in_size - offset;
  out.type = (PacketType)header->type;
  out.channel = (PacketChannelType)header->channel_id;
  out.flags = {.reliable = header->flags.is_reliable,
               .encrypted = header->flags.is_encrypted,
               .compressed = 0,
               .priority = header->flags.priority,
               .acknowledged = 0,
               .awaiting_ack = 0,
               .reserved = 0};

  // Prepare a string buffer for the payload
  std::string payload(reinterpret_cast<const char*>(in_buffer + offset),
                      payload_size);

  DecryptPayloadIfNeeded((byte*)payload.data(), payload_size, header);
  DecompressPayloadIfNeeded((byte*)payload.data(), payload_size, header);

  out.data = std::move(payload);

  return true;
}

}  // namespace tx::network
