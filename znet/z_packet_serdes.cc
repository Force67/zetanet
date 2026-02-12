// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_serdes.h"

#include <limits>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {

static constexpr char kLogTag[] = "z-packet-serdes";
static constexpr u32 kTimeshift =
    1701290985;
static constexpr u32 kFnv1aOffset = 2166136261u;
static constexpr u32 kFnv1aPrime = 16777619u;

namespace {
u32 ComputeChecksum32(const byte* data, mem_size size) {
  u32 hash = kFnv1aOffset;
  for (mem_size i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= kFnv1aPrime;
  }
  return hash;
}

u16 ComputePacketHeaderChecksum(const PacketHeader& header) {
  PacketHeader header_copy = header;
  header_copy.header_checksum = 0;
  return static_cast<u16>(
      ComputeChecksum32(reinterpret_cast<const byte*>(&header_copy),
                        sizeof(PacketHeader)) &
      0xFFFFu);
}
}  // namespace

base::Vector<byte> PacketBuilder::BuildPacket(OutgoingPacket& packet_info,
                                              const u32 next_sequence_number) {
  if (packet_info.flags.compressed) {
    BASE_LOGE(kLogTag, "Compressed payloads are currently unsupported");
    return {};
  }

  base::Vector<byte> payload;
  if (packet_info.heap_data_size > 0) {
    if (!packet_info.payload.data) {
      BASE_LOGE(kLogTag, "Payload pointer is null while size is non-zero");
      return {};
    }
    payload.resize(packet_info.heap_data_size);
    std::memcpy(payload.data(), packet_info.payload.data, payload.size());
  }

  if (!EncryptPayloadIfNeeded(packet_info, next_sequence_number, payload)) {
    BASE_LOGE(kLogTag, "Failed to encrypt outgoing payload");
    return {};
  }

  if (payload.size() > std::numeric_limits<u32>::max()) {
    BASE_LOGE(kLogTag, "Payload exceeds protocol size limit");
    return {};
  }
  const u32 payload_size = static_cast<u32>(payload.size());
  u32 size_of_headers =
      sizeof(PacketHeader) +
      (packet_info.flags.reliable * sizeof(ReliableHeader)) +
      (packet_info.flags.compressed * sizeof(CompressedPayloadHeader)) +
      ((!packet_info.flags.compressed) * sizeof(UncompressedPayloadHeader));
  if (size_of_headers > std::numeric_limits<u32>::max() - payload_size) {
    BASE_LOGE(kLogTag, "Packet size overflow");
    return {};
  }

  base::Vector<byte> packet(size_of_headers + payload_size);
  FillPacketHeader(packet, packet_info, payload_size, next_sequence_number);

  // and we copy the payload to its appropriate place
  if (payload_size > 0) {
    std::memcpy(packet.data() + size_of_headers, payload.data(), payload_size);
  }

  if (packet.size() < sizeof(PacketHeader)) {
    BASE_LOGE(kLogTag, "Packet is smaller than header size");
    return {};
  }

  PacketHeader header{};
  std::memcpy(&header, packet.data(), sizeof(PacketHeader));

  mem_size offset = sizeof(PacketHeader);
  if (header.flags.is_reliable) {
    offset += sizeof(ReliableHeader);
  }
  if (header.flags.is_compressed) {
    BASE_LOGE(kLogTag, "Compressed payloads are currently unsupported");
    return {};
  }

  if (offset + sizeof(UncompressedPayloadHeader) > packet.size()) {
    BASE_LOGE(kLogTag, "Invalid packet header layout");
    return {};
  }

  UncompressedPayloadHeader uncompressed_header{};
  std::memcpy(&uncompressed_header, packet.data() + offset,
              sizeof(UncompressedPayloadHeader));
  offset += sizeof(UncompressedPayloadHeader);

  const mem_size wire_payload_size = packet.size() - offset;
  uncompressed_header.checksum =
      ComputeChecksum32(packet.data() + offset, wire_payload_size);
  std::memcpy(packet.data() + sizeof(PacketHeader) +
                  (header.flags.is_reliable ? sizeof(ReliableHeader) : 0),
              &uncompressed_header, sizeof(UncompressedPayloadHeader));

  header.header_checksum = ComputePacketHeaderChecksum(header);
  std::memcpy(packet.data(), &header, sizeof(PacketHeader));

  if (header.total_packet_data_size != packet.size()) {
    BASE_LOGE(kLogTag, "Packet size mismatch while finalizing");
    return {};
  }

  return packet;
}

void PacketBuilder::FillPacketHeader(const base::Span<byte> outgoing_data,
                                     const OutgoingPacket& packet_info,
                                     u32 payload_size,
                                     u32 next_sequence_number) {
  byte* readptr = const_cast<byte*>(outgoing_data.data());
  PacketHeader header{};
  // build core header.
  header.magic = PacketHeader::kMagic;
  header.header_checksum = 0;
  header.total_packet_data_size = static_cast<u32>(outgoing_data.size());
  header.version = 1;
  header.flags = {.is_reliable = packet_info.flags.reliable,
                  .is_encrypted = packet_info.flags.encrypted,
                  .is_compressed = packet_info.flags.compressed,
                  .is_fragmented = 0,
                  .priority = packet_info.flags.priority,
                  .reserved = 0};
  header.type = static_cast<u16>(packet_info.type);
  header.alignment = 0;
  header.padding_number = 0;
  header.channel_id = static_cast<u8>(packet_info.channel);
  header.timestamp = static_cast<u32>(base::GetUnixTimeStamp() - kTimeshift);
  std::memcpy(readptr, &header, sizeof(PacketHeader));
  readptr += sizeof(PacketHeader);

  if (packet_info.flags.reliable) {
    ReliableHeader reliable_header{};
    reliable_header.sequence_number = next_sequence_number;

    if (packet_info.type == PacketType::Acknowledgement) {
      reliable_header.acknowledgment_number =
          static_cast<u32>(packet_info.payload.scalar);
    } else {
      reliable_header.acknowledgment_number = 0;
    }
    std::memcpy(readptr, &reliable_header, sizeof(ReliableHeader));
    readptr += sizeof(ReliableHeader);
  }

  if (packet_info.flags.compressed) {
    CompressedPayloadHeader compressed_header{};
    compressed_header.compressed_size = payload_size;
    compressed_header.checksum = 0;
    compressed_header.flags = {.is_little_endian = 1, .reserved = 0};
    compressed_header.padding[0] = 0;
    compressed_header.padding[1] = 0;
    compressed_header.padding[2] = 0;
    std::memcpy(readptr, &compressed_header, sizeof(CompressedPayloadHeader));
    readptr += sizeof(CompressedPayloadHeader);
  } else {
    UncompressedPayloadHeader uncompressed_header{};
    uncompressed_header.checksum = 0;
    std::memcpy(readptr, &uncompressed_header, sizeof(UncompressedPayloadHeader));
    readptr += sizeof(UncompressedPayloadHeader);
  }
}

bool PacketUnpacker::UnpackPacket(const byte* in_buffer,
                                  size_t in_size,
                                  IncomingPacket& out) {
  if (!in_buffer || in_size < sizeof(PacketHeader)) {
    BASE_LOGE(kLogTag, "Invalid packet buffer");
    return false;
  }

  PacketHeader header{};
  std::memcpy(&header, in_buffer, sizeof(PacketHeader));
  if (!ValidatePacketHeader(header, in_size)) {
    BASE_LOGE(kLogTag, "Invalid packet header");
    return false;
  }
  if (header.header_checksum != ComputePacketHeaderChecksum(header)) {
    BASE_LOGE(kLogTag, "Header checksum mismatch");
    return false;
  }

  const PacketType packet_type = static_cast<PacketType>(header.type);
  const PacketChannelType channel =
      static_cast<PacketChannelType>(header.channel_id);
  if (IsSystemMessage(packet_type) && channel != PacketChannelType::Control) {
    BASE_LOGE(kLogTag, "System packet on non-control channel");
    return false;
  }
  if (!IsSystemMessage(packet_type) && channel != PacketChannelType::Data) {
    BASE_LOGE(kLogTag, "Data packet on non-data channel");
    return false;
  }

  mem_size offset = sizeof(PacketHeader);

  if (header.flags.is_reliable) {
    if (offset + sizeof(ReliableHeader) > in_size) {
      BASE_LOGE(kLogTag, "Truncated reliable header");
      return false;
    }
    ReliableHeader reliable_header{};
    std::memcpy(&reliable_header, in_buffer + offset, sizeof(ReliableHeader));
    out.sequence_number = reliable_header.sequence_number;
    out.acknowledgement_number = reliable_header.acknowledgment_number;
    offset += sizeof(ReliableHeader);
  } else {
    out.sequence_number = 0;
    out.acknowledgement_number = 0;
  }

  u32 expected_payload_checksum = 0;
  if (header.flags.is_compressed) {
    if (offset + sizeof(CompressedPayloadHeader) > in_size) {
      BASE_LOGE(kLogTag, "Truncated compressed payload header");
      return false;
    }
    CompressedPayloadHeader compressed_header{};
    std::memcpy(&compressed_header, in_buffer + offset,
                sizeof(CompressedPayloadHeader));
    expected_payload_checksum = compressed_header.checksum;
    offset += sizeof(CompressedPayloadHeader);
  } else {
    if (offset + sizeof(UncompressedPayloadHeader) > in_size) {
      BASE_LOGE(kLogTag, "Truncated uncompressed payload header");
      return false;
    }
    UncompressedPayloadHeader uncompressed_header{};
    std::memcpy(&uncompressed_header, in_buffer + offset,
                sizeof(UncompressedPayloadHeader));
    expected_payload_checksum = uncompressed_header.checksum;
    offset += sizeof(UncompressedPayloadHeader);
  }
  if (offset > in_size) {
    BASE_LOGE(kLogTag, "Invalid payload offset");
    return false;
  }

  size_t payload_size = in_size - offset;
  const u32 payload_checksum = ComputeChecksum32(in_buffer + offset, payload_size);
  if (payload_checksum != expected_payload_checksum) {
    BASE_LOGE(kLogTag, "Payload checksum mismatch");
    return false;
  }

  out.type = packet_type;
  out.channel = channel;
  out.flags = {.reliable = header.flags.is_reliable,
               .encrypted = header.flags.is_encrypted,
               .compressed = header.flags.is_compressed,
               .priority = header.flags.priority,
               .acknowledged = 0,
               .awaiting_ack = 0,
               .reserved = 0};

  base::Vector<byte> payload_data(payload_size);
  if (payload_size > 0) {
    std::memcpy(payload_data.data(), in_buffer + offset, payload_size);
  }
  if (!DecryptPayloadIfNeeded(payload_data, out.sequence_number,
                              out.acknowledgement_number, header)) {
    BASE_LOGE(kLogTag, "Encrypted payload authentication/decryption failed");
    return false;
  }

  if (payload_data.empty()) {
    out.data.clear();
  } else {
    out.data.assign(reinterpret_cast<const char*>(payload_data.data()),
                    payload_data.size());
  }

  return true;
}

}  // namespace tx::network
