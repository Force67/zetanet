// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_packet_serdes.h"

#include <limits>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

#include <znet/z_compression_wrapper.h>

namespace tx::network {

static constexpr char kLogTag[] = "z-packet-serdes";
static constexpr u32 kTimeshift =
    1701290985;
static constexpr u32 kFnv1aOffset = 2166136261u;
static constexpr u32 kFnv1aPrime = 16777619u;

namespace {
constexpr mem_size kPacketHeaderWireSize = sizeof(PacketHeader);
constexpr mem_size kReliableHeaderWireSize = sizeof(ReliableHeader);
constexpr mem_size kUncompressedHeaderWireSize = sizeof(UncompressedPayloadHeader);
constexpr mem_size kCompressedHeaderWireSize = sizeof(CompressedPayloadHeader);

constexpr mem_size kHeaderMagicOffset = 0;
constexpr mem_size kHeaderChecksumOffset = 2;
constexpr mem_size kHeaderTotalSizeOffset = 4;
constexpr mem_size kHeaderVersionOffset = 8;
constexpr mem_size kHeaderFlagsOffset = 9;
constexpr mem_size kHeaderTypeOffset = 10;
constexpr mem_size kHeaderAlignmentOffset = 12;
constexpr mem_size kHeaderPaddingOffset = 14;
constexpr mem_size kHeaderChannelOffset = 15;
constexpr mem_size kHeaderTimestampOffset = 16;

constexpr mem_size kReliableSequenceOffset = 0;
constexpr mem_size kReliableAcknowledgementOffset = 4;

constexpr mem_size kCompressedSizeOffset = 0;
constexpr mem_size kCompressedOriginalSizeOffset = 4;
constexpr mem_size kCompressedChecksumOffset = 8;
constexpr mem_size kCompressedFlagsOffset = 12;

constexpr mem_size kUncompressedChecksumOffset = 0;

u8 PackHeaderFlags(const u8 reliable,
                   const u8 encrypted,
                   const u8 compressed,
                   const u8 priority) {
  return static_cast<u8>((reliable ? 1u : 0u) |
                         ((encrypted ? 1u : 0u) << 1u) |
                         ((compressed ? 1u : 0u) << 2u) |
                         ((priority & 0x3u) << 4u));
}

void UnpackHeaderFlags(const u8 flags_byte, PacketHeader& out) {
  out.flags = {.is_reliable = static_cast<u8>(flags_byte & 0x1u),
               .is_encrypted = static_cast<u8>((flags_byte >> 1u) & 0x1u),
               .is_compressed = static_cast<u8>((flags_byte >> 2u) & 0x1u),
               .is_fragmented = static_cast<u8>((flags_byte >> 3u) & 0x1u),
               .priority = static_cast<u8>((flags_byte >> 4u) & 0x3u),
               .reserved = static_cast<u8>((flags_byte >> 6u) & 0x3u)};
}

u32 ComputeChecksum32(const byte* data, mem_size size) {
  u32 hash = kFnv1aOffset;
  for (mem_size i = 0; i < size; ++i) {
    hash ^= data[i];
    hash *= kFnv1aPrime;
  }
  return hash;
}

u16 ComputePacketHeaderChecksum(const byte* header_wire) {
  byte header_copy[kPacketHeaderWireSize];
  std::memcpy(header_copy, header_wire, kPacketHeaderWireSize);
  wire_le::StoreU16(header_copy + kHeaderChecksumOffset, 0);
  return static_cast<u16>(
      ComputeChecksum32(header_copy, kPacketHeaderWireSize) & 0xFFFFu);
}
}  // namespace

base::Vector<byte> PacketBuilder::BuildPacket(OutgoingPacket& packet_info,
                                              const u32 next_sequence_number) {
  const byte* payload_source = nullptr;
  u32 payload_size = 0;
  u32 original_payload_size = 0;
  if (packet_info.heap_data_size > 0) {
    if (!packet_info.payload.data) {
      BASE_LOGE(kLogTag, "Payload pointer is null while size is non-zero");
      return {};
    }
    payload_source = packet_info.payload.data;
    payload_size = packet_info.heap_data_size;
  }
  original_payload_size = payload_size;

  // Compression (before encryption)
  base::Vector<byte> compressed_payload;
  if (packet_info.flags.compressed && payload_size > 0) {
    if (!ZCompressionContext::Compress(payload_source, payload_size,
                                       compressed_payload)) {
      BASE_LOGE(kLogTag, "Compression failed, sending uncompressed");
      packet_info.flags.compressed = 0;
    } else if (compressed_payload.size() >= payload_size) {
      // Compression didn't help, send uncompressed
      packet_info.flags.compressed = 0;
    } else {
      payload_source = compressed_payload.data();
      payload_size = static_cast<u32>(compressed_payload.size());
    }
  }

  // Encryption
  base::Vector<byte> encrypted_payload;
  if (packet_info.flags.encrypted) {
    encrypted_payload.resize(payload_size);
    if (payload_size > 0) {
      std::memcpy(encrypted_payload.data(), payload_source, payload_size);
    }
    if (!EncryptPayloadIfNeeded(packet_info, next_sequence_number,
                                encrypted_payload)) {
      BASE_LOGE(kLogTag, "Failed to encrypt outgoing payload");
      return {};
    }
    if (encrypted_payload.size() > std::numeric_limits<u32>::max()) {
      BASE_LOGE(kLogTag, "Payload exceeds protocol size limit");
      return {};
    }
    payload_size = static_cast<u32>(encrypted_payload.size());
    payload_source = payload_size > 0 ? encrypted_payload.data() : nullptr;
  }

  u32 size_of_headers =
      static_cast<u32>(kPacketHeaderWireSize) +
      (packet_info.flags.reliable ? static_cast<u32>(kReliableHeaderWireSize) : 0u) +
      (packet_info.flags.compressed ? static_cast<u32>(kCompressedHeaderWireSize)
                                    : static_cast<u32>(kUncompressedHeaderWireSize));
  if (size_of_headers > std::numeric_limits<u32>::max() - payload_size) {
    BASE_LOGE(kLogTag, "Packet size overflow");
    return {};
  }

  base::Vector<byte> packet(size_of_headers + payload_size);
  FillPacketHeader(packet, packet_info, payload_size, original_payload_size,
                   next_sequence_number);

  // and we copy the payload to its appropriate place
  if (payload_size > 0) {
    std::memcpy(packet.data() + size_of_headers, payload_source, payload_size);
  }

  if (packet.size() < kPacketHeaderWireSize) {
    BASE_LOGE(kLogTag, "Packet is smaller than header size");
    return {};
  }

  mem_size offset = kPacketHeaderWireSize;
  if (packet_info.flags.reliable) {
    offset += kReliableHeaderWireSize;
  }

  if (packet_info.flags.compressed) {
    if (offset + kCompressedHeaderWireSize > packet.size()) {
      BASE_LOGE(kLogTag, "Invalid packet header layout");
      return {};
    }
    const mem_size payload_offset = offset + kCompressedHeaderWireSize;
    const mem_size wire_payload_size = packet.size() - payload_offset;
    const u32 payload_checksum =
        ComputeChecksum32(packet.data() + payload_offset, wire_payload_size);
    wire_le::StoreU32(packet.data() + offset + kCompressedChecksumOffset,
                      payload_checksum);
  } else {
    if (offset + kUncompressedHeaderWireSize > packet.size()) {
      BASE_LOGE(kLogTag, "Invalid packet header layout");
      return {};
    }
    const mem_size payload_offset = offset + kUncompressedHeaderWireSize;
    const mem_size wire_payload_size = packet.size() - payload_offset;
    const u32 payload_checksum =
        ComputeChecksum32(packet.data() + payload_offset, wire_payload_size);
    wire_le::StoreU32(packet.data() + offset + kUncompressedChecksumOffset,
                      payload_checksum);
  }

  const u16 header_checksum = ComputePacketHeaderChecksum(packet.data());
  wire_le::StoreU16(packet.data() + kHeaderChecksumOffset, header_checksum);

  if (wire_le::LoadU32(packet.data() + kHeaderTotalSizeOffset) != packet.size()) {
    BASE_LOGE(kLogTag, "Packet size mismatch while finalizing");
    return {};
  }

  return packet;
}

void PacketBuilder::FillPacketHeader(const base::Span<byte> outgoing_data,
                                     const OutgoingPacket& packet_info,
                                     u32 payload_size,
                                     u32 original_payload_size,
                                     u32 next_sequence_number) {
  byte* write_ptr = const_cast<byte*>(outgoing_data.data());
  wire_le::StoreU16(write_ptr + kHeaderMagicOffset, PacketHeader::kMagic);
  wire_le::StoreU16(write_ptr + kHeaderChecksumOffset, 0);
  wire_le::StoreU32(write_ptr + kHeaderTotalSizeOffset,
                    static_cast<u32>(outgoing_data.size()));
  write_ptr[kHeaderVersionOffset] = kProtocolVersion;
  write_ptr[kHeaderFlagsOffset] = PackHeaderFlags(
      packet_info.flags.reliable, packet_info.flags.encrypted,
      packet_info.flags.compressed, packet_info.flags.priority);
  wire_le::StoreU16(write_ptr + kHeaderTypeOffset,
                    static_cast<u16>(packet_info.type));
  wire_le::StoreU16(write_ptr + kHeaderAlignmentOffset, 0);
  write_ptr[kHeaderPaddingOffset] = 0;
  write_ptr[kHeaderChannelOffset] = static_cast<u8>(packet_info.channel);
  wire_le::StoreU32(
      write_ptr + kHeaderTimestampOffset,
      static_cast<u32>(base::GetUnixTimeStamp() - kTimeshift));
  write_ptr += kPacketHeaderWireSize;

  if (packet_info.flags.reliable) {
    wire_le::StoreU32(write_ptr + kReliableSequenceOffset, next_sequence_number);
    const u32 acknowledgement =
        (packet_info.type == PacketType::Acknowledgement)
            ? static_cast<u32>(packet_info.payload.scalar)
            : 0;
    wire_le::StoreU32(write_ptr + kReliableAcknowledgementOffset,
                      acknowledgement);
    write_ptr += kReliableHeaderWireSize;
  }

  if (packet_info.flags.compressed) {
    wire_le::StoreU32(write_ptr + kCompressedSizeOffset, payload_size);
    wire_le::StoreU32(write_ptr + kCompressedOriginalSizeOffset,
                      original_payload_size);
    wire_le::StoreU32(write_ptr + kCompressedChecksumOffset, 0);
    write_ptr[kCompressedFlagsOffset] = 1;  // payload metadata is LE.
    write_ptr[kCompressedFlagsOffset + 1] = 0;
    write_ptr[kCompressedFlagsOffset + 2] = 0;
    write_ptr[kCompressedFlagsOffset + 3] = 0;
  } else {
    wire_le::StoreU32(write_ptr + kUncompressedChecksumOffset, 0);
  }
}

bool PacketUnpacker::UnpackPacket(const byte* in_buffer,
                                  mem_size in_size,
                                  IncomingPacket& out) {
  if (!in_buffer || in_size < kPacketHeaderWireSize) {
    BASE_LOGE(kLogTag, "Invalid packet buffer");
    return false;
  }

  PacketHeader header{};
  header.magic = wire_le::LoadU16(in_buffer + kHeaderMagicOffset);
  header.header_checksum = wire_le::LoadU16(in_buffer + kHeaderChecksumOffset);
  header.total_packet_data_size =
      wire_le::LoadU32(in_buffer + kHeaderTotalSizeOffset);
  header.version = in_buffer[kHeaderVersionOffset];
  UnpackHeaderFlags(in_buffer[kHeaderFlagsOffset], header);
  header.type = wire_le::LoadU16(in_buffer + kHeaderTypeOffset);
  header.alignment = wire_le::LoadU16(in_buffer + kHeaderAlignmentOffset);
  header.padding_number = in_buffer[kHeaderPaddingOffset];
  header.channel_id = in_buffer[kHeaderChannelOffset];
  header.timestamp = wire_le::LoadU32(in_buffer + kHeaderTimestampOffset);
  if (!ValidatePacketHeader(header, in_size)) {
    BASE_LOGE(kLogTag, "Invalid packet header");
    return false;
  }
  if (header.header_checksum != ComputePacketHeaderChecksum(in_buffer)) {
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

  mem_size offset = kPacketHeaderWireSize;

  if (header.flags.is_reliable) {
    if (offset + kReliableHeaderWireSize > in_size) {
      BASE_LOGE(kLogTag, "Truncated reliable header");
      return false;
    }
    out.sequence_number =
        wire_le::LoadU32(in_buffer + offset + kReliableSequenceOffset);
    out.acknowledgement_number =
        wire_le::LoadU32(in_buffer + offset + kReliableAcknowledgementOffset);
    offset += kReliableHeaderWireSize;
  } else {
    out.sequence_number = 0;
    out.acknowledgement_number = 0;
  }

  u32 expected_payload_checksum = 0;
  u32 original_size = 0;
  u32 compressed_size = 0;
  if (header.flags.is_compressed) {
    if (offset + kCompressedHeaderWireSize > in_size) {
      BASE_LOGE(kLogTag, "Truncated compressed payload header");
      return false;
    }
    const u8 compression_flags = in_buffer[offset + kCompressedFlagsOffset];
    if ((compression_flags & ~0x1u) != 0) {
      BASE_LOGE(kLogTag, "Invalid compressed payload flags");
      return false;
    }
    compressed_size = wire_le::LoadU32(in_buffer + offset + kCompressedSizeOffset);
    original_size =
        wire_le::LoadU32(in_buffer + offset + kCompressedOriginalSizeOffset);
    expected_payload_checksum =
        wire_le::LoadU32(in_buffer + offset + kCompressedChecksumOffset);
    offset += kCompressedHeaderWireSize;
  } else {
    if (offset + kUncompressedHeaderWireSize > in_size) {
      BASE_LOGE(kLogTag, "Truncated uncompressed payload header");
      return false;
    }
    expected_payload_checksum =
        wire_le::LoadU32(in_buffer + offset + kUncompressedChecksumOffset);
    offset += kUncompressedHeaderWireSize;
  }
  if (offset > in_size) {
    BASE_LOGE(kLogTag, "Invalid payload offset");
    return false;
  }

  mem_size payload_size = in_size - offset;
  if (header.flags.is_compressed && compressed_size != payload_size) {
    BASE_LOGE(kLogTag, "Compressed payload size mismatch");
    return false;
  }
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

  // Read raw payload into a vector for processing
  base::Vector<byte> payload_data(payload_size);
  if (payload_size > 0) {
    std::memcpy(payload_data.data(), in_buffer + offset, payload_size);
  }

  // Decrypt if needed
  if (header.flags.is_encrypted) {
    if (!DecryptPayloadIfNeeded(payload_data, out.sequence_number,
                                out.acknowledgement_number, header)) {
      BASE_LOGE(kLogTag, "Encrypted payload authentication/decryption failed");
      return false;
    }
  }

  // Decompress if needed
  if (header.flags.is_compressed) {
    base::Vector<byte> decompressed;
    if (!ZCompressionContext::Decompress(payload_data.data(), payload_data.size(),
                                         original_size, decompressed)) {
      BASE_LOGE(kLogTag, "Decompression failed");
      return false;
    }
    payload_data = std::move(decompressed);
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
