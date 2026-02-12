// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_crypto_wrapper.h>
#include <znet/z_compression_wrapper.h>

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
                        u32 next_sequence_number);

  void EncryptPayloadIfNeeded(OutgoingPacket& packet_info) {
    if (packet_info.flags.encrypted && packet_info.heap_data_size > 0 &&
        crypto_context_) {
      crypto_context_->EncryptPayload(packet_info.payload.data,
                                      packet_info.heap_data_size);
    }
  }

  void CompressPayloadIfNeeded(OutgoingPacket& packet_info,
                               base::Vector<char>& compressed_data) {
    if (packet_info.flags.compressed && packet_info.heap_data_size > 0) {
      compressed_data = ZCompressionContext::Compress(base::Span<char>(
          (char*)packet_info.payload.data, packet_info.heap_data_size));
    }
  }
};

class PacketUnpacker {
 public:
  PacketUnpacker(ZCryptoContext* crypto_context)
      : crypto_context_(crypto_context) {}

  bool UnpackPacket(const byte* in_buffer, size_t in_size, IncomingPacket& out);

 private:
  ZCryptoContext* crypto_context_;

  bool ValidatePacketHeader(const PacketHeader* header, size_t size) const {
    if (header->magic != PacketHeader::kMagic || size < sizeof(PacketHeader)) {
      return false;
    }
    return true;
  }

  void DecryptPayloadIfNeeded(byte* data,
                              size_t size,
                              const PacketHeader* header) {
    if (header->flags.is_encrypted && size > 0 && crypto_context_) {
      crypto_context_->DecryptPayload(data, size);
    }
  }

  void DecompressPayloadIfNeeded(byte* data,
                                 size_t size,
                                 const PacketHeader* header) {
    if (header->flags.is_compressed && size > 0) {
      ZCompressionContext::Decompress(data, size, 1337);
    }
  };
};
}  // namespace tx::network
