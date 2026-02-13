// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <lz4.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/vector.h>
#include <base/containers/span.h>
#endif

namespace tx::network {

// wrapper around the preferred compression library
class ZCompressionContext {
 public:
  static constexpr mem_size kMaxDecompressedSize = 64 * 1024 * 1024;  // 64 MB limit

  static bool Compress(const byte* input_data, mem_size input_size,
                       base::Vector<byte>& compressed) {
    if (input_size == 0) {
      compressed.clear();
      return true;
    }
    int max_compressed_size = LZ4_compressBound(static_cast<int>(input_size));
    compressed.resize(static_cast<mem_size>(max_compressed_size));

    int compressed_size =
        LZ4_compress_default(reinterpret_cast<const char*>(input_data),
                             reinterpret_cast<char*>(compressed.data()),
                             static_cast<int>(input_size), max_compressed_size);

    if (compressed_size <= 0) {
      compressed.clear();
      return false;
    }

    compressed.resize(static_cast<mem_size>(compressed_size));
    return true;
  }

  static bool Decompress(const byte* data, mem_size data_size,
                          mem_size original_size,
                          base::Vector<byte>& decompressed) {
    if (original_size > kMaxDecompressedSize) {
      decompressed.clear();
      return false;
    }
    if (data_size == 0 && original_size == 0) {
      decompressed.clear();
      return true;
    }
    decompressed.resize(original_size);

    int decompressed_size = LZ4_decompress_safe(
        reinterpret_cast<const char*>(data),
        reinterpret_cast<char*>(decompressed.data()),
        static_cast<int>(data_size), static_cast<int>(original_size));

    if (decompressed_size < 0 ||
        static_cast<mem_size>(decompressed_size) != original_size) {
      decompressed.clear();
      return false;
    }

    return true;
  }
};

}  // namespace tx::network
