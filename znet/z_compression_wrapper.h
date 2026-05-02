// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <limits>

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
  static constexpr mem_size kMaxExpansionRatio = 256;
  static constexpr mem_size kExpansionSlackBytes = 1024;

  static bool Compress(const byte* input_data, mem_size input_size,
                       base::Vector<byte>& compressed) {
    if (input_size == 0) {
      compressed.clear();
      return true;
    }
    if (!input_data || input_size > static_cast<mem_size>(std::numeric_limits<int>::max())) {
      compressed.clear();
      return false;
    }
    int max_compressed_size = LZ4_compressBound(static_cast<int>(input_size));
    if (max_compressed_size <= 0) {
      compressed.clear();
      return false;
    }
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
    if (original_size > kMaxDecompressedSize ||
        data_size > static_cast<mem_size>(std::numeric_limits<int>::max()) ||
        original_size > static_cast<mem_size>(std::numeric_limits<int>::max())) {
      decompressed.clear();
      return false;
    }
    if (data_size == 0 && original_size == 0) {
      decompressed.clear();
      return true;
    }
    if (!data || data_size == 0 || original_size == 0) {
      decompressed.clear();
      return false;
    }
    const mem_size max_reasonable_output =
        (data_size > (std::numeric_limits<mem_size>::max() - kExpansionSlackBytes) /
                         kMaxExpansionRatio)
            ? std::numeric_limits<mem_size>::max()
            : data_size * kMaxExpansionRatio + kExpansionSlackBytes;
    if (original_size > max_reasonable_output) {
      decompressed.clear();
      return false;
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
