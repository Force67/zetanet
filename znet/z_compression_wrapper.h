// Copyright (C) 2023-2025 Vincent Hengel
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
  static base::Vector<char> Compress(const base::Span<char>& input_data) {
    int input_size = static_cast<int>(input_data.size());
    int max_compressed_size = LZ4_compressBound(input_size);
    base::Vector<char> compressed_data(max_compressed_size);

    mem_size compressed_size =
        LZ4_compress_default(input_data.data(), compressed_data.data(),
                             input_size, max_compressed_size);

    compressed_data.resize(compressed_size);
    return compressed_data;
  }

  static base::Vector<char> Decompress(const byte* data,
                                       mem_size data_size,
                                       mem_size original_size) {
    base::Vector<char> decompressed_data(original_size);

    int decompressed_size = LZ4_decompress_safe(
        (const char*)data, decompressed_data.data(),
        static_cast<int>(data_size), static_cast<int>(original_size));

    if (decompressed_size < 0) {
      // decompression error
    }

    return decompressed_data;
  }
};

}  // namespace tx::network
