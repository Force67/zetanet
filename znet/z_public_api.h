// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>
#include <cstddef>

namespace tx::network {

ZNET_API void *ZCreateContext();

ZNET_API void SetBaseLogHandlerFwd(void *user_pointer,
                                   void (*callback)(void *user_pointer,
                                                    const char *channel_name,
                                                    int level,
                                                    const char *msg));

struct ZPacketAllocatorClassStats {
  size_t block_size;
  size_t request_count;
  size_t hit_count;
  size_t target_cached_blocks;
  size_t cached_free_blocks;
  double ewma_demand;
};

struct ZPacketAllocatorStats {
  static constexpr size_t kMaxClasses = 11;
  size_t total_requests;
  size_t pool_hits;
  size_t fallback_allocations;
  size_t class_count;
  ZPacketAllocatorClassStats classes[kMaxClasses];
};

ZNET_API void ZResetPacketAllocatorStats();
ZNET_API bool ZGetPacketAllocatorStats(ZPacketAllocatorStats *out_stats);
ZNET_API void ZDumpPacketAllocatorStats();
}  // namespace tx::network
