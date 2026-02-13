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
  mem_size block_size;
  mem_size request_count;
  mem_size hit_count;
  mem_size target_cached_blocks;
  mem_size cached_free_blocks;
  double ewma_demand;
};

struct ZPacketAllocatorStats {
  static constexpr mem_size kMaxClasses = 11;
  mem_size total_requests;
  mem_size pool_hits;
  mem_size fallback_allocations;
  mem_size class_count;
  ZPacketAllocatorClassStats classes[kMaxClasses];
};

ZNET_API void ZResetPacketAllocatorStats();
ZNET_API bool ZGetPacketAllocatorStats(ZPacketAllocatorStats *out_stats);
ZNET_API void ZDumpPacketAllocatorStats();
}  // namespace tx::network
