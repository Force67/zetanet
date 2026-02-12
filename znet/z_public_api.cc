// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_public_api.h"
#include "z_network_allocator.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif
#include <array>
#include <cstdio>

ZNET_API void *tx::network::ZCreateContext() { return nullptr; }

ZNET_API void tx::network::SetBaseLogHandlerFwd(
    void *user_pointer,
    void (*callback)(void *user_pointer, const char *channel_name, int level,
                     const char *msg)) {
#ifdef ZNET_USE_STL
  base::SetLogHandler(callback, user_pointer);
#else
  base::SetLogHandler(reinterpret_cast<base::LogHandler>(callback),
                      user_pointer);
#endif
}

ZNET_API void tx::network::ZResetPacketAllocatorStats() {
  PacketBufferPool::Instance().ResetStats();
}

ZNET_API bool tx::network::ZGetPacketAllocatorStats(
    ZPacketAllocatorStats *out_stats) {
  if (!out_stats) {
    return false;
  }

  const PacketBufferPool::Stats global = PacketBufferPool::Instance().GetStats();
  std::array<PacketBufferPool::ClassStats, PacketBufferPool::kClassCount>
      class_stats{};
  PacketBufferPool::Instance().GetClassStats(class_stats);

  out_stats->total_requests = global.total_requests;
  out_stats->pool_hits = global.pool_hits;
  out_stats->fallback_allocations = global.fallback_allocations;
  out_stats->class_count = PacketBufferPool::kClassCount;

  for (size_t i = 0; i < out_stats->class_count; ++i) {
    out_stats->classes[i].block_size = class_stats[i].block_size;
    out_stats->classes[i].request_count = class_stats[i].request_count;
    out_stats->classes[i].hit_count = class_stats[i].hit_count;
    out_stats->classes[i].target_cached_blocks =
        class_stats[i].target_cached_blocks;
    out_stats->classes[i].cached_free_blocks = class_stats[i].cached_free_blocks;
    out_stats->classes[i].ewma_demand = class_stats[i].ewma_demand;
  }
  return true;
}

ZNET_API void tx::network::ZDumpPacketAllocatorStats() {
  ZPacketAllocatorStats stats{};
  if (!ZGetPacketAllocatorStats(&stats)) {
    std::fprintf(stderr, "Allocator stats unavailable\n");
    return;
  }
  const double hit_rate =
      stats.total_requests == 0
          ? 0.0
          : (100.0 * static_cast<double>(stats.pool_hits) /
             static_cast<double>(stats.total_requests));
  std::fprintf(stderr,
               "PacketAllocator total=%zu hits=%zu hit_rate=%.2f%% fallback=%zu\n",
               stats.total_requests, stats.pool_hits, hit_rate,
               stats.fallback_allocations);
  for (size_t i = 0; i < stats.class_count; ++i) {
    const ZPacketAllocatorClassStats &c = stats.classes[i];
    if (c.request_count == 0 && c.cached_free_blocks == 0) {
      continue;
    }
    std::fprintf(stderr,
                 "  class[%zu] block=%zu req=%zu hit=%zu target=%zu free=%zu "
                 "ewma=%.2f\n",
                 i, c.block_size, c.request_count, c.hit_count,
                 c.target_cached_blocks, c.cached_free_blocks, c.ewma_demand);
  }
}
