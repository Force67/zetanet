// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once
#include <cstdint>
#include <bit>
#include <limits>
#include <mutex>  // libc++ does not leak lock_guard transitively

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/atomic.h>
#include <base/containers/array.h>
#include <base/containers/vector.h>
#include <base/threading/mutex.h>
#include <new>
#endif

namespace tx::network {
class PacketBufferPool {
 public:
  static constexpr mem_size kMinClassSize = 64;
  static constexpr mem_size kMaxClassSize = 65536;
  static constexpr mem_size kClassCount = 11;
  static constexpr mem_size kRetunePeriod = 4096;
  static constexpr mem_size kCacheBudgetBytes = 16 * 1024 * 1024;
  static constexpr mem_size kMinTargetPerClass = 8;

  struct Stats {
    mem_size total_requests{0};
    mem_size pool_hits{0};
    mem_size fallback_allocations{0};
  };

  struct ClassStats {
    mem_size block_size{0};
    mem_size request_count{0};
    mem_size hit_count{0};
    mem_size target_cached_blocks{0};
    mem_size cached_free_blocks{0};
    double ewma_demand{0.0};
  };

  static PacketBufferPool& Instance() {
    static PacketBufferPool instance;
    return instance;
  }

  unsigned char* Allocate(mem_size requested_size) {
    if (requested_size == 0) {
      return nullptr;
    }
    if (requested_size > std::numeric_limits<std::uint32_t>::max()) {
      return nullptr;
    }

    const mem_size class_index = SizeToClassIndex(requested_size);
    total_requests_.fetch_add(1, std::memory_order_relaxed);

    if (class_index == kInvalidClassIndex) {
      fallback_allocations_.fetch_add(1, std::memory_order_relaxed);
      return AllocateNewBlock(requested_size, kInvalidClassIndex, false);
    }

    ClassBucket& bucket = classes_[class_index];
    bucket.requests.fetch_add(1, std::memory_order_relaxed);
    bucket.total_requests.fetch_add(1, std::memory_order_relaxed);

    {
      std::lock_guard<base::Mutex> lock(bucket.mutex);
      if (!bucket.free_list.empty()) {
        pool_hits_.fetch_add(1, std::memory_order_relaxed);
        bucket.hits.fetch_add(1, std::memory_order_relaxed);
        bucket.total_hits.fetch_add(1, std::memory_order_relaxed);
        BlockHeader* header = bucket.free_list.back();
        bucket.free_list.erase(bucket.free_list.size() - 1);
        header->ref_count.store(1, std::memory_order_relaxed);
        header->requested_size = static_cast<std::uint32_t>(requested_size);
        return BlockData(header);
      }
    }

    return AllocateNewBlock(requested_size, class_index, true);
  }

  void Retain(unsigned char* data) {
    if (!data) {
      return;
    }
    HeaderFromData(data)->ref_count.fetch_add(1, std::memory_order_relaxed);
  }

  void Release(unsigned char* data) {
    if (!data) {
      return;
    }

    BlockHeader* header = HeaderFromData(data);
    const std::uint32_t previous =
        header->ref_count.fetch_sub(1, std::memory_order_acq_rel);
    if (previous != 1) {
      return;
    }

    if (!header->pooled || header->size_class_index == kInvalidClassIndex) {
      ::operator delete(header);
      return;
    }

    ClassBucket& bucket = classes_[header->size_class_index];
    const mem_size target =
        bucket.target_cached_blocks.load(std::memory_order_relaxed);
    bool keep = false;
    {
      std::lock_guard<base::Mutex> lock(bucket.mutex);
      if (bucket.free_list.size() < target) {
        bucket.free_list.push_back(header);
        keep = true;
      }
    }
    if (!keep) {
      ::operator delete(header);
    }

    MaybeRetune();
  }

  mem_size GetCapacity(const unsigned char* data) const {
    if (!data) {
      return 0;
    }
    return HeaderFromDataConst(data)->capacity;
  }

  Stats GetStats() const {
    Stats stats;
    stats.total_requests = total_requests_.load(std::memory_order_relaxed);
    stats.pool_hits = pool_hits_.load(std::memory_order_relaxed);
    stats.fallback_allocations =
        fallback_allocations_.load(std::memory_order_relaxed);
    return stats;
  }

  void GetClassStats(base::Array<ClassStats, kClassCount>& out) const {
    for (mem_size i = 0; i < kClassCount; ++i) {
      const ClassBucket& bucket = classes_[i];
      out[i].block_size = bucket.block_size;
      out[i].request_count = bucket.total_requests.load(std::memory_order_relaxed);
      out[i].hit_count = bucket.total_hits.load(std::memory_order_relaxed);
      out[i].target_cached_blocks =
          bucket.target_cached_blocks.load(std::memory_order_relaxed);
      out[i].ewma_demand = bucket.ewma_demand.load(std::memory_order_relaxed);
      {
        std::lock_guard<base::Mutex> lock(bucket.mutex);
        out[i].cached_free_blocks = bucket.free_list.size();
      }
    }
  }

  void ResetStats() {
    total_requests_.store(0, std::memory_order_relaxed);
    pool_hits_.store(0, std::memory_order_relaxed);
    fallback_allocations_.store(0, std::memory_order_relaxed);
    for (mem_size i = 0; i < kClassCount; ++i) {
      ClassBucket& bucket = classes_[i];
      bucket.requests.store(0, std::memory_order_relaxed);
      bucket.hits.store(0, std::memory_order_relaxed);
      bucket.total_requests.store(0, std::memory_order_relaxed);
      bucket.total_hits.store(0, std::memory_order_relaxed);
      bucket.ewma_demand.store(0.0, std::memory_order_relaxed);
    }
  }

  void BoostClassCacheForSize(mem_size requested_size, mem_size min_target_blocks) {
    if (min_target_blocks == 0) {
      return;
    }
    const mem_size class_index = SizeToClassIndex(requested_size);
    if (class_index == kInvalidClassIndex) {
      return;
    }
    ClassBucket& bucket = classes_[class_index];
    mem_size current_target = bucket.target_cached_blocks.load(std::memory_order_relaxed);
    while (current_target < min_target_blocks &&
           !bucket.target_cached_blocks.compare_exchange_weak(
               current_target, min_target_blocks, std::memory_order_relaxed)) {
    }
  }

 private:
  struct alignas(std::max_align_t) BlockHeader {
    base::Atomic<std::uint32_t> ref_count;
    std::uint32_t requested_size;
    std::uint32_t size_class_index;
    bool pooled;
    unsigned char reserved[3];
    mem_size capacity;
  };

  struct ClassBucket {
    mem_size block_size{0};
    base::Atomic<mem_size> requests{0};
    base::Atomic<mem_size> hits{0};
    base::Atomic<mem_size> total_requests{0};
    base::Atomic<mem_size> total_hits{0};
    base::Atomic<double> ewma_demand{0.0};
    base::Atomic<mem_size> target_cached_blocks{kMinTargetPerClass};
    base::Vector<BlockHeader*> free_list;
    mutable base::Mutex mutex;
  };

  static constexpr std::uint32_t kInvalidClassIndex = 0xFFFFFFFFu;

  PacketBufferPool() {
    mem_size block_size = kMinClassSize;
    for (mem_size i = 0; i < kClassCount; ++i) {
      classes_[i].block_size = block_size;
      classes_[i].target_cached_blocks.store(kMinTargetPerClass,
                                             std::memory_order_relaxed);
      block_size <<= 1;
    }
  }

  ~PacketBufferPool() {
    for (ClassBucket& bucket : classes_) {
      std::lock_guard<base::Mutex> lock(bucket.mutex);
      for (BlockHeader* header : bucket.free_list) {
        ::operator delete(header);
      }
      bucket.free_list.clear();
    }
  }

  PacketBufferPool(const PacketBufferPool&) = delete;
  PacketBufferPool& operator=(const PacketBufferPool&) = delete;

  static mem_size SizeToClassIndex(mem_size requested_size) {
    if (requested_size > kMaxClassSize) {
      return kInvalidClassIndex;
    }
    if (requested_size <= kMinClassSize) {
      return 0;
    }
    // ceil(log2(requested_size)) - log2(kMinClassSize)
    const unsigned min_bits = 6u;
    const unsigned ceil_log2 =
        static_cast<unsigned>(std::bit_width(requested_size - 1));
    const unsigned index = ceil_log2 - min_bits;
    return index < kClassCount ? index : kInvalidClassIndex;
  }

  static BlockHeader* HeaderFromData(unsigned char* data) {
    return reinterpret_cast<BlockHeader*>(data) - 1;
  }

  static const BlockHeader* HeaderFromDataConst(const unsigned char* data) {
    return reinterpret_cast<const BlockHeader*>(data) - 1;
  }

  static unsigned char* BlockData(BlockHeader* header) {
    return reinterpret_cast<unsigned char*>(header + 1);
  }

  unsigned char* AllocateNewBlock(mem_size requested_size,
                                  mem_size class_index,
                                  bool pooled) {
    const mem_size capacity =
        (class_index == kInvalidClassIndex) ? requested_size
                                            : classes_[class_index].block_size;
    if (capacity > std::numeric_limits<mem_size>::max() - sizeof(BlockHeader)) {
      return nullptr;
    }
    BlockHeader* header = reinterpret_cast<BlockHeader*>(
        ::operator new(sizeof(BlockHeader) + capacity));
    header->ref_count.store(1, std::memory_order_relaxed);
    header->requested_size = static_cast<std::uint32_t>(requested_size);
    header->size_class_index = static_cast<std::uint32_t>(class_index);
    header->pooled = pooled;
    header->reserved[0] = 0;
    header->reserved[1] = 0;
    header->reserved[2] = 0;
    header->capacity = capacity;
    return BlockData(header);
  }

  void MaybeRetune() {
    const mem_size requests = total_requests_.load(std::memory_order_relaxed);
    if (requests < kRetunePeriod || (requests % kRetunePeriod) != 0) {
      return;
    }
    if (!retune_mutex_.try_lock()) {
      return;
    }
    RetuneTargets();
    retune_mutex_.unlock();
  }

  void RetuneTargets() {
    double demand_sum = 0.0;
    for (mem_size i = 0; i < kClassCount; ++i) {
      const mem_size requests =
          classes_[i].requests.exchange(0, std::memory_order_relaxed);
      const double old = classes_[i].ewma_demand.load(std::memory_order_relaxed);
      const double updated = old * 0.8 + static_cast<double>(requests) * 0.2;
      classes_[i].ewma_demand.store(updated, std::memory_order_relaxed);
      demand_sum += updated;
    }

    if (demand_sum <= 0.0) {
      return;
    }

    for (mem_size i = 0; i < kClassCount; ++i) {
      const double demand = classes_[i].ewma_demand.load(std::memory_order_relaxed);
      const double weight = demand / demand_sum;
      mem_size target = static_cast<mem_size>(
          (weight * static_cast<double>(kCacheBudgetBytes)) /
          static_cast<double>(classes_[i].block_size));
      if (target < kMinTargetPerClass) {
        target = kMinTargetPerClass;
      }

      classes_[i].target_cached_blocks.store(target, std::memory_order_relaxed);
      TrimClassCache(i, target);
    }
  }

  void TrimClassCache(mem_size class_index, mem_size target) {
    ClassBucket& bucket = classes_[class_index];
    base::Vector<BlockHeader*> overflow;
    {
      std::lock_guard<base::Mutex> lock(bucket.mutex);
      if (bucket.free_list.size() <= target) {
        return;
      }
      overflow.reserve(bucket.free_list.size() - target);
      while (bucket.free_list.size() > target) {
        overflow.push_back(bucket.free_list.back());
        bucket.free_list.erase(bucket.free_list.size() - 1);
      }
    }
    for (BlockHeader* header : overflow) {
      ::operator delete(header);
    }
  }

  base::Array<ClassBucket, kClassCount> classes_{};
  mutable base::Mutex retune_mutex_;
  base::Atomic<mem_size> total_requests_{0};
  base::Atomic<mem_size> pool_hits_{0};
  base::Atomic<mem_size> fallback_allocations_{0};
};

class PacketAllocator {
 public:
  PacketAllocator(mem_size block_size, mem_size pool_size)
      : block_size_(block_size), pool_size_(pool_size) {}

  void* Allocate() {
    (void)pool_size_;
    return PacketBufferPool::Instance().Allocate(block_size_);
  }

  void Deallocate(void* block) {
    if (!block) {
      return;
    }
    PacketBufferPool::Instance().Release(reinterpret_cast<unsigned char*>(block));
  }

 private:
  mem_size block_size_;
  mem_size pool_size_;
};

class PacketDeleter {
 public:
  PacketDeleter() : allocator_(nullptr) {}
  explicit PacketDeleter(PacketAllocator& allocator)
      : allocator_(&allocator) {}

  void operator()(void* p) const {
    if (!p) {
      return;
    }
    if (allocator_) {
      allocator_->Deallocate(p);
      return;
    }
    PacketBufferPool::Instance().Release(reinterpret_cast<unsigned char*>(p));
  }

 private:
  PacketAllocator* allocator_;
};
}  // namespace tx::network
