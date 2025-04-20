#pragma once
#include <vector>
#include <mutex>
#include <memory>

namespace tx::network {
class PacketAllocator {
 public:
  PacketAllocator(size_t blockSize, size_t poolSize)
      : blockSize_(blockSize), poolSize_(poolSize) {
    InitializePool();
  }

  void* Allocate() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) {
      return ::operator new(blockSize_);
    }
    void* block = pool_.back();
    pool_.pop_back();
    return block;
  }

  void Deallocate(void* block) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.size() < poolSize_) {
      pool_.push_back(block);
    } else {
      ::operator delete(block);
    }
  }

 private:
  void InitializePool() {
    for (size_t i = 0; i < poolSize_; ++i) {
      pool_.push_back(::operator new(blockSize_));
    }
  }

  size_t blockSize_;
  size_t poolSize_;
  std::vector<void*> pool_;
  std::mutex mutex_;
};

class PacketDeleter {
 public:
  PacketDeleter(PacketAllocator& allocator) : allocator_(allocator) {}

  void operator()(void* p) { allocator_.Deallocate(p); }

 private:
  PacketAllocator& allocator_;
};
}