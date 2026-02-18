// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_packets.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/mpsc_queue.h>
#endif

namespace tx::network {

template <typename T>
class PriorityMPSCQueue {
 public:
  // Enqueue item with priority
  void enqueue(T&& item, PacketPriority priority) {
    switch (priority) {
      case PacketPriority::Critical:
        critial_priority_queue_.enqueue(std::move(item));
        break;
      case PacketPriority::High:
        high_priority_queue_.enqueue(std::move(item));
        break;
      case PacketPriority::Medium:
        medium_priority_queue_.enqueue(std::move(item));
        break;
      case PacketPriority::Low:
        low_priority_queue_.enqueue(std::move(item));
        break;
    }
  }

  // Dequeue item (highest priority first).
  // Uses lock-free size_approx() to skip empty queues without acquiring a mutex.
  bool dequeue(T& item) {
    if (critial_priority_queue_.size_approx() > 0 &&
        critial_priority_queue_.dequeue(item))
      return true;
    if (high_priority_queue_.size_approx() > 0 &&
        high_priority_queue_.dequeue(item))
      return true;
    if (medium_priority_queue_.size_approx() > 0 &&
        medium_priority_queue_.dequeue(item))
      return true;
    if (low_priority_queue_.size_approx() > 0 &&
        low_priority_queue_.dequeue(item))
      return true;
    return false;
  }

  // Check if the queue is empty (lock-free).
  bool empty() const {
    return size_approx() == 0;
  }

  mem_size size_approx() const {
    return critial_priority_queue_.size_approx() + high_priority_queue_.size_approx() +
           medium_priority_queue_.size_approx() + low_priority_queue_.size_approx();
  }

 private:
  base::MPSCQueue<T> critial_priority_queue_;
  base::MPSCQueue<T> high_priority_queue_;
  base::MPSCQueue<T> medium_priority_queue_;
  base::MPSCQueue<T> low_priority_queue_;
};

}  // namespace tx::network
