// Copyright (C) 2023-2025 Vincent Hengel
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

  // Dequeue item (highest priority first)
  bool dequeue(T& item) {
    if (!critial_priority_queue_.empty()) {
      return critial_priority_queue_.dequeue(item);
    } else if (!high_priority_queue_.empty()) {
      return high_priority_queue_.dequeue(item);
    } else if (!medium_priority_queue_.empty()) {
      return medium_priority_queue_.dequeue(item);
    } else if (!low_priority_queue_.empty()) {
      return low_priority_queue_.dequeue(item);
    }
    return false;  // All queues are empty
  }

  // Check if the queue is empty
  bool empty() const {
    return critial_priority_queue_.empty() && high_priority_queue_.empty() &&
           medium_priority_queue_.empty() && low_priority_queue_.empty();
  }

 private:
  base::MPSCQueue<T> critial_priority_queue_;
  base::MPSCQueue<T> high_priority_queue_;
  base::MPSCQueue<T> medium_priority_queue_;
  base::MPSCQueue<T> low_priority_queue_;
};

}  // namespace tx::network
