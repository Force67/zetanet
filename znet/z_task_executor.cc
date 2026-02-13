// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_task_executor.h"

#include <algorithm>
#include <thread>

namespace tx::network {
namespace {
mem_size ResolveWorkerCount(mem_size requested) {
  if (requested > 0) {
    return requested;
  }
  const unsigned int hardware_threads = std::thread::hardware_concurrency();
  if (hardware_threads <= 1u) {
    return 1;
  }
  return static_cast<mem_size>(hardware_threads - 1u);
}
}  // namespace

ZThreadPoolTaskExecutor::ZThreadPoolTaskExecutor()
    : ZThreadPoolTaskExecutor(Options{}) {}

ZThreadPoolTaskExecutor::ZThreadPoolTaskExecutor(const Options& options)
    : worker_count_(ResolveWorkerCount(options.worker_count)),
      max_queued_tasks_(options.max_queued_tasks) {
  workers_.reserve(worker_count_);
  for (mem_size i = 0; i < worker_count_; ++i) {
    workers_.emplace_back(&ZThreadPoolTaskExecutor::WorkerLoop, this);
  }
}

ZThreadPoolTaskExecutor::~ZThreadPoolTaskExecutor() {
  Drain();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
  }
  task_cv_.notify_all();
  space_cv_.notify_all();

  for (auto& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
}

void ZThreadPoolTaskExecutor::Submit(Task task) {
  if (!task) {
    return;
  }

  std::unique_lock<std::mutex> lock(mutex_);
  if (stopping_) {
    return;
  }

  if (max_queued_tasks_ > 0) {
    space_cv_.wait(lock, [this] {
      return stopping_ || tasks_.size() < max_queued_tasks_;
    });
    if (stopping_) {
      return;
    }
  }

  tasks_.push(std::move(task));
  task_cv_.notify_one();
}

void ZThreadPoolTaskExecutor::Drain() {
  std::unique_lock<std::mutex> lock(mutex_);
  idle_cv_.wait(lock, [this] {
    return tasks_.empty() && active_workers_ == 0;
  });
}

void ZThreadPoolTaskExecutor::WorkerLoop() {
  while (true) {
    Task task;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      task_cv_.wait(lock, [this] {
        return stopping_ || !tasks_.empty();
      });

      if (stopping_ && tasks_.empty()) {
        return;
      }

      task = std::move(tasks_.front());
      tasks_.pop();
      ++active_workers_;
      if (max_queued_tasks_ > 0) {
        space_cv_.notify_one();
      }
    }

    try {
      task();
    } catch (...) {
      // Swallow task exceptions to keep worker threads alive.
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      --active_workers_;
      if (tasks_.empty() && active_workers_ == 0) {
        idle_cv_.notify_all();
      }
    }
  }
}

}  // namespace tx::network
