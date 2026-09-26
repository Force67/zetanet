// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_task_executor.h"

namespace tx::network {
namespace {
mem_size ResolveWorkerCount(mem_size requested) {
  if (requested > 0) {
    return requested;
  }
  const u32 hardware_threads = base::GetProcessorCount();
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
    workers_.push_back(base::MakeUnique<base::Thread>(
        "znet-worker", [this] { WorkerLoop(); }, /*start_now=*/true));
  }
}

ZThreadPoolTaskExecutor::~ZThreadPoolTaskExecutor() {
  Drain();
  {
    base::LockGuard<base::Mutex> lock(mutex_);
    stopping_ = true;
  }
  task_cv_.NotifyAll();
  space_cv_.NotifyAll();

  for (auto& worker : workers_) {
    worker->Join();
  }
}

void ZThreadPoolTaskExecutor::Submit(Task task) {
  if (!task) {
    return;
  }

  base::UniqueLock<base::Mutex> lock(mutex_);
  if (stopping_) {
    return;
  }

  if (max_queued_tasks_ > 0) {
    space_cv_.Wait(lock, [this] {
      return stopping_ || tasks_.size() < max_queued_tasks_;
    });
    if (stopping_) {
      return;
    }
  }

  tasks_.push(base::move(task));
  task_cv_.NotifyOne();
}

void ZThreadPoolTaskExecutor::Drain() {
  base::UniqueLock<base::Mutex> lock(mutex_);
  idle_cv_.Wait(lock, [this] {
    return tasks_.empty() && active_workers_ == 0;
  });
}

void ZThreadPoolTaskExecutor::WorkerLoop() {
  while (true) {
    Task task;
    {
      base::UniqueLock<base::Mutex> lock(mutex_);
      task_cv_.Wait(lock, [this] {
        return stopping_ || !tasks_.empty();
      });

      if (stopping_ && tasks_.empty()) {
        return;
      }

      task = base::move(tasks_.front());
      tasks_.pop();
      ++active_workers_;
      if (max_queued_tasks_ > 0) {
        space_cv_.NotifyOne();
      }
    }

    task();

    {
      base::LockGuard<base::Mutex> lock(mutex_);
      --active_workers_;
      if (tasks_.empty() && active_workers_ == 0) {
        idle_cv_.NotifyAll();
      }
    }
  }
}

}  // namespace tx::network
