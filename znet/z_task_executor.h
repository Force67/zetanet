// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#endif

#include <znet/z_abi.h>

namespace tx::network {

// Pluggable task executor for internal hot paths; supply your own to hook
// into an existing job system, otherwise the built-in pool is used.
class ZNET_API ITaskExecutor {
 public:
  using Task = std::function<void()>;

  virtual ~ITaskExecutor() = default;

  virtual void Submit(Task task) = 0;

  virtual void Drain() = 0;
};

class ZNET_API ZInlineTaskExecutor final : public ITaskExecutor {
 public:
  void Submit(Task task) override {
    if (task) {
      task();
    }
  }

  void Drain() override {}
};

class ZNET_API ZThreadPoolTaskExecutor final : public ITaskExecutor {
 public:
  struct Options {
    mem_size worker_count{0};      // 0 = hardware default
    mem_size max_queued_tasks{0};  // 0 = unbounded
  };

  ZThreadPoolTaskExecutor();
  explicit ZThreadPoolTaskExecutor(const Options& options);
  ~ZThreadPoolTaskExecutor() override;

  void Submit(Task task) override;
  void Drain() override;

  mem_size worker_count() const { return worker_count_; }

 private:
  void WorkerLoop();

 private:
  mem_size worker_count_{0};
  mem_size max_queued_tasks_{0};

  std::vector<std::thread> workers_;
  std::queue<Task> tasks_;
  mem_size active_workers_{0};
  bool stopping_{false};

  std::mutex mutex_;
  std::condition_variable task_cv_;
  std::condition_variable space_cv_;
  std::condition_variable idle_cv_;
};

}  // namespace tx::network
