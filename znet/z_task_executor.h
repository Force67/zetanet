// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/threading/lock_guard.h>
#include <base/threading/mutex.h>
#include <base/threading/condition_variable.h>
#include <base/threading/thread.h>
#include <base/functional/function.h>
#include <base/containers/queue.h>
#include <base/containers/vector.h>
#include <base/memory/unique_pointer.h>
#include <base/arch.h>
#endif

#include <znet/z_abi.h>

namespace tx::network {

// Pluggable task executor for internal hot paths; supply your own to hook
// into an existing job system, otherwise the built-in pool is used.
class ZNET_API ITaskExecutor {
 public:
  using Task = base::Function<void()>;

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

  // base::Thread is not movable, hence the pointers.
  base::Vector<base::UniquePointer<base::Thread>> workers_;
  base::Queue<Task> tasks_;
  mem_size active_workers_{0};
  bool stopping_{false};

  base::Mutex mutex_;
  base::ConditionVariable task_cv_;
  base::ConditionVariable space_cv_;
  base::ConditionVariable idle_cv_;
};

}  // namespace tx::network
