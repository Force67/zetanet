// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <chrono>
#endif

#ifndef ZNET_BASE_CLOCK_DEFINED
#define ZNET_BASE_CLOCK_DEFINED 1
namespace base {
class Clock {
 public:
  using clock = std::chrono::steady_clock;
  using rep = clock::rep;
  using period = clock::period;
  using duration = clock::duration;
  using time_point = clock::time_point;
  static constexpr bool is_steady = clock::is_steady;

  static time_point now() noexcept { return clock::now(); }
};
}  // namespace base
#endif

