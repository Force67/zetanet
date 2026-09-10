// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/array.h>
#endif
#include <znet/z_clock.h>

#include <chrono>

namespace tx::network {

// Client-side monotonic estimate of a remote authority clock. Applies RTT/2
// compensation and blends gradually toward new samples.
class ZSynchronizedClock {
 public:
  ZSynchronizedClock() noexcept { Reset(); }

  void Reset() noexcept {
    simulated_tick_ms_ = 0;
    synchronized_ = false;
    filtered_offset_ms_ = 0.0;
    sample_count_ = 0;
    sample_cursor_ = 0;
  }

  u64 GetCurrentTick() const noexcept { return simulated_tick_ms_; }

  bool IsSynchronized() const noexcept { return synchronized_; }

  // NTP sample: t0 client send, t1 server receive, t2 server send, t3 client
  // receive.
  void SynchronizeFromNtpSample(u64 client_send_tick_ms,
                                u64 client_receive_tick_ms,
                                u64 server_receive_tick_ms,
                                u64 server_send_tick_ms) noexcept {
    if (client_receive_tick_ms < client_send_tick_ms ||
        server_send_tick_ms < server_receive_tick_ms) {
      return;
    }

    const i64 t0 = static_cast<i64>(client_send_tick_ms);
    const i64 t1 = static_cast<i64>(server_receive_tick_ms);
    const i64 t2 = static_cast<i64>(server_send_tick_ms);
    const i64 t3 = static_cast<i64>(client_receive_tick_ms);

    const i64 client_round_trip_ms = t3 - t0;
    const i64 server_processing_ms = t2 - t1;
    i64 network_delay_ms = client_round_trip_ms - server_processing_ms;
    if (network_delay_ms < 0) {
      network_delay_ms = 0;
    }
    if (network_delay_ms > static_cast<i64>(0xFFFFFFFFu)) {
      network_delay_ms = static_cast<i64>(0xFFFFFFFFu);
    }

    // NTP offset estimate; asymmetry bias is unidentifiable, callers may
    // compensate via SetAsymmetryCompensationMs().
    double offset_ms = 0.5 * static_cast<double>((t1 - t0) + (t2 - t3));
    offset_ms += static_cast<double>(asymmetry_compensation_ms_);

    StoreSample(offset_ms, static_cast<u32>(network_delay_ms),
                client_receive_tick_ms);
    const Sample best = SelectBestSample(client_receive_tick_ms);

    if (!synchronized_) {
      filtered_offset_ms_ = best.offset_ms;
      synchronized_ = true;
    } else {
      const double error = best.offset_ms - filtered_offset_ms_;
      const double abs_error = error >= 0.0 ? error : -error;
      double alpha = 0.05;
      if (abs_error > 40.0) {
        alpha = 0.25;
      } else if (abs_error > 12.0) {
        alpha = 0.12;
      }
      filtered_offset_ms_ += error * alpha;
    }

    Update(client_receive_tick_ms);
  }

  void SetAsymmetryCompensationMs(i32 compensation_ms) noexcept {
    asymmetry_compensation_ms_ = compensation_ms;
  }

  i32 GetAsymmetryCompensationMs() const noexcept {
    return asymmetry_compensation_ms_;
  }

  void Update(u64 local_tick_ms) noexcept {
    if (!synchronized_) {
      return;
    }

    double estimate = static_cast<double>(local_tick_ms) + filtered_offset_ms_;
    if (estimate < 0.0) {
      estimate = 0.0;
    }
    u64 next_tick = static_cast<u64>(estimate + 0.5);

    // Stay monotonic.
    if (next_tick < simulated_tick_ms_) {
      next_tick = simulated_tick_ms_;
    }
    simulated_tick_ms_ = next_tick;
  }

 private:
  struct Sample {
    double offset_ms{0.0};
    u32 delay_ms{0};
    u64 local_tick_ms{0};
  };
  static constexpr mem_size kMaxSamples = 16;
  static constexpr u64 kSampleRetentionMs = 10000;

  void StoreSample(double offset_ms, u32 delay_ms, u64 local_tick_ms) noexcept {
    samples_[sample_cursor_] = Sample{
        .offset_ms = offset_ms,
        .delay_ms = delay_ms,
        .local_tick_ms = local_tick_ms,
    };
    sample_cursor_ = (sample_cursor_ + 1) % kMaxSamples;
    if (sample_count_ < kMaxSamples) {
      ++sample_count_;
    }
  }

  Sample SelectBestSample(u64 now_local_tick_ms) const noexcept {
    Sample best{};
    bool found = false;

    for (mem_size i = 0; i < sample_count_; ++i) {
      const Sample& s = samples_[i];
      if (s.local_tick_ms == 0) {
        continue;
      }
      if (now_local_tick_ms >= s.local_tick_ms &&
          (now_local_tick_ms - s.local_tick_ms) > kSampleRetentionMs) {
        continue;
      }
      if (!found || s.delay_ms < best.delay_ms ||
          (s.delay_ms == best.delay_ms && s.local_tick_ms > best.local_tick_ms)) {
        best = s;
        found = true;
      }
    }

    if (found) {
      return best;
    }

    if (sample_count_ > 0) {
      return samples_[(sample_cursor_ + kMaxSamples - 1) % kMaxSamples];
    }
    return Sample{};
  }

  u64 simulated_tick_ms_{0};
  bool synchronized_{false};
  double filtered_offset_ms_{0.0};
  i32 asymmetry_compensation_ms_{0};
  base::Array<Sample, kMaxSamples> samples_{};
  mem_size sample_count_{0};
  mem_size sample_cursor_{0};
};

}  // namespace tx::network
