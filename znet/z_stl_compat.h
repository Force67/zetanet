// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
// STL compatibility layer: STL-based replacements for the equilibrium/base
// types used by zetanet, active when ZNET_USE_STL is defined.
#pragma once

#ifdef ZNET_USE_STL

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <span>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <queue>
#include <mutex>
#include <functional>
#include <cstdio>
#include <cstdarg>
#include <utility>
#include <map>
#include <array>
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <immintrin.h>
#endif

// Primitive type aliases (matching equilibrium/base/arch.h)
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using f32 = float;
using f64 = double;
using mem_size = size_t;
using byte = unsigned char;

// Utility macros
#if defined(_MSC_VER)
#define STRONG_INLINE __forceinline
#else
#define STRONG_INLINE inline __attribute__((always_inline))
#endif

#ifndef _countof
template <typename T, size_t N>
constexpr size_t _countof_impl(const T (&)[N]) noexcept {
  return N;
}
#define _countof(arr) _countof_impl(arr)
#endif

#ifndef constinit
#if __cpp_constinit >= 201907L
// keyword already exists
#else
#define constinit
#endif
#endif

namespace base {

using String = std::string;
using StringRef = std::string_view;

enum class VectorReservePolicy { kDefault, kForData };

template <typename T>
class Vector : public std::vector<T> {
 public:
  using std::vector<T>::vector;
  Vector() = default;
  explicit Vector(size_t count, VectorReservePolicy)
      : std::vector<T>(count) {}

  size_t length() const { return this->size(); }

  void erase(size_t index) {
    this->std::vector<T>::erase(this->begin() + index);
  }
};

template <typename T>
class Span : public std::span<const T> {
 public:
  using std::span<const T>::span;
  Span() : std::span<const T>() {}
  Span(const T* data, size_t count) : std::span<const T>(data, count) {}

  size_t length() const { return this->size(); }
};

// Smart pointers
template <typename T>
class UniquePointer : public std::unique_ptr<T> {
 public:
  using std::unique_ptr<T>::unique_ptr;
  T* Get_UseOnlyIfYouKnowWhatYouareDoing() const { return this->get(); }
  void Reset(T* p = nullptr) { this->reset(p); }
};

template <typename T, typename... Args>
UniquePointer<T> MakeUnique(Args&&... args) {
  return UniquePointer<T>(new T(std::forward<Args>(args)...));
}

template <typename T>
constexpr std::remove_reference_t<T>&& move(T&& t) noexcept {
  return std::move(t);
}

template <typename T>
using Atomic = std::atomic<T>;

using Mutex = std::mutex;

template <typename K, typename V>
using Map = std::map<K, V>;

template <typename T>
using Queue = std::queue<T>;

template <typename T, size_t N>
using Array = std::array<T, N>;

// --- Time ---
#ifndef ZNET_BASE_CLOCK_DEFINED
#define ZNET_BASE_CLOCK_DEFINED 1
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
#endif

inline u64 GetUnixTimeStamp() {
  return static_cast<u64>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// --- Spinlock ---
class SpinLock {
 public:
  void lock() noexcept {
    for (;;) {
      if (!flag_.exchange(true, std::memory_order_acquire)) return;
      while (flag_.load(std::memory_order_relaxed)) {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
        _mm_pause();
#elif defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#elif defined(__aarch64__)
        asm volatile("yield");
#else
        std::this_thread::yield();
#endif
      }
    }
  }
  void unlock() noexcept { flag_.store(false, std::memory_order_release); }
 private:
  std::atomic<bool> flag_{false};
};

// --- MPSC queue: lock-free producers, single consumer ---
// A dequeue racing a producer between its exchange and link store may
// transiently report empty; callers treat dequeue() == false as "not now".
template <typename T>
class MPSCQueue {
  struct Node {
    std::atomic<Node*> next{nullptr};
    T value{};

    Node() = default;
    explicit Node(T&& v) : value(std::move(v)) {}
  };

 public:
  MPSCQueue() {
    Node* stub = new Node();
    push_end_.store(stub, std::memory_order_relaxed);
    pop_end_ = stub;
  }

  ~MPSCQueue() {
    Node* node = pop_end_;
    while (node) {
      Node* next = node->next.load(std::memory_order_relaxed);
      delete node;
      node = next;
    }
  }

  MPSCQueue(const MPSCQueue&) = delete;
  MPSCQueue& operator=(const MPSCQueue&) = delete;

  void enqueue(T&& item) {
    Node* node = new Node(std::move(item));
    approx_size_.fetch_add(1, std::memory_order_relaxed);
    Node* prev = push_end_.exchange(node, std::memory_order_acq_rel);
    prev->next.store(node, std::memory_order_release);
  }

  // Single-consumer only.
  bool dequeue(T& item) {
    Node* tail = pop_end_;
    Node* next = tail->next.load(std::memory_order_acquire);
    if (!next) {
      return false;
    }
    item = std::move(next->value);
    pop_end_ = next;
    delete tail;
    approx_size_.fetch_sub(1, std::memory_order_relaxed);
    return true;
  }

  bool empty() const {
    return approx_size_.load(std::memory_order_relaxed) == 0;
  }

  size_t size_approx() const {
    return approx_size_.load(std::memory_order_relaxed);
  }

 private:
  alignas(64) std::atomic<Node*> push_end_;
  alignas(64) Node* pop_end_;
  std::atomic<size_t> approx_size_{0};
};

// --- ID generator; ids are not reused ---
template <typename T, T InvalidId, T MaxId>
class IdSet {
 public:
  T GenerateId() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (next_id_ >= MaxId)
      return InvalidId;
    return next_id_++;
  }

  void ReleaseId(T) {}

 private:
  T next_id_{0};
  std::mutex mutex_;
};

// Logging
enum class LogLevel : int {
  kVerbose = 0,
  kDebug = 1,
  kInfo = 2,
  kWarning = 3,
  kError = 4,
  kFatal = 5
};

using LogHandler = void (*)(void* user_pointer,
                            const char* channel_name,
                            int level,
                            const char* msg);

inline LogHandler g_log_handler = nullptr;
inline void* g_log_user_pointer = nullptr;

inline void SetLogHandler(LogHandler handler, void* user_pointer) {
  g_log_handler = handler;
  g_log_user_pointer = user_pointer;
}

inline const char* LogLevelToName(LogLevel level) {
  switch (level) {
    case LogLevel::kVerbose:
      return "VERBOSE";
    case LogLevel::kDebug:
      return "DEBUG";
    case LogLevel::kInfo:
      return "INFO";
    case LogLevel::kWarning:
      return "WARNING";
    case LogLevel::kError:
      return "ERROR";
    case LogLevel::kFatal:
      return "FATAL";
    default:
      return "UNKNOWN";
  }
}

// snprintf-based formatting; one {} per argument.
namespace detail {
inline std::string format_one(const char* fmt) {
  return std::string(fmt);
}

inline void append_value(std::string& out, const char* val) {
  out += val;
}
inline void append_value(std::string& out, const std::string& val) {
  out += val;
}
inline void append_value(std::string& out, std::string_view val) {
  out.append(val.data(), val.size());
}
inline void append_value(std::string& out, char val) {
  out += val;
}
template <typename T>
inline std::enable_if_t<std::is_integral_v<T>> append_value(std::string& out,
                                                             T val) {
  char buf[32];
  if constexpr (std::is_signed_v<T>)
    std::snprintf(buf, sizeof(buf), "%lld", (long long)val);
  else
    std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)val);
  out += buf;
}
template <typename T>
inline std::enable_if_t<std::is_floating_point_v<T>> append_value(
    std::string& out,
    T val) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%f", (double)val);
  out += buf;
}

template <typename T, typename... Args>
inline std::string format_one(const char* fmt, T&& first, Args&&... rest) {
  std::string result;
  const char* p = fmt;
  while (*p) {
    if (*p == '{' && *(p + 1) == '}') {
      append_value(result, std::forward<T>(first));
      p += 2;
      result += format_one(p, std::forward<Args>(rest)...);
      return result;
    }
    result += *p++;
  }
  return result;
}
}  // namespace detail

template <typename... Args>
inline std::string Format(const char* fmt, Args&&... args) {
  return detail::format_one(fmt, std::forward<Args>(args)...);
}

inline void LogMessage(const char* tag, LogLevel level, const std::string& msg) {
  if (g_log_handler) {
    g_log_handler(g_log_user_pointer, tag, static_cast<int>(level),
                  msg.c_str());
  } else {
    std::fprintf(stderr, "[%s] %s: %s\n", tag, LogLevelToName(level),
                 msg.c_str());
  }
}

}  // namespace base

#include <filesystem>
#include <fstream>

namespace base {  // reopen

class Path {
 public:
  Path() = default;
  Path(const std::string& p) : path_(p) {}
  Path(const std::filesystem::path& p) : path_(p.string()) {}

  const std::string& path() const { return path_; }
  std::string ToAsciiString() const { return path_; }
  Path BaseName() const {
    return Path(std::filesystem::path(path_).filename().string());
  }
  Path DirName() const {
    return Path(std::filesystem::path(path_).parent_path().string());
  }

 private:
  std::string path_;
};

class File {
 public:
  static constexpr int FLAG_OPEN = 1;
  static constexpr int FLAG_READ = 2;
  static constexpr int FLAG_WRITE = 4;
  static constexpr int FLAG_CREATE_ALWAYS = 8;

  File(const Path& path, int flags) {
    std::ios_base::openmode mode{};
    if (flags & FLAG_READ)
      mode |= std::ios::in | std::ios::binary;
    if (flags & FLAG_WRITE)
      mode |= std::ios::out | std::ios::binary;
    if (flags & FLAG_CREATE_ALWAYS)
      mode |= std::ios::trunc;
    stream_.open(path.path(), mode);
  }

  bool IsValid() const { return stream_.is_open(); }

  int64_t GetLength() {
    auto pos = stream_.tellg();
    stream_.seekg(0, std::ios::end);
    auto len = stream_.tellg();
    stream_.seekg(pos);
    return static_cast<int64_t>(len);
  }

  int Read(int64_t offset, char* buffer, size_t count) {
    stream_.seekg(offset);
    stream_.read(buffer, count);
    return static_cast<int>(stream_.gcount());
  }

  int Write(int64_t offset, const char* data, size_t size) {
    stream_.seekp(offset);
    stream_.write(data, size);
    return stream_.good() ? static_cast<int>(size) : -1;
  }

  int WriteAtCurrentPos(const char* data, int size) {
    stream_.write(data, size);
    return stream_.good() ? size : -1;
  }

  bool Flush() {
    stream_.flush();
    return stream_.good();
  }

 private:
  std::fstream stream_;
};

}  // namespace base

// Logging macros
#define BASE_LOGI(tag, fmt, ...) \
  base::LogMessage(tag, base::LogLevel::kInfo, base::Format(fmt, ##__VA_ARGS__))
#define BASE_LOGW(tag, fmt, ...) \
  base::LogMessage(tag, base::LogLevel::kWarning, base::Format(fmt, ##__VA_ARGS__))
#define BASE_LOGE(tag, fmt, ...) \
  base::LogMessage(tag, base::LogLevel::kError, base::Format(fmt, ##__VA_ARGS__))
#define BASE_LOGD(tag, fmt, ...) \
  base::LogMessage(tag, base::LogLevel::kDebug, base::Format(fmt, ##__VA_ARGS__))

#endif  // ZNET_USE_STL
