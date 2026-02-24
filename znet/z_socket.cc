// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_socket.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

#include <chrono>
#include <thread>

namespace tx::network {
static constexpr char kLogTag[] = "z-socket";

#define ZSOCKET_ASYNC 1

namespace {
void SetSockaddrPort(sockaddr_storage& address, u16 port) {
  if (address.ss_family == AF_INET6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&address);
    addr6->sin6_port = htons(port);
  } else if (address.ss_family == AF_INET) {
    auto* addr4 = reinterpret_cast<sockaddr_in*>(&address);
    addr4->sin_port = htons(port);
  }
}

bool AddressFromSockaddr(const sockaddr_storage& address, ZSocket::Address& out) {
  memset(&out, 0, sizeof(out));

  if (address.ss_family == AF_INET6) {
    const auto* addr6 = reinterpret_cast<const sockaddr_in6*>(&address);
    if (::inet_ntop(AF_INET6, &addr6->sin6_addr, out.ip, sizeof(out.ip)) ==
        nullptr) {
      return false;
    }
    out.port = ::ntohs(addr6->sin6_port);
    out.address_family = AF_INET6;
    return true;
  }

  if (address.ss_family == AF_INET) {
    const auto* addr4 = reinterpret_cast<const sockaddr_in*>(&address);
    if (::inet_ntop(AF_INET, &addr4->sin_addr, out.ip, sizeof(out.ip)) ==
        nullptr) {
      return false;
    }
    out.port = ::ntohs(addr4->sin_port);
    out.address_family = AF_INET;
    return true;
  }

  return false;
}

bool ResolveSockaddr(const base::StringRef host,
                     u16 port,
                     int family,
                     sockaddr_storage& out_sockaddr,
                     socklen_t& out_len,
                     ZSocket::Address* out_address) {
  if (host.empty()) {
    return false;
  }

#if defined(_WIN32)
  WSADATA wsa_data{};
  if (::WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    return false;
  }
#endif

  addrinfo hints{};
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  base::String host_str(host.data(), host.size());
  addrinfo* results = nullptr;
  const int result = ::getaddrinfo(host_str.c_str(), nullptr, &hints, &results);
  if (result != 0 || results == nullptr) {
#if defined(_WIN32)
    ::WSACleanup();
#endif
    return false;
  }

  bool success = false;
  for (addrinfo* candidate = results; candidate != nullptr;
       candidate = candidate->ai_next) {
    if (candidate->ai_addr == nullptr ||
        candidate->ai_addrlen > sizeof(out_sockaddr) ||
        (candidate->ai_family != AF_INET && candidate->ai_family != AF_INET6)) {
      continue;
    }

    memset(&out_sockaddr, 0, sizeof(out_sockaddr));
    memcpy(&out_sockaddr, candidate->ai_addr, candidate->ai_addrlen);
    SetSockaddrPort(out_sockaddr, port);
    out_len = static_cast<socklen_t>(candidate->ai_addrlen);

    if (out_address != nullptr) {
      if (!AddressFromSockaddr(out_sockaddr, *out_address)) {
        continue;
      }
    }
    success = true;
    break;
  }

  ::freeaddrinfo(results);
#if defined(_WIN32)
  ::WSACleanup();
#endif
  return success;
}

u32 NextRandom(u32& state) {
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  if (state == 0) {
    state = 1;
  }
  return state;
}

bool RollPercent(u32 percentage, u32& state) {
  if (percentage == 0) {
    return false;
  }
  return (NextRandom(state) % 100u) < percentage;
}
}  // namespace

ZSocket::ZSocket() : socket_(ZNET_INVALID_SOCKET) {}

ZSocket::~ZSocket() {
  DestroySocket();
}

bool ZSocket::CreateServer(u16 port, bool ipv6) {
  if (!InitSocket()) {
    BASE_LOGE(kLogTag, "InitSocket failed");
    return false;
  }

  address_family_ = ipv6 ? AF_INET6 : AF_INET;
  memset(&server_, 0, sizeof(server_));

  if (ipv6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&server_);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    addr6->sin6_addr = in6addr_any;
    server_len_ = sizeof(sockaddr_in6);
  } else {
    auto* addr4 = reinterpret_cast<sockaddr_in*>(&server_);
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    addr4->sin_addr.s_addr = INADDR_ANY;
    server_len_ = sizeof(sockaddr_in);
  }

  socket_ = ::socket(address_family_, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_ == ZNET_INVALID_SOCKET) {
    BASE_LOGE(kLogTag, "Could not create socket. Error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }


  if (ipv6) {
    // Allow IPv6-only mode
    int v6only = 1;
    setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY,
               reinterpret_cast<const char*>(&v6only), sizeof(v6only));
  }

  // Enlarge socket buffers to reduce kernel-level drops under high throughput.
  {
    int buf_size = 4 * 1024 * 1024;  // 4 MB
    setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&buf_size), sizeof(buf_size));
    setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&buf_size), sizeof(buf_size));
  }

  if (::bind(socket_, reinterpret_cast<struct sockaddr*>(&server_), server_len_) ==
      ZNET_SOCKET_ERROR) {
    BASE_LOGE(kLogTag, "Bind failed with error : {}", ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

#if ZSOCKET_ASYNC
#if defined(_WIN32)
  u_long mode = 1;
  if (ioctlsocket(socket_, FIONBIO, &mode) != 0) {
    DestroySocket();
    return false;
  }
#else
  int flags = fcntl(socket_, F_GETFL, 0);
  if (flags == -1 || fcntl(socket_, F_SETFL, flags | O_NONBLOCK) == -1) {
    DestroySocket();
    return false;
  }
#endif
  BASE_LOGI(kLogTag, "Server set to non-blocking mode");
#endif
  BASE_LOGI(kLogTag, "Server socket initialized on port {} ({})", port,
            ipv6 ? "IPv6" : "IPv4");
  return true;
}

bool ZSocket::CreateClient(const base::StringRef ip,
                           int port,
                           bool ipv6,
                           u16 local_bind_port) {
  if (!InitSocket()) {
    BASE_LOGE(kLogTag, "InitSocket failed");
    return false;
  }

  const int requested_family = ipv6 ? AF_INET6 : AF_INET;
  ZSocket::Address resolved_endpoint{};
  if (!ResolveSockaddr(ip, static_cast<u16>(port), requested_family, server_,
                       server_len_, &resolved_endpoint)) {
    BASE_LOGE(kLogTag, "Failed to resolve endpoint '{}:{}'", ip, port);
    DestroySocket();
    return false;
  }

  address_family_ = resolved_endpoint.address_family;
  socket_ = ::socket(address_family_, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_ == ZNET_INVALID_SOCKET) {
    BASE_LOGE(kLogTag, "Could not create socket. Error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

  // Enlarge socket buffers to reduce kernel-level drops under high throughput.
  {
    int buf_size = 4 * 1024 * 1024;  // 4 MB
    setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&buf_size), sizeof(buf_size));
    setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&buf_size), sizeof(buf_size));
  }

  if (local_bind_port != 0) {
    sockaddr_storage local_addr{};
    socklen_t local_len = 0;
    if (address_family_ == AF_INET6) {
      auto* local6 = reinterpret_cast<sockaddr_in6*>(&local_addr);
      local6->sin6_family = AF_INET6;
      local6->sin6_addr = in6addr_any;
      local6->sin6_port = htons(local_bind_port);
      local_len = sizeof(sockaddr_in6);
    } else {
      auto* local4 = reinterpret_cast<sockaddr_in*>(&local_addr);
      local4->sin_family = AF_INET;
      local4->sin_addr.s_addr = INADDR_ANY;
      local4->sin_port = htons(local_bind_port);
      local_len = sizeof(sockaddr_in);
    }
    if (::bind(socket_, reinterpret_cast<sockaddr*>(&local_addr),
               local_len) == ZNET_SOCKET_ERROR) {
      BASE_LOGE(kLogTag, "Client bind({}) failed with error : {}",
                local_bind_port, ZSocket::GetErrorString());
      DestroySocket();
      return false;
    }
  }

#if ZSOCKET_ASYNC
#if defined(_WIN32)
  u_long mode = 1;
  if (ioctlsocket(socket_, FIONBIO, &mode) != 0) {
    BASE_LOGE(kLogTag, "ioctlsocket failed with error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }
#else
  int flags = fcntl(socket_, F_GETFL, 0);
  if (flags == -1 || fcntl(socket_, F_SETFL, flags | O_NONBLOCK) == -1) {
    BASE_LOGE(kLogTag, "fcntl failed with error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }
#endif
  BASE_LOGI(kLogTag, "Client set to non-blocking mode");
#endif

  base::String host(ip.data(), ip.size());
  if (host == resolved_endpoint.ip) {
    BASE_LOGI(kLogTag, "Client socket initialized for {}:{}", resolved_endpoint.ip,
              port);
  } else {
    BASE_LOGI(kLogTag, "Client socket initialized for {}:{} (resolved to {})",
              host.c_str(), port, resolved_endpoint.ip);
  }
  return true;
}

bool ZSocket::ResolveAddress(const base::StringRef host,
                             u16 port,
                             bool ipv6,
                             Address& out) {
  sockaddr_storage resolved{};
  socklen_t resolved_len = 0;
  const int requested_family = ipv6 ? AF_INET6 : AF_INET;
  return ResolveSockaddr(host, port, requested_family, resolved, resolved_len,
                         &out);
}

i32 ZSocket::Send(const Address& target, const base::Span<byte> data) {
  // Fast path: use cached sockaddr if available (populated by Receive).
  if (target.cached_sa_len > 0) {
    sockaddr_storage sa = target.cached_sa;
    return InternalSend(sa, target.cached_sa_len, data);
  }

  sockaddr_storage target_addr{};
  socklen_t addr_len = 0;

  if (target.address_family == AF_INET6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&target_addr);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = ::htons(target.port);
    if (::inet_pton(AF_INET6, target.ip, &addr6->sin6_addr) <= 0) {
      BASE_LOGE(kLogTag, "Failed to convert IPv6 address: {}", target.ip);
      return -1;
    }
    addr_len = sizeof(sockaddr_in6);
  } else {
    auto* addr4 = reinterpret_cast<sockaddr_in*>(&target_addr);
    addr4->sin_family = AF_INET;
    addr4->sin_port = ::htons(target.port);
    if (::inet_pton(AF_INET, target.ip, &addr4->sin_addr) <= 0) {
      BASE_LOGE(kLogTag, "Failed to convert IPv4 address: {}", target.ip);
      return -1;
    }
    addr_len = sizeof(sockaddr_in);
  }

  return InternalSend(target_addr, addr_len, data);
}

i32 ZSocket::SendCached(const Address& addr, const base::Span<byte> data) {
  if (addr.cached_sa_len > 0) {
    sockaddr_storage sa = addr.cached_sa;
    return InternalSend(sa, addr.cached_sa_len, data);
  }
  return Send(addr, data);
}

const char* ZSocket::GetErrorString(Error error) {
  static constinit const char*
      ErrorStrings[static_cast<int>(Error::ErrorCount)]{"Success",
                                                        "AccessDenied",
                                                        "AddressInUse",
                                                        "AddressNotSupported",
                                                        "ConnectionRefused",
                                                        "ConnectionReset",
                                                        "HostUnreachable",
                                                        "NetworkUnreachable",
                                                        "NotConnected",
                                                        "OperationInProgress",
                                                        "ConnectionTimedOut",
                                                        "ConnectionAborted",
                                                        "UnknownError"};

  auto index = static_cast<i32>(error);
  if (index >= 0 && index < static_cast<i32>(Error::ErrorCount)) {
    return ErrorStrings[index];
  }

  return "InvalidError";
}

i32 ZSocket::InternalSend(sockaddr_storage& target, socklen_t addr_len,
                          const base::Span<byte> data) {
  if (socket_ == ZNET_INVALID_SOCKET)
    return -1;

  const auto send_direct = [&](sockaddr_storage& out_target,
                               socklen_t out_len,
                               const byte* bytes,
                               mem_size size) -> i32 {
    return ::sendto(socket_, reinterpret_cast<const char*>(bytes),
                    static_cast<int>(size), 0,
                    reinterpret_cast<struct sockaddr*>(&out_target), out_len);
  };

  const bool chaos_enabled = chaos_options_.drop_percent > 0 ||
                             chaos_options_.reorder_percent > 0 ||
                             chaos_options_.jitter_ms > 0;
  if (!chaos_enabled) {
    return send_direct(target, addr_len, data.data(), data.size());
  }

  std::lock_guard<std::mutex> lock(chaos_mutex_);
  if (chaos_rng_state_ == 0) {
    chaos_rng_state_ = chaos_options_.seed != 0 ? chaos_options_.seed : 1;
  }

  const auto send_with_chaos = [&](sockaddr_storage& out_target,
                                   socklen_t out_len,
                                   const byte* bytes,
                                   mem_size size) -> i32 {
    if (RollPercent(chaos_options_.drop_percent, chaos_rng_state_)) {
      return static_cast<i32>(size);
    }
    if (chaos_options_.jitter_ms > 0) {
      const u32 delay = NextRandom(chaos_rng_state_) %
                        (chaos_options_.jitter_ms + 1u);
      if (delay > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
      }
    }
    return send_direct(out_target, out_len, bytes, size);
  };

  if (chaos_pending_) {
    i32 current_result =
        send_with_chaos(target, addr_len, data.data(), data.size());
    if (!chaos_pending_bytes_.empty()) {
      send_with_chaos(chaos_pending_target_, chaos_pending_len_,
                      chaos_pending_bytes_.data(), chaos_pending_bytes_.size());
    }
    chaos_pending_ = false;
    chaos_pending_bytes_.clear();
    return current_result;
  }

  if (data.size() > 0 &&
      RollPercent(chaos_options_.reorder_percent, chaos_rng_state_)) {
    chaos_pending_ = true;
    chaos_pending_target_ = target;
    chaos_pending_len_ = addr_len;
    chaos_pending_bytes_.assign(data.data(), data.data() + data.size());
    return static_cast<i32>(data.size());
  }

  return send_with_chaos(target, addr_len, data.data(), data.size());
}

void ZSocket::SetChaosOptions(const ChaosOptions& options) {
  std::lock_guard<std::mutex> lock(chaos_mutex_);
  chaos_options_ = options;
  if (chaos_options_.drop_percent > 100) {
    chaos_options_.drop_percent = 100;
  }
  if (chaos_options_.reorder_percent > 100) {
    chaos_options_.reorder_percent = 100;
  }
  if (chaos_options_.seed == 0) {
    chaos_options_.seed = 1;
  }
  chaos_pending_ = false;
  chaos_pending_bytes_.clear();
  chaos_rng_state_ = chaos_options_.seed;
}

i32 ZSocket::Receive(Address& sender, char* buffer, mem_size length) {
  if (socket_ == ZNET_INVALID_SOCKET)
    return -1;
  sockaddr_storage sender_addr{};
  socklen_t sender_len = sizeof(sender_addr);
  i32 result = InternalReceive(sender_addr, sender_len, buffer, length);
  if (result > 0) {
    // Fast path: if the raw binary address matches the previous receive,
    // skip the expensive inet_ntop conversion.  This is the common case
    // when the same peer sends many packets in a row.
    if (sender.cached_sa_len == sender_len &&
        memcmp(&sender.cached_sa, &sender_addr, sender_len) == 0) {
      return result;  // ip/port/family already correct from last time
    }

    // New or changed sender — do the full conversion.
    sender.cached_sa = sender_addr;
    sender.cached_sa_len = sender_len;

    if (sender_addr.ss_family == AF_INET6) {
      auto* addr6 = reinterpret_cast<sockaddr_in6*>(&sender_addr);
      ::inet_ntop(AF_INET6, &addr6->sin6_addr, sender.ip, sizeof(sender.ip));
      sender.port = ::ntohs(addr6->sin6_port);
      sender.address_family = AF_INET6;
    } else {
      auto* addr4 = reinterpret_cast<sockaddr_in*>(&sender_addr);
      ::inet_ntop(AF_INET, &addr4->sin_addr, sender.ip, sizeof(sender.ip));
      sender.port = ::ntohs(addr4->sin_port);
      sender.address_family = AF_INET;
    }
  }
  return result;
}

i32 ZSocket::InternalReceive(sockaddr_storage& sender,
                             socklen_t& sender_len,
                             char* buffer,
                             mem_size length) {
  sender_len = sizeof(sockaddr_storage);
  int bytes_received = ::recvfrom(socket_, buffer, length, 0,
                                  reinterpret_cast<struct sockaddr*>(&sender),
                                  &sender_len);
  return bytes_received;
}
}  // namespace tx::network
