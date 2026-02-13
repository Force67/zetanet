// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_socket.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-socket";

#define ZSOCKET_ASYNC 1

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

  address_family_ = ipv6 ? AF_INET6 : AF_INET;

  socket_ = ::socket(address_family_, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_ == ZNET_INVALID_SOCKET) {
    BASE_LOGE(kLogTag, "Could not create socket. Error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

  memset(&server_, 0, sizeof(server_));
  std::string ip_str(ip.data(), ip.size());

  if (ipv6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&server_);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    if (::inet_pton(AF_INET6, ip_str.c_str(), &addr6->sin6_addr) <= 0) {
      BASE_LOGE(kLogTag, "inet_pton (IPv6) failed with error : {}",
                ZSocket::GetErrorString());
      DestroySocket();
      return false;
    }
    server_len_ = sizeof(sockaddr_in6);
  } else {
    auto* addr4 = reinterpret_cast<sockaddr_in*>(&server_);
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    if (::inet_pton(AF_INET, ip_str.c_str(), &addr4->sin_addr) <= 0) {
      BASE_LOGE(kLogTag, "inet_pton (IPv4) failed with error : {}",
                ZSocket::GetErrorString());
      DestroySocket();
      return false;
    }
    server_len_ = sizeof(sockaddr_in);
  }

  if (local_bind_port != 0) {
    sockaddr_storage local_addr{};
    socklen_t local_len = 0;
    if (ipv6) {
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

  BASE_LOGI(kLogTag, "Client socket initialized for {}:{}", ip_str.c_str(), port);
  return true;
}

i32 ZSocket::Send(const Address& target, const base::Span<byte> data) {
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
  return ::sendto(socket_, reinterpret_cast<const char*>(data.data()),
                  static_cast<int>(data.size()), 0,
                  reinterpret_cast<struct sockaddr*>(&target),
                  addr_len);
}

i32 ZSocket::Receive(Address& sender, char* buffer, size_t length) {
  if (socket_ == ZNET_INVALID_SOCKET)
    return -1;
  sockaddr_storage sender_addr{};
  socklen_t sender_len = sizeof(sender_addr);
  i32 result = InternalReceive(sender_addr, sender_len, buffer, length);
  if (result > 0) {
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
                             size_t length) {
  sender_len = sizeof(sockaddr_storage);
  int bytes_received = ::recvfrom(socket_, buffer, length, 0,
                                  reinterpret_cast<struct sockaddr*>(&sender),
                                  &sender_len);
  return bytes_received;
}
}  // namespace tx::network
