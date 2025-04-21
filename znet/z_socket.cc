// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_socket.h"
#include <ws2tcpip.h>  // Header for inet_pton
#include <base/logging.h>

namespace tx::network {
static constexpr char kLogTag[] = "z-socket";

#define ASYNC_SOCKET 1
ZSocket::ZSocket() : socket_(INVALID_SOCKET) {}

ZSocket::~ZSocket() {
  DestroySocket();
}

bool ZSocket::CreateServer(u16 port, bool ipv6) {
  if (!InitSocket()) {
    BASE_LOGE(kLogTag, "InitSocket failed");
    return false;
  }
  server_.sin_port = htons(port);
  if (ipv6) {
    server_.sin_family = AF_INET6;
    // Set other IPv6-specific fields if necessary
  } else {
    server_.sin_family = AF_INET;
    server_.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces for IPv4
  }

  socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_ == INVALID_SOCKET) {
    BASE_LOGE(kLogTag, "Could not create socket. Error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

  if (bind(socket_, (struct sockaddr*)&server_, sizeof(server_)) ==
      SOCKET_ERROR) {
    BASE_LOGE(kLogTag, "Bind failed with error : {}", ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

#if ZSOCKET_ASYNC
  // Set non-blocking mode
  u_long mode = 1;
  if (ioctlsocket(socket_, FIONBIO, &mode) != 0) {
    // Handle error...
    DestroySocket();
    return false;
  }
  BASE_LOGI(kLogTag, "Server set to non-blocking mode");
#endif
  BASE_LOGI(kLogTag, "Server socket initialized on port {}", port);
  return true;
}

bool ZSocket::CreateClient(const base::StringRef ip, int port, bool ipv6) {
  if (!InitSocket()) {
    BASE_LOGE(kLogTag,"InitSocket failed");
    return false;
  }

  // Create the socket
  socket_ = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_ == INVALID_SOCKET) {
    BASE_LOGE(kLogTag,"Could not create socket. Error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

  // Configure the server address structure
  if (ipv6) {
    server_.sin_family = AF_INET6;
    // Set other IPv6-specific fields if necessary
  } else {
    server_.sin_family = AF_INET;
  }
  server_.sin_port = htons(port);

  // Convert IP address from string to binary form
  if ((ipv6 && ::inet_pton(AF_INET6, ip.c_str(), &server_.sin_addr) <= 0) ||
      (!ipv6 && ::inet_pton(AF_INET, ip.c_str(), &server_.sin_addr) <= 0)) {
    BASE_LOGE(kLogTag,"inet_pton failed with error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }

#if ZSOCKET_ASYNC
  // Set non-blocking mode
  u_long mode = 1;
  if (ioctlsocket(socket_, FIONBIO, &mode) != 0) {
    BASE_LOGE(kLogTag,"ioctlsocket failed with error : {}",
              ZSocket::GetErrorString());
    DestroySocket();
    return false;
  }
  BASE_LOGI(kLogTag, "Client set to non-blocking mode");
#endif

  BASE_LOGI(kLogTag, "Client socket initialized for {}:{}", ip.c_str(), port);
  return true;
}

i32 ZSocket::Send(const Address& target, const base::Span<byte> data) {
  sockaddr_in target_addr{
      .sin_family = AF_INET,
      .sin_port = ::htons(target.port),
  };
  if (::inet_pton(AF_INET, target.ip, &target_addr.sin_addr) <= 0) {
    BASE_LOGE(kLogTag,"Failed to convert IP address: {}", target.ip);
    return -1;
  }
  return InternalSend(target_addr, data);
}

const char* ZSocket::GetErrorString(Error error) {
  // keep in sync with the Error enum
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

i32 ZSocket::InternalSend(sockaddr_in& target, const base::Span<byte> data) {
  if (socket_ == INVALID_SOCKET)
    return -1;
  return ::sendto(socket_, reinterpret_cast<const char*>(data.data()),
                  static_cast<int>(data.size()), 0,
                  reinterpret_cast<struct sockaddr*>(&target),
                  sizeof(sockaddr_in));
}

i32 ZSocket::Receive(Address& sender, char* buffer, size_t length) {
  if (socket_ == INVALID_SOCKET)
    return -1;
  sockaddr_in sender_addr;  // Für IPv4, für IPv6 verwenden Sie sockaddr_in6
  int sender_addr_size = sizeof(sender_addr);
  i32 result = InternalReceive(sender_addr, buffer, length);
  if (result > 0) {
    ::inet_ntop(AF_INET, &sender_addr.sin_addr, sender.ip, sizeof(sender.ip));
    sender.port = ::ntohs(sender_addr.sin_port);
  }
  return result;
}

i32 tx::network::ZSocket::InternalReceive(sockaddr_in& sender,
                                          char* buffer,
                                          size_t length) {
  int sender_addr_size = sizeof(sockaddr_in);
  int bytes_received = ::recvfrom(socket_, buffer, length, 0,
                                  reinterpret_cast<struct sockaddr*>(&sender),
                                  &sender_addr_size);

  return bytes_received;
}
}  // namespace tx::network