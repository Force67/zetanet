// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/span.h>
#include <base/strings/string_ref.h>
#endif

// Platform-specific socket includes and typedefs
#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
#define ZNET_INVALID_SOCKET INVALID_SOCKET
#define ZNET_SOCKET_ERROR SOCKET_ERROR
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
using socket_t = int;
#define ZNET_INVALID_SOCKET (-1)
#define ZNET_SOCKET_ERROR (-1)
#endif

namespace tx::network {
class ZSocket {
 public:
  ZSocket();
  ~ZSocket();

  bool InitSocket();
  void DestroySocket();

  bool CreateServer(u16 port, bool ipv6 = false);
  bool CreateClient(const base::StringRef ip,
                    int port,
                    bool ipv6 = false,
                    u16 local_bind_port = 0);

  struct Address {
    char ip[46]{};  // INET6_ADDRSTRLEN
    u16 port{};
    u8 address_family{AF_INET};

    bool operator==(const Address& other) const {
      if (port == other.port && address_family == other.address_family) {
        return memcmp(ip, other.ip, sizeof(ip)) == 0;
      }
      return false;
    }
  };

  i32 Send(const Address& addr, const base::Span<byte> data);
  i32 Receive(Address& sender, char* buffer, size_t length);

  // Send to server sock addr
  i32 SendtoServer(const base::Span<byte> data) {
    return InternalSend(server_, server_len_, data);
  }

  // OS specific error.
  static i32 GetLastSocketPlatformError();

  enum class Error {
    Success,
    AccessDenied,
    AddressInUse,
    AddressNotSupported,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    NotConnected,
    OperationInProgress,
    ConnectionTimedOut,
    ConnectionAborted,
    UnknownError,
    ErrorCount  // This should always be the last element
  };
  static Error GetLastError();
  static const char* GetErrorString(Error error);

  inline static const char* GetErrorString() {
    return GetErrorString(GetLastError());
  }

 private:
  i32 InternalSend(sockaddr_storage&, socklen_t addr_len, const base::Span<byte> data);
  i32 InternalReceive(sockaddr_storage& sender, socklen_t& sender_len, char* buffer, size_t length);

 private:
#if defined(_WIN32)
  WSADATA wsa_;
  bool wsa_initialized_{false};
#endif
  socket_t socket_;
  sockaddr_storage server_{};
  socklen_t server_len_{0};
  int address_family_{AF_INET};
};
}  // namespace tx::network
