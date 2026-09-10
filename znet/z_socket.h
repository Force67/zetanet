// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/span.h>
#include <base/containers/vector.h>
#include <base/strings/string_ref.h>
#endif

#include <mutex>

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
#include <netdb.h>
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

  struct ChaosOptions {
    u32 drop_percent{0};
    u32 reorder_percent{0};
    u32 jitter_ms{0};
    u32 seed{1};
  };

  struct Address {
    char ip[46]{};
    u16 port{};
    u8 address_family{AF_INET};

    // Binary sockaddr filled by Receive() and ResolveAddress(), letting
    // Send() skip inet_pton per packet.
    sockaddr_storage cached_sa{};
    socklen_t cached_sa_len{0};

    bool operator==(const Address& other) const {
      if (port != other.port || address_family != other.address_family) {
        return false;
      }
      // Compare only the significant bytes of the address.
      if (address_family == AF_INET) {
        return memcmp(ip, other.ip, 16) == 0;
      }
      return memcmp(ip, other.ip, sizeof(ip)) == 0;
    }
  };

  static bool ResolveAddress(const base::StringRef host,
                             u16 port,
                             bool ipv6,
                             Address& out);

  i32 Send(const Address& addr, const base::Span<byte> data);
  // Uses the pre-cached sockaddr; no inet_pton.
  i32 SendCached(const Address& addr, const base::Span<byte> data);
  i32 Receive(Address& sender, char* buffer, mem_size length);
  // Blocks until readable or timeout; lets receive loops on the non-blocking
  // socket sleep instead of spinning on EAGAIN.
  bool WaitReadable(i32 timeout_ms);
  void SetChaosOptions(const ChaosOptions& options);

  i32 SendtoServer(const base::Span<byte> data) {
    return InternalSend(server_, server_len_, data);
  }

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
    ErrorCount
  };
  static Error GetLastError();
  static const char* GetErrorString(Error error);

  inline static const char* GetErrorString() {
    return GetErrorString(GetLastError());
  }

 private:
  i32 InternalSend(sockaddr_storage&, socklen_t addr_len, const base::Span<byte> data);
  i32 InternalReceive(sockaddr_storage& sender, socklen_t& sender_len, char* buffer, mem_size length);

 private:
#if defined(_WIN32)
  WSADATA wsa_;
  bool wsa_initialized_{false};
#endif
  socket_t socket_;
  sockaddr_storage server_{};
  socklen_t server_len_{0};
  int address_family_{AF_INET};
  ChaosOptions chaos_options_{};
  std::mutex chaos_mutex_;
  bool chaos_pending_{false};
  sockaddr_storage chaos_pending_target_{};
  socklen_t chaos_pending_len_{0};
  base::Vector<byte> chaos_pending_bytes_{};
  u32 chaos_rng_state_{0};
};
}  // namespace tx::network
