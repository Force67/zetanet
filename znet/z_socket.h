// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <base/arch.h>
#include <base/containers/span.h>
#include <base/strings/string_ref.h>

namespace tx::network {
class ZSocket {
 public:
  ZSocket();
  ~ZSocket();

  bool InitSocket();
  void DestroySocket();

  bool CreateServer(u16 port, bool ipv6 = false);
  bool CreateClient(const base::StringRef ip, int port, bool ipv6 = false);

  struct Address {
    char ip[22]{};
    u16 port{};

    bool operator==(const Address& other) {
      if (port == other.port) {
        return memcmp(ip, other.ip, sizeof(ip)) == 0;
      }
      return false;
    }
  };

  i32 Send(const Address& addr, const base::Span<byte> data);
  i32 Receive(Address& sender, char* buffer, size_t length);

  // Send to server sock addr
  i32 SendtoServer(const base::Span<byte> data) {
    return InternalSend(server_, data);
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

  inline static const char* GetErrorString() { return GetErrorString(GetLastError()); }

 private:
  i32 InternalSend(sockaddr_in&, const base::Span<byte> data);
  i32 InternalReceive(sockaddr_in& sender, char* buffer, size_t length);

 private:
  WSADATA wsa_;
  SOCKET socket_;
  struct sockaddr_in server_;
  int server_len_;
};
}  // namespace tx::network