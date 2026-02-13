// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#if defined(_WIN32)

#include "z_socket.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

#pragma comment(lib, "Ws2_32.lib")

namespace tx::network {
static constexpr char kLogTag[] = "z-socket";

bool ZSocket::InitSocket() {
  if (::WSAStartup(MAKEWORD(2, 2), &wsa_) != 0) {
    BASE_LOGE(kLogTag, "Failed to initialize Winsock. Error Code : {}",
              ZSocket::GetErrorString());
    return false;
  }
  wsa_initialized_ = true;
  return true;
}

void ZSocket::DestroySocket() {
  if (socket_ != ZNET_INVALID_SOCKET) {
    ::closesocket(socket_);
    socket_ = ZNET_INVALID_SOCKET;
  }
  if (wsa_initialized_) {
    ::WSACleanup();
    wsa_initialized_ = false;
  }
}

i32 ZSocket::GetLastSocketPlatformError() {
  return ::WSAGetLastError();
}

ZSocket::Error ZSocket::GetLastError() {
  i32 error = ::WSAGetLastError();
  switch (error) {
    case WSAEACCES:
      return Error::AccessDenied;
    case WSAEADDRINUSE:
      return Error::AddressInUse;
    case WSAEAFNOSUPPORT:
      return Error::AddressNotSupported;
    case WSAECONNREFUSED:
      return Error::ConnectionRefused;
    case WSAECONNRESET:
      return Error::ConnectionReset;
    case WSAEHOSTUNREACH:
      return Error::HostUnreachable;
    case WSAENETUNREACH:
      return Error::NetworkUnreachable;
    case WSAENOTCONN:
      return Error::NotConnected;
    case WSAEINPROGRESS:
      return Error::OperationInProgress;
    case WSAETIMEDOUT:
      return Error::ConnectionTimedOut;
    case WSAECONNABORTED:
      return Error::ConnectionAborted;
  }
  return Error::UnknownError;
}
}  // namespace tx::network

#endif  // _WIN32
