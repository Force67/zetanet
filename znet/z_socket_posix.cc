// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#if !defined(_WIN32)

#include "z_socket.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-socket-posix";

bool ZSocket::InitSocket() {
  // No platform init needed on POSIX (no WSAStartup equivalent)
  return true;
}

void ZSocket::DestroySocket() {
  if (socket_ != ZNET_INVALID_SOCKET) {
    ::close(socket_);
    socket_ = ZNET_INVALID_SOCKET;
  }
}

i32 ZSocket::GetLastSocketPlatformError() {
  return errno;
}

ZSocket::Error ZSocket::GetLastError() {
  i32 error = errno;
  switch (error) {
    case EACCES:
      return Error::AccessDenied;
    case EADDRINUSE:
      return Error::AddressInUse;
    case EAFNOSUPPORT:
      return Error::AddressNotSupported;
    case ECONNREFUSED:
      return Error::ConnectionRefused;
    case ECONNRESET:
      return Error::ConnectionReset;
    case EHOSTUNREACH:
      return Error::HostUnreachable;
    case ENETUNREACH:
      return Error::NetworkUnreachable;
    case ENOTCONN:
      return Error::NotConnected;
    case EBADF:
#if defined(ENOTSOCK)
    case ENOTSOCK:
#endif
      return Error::NotConnected;
    case EINPROGRESS:
      return Error::OperationInProgress;
    case ETIMEDOUT:
      return Error::ConnectionTimedOut;
    case ECONNABORTED:
      return Error::ConnectionAborted;
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return Error::Success;  // non-blocking: no data available is not an error
  }
  return Error::UnknownError;
}

}  // namespace tx::network

#endif  // !_WIN32
