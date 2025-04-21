// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <base/logging.h>

namespace tx::network {

ZSocket::ZSocket() : socket_(-1) {}

ZSocket::~ZSocket() {
  DestroySocket();
}

bool ZSocket::InitSocket() {
  socket_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (socket_ == -1) {
    LOG_ERROR("Failed to initialize socket. Error Code : {}",
              ZSocket::GetLastSocketError());
    return false;
  }
  return true;
}

void ZSocket::DestroySocket() {
  if (socket_ != -1) {
    ::close(socket_);
    socket_ = -1;
  }
}

int ZSocket::GetLastSocketPlatformError() {
  return errno;
}

ZSocket::Error ZSocket::GetLastError() {
  i32 error = errno;
  switch (error) {
    case EACCES:
      return SocketError::AccessDenied;
    case EADDRINUSE:
      return SocketError::AddressInUse;
    case EAFNOSUPPORT:
      return SocketError::AddressNotSupported;
    case ECONNREFUSED:
      return SocketError::ConnectionRefused;
    case ECONNRESET:
      return SocketError::ConnectionReset;
    case EHOSTUNREACH:
      return SocketError::HostUnreachable;
    case ENETUNREACH:
      return SocketError::NetworkUnreachable;
    case ENOTCONN:
      return SocketError::NotConnected;
    case EINPROGRESS:
      return SocketError::OperationInProgress;
    case ETIMEDOUT:
      return SocketError::ConnectionTimedOut;
    case ECONNABORTED:
      return SocketError::ConnectionAborted;
  }
  return Error::UnknownError;
}

}  // namespace tx::network
