// Copyright (C) 2023 Team overLOAD.
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <base/memory/unique_pointer.h>

#include <network/zeta/z_crypto_wrapper.h>
#include <network/zeta/z_packet_queues.h>
#include <network/zeta/z_socket.h>
#include <network/zeta/z_peer_mapping.h>

namespace tx::network {

class ZAsyncTransportLayer {
 public:
  ZAsyncTransportLayer();
  ~ZAsyncTransportLayer();

  enum class State { kDisconnected, kConnecting, kConnected, kDisconnecting };
  enum class ConnectionType { kClient, kServer, kP2PNode };

  struct InitOptions {
    const base::StringRef ip;
    u16 port;
    ConnectionType setup_type;
    bool use_encryption;
    bool use_compression;
    bool allow_ipv6;
  };
  bool Init(const InitOptions&);

  void Deinit();


  State state() const { return state_; }

 private:
  tx::network::ZSocket socket_;
  bool stop_threads;

 protected:
  State state_{State::kDisconnected};
  base::UniquePointer<ZCryptoContext> crypto_context_;
  ZPacketQueue packet_queue_;
  ZPeerMapping peer_mapping_;
};
}  // namespace tx::network
