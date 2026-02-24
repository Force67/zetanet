// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>
#include <znet/z_system_command.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#include <unordered_map>
#include <unordered_set>
#else
#include <base/memory/unique_pointer.h>
#endif

#include <znet/z_transport.h>

#undef SendMessage

namespace tx::network {

class ZNET_API ZServer final : public ZAsyncTransportLayer {
 public:
  struct StartOptions {
    bool use_encryption{false};
    base::StringRef pre_shared_key{};
    bool use_compression{false};
    bool allow_ipv6{false};
    bool start_threads{false};
    ZSocket::ChaosOptions chaos{};
  };

  bool Begin(u16 port);
  bool Begin(u16 port, const StartOptions& options);

  bool Update();
  void SendMessage(ZPeerId id, const base::String& data);

  // Fetches the next packet from the queue
  bool Poll(PacketChannelType t, IncomingPacket& p) {
    if (packet_queue_.Pop(t, p)) {
      if (IsSystemMessage(p.type)) {
        ProcessSystemMessage(p);
      }
      return true;
    }
    return false;
  }

  // add a package to the queue, priority etc are decided based on the data in
  // outgoing packet
  void Push(OutgoingPacket&& p) {
    if (state_ != State::kConnected)
      return;
    packet_queue_.Push(std::move(p));
  }

  void ProcessSystemMessage(const IncomingPacket& p);
  void SendServerHello(ZPeerId, u16 protocol_version, u32 negotiated_features);
  void SendServerGoodbye(ZPeerId, system_commands::HandshakeRejectReason reason);
  void SendClockSyncResponse(ZPeerId dest,
                             u64 echoed_client_tick_ms,
                             u64 server_receive_tick_ms);

 private:
  struct PeerHandshakeInfo {
    u16 protocol_version{0};
    u32 negotiated_features{0};
    base::Clock::time_point connected_at{};
  };

  std::unordered_set<u32> handshaked_peers_;
  std::unordered_map<u32, PeerHandshakeInfo> peer_handshake_info_;
};
}  // namespace tx::network
