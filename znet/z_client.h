// Copyright (C) 2023 Team overLOAD.
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <base/memory/unique_pointer.h>

#include <network/zeta/z_peer.h>
#include <network/zeta/z_transport.h>

#undef SendMessage

namespace tx::network {

class ZClient final : public ZAsyncTransportLayer {
 public:
  bool Connect(const base::StringRef address, u16 port);
  void Disconnect();
  void Update();
  void SendMessage(const ZPeerId, const std::string& data);

  // Fetches the next packet from the queue
  inline bool Poll(PacketChannelType t, IncomingPacket& p) {
    for (u8 i = (u8)PacketChannelType::Control; i < (u8)PacketChannelType::Data;
         ++i) {
      if (packet_queue_.Pop((PacketChannelType)i, p)) {
        if (IsSystemMessage(p.type)) {
          ProcessSystemMessage(p);
        }
        return true;
      }
    }
    return false;
  }

  inline void Push(OutgoingPacket&& p) { packet_queue_.Push(base::move(p)); }

  void ProcessSystemMessage(const IncomingPacket& p);

  void SendClientHello();
};
}  // namespace tx::network