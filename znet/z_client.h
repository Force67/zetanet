// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/memory/unique_pointer.h>
#endif

#include <znet/z_abi.h>
#include <znet/z_peer.h>
#include <znet/z_transport.h>

#undef SendMessage

namespace tx::network {

class ZNET_API ZClient final : public ZAsyncTransportLayer {
 public:
  bool Connect(const base::StringRef address, u16 port);
  void Disconnect();
  void Update();
  void SendMessage(const ZPeerId, const std::string& data);

  // Fetches the next packet from the queue
  inline bool Poll(PacketChannelType t, IncomingPacket& p) {
    for (u8 i = (u8)PacketChannelType::Control; i <= (u8)PacketChannelType::Data;
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

  inline void Push(OutgoingPacket&& p) { packet_queue_.Push(std::move(p)); }

  void ProcessSystemMessage(const IncomingPacket& p);

  void SendClientHello();
  void SendClientAuthProof(const std::string& proof);
};
}  // namespace tx::network
