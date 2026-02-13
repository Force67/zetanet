// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/memory/unique_pointer.h>
#endif

#include <znet/z_transport.h>

#undef SendMessage

namespace tx::network {

class ZNET_API ZServer final : public ZAsyncTransportLayer {
 public:
  bool Begin(u16 port);

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
  void SendServerHello(ZPeerId);
};
}  // namespace tx::network
