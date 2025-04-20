// Copyright (C) 2023 Team overLOAD.
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <network/zeta/z_transport.h>

namespace tx::network {

class ZP2PNode {
 public:
 enum class Type { Host, Client };
  bool Begin(u16 port);

  bool Update();
  void SendMessage(ZPeerId id, const std::string& data);

  void BecomeHost();

 private:
  ZAsyncTransportLayer transport_layer_;
};
}  // namespace tx::network