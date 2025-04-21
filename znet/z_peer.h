// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_socket.h>

namespace tx::network {

struct ZPeerId {
  using id_type = u32;
  id_type id;
  // invalid id
  static constexpr id_type invalid_id = 0xFFFFFFFF;
  // biggest assignable id
  static constexpr id_type max_id = invalid_id - 1;
  // id to send to all peers
  static constexpr id_type to_all = max_id - 1;
  // send to server socket
  static constexpr id_type to_server = max_id - 2;

  ZPeerId() : id(invalid_id) {}
  ZPeerId(id_type id) : id(id) {}
    
  bool operator==(const ZPeerId& other) const { return id == other.id; }
};

struct ZPeer {
  ZPeerId identifier;
  ZSocket::Address address;
};
}  // namespace tx::network