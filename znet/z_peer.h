// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_socket.h>

namespace tx::network {

struct ZPeerId {
  using id_type = u32;
  id_type id;
  static constexpr id_type invalid_id = 0xFFFFFFFF;
  static constexpr id_type max_id = invalid_id - 1;
  static constexpr id_type to_all = max_id - 1;
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
