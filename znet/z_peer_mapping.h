// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <base/containers/vector.h>
#include <base/containers/id_set.h>
#include <znet/z_peer.h>

namespace tx::network {

class ZPeerMapping {
 public:
  ZPeerMapping() = default;
  ~ZPeerMapping() = default;

  ZPeer& CreatePeer(const ZSocket::Address& addr) {
    u32 id = z_peer_ids_.GenerateId();
    return peer_list_.emplace_back(id, addr);
  }

  bool DestroyPeer(ZPeerId id) {
    for (mem_size i = 0; i < peer_list_.size(); ++i) {
      if (peer_list_[i].identifier == id) {
        z_peer_ids_.ReleaseId(id.id);
        peer_list_.erase(i);
        return true;
      }
    }
    return false;
  }

  ZPeer* GetPeer(ZPeerId id) {
    for (auto& peer : peer_list_) {
      if (peer.identifier == id) {
        return &peer;
      }
    }
    return nullptr;
  }

  ZPeer* GetOrCreatePeer(const ZSocket::Address& addr) {
    for (auto& peer : peer_list_) {
      if (peer.address == addr) {
        return &peer;
      }
    }
    return &CreatePeer(addr);
  }

  ZPeer* GetPeerByAddress(const ZSocket::Address& addr) {
    for (auto& peer : peer_list_) {
      if (peer.address == addr) {
        return &peer;
      }
    }
    return nullptr;
  }

  auto& GetPeerList() { return peer_list_; }

 private:
  base::IdSet<ZPeerId::id_type, ZPeerId::invalid_id, ZPeerId::max_id>
      z_peer_ids_;
  base::Vector<ZPeer> peer_list_;
};
}  // namespace tx::network