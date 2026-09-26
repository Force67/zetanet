// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/threading/lock_guard.h>
#include <base/threading/mutex.h>
#include <base/containers/vector.h>
#include <base/containers/id_set.h>
#endif

#include <znet/z_peer.h>

namespace tx::network {

class ZPeerMapping {
 public:
  static constexpr mem_size kMaxPeers = 2048;

  ZPeerMapping() = default;
  ~ZPeerMapping() = default;

  ZPeer* CreatePeer(const ZSocket::Address& addr) {
    base::LockGuard<base::SharedMutex> lock(mutex_);
    if (peer_list_.size() >= kMaxPeers) {
      return nullptr;
    }
    u32 id = z_peer_ids_.GenerateId();
    if (id == ZPeerId::invalid_id) {
      return nullptr;
    }
    return &peer_list_.emplace_back(ZPeer{ZPeerId(id), addr});
  }

  bool DestroyPeer(ZPeerId id) {
    base::LockGuard<base::SharedMutex> lock(mutex_);
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
    base::SharedLockGuard<base::SharedMutex> lock(mutex_);
    for (auto& peer : peer_list_) {
      if (peer.identifier == id) {
        return &peer;
      }
    }
    return nullptr;
  }

  ZPeer* GetOrCreatePeer(const ZSocket::Address& addr) {
    // Peer almost always exists; take only the shared lock so concurrent
    // receivers scan in parallel.
    {
      base::SharedLockGuard<base::SharedMutex> lock(mutex_);
      for (auto& peer : peer_list_) {
        if (peer.address == addr) {
          return &peer;
        }
      }
    }
    base::LockGuard<base::SharedMutex> lock(mutex_);
    // Re-scan: another thread may have created the peer in between.
    for (auto& peer : peer_list_) {
      if (peer.address == addr) {
        return &peer;
      }
    }
    if (peer_list_.size() >= kMaxPeers) {
      return nullptr;
    }
    u32 id = z_peer_ids_.GenerateId();
    if (id == ZPeerId::invalid_id) {
      return nullptr;
    }
    return &peer_list_.emplace_back(ZPeer{ZPeerId(id), addr});
  }

  // Copies the address out under the lock; a concurrent GetOrCreatePeer can
  // reallocate peer_list_ and invalidate ZPeer* handles.
  bool ResolvePeerAddress(ZPeerId id, ZSocket::Address& out_address) {
    base::SharedLockGuard<base::SharedMutex> lock(mutex_);
    for (auto& peer : peer_list_) {
      if (peer.identifier == id) {
        out_address = peer.address;
        return true;
      }
    }
    return false;
  }

  ZPeer* GetPeerByAddress(const ZSocket::Address& addr) {
    base::SharedLockGuard<base::SharedMutex> lock(mutex_);
    for (auto& peer : peer_list_) {
      if (peer.address == addr) {
        return &peer;
      }
    }
    return nullptr;
  }

  base::Vector<ZPeer> GetPeerList() {
    base::SharedLockGuard<base::SharedMutex> lock(mutex_);
    return peer_list_;
  }

  // Copy-assignment reuses capacity, making broadcast fanout
  // allocation-free in steady state.
  void CopyPeerList(base::Vector<ZPeer>& out) const {
    base::SharedLockGuard<base::SharedMutex> lock(mutex_);
    out = peer_list_;
  }

  mem_size PeerCount() const {
    base::SharedLockGuard<base::SharedMutex> lock(mutex_);
    return peer_list_.size();
  }

 private:
  mutable base::SharedMutex mutex_;
  base::IdSet<ZPeerId::id_type, ZPeerId::invalid_id, ZPeerId::max_id>
      z_peer_ids_;
  base::Vector<ZPeer> peer_list_;
};
}  // namespace tx::network
