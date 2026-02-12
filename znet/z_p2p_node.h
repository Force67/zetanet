// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>
#include <znet/z_transport.h>

#include <mutex>
#include <queue>
#include <string>

namespace tx::network {

class ZNET_API ZP2PNode final : public ZAsyncTransportLayer {
 public:
  enum class Type { Host, Client };

  bool Begin(u16 port);
  bool Connect(const base::StringRef host_ip, u16 host_port, u16 local_port);

  bool Update();
  bool Poll(PacketChannelType channel, IncomingPacket& packet);
  void SendMessage(ZPeerId id, const std::string& data);

  void BecomeHost();
  Type type() const { return type_; }
  bool is_host() const { return type_ == Type::Host; }

 private:
  enum class ControlKind : u8 {
    Invalid = 0,
    JoinHello = 1,
    PeerRoster = 2,
    HostTransition = 3,
  };

  bool InitAsHost(u16 port);
  bool InitAsClient(const base::StringRef host_ip, u16 host_port, u16 local_port);
  bool PromoteToHost(bool announce_transition);
  bool ReconnectToHost(const ZSocket::Address& endpoint);

  void ProcessIncomingPacket(const IncomingPacket& packet);
  void ProcessControlPacket(const IncomingPacket& packet);

  void SendJoinHello();
  void BroadcastPeerRoster();
  void BroadcastHostTransition(const ZSocket::Address& endpoint);
  void PushControlPacket(u32 destination_peer_id, const base::Vector<byte>& payload);

  static bool SerializeAddress(base::Vector<byte>& buffer,
                               const ZSocket::Address& address);
  static bool DeserializeAddress(const byte* data,
                                 size_t data_size,
                                 size_t& cursor,
                                 ZSocket::Address& address);
  static bool IsSelfAddress(const ZSocket::Address& address, u16 self_port);

  void QueueIncoming(const IncomingPacket& packet);
  void SetHostEndpoint(const ZSocket::Address& endpoint);

 private:
  static constexpr u32 kControlMagic = 0x5A503250;  // "ZP2P"
  static constexpr u8 kControlVersion = 1;

  Type type_{Type::Host};
  u16 local_port_{0};
  std::string advertised_ip_{"127.0.0.1"};
  ZSocket::Address host_endpoint_{};

  std::mutex incoming_mutex_;
  std::queue<IncomingPacket> incoming_control_;
  std::queue<IncomingPacket> incoming_data_;
};
}  // namespace tx::network
