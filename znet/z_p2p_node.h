// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>
#include <znet/z_clock.h>
#include <znet/z_stl_compat.h>
#include <znet/z_transport.h>

#include <chrono>
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
  void SendMessage(ZPeerId id, const base::String& data);

  void BecomeHost();
  Type type() const { return type_; }
  bool is_host() const { return type_ == Type::Host; }

 private:
  enum class ControlKind : u8 {
    Invalid = 0,
    JoinHello = 1,
    PeerRoster = 2,
    HostTransition = 3,
    KeepAlive = 4,
    PunchProbe = 5,
    PunchAck = 6,
    Welcome = 7,
  };

  struct PunchPeerState {
    ZSocket::Address address{};
    u32 attempts_sent{0};
    bool acknowledged{false};
    base::Clock::time_point next_probe_time{};
    base::Clock::time_point last_keepalive_time{};
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
  void SendWelcome(const ZPeer& peer);
  void SendPunchProbe(const ZSocket::Address& endpoint);
  void SendPunchAck(const ZSocket::Address& endpoint);
  void SendKeepAlive(const ZSocket::Address& endpoint);
  void TickNatPunchthrough();
  PunchPeerState* FindPunchPeerState(const ZSocket::Address& endpoint);
  PunchPeerState& GetOrCreatePunchPeerState(const ZSocket::Address& endpoint);
  void ArmPunchProbe(const ZSocket::Address& endpoint);
  bool IsSelfAddress(const ZSocket::Address& address) const;
  void PushControlPacket(u32 destination_peer_id, const base::Vector<byte>& payload);
  void PushControlPacketToAddress(const ZSocket::Address& destination,
                                  const base::Vector<byte>& payload);

  static bool SerializeAddress(base::Vector<byte>& buffer,
                               const ZSocket::Address& address);
  static bool DeserializeAddress(const byte* data,
                                 mem_size data_size,
                                 mem_size& cursor,
                                 ZSocket::Address& address);

  void QueueIncoming(const IncomingPacket& packet);
  void SetHostEndpoint(const ZSocket::Address& endpoint);

 private:
  static constexpr u32 kControlMagic = 0x5A503250;  // "ZP2P"
  static constexpr u8 kControlVersion = 1;

  Type type_{Type::Host};
  u16 local_port_{0};
  base::String advertised_ip_{"127.0.0.1"};
  ZSocket::Address host_endpoint_{};
  ZSocket::Address public_endpoint_{};
  bool has_public_endpoint_{false};
  base::Clock::time_point last_host_keepalive_time_{};
  base::Vector<PunchPeerState> punch_peers_;

  base::Mutex incoming_mutex_;
  base::Queue<IncomingPacket> incoming_control_;
  base::Queue<IncomingPacket> incoming_data_;
};
}  // namespace tx::network
