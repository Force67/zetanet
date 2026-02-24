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
  struct StartOptions {
    bool use_encryption{false};
    base::StringRef pre_shared_key{};
    bool use_compression{false};
    bool allow_ipv6{false};
    bool start_threads{true};
    ZSocket::ChaosOptions chaos{};
  };

  enum class Type { Host, Client };

  enum class PeerEventType : u8 {
    PeerJoined = 1,
    PeerLeft = 2,
    RelayFallback = 3,
    Reconnected = 4,
    ConnectionFailure = 5,
  };

  struct PeerEvent {
    PeerEventType type{PeerEventType::PeerJoined};
    u32 peer_id{0};
    u32 detail{0};
  };

  bool Begin(u16 port);
  bool Begin(u16 port, const StartOptions& options);
  bool Connect(const base::StringRef host_ip, u16 host_port, u16 local_port);
  bool Connect(const base::StringRef host_ip,
               u16 host_port,
               u16 local_port,
               const StartOptions& options);

  bool Update();
  bool Poll(PacketChannelType channel, IncomingPacket& packet);
  void SendMessage(ZPeerId id, const base::String& data);
  bool SendPacket(OutgoingPacket&& packet);
  bool PollPeerEvent(PeerEvent& event);

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
    RelayRequest = 8,
    RelayDelivery = 9,
  };

  struct PunchPeerState {
    ZSocket::Address address{};
    u32 attempts_sent{0};
    bool acknowledged{false};
    bool relay_mode{false};
    base::Clock::time_point next_probe_time{};
    base::Clock::time_point last_keepalive_time{};
  };

  struct RelayEnvelope {
    PacketChannelType channel{PacketChannelType::Data};
    PackageFlags flags{};
    PacketType packet_type{PacketType::Message};
    u32 source_peer_id{0};
    u32 destination_peer_id{0};
    u32 acknowledgement_number{0};
    u32 sequence_number{0};
    base::String payload{};
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
  bool SendRelayRequest(const OutgoingPacket& packet);
  bool ForwardRelayEnvelope(const RelayEnvelope& envelope);
  void HandleRelayRequest(const IncomingPacket& packet,
                          const byte* data,
                          mem_size data_size,
                          mem_size& cursor);
  void HandleRelayDelivery(const byte* data,
                           mem_size data_size,
                           mem_size& cursor);
  static bool SerializeRelayEnvelope(ControlKind kind,
                                     const RelayEnvelope& envelope,
                                     base::Vector<byte>& out_payload);
  static bool DeserializeRelayEnvelope(const byte* data,
                                       mem_size data_size,
                                       mem_size& cursor,
                                       RelayEnvelope& out_envelope);
  bool IsHostPeerId(u32 peer_id);
  bool ShouldUseRelayForPeer(u32 peer_id);
  void EmitPeerEvent(PeerEventType type, u32 peer_id, u32 detail = 0);
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
  StartOptions start_options_{};
  u16 local_port_{0};
  base::String advertised_ip_{"127.0.0.1"};
  ZSocket::Address host_endpoint_{};
  ZSocket::Address public_endpoint_{};
  bool has_public_endpoint_{false};
  base::Clock::time_point last_host_keepalive_time_{};
  base::Vector<PunchPeerState> punch_peers_;
  base::Map<u32, bool> relay_announcement_state_{};
  base::Map<u32, base::Clock::time_point> recently_seen_peers_{};
  base::Map<u32, bool> announced_peer_presence_{};

  base::Mutex incoming_mutex_;
  base::Queue<IncomingPacket> incoming_control_;
  base::Queue<IncomingPacket> incoming_data_;
  base::Mutex event_mutex_;
  base::Queue<PeerEvent> peer_events_;
};
}  // namespace tx::network
