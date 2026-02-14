// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#include "z_p2p_node.h"
#include "z_wire_le.h"

#include <znet/z_stl_compat.h>

#include <chrono>
#include <cstring>
#include <thread>

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-p2p-node";
constexpr auto kPunchProbeInterval = std::chrono::milliseconds(120);
constexpr u32 kMaxPunchProbeAttempts = 12;
constexpr auto kPeerKeepAliveInterval = std::chrono::seconds(10);
constexpr auto kHostKeepAliveInterval = std::chrono::seconds(2);

bool AddressFromString(const base::StringRef ip, u16 port, ZSocket::Address& out) {
  return ZSocket::ResolveAddress(ip, port, /*ipv6=*/false, out);
}
}  // namespace

bool ZP2PNode::Begin(u16 port) {
  if (port == 0) {
    BASE_LOGE(kLogTag, "Begin() requires a non-zero port");
    return false;
  }
  local_port_ = port;
  has_public_endpoint_ = false;
  std::memset(&public_endpoint_, 0, sizeof(public_endpoint_));
  return InitAsHost(port);
}

bool ZP2PNode::Connect(const base::StringRef host_ip,
                       u16 host_port,
                       u16 local_port) {
  if (host_port == 0 || local_port == 0) {
    BASE_LOGE(kLogTag, "Connect() requires non-zero host_port/local_port");
    return false;
  }
  local_port_ = local_port;
  if (!InitAsClient(host_ip, host_port, local_port_)) {
    return false;
  }
  SendJoinHello();
  return true;
}

bool ZP2PNode::Update() {
  IncomingPacket packet;
  while (packet_queue_.Pop(PacketChannelType::Control, packet)) {
    ProcessIncomingPacket(packet);
  }
  while (packet_queue_.Pop(PacketChannelType::Data, packet)) {
    ProcessIncomingPacket(packet);
  }
  TickNatPunchthrough();
  return state_ != State::kDisconnected;
}

bool ZP2PNode::Poll(PacketChannelType channel, IncomingPacket& packet) {
  std::lock_guard<base::Mutex> lock(incoming_mutex_);
  auto& queue =
      channel == PacketChannelType::Control ? incoming_control_ : incoming_data_;
  if (queue.empty()) {
    return false;
  }
  packet = std::move(queue.front());
  queue.pop();
  return true;
}

void ZP2PNode::SendMessage(ZPeerId id, const base::String& data) {
  if (state_ != State::kConnected) {
    return;
  }
  const u8 use_encryption = crypto_context_ ? 1 : 0;
  const u8 use_compression = compression_enabled() ? 1 : 0;
  const PackageFlags flags{.reliable = 1,
                           .encrypted = use_encryption,
                           .compressed = use_compression,
                           .priority = static_cast<u8>(PacketPriority::Medium),
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};

  OutgoingPacket out(
      id.id, PacketType::Message, PacketChannelType::Data, flags,
      base::Span<byte>(reinterpret_cast<const byte*>(data.data()), data.size()));
  packet_queue_.Push(std::move(out));
}

void ZP2PNode::BecomeHost() {
  if (!PromoteToHost(true)) {
    BASE_LOGE(kLogTag, "BecomeHost() failed");
  }
}

bool ZP2PNode::InitAsHost(u16 port) {
  Deinit();
  punch_peers_.clear();
  {
    std::lock_guard<base::Mutex> lock(incoming_mutex_);
    while (!incoming_control_.empty()) {
      incoming_control_.pop();
    }
    while (!incoming_data_.empty()) {
      incoming_data_.pop();
    }
  }
  const ZAsyncTransportLayer::InitOptions options{
      .ip = base::StringRef(advertised_ip_.data(), advertised_ip_.size()),
      .port = port,
      .local_bind_port = 0,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kServer,
      .use_encryption = false,
      .use_compression = false,
      .allow_ipv6 = false};
  if (!ZAsyncTransportLayer::Init(options)) {
    return false;
  }

  ZSocket::Address endpoint{};
  if (has_public_endpoint_) {
    endpoint = public_endpoint_;
  } else if (!AddressFromString(
                 base::StringRef(advertised_ip_.data(), advertised_ip_.size()),
                 port, endpoint)) {
    BASE_LOGE(kLogTag, "Failed to build host endpoint");
    Deinit();
    return false;
  }

  SetHostEndpoint(endpoint);
  type_ = Type::Host;
  state_ = State::kConnected;
  last_host_keepalive_time_ = std::chrono::steady_clock::now();
  return true;
}

bool ZP2PNode::InitAsClient(const base::StringRef host_ip,
                            u16 host_port,
                            u16 local_port) {
  Deinit();
  punch_peers_.clear();
  has_public_endpoint_ = false;
  std::memset(&public_endpoint_, 0, sizeof(public_endpoint_));
  {
    std::lock_guard<base::Mutex> lock(incoming_mutex_);
    while (!incoming_control_.empty()) {
      incoming_control_.pop();
    }
    while (!incoming_data_.empty()) {
      incoming_data_.pop();
    }
  }
  const ZAsyncTransportLayer::InitOptions options{
      .ip = host_ip,
      .port = host_port,
      .local_bind_port = local_port,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kClient,
      .use_encryption = false,
      .use_compression = false,
      .allow_ipv6 = false};
  if (!ZAsyncTransportLayer::Init(options)) {
    return false;
  }

  ZSocket::Address endpoint{};
  if (!AddressFromString(host_ip, host_port, endpoint)) {
    BASE_LOGE(kLogTag, "Failed to store host endpoint");
    Deinit();
    return false;
  }

  SetHostEndpoint(endpoint);
  type_ = Type::Client;
  state_ = State::kConnected;
  last_host_keepalive_time_ = std::chrono::steady_clock::now();
  return true;
}

bool ZP2PNode::PromoteToHost(bool announce_transition) {
  if (type_ == Type::Host && state_ == State::kConnected) {
    return true;
  }
  if (local_port_ == 0) {
    BASE_LOGE(kLogTag, "Cannot promote to host without a fixed local port");
    return false;
  }

  base::Vector<ZSocket::Address> known_peers;
  for (const auto& peer : peer_mapping_.GetPeerList()) {
    if (!IsSelfAddress(peer.address)) {
      known_peers.push_back(peer.address);
    }
  }

  if (announce_transition && state_ == State::kConnected) {
    ZSocket::Address new_host{};
    if (has_public_endpoint_) {
      new_host = public_endpoint_;
    } else if (!AddressFromString(
                   base::StringRef(advertised_ip_.data(), advertised_ip_.size()),
                   local_port_, new_host)) {
      BASE_LOGE(kLogTag, "Failed to create transition host endpoint");
      return false;
    }

    BroadcastHostTransition(new_host);
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
  }

  if (!InitAsHost(local_port_)) {
    return false;
  }

  for (const auto& peer_address : known_peers) {
    if (!IsSelfAddress(peer_address)) {
      peer_mapping_.GetOrCreatePeer(peer_address);
      ArmPunchProbe(peer_address);
    }
  }
  BroadcastPeerRoster();
  return true;
}

bool ZP2PNode::ReconnectToHost(const ZSocket::Address& endpoint) {
  if (IsSelfAddress(endpoint)) {
    return PromoteToHost(false);
  }

  base::Vector<ZSocket::Address> known_peers;
  for (const auto& peer : peer_mapping_.GetPeerList()) {
    if (!IsSelfAddress(peer.address)) {
      known_peers.push_back(peer.address);
    }
  }

  if (!InitAsClient(base::StringRef(endpoint.ip), endpoint.port, local_port_)) {
    return false;
  }

  for (const auto& peer_address : known_peers) {
    if (!IsSelfAddress(peer_address)) {
      peer_mapping_.GetOrCreatePeer(peer_address);
      ArmPunchProbe(peer_address);
    }
  }
  SendJoinHello();
  return true;
}

void ZP2PNode::ProcessIncomingPacket(const IncomingPacket& packet) {
  if (packet.channel == PacketChannelType::Control &&
      packet.type == PacketType::NetworkControl) {
    ProcessControlPacket(packet);
    return;
  }
  QueueIncoming(packet);
}

void ZP2PNode::ProcessControlPacket(const IncomingPacket& packet) {
  const byte* data = reinterpret_cast<const byte*>(packet.data.data());
  const mem_size size = packet.data.size();
  mem_size cursor = 0;

  u32 magic = 0;
  if (!wire_le::ReadU32(data, size, cursor, magic) || magic != kControlMagic) {
    return;
  }
  if (cursor >= size) {
    return;
  }
  const u8 version = data[cursor++];
  if (version != kControlVersion) {
    return;
  }
  if (cursor >= size) {
    return;
  }
  const ControlKind kind = static_cast<ControlKind>(data[cursor++]);
  ZPeer* source_peer = peer_mapping_.GetPeer(ZPeerId(packet.source_peer_id));

  switch (kind) {
    case ControlKind::JoinHello: {
      if (type_ != Type::Host || !source_peer) {
        return;
      }

      // Optional compatibility field: announced local port from joining node.
      u16 announced_local_port = 0;
      if (cursor + sizeof(u16) <= size) {
        wire_le::ReadU16(data, size, cursor, announced_local_port);
      }
      (void)announced_local_port;

      peer_mapping_.GetOrCreatePeer(source_peer->address);
      SendWelcome(*source_peer);
      BroadcastPeerRoster();
      break;
    }
    case ControlKind::Welcome: {
      if (type_ != Type::Client) {
        return;
      }
      if (!source_peer || !(source_peer->address == host_endpoint_)) {
        return;
      }

      ZSocket::Address observed_endpoint{};
      if (!DeserializeAddress(data, size, cursor, observed_endpoint)) {
        return;
      }

      public_endpoint_ = observed_endpoint;
      has_public_endpoint_ = true;
      break;
    }
    case ControlKind::PeerRoster: {
      if (type_ == Type::Client) {
        if (!source_peer || !(source_peer->address == host_endpoint_)) {
          return;
        }
      }
      u16 peer_count = 0;
      if (!wire_le::ReadU16(data, size, cursor, peer_count)) {
        return;
      }
      for (u16 i = 0; i < peer_count; ++i) {
        ZSocket::Address peer_address{};
        if (!DeserializeAddress(data, size, cursor, peer_address)) {
          return;
        }
        if (IsSelfAddress(peer_address)) {
          continue;
        }
        peer_mapping_.GetOrCreatePeer(peer_address);
        if (type_ == Type::Client && !(peer_address == host_endpoint_)) {
          ArmPunchProbe(peer_address);
        }
      }
      break;
    }
    case ControlKind::HostTransition: {
      if (type_ == Type::Client) {
        if (!source_peer || !(source_peer->address == host_endpoint_)) {
          return;
        }
      }
      ZSocket::Address next_host{};
      if (!DeserializeAddress(data, size, cursor, next_host)) {
        return;
      }
      if (IsSelfAddress(next_host)) {
        PromoteToHost(false);
        return;
      }
      if (!ReconnectToHost(next_host)) {
        BASE_LOGE(kLogTag, "Failed to reconnect to transitioned host {}:{}",
                  next_host.ip, next_host.port);
      }
      break;
    }
    case ControlKind::KeepAlive: {
      if (!source_peer) {
        return;
      }
      if (!IsSelfAddress(source_peer->address)) {
        auto& state = GetOrCreatePunchPeerState(source_peer->address);
        state.last_keepalive_time = std::chrono::steady_clock::now();
      }
      break;
    }
    case ControlKind::PunchProbe: {
      if (!source_peer) {
        return;
      }
      if (!IsSelfAddress(source_peer->address)) {
        auto& state = GetOrCreatePunchPeerState(source_peer->address);
        state.last_keepalive_time = std::chrono::steady_clock::now();
        ArmPunchProbe(source_peer->address);
        SendPunchAck(source_peer->address);
      }
      break;
    }
    case ControlKind::PunchAck: {
      if (!source_peer) {
        return;
      }
      if (!IsSelfAddress(source_peer->address)) {
        auto& state = GetOrCreatePunchPeerState(source_peer->address);
        state.acknowledged = true;
        state.last_keepalive_time = std::chrono::steady_clock::now();
      }
      break;
    }
    default:
      break;
  }
}

void ZP2PNode::SendJoinHello() {
  base::Vector<byte> payload;
  payload.reserve(12);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::JoinHello));
  wire_le::AppendU16(payload, local_port_);
  PushControlPacket(ZPeerId::to_server, payload);
}

void ZP2PNode::BroadcastPeerRoster() {
  if (type_ != Type::Host) {
    return;
  }
  base::Vector<ZSocket::Address> roster;
  for (const auto& peer : peer_mapping_.GetPeerList()) {
    if (!IsSelfAddress(peer.address)) {
      roster.push_back(peer.address);
    }
  }

  if (roster.size() > 0xFFFFu) {
    BASE_LOGE(kLogTag, "Peer roster too large: {}", roster.size());
    return;
  }

  base::Vector<byte> payload;
  payload.reserve(16 + roster.size() * 24);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::PeerRoster));
  wire_le::AppendU16(payload, static_cast<u16>(roster.size()));
  for (const auto& address : roster) {
    if (!SerializeAddress(payload, address)) {
      BASE_LOGE(kLogTag, "Failed to serialize roster address {}:{}",
                address.ip, address.port);
      return;
    }
  }
  PushControlPacket(ZPeerId::to_all, payload);
}

void ZP2PNode::BroadcastHostTransition(const ZSocket::Address& endpoint) {
  base::Vector<byte> payload;
  payload.reserve(48);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::HostTransition));
  if (!SerializeAddress(payload, endpoint)) {
    BASE_LOGE(kLogTag, "Failed to serialize host transition endpoint");
    return;
  }
  PushControlPacket(ZPeerId::to_all, payload);
}

void ZP2PNode::SendWelcome(const ZPeer& peer) {
  base::Vector<byte> payload;
  payload.reserve(48);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::Welcome));
  if (!SerializeAddress(payload, peer.address)) {
    BASE_LOGE(kLogTag, "Failed to serialize welcome endpoint for peer {}",
              peer.identifier.id);
    return;
  }
  PushControlPacket(peer.identifier.id, payload);
}

void ZP2PNode::SendPunchProbe(const ZSocket::Address& endpoint) {
  base::Vector<byte> payload;
  payload.reserve(8);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::PunchProbe));
  PushControlPacketToAddress(endpoint, payload);
}

void ZP2PNode::SendPunchAck(const ZSocket::Address& endpoint) {
  base::Vector<byte> payload;
  payload.reserve(8);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::PunchAck));
  PushControlPacketToAddress(endpoint, payload);
}

void ZP2PNode::SendKeepAlive(const ZSocket::Address& endpoint) {
  base::Vector<byte> payload;
  payload.reserve(8);
  wire_le::AppendU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::KeepAlive));
  PushControlPacketToAddress(endpoint, payload);
}

void ZP2PNode::TickNatPunchthrough() {
  if (state_ != State::kConnected) {
    return;
  }

  const auto now = std::chrono::steady_clock::now();

  if (type_ == Type::Client && !IsSelfAddress(host_endpoint_)) {
    if (last_host_keepalive_time_.time_since_epoch().count() == 0 ||
        now - last_host_keepalive_time_ >= kHostKeepAliveInterval) {
      SendKeepAlive(host_endpoint_);
      last_host_keepalive_time_ = now;
    }
  }

  for (auto& punch_peer : punch_peers_) {
    if (IsSelfAddress(punch_peer.address)) {
      continue;
    }
    if (type_ == Type::Client && (punch_peer.address == host_endpoint_)) {
      continue;
    }

    if (!punch_peer.acknowledged) {
      if (punch_peer.attempts_sent < kMaxPunchProbeAttempts &&
          now >= punch_peer.next_probe_time) {
        SendPunchProbe(punch_peer.address);
        ++punch_peer.attempts_sent;
        punch_peer.next_probe_time = now + kPunchProbeInterval;
        punch_peer.last_keepalive_time = now;
      }
      continue;
    }

    if (punch_peer.last_keepalive_time.time_since_epoch().count() == 0 ||
        now - punch_peer.last_keepalive_time >= kPeerKeepAliveInterval) {
      SendKeepAlive(punch_peer.address);
      punch_peer.last_keepalive_time = now;
    }
  }
}

ZP2PNode::PunchPeerState* ZP2PNode::FindPunchPeerState(
    const ZSocket::Address& endpoint) {
  for (auto& state : punch_peers_) {
    if (state.address == endpoint) {
      return &state;
    }
  }
  return nullptr;
}

ZP2PNode::PunchPeerState& ZP2PNode::GetOrCreatePunchPeerState(
    const ZSocket::Address& endpoint) {
  if (auto* existing = FindPunchPeerState(endpoint)) {
    return *existing;
  }

  PunchPeerState state{};
  state.address = endpoint;
  state.next_probe_time = std::chrono::steady_clock::now();
  state.last_keepalive_time = state.next_probe_time;
  punch_peers_.push_back(state);
  return punch_peers_.back();
}

void ZP2PNode::ArmPunchProbe(const ZSocket::Address& endpoint) {
  if (IsSelfAddress(endpoint)) {
    return;
  }
  if (type_ == Type::Client && endpoint == host_endpoint_) {
    return;
  }

  auto& state = GetOrCreatePunchPeerState(endpoint);
  if (state.acknowledged) {
    return;
  }

  if (state.attempts_sent >= kMaxPunchProbeAttempts) {
    state.attempts_sent = 0;
  }
  state.next_probe_time = std::chrono::steady_clock::now();
}

bool ZP2PNode::IsSelfAddress(const ZSocket::Address& address) const {
  if (has_public_endpoint_ && address == public_endpoint_) {
    return true;
  }

  if (local_port_ == 0 || address.port != local_port_) {
    return false;
  }

  if (std::strcmp(address.ip, "127.0.0.1") == 0 ||
      std::strcmp(address.ip, "0.0.0.0") == 0 ||
      std::strcmp(address.ip, "::1") == 0) {
    return true;
  }

  return false;
}

void ZP2PNode::PushControlPacket(u32 destination_peer_id,
                                 const base::Vector<byte>& payload) {
  if (state_ != State::kConnected) {
    return;
  }
  const u8 use_encryption = crypto_context_ ? 1 : 0;
  const PackageFlags flags{.reliable = 1,
                           .encrypted = use_encryption,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::High),
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(destination_peer_id, PacketType::NetworkControl,
                     PacketChannelType::Control, flags,
                     base::Span<byte>(payload.data(), payload.size()));
  packet_queue_.Push(std::move(out));
}

void ZP2PNode::PushControlPacketToAddress(const ZSocket::Address& destination,
                                          const base::Vector<byte>& payload) {
  ZPeer* peer = peer_mapping_.GetOrCreatePeer(destination);
  if (!peer) {
    BASE_LOGE(kLogTag, "Failed to route control packet to {}:{}",
              destination.ip, destination.port);
    return;
  }
  PushControlPacket(peer->identifier.id, payload);
}

bool ZP2PNode::SerializeAddress(base::Vector<byte>& buffer,
                                const ZSocket::Address& address) {
  const mem_size ip_len = strnlen(address.ip, sizeof(address.ip));
  if (ip_len == 0 || ip_len > 0xFFu) {
    return false;
  }
  buffer.push_back(static_cast<byte>(address.address_family));
  buffer.push_back(static_cast<byte>(ip_len));
  for (mem_size i = 0; i < ip_len; ++i) {
    buffer.push_back(static_cast<byte>(address.ip[i]));
  }
  wire_le::AppendU16(buffer, address.port);
  return true;
}

bool ZP2PNode::DeserializeAddress(const byte* data,
                                  mem_size data_size,
                                  mem_size& cursor,
                                  ZSocket::Address& address) {
  if (cursor >= data_size) {
    return false;
  }
  const u8 addr_family = data[cursor++];
  if (cursor >= data_size) {
    return false;
  }
  const mem_size ip_len = data[cursor++];
  if (ip_len == 0 || ip_len >= sizeof(address.ip)) {
    return false;
  }
  if (cursor + ip_len + sizeof(u16) > data_size) {
    return false;
  }

  std::memset(&address, 0, sizeof(address));
  address.address_family = addr_family;
  std::memcpy(address.ip, data + cursor, ip_len);
  cursor += ip_len;

  u16 port = 0;
  if (!wire_le::ReadU16(data, data_size, cursor, port)) {
    return false;
  }
  address.port = port;
  return true;
}

void ZP2PNode::QueueIncoming(const IncomingPacket& packet) {
  std::lock_guard<base::Mutex> lock(incoming_mutex_);
  auto& queue = packet.channel == PacketChannelType::Control ? incoming_control_
                                                              : incoming_data_;
  queue.push(packet);
}

void ZP2PNode::SetHostEndpoint(const ZSocket::Address& endpoint) {
  host_endpoint_ = endpoint;
}

}  // namespace tx::network
