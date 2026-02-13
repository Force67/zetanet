// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#include "z_p2p_node.h"

#include <znet/z_stl_compat.h>

#include <chrono>
#include <cstring>
#include <thread>

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-p2p-node";

bool ReadU16(const byte* data, size_t data_size, size_t& cursor, u16& out) {
  if (cursor + sizeof(u16) > data_size) {
    return false;
  }
  out = static_cast<u16>(data[cursor] |
                         (static_cast<u16>(data[cursor + 1]) << 8));
  cursor += sizeof(u16);
  return true;
}

bool ReadU32(const byte* data, size_t data_size, size_t& cursor, u32& out) {
  if (cursor + sizeof(u32) > data_size) {
    return false;
  }
  out = static_cast<u32>(data[cursor]) |
        (static_cast<u32>(data[cursor + 1]) << 8) |
        (static_cast<u32>(data[cursor + 2]) << 16) |
        (static_cast<u32>(data[cursor + 3]) << 24);
  cursor += sizeof(u32);
  return true;
}

void PushU16(base::Vector<byte>& out, u16 value) {
  out.push_back(static_cast<byte>(value & 0xFFu));
  out.push_back(static_cast<byte>((value >> 8) & 0xFFu));
}

void PushU32(base::Vector<byte>& out, u32 value) {
  out.push_back(static_cast<byte>(value & 0xFFu));
  out.push_back(static_cast<byte>((value >> 8) & 0xFFu));
  out.push_back(static_cast<byte>((value >> 16) & 0xFFu));
  out.push_back(static_cast<byte>((value >> 24) & 0xFFu));
}

bool AddressFromString(const base::StringRef ip, u16 port, ZSocket::Address& out) {
  if (ip.empty() || ip.size() >= sizeof(out.ip)) {
    return false;
  }
  std::memset(&out, 0, sizeof(out));
  std::memcpy(out.ip, ip.data(), ip.size());
  out.port = port;
  // Detect address family from IP string
  base::String ip_str(ip.data(), ip.size());
  out.address_family = (ip_str.find(':') != base::String::npos) ? AF_INET6 : AF_INET;
  return true;
}
}  // namespace

bool ZP2PNode::Begin(u16 port) {
  if (port == 0) {
    BASE_LOGE(kLogTag, "Begin() requires a non-zero port");
    return false;
  }
  local_port_ = port;
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
  if (!AddressFromString(base::StringRef(advertised_ip_.data(), advertised_ip_.size()),
                         port, endpoint)) {
    BASE_LOGE(kLogTag, "Failed to build host endpoint");
    Deinit();
    return false;
  }
  SetHostEndpoint(endpoint);
  type_ = Type::Host;
  state_ = State::kConnected;
  return true;
}

bool ZP2PNode::InitAsClient(const base::StringRef host_ip,
                            u16 host_port,
                            u16 local_port) {
  Deinit();
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
    if (!IsSelfAddress(peer.address, local_port_)) {
      known_peers.push_back(peer.address);
    }
  }

  if (announce_transition && state_ == State::kConnected) {
    ZSocket::Address new_host{};
    if (!AddressFromString(
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
    if (!IsSelfAddress(peer_address, local_port_)) {
      peer_mapping_.GetOrCreatePeer(peer_address);
    }
  }
  BroadcastPeerRoster();
  return true;
}

bool ZP2PNode::ReconnectToHost(const ZSocket::Address& endpoint) {
  if (IsSelfAddress(endpoint, local_port_)) {
    return PromoteToHost(false);
  }

  base::Vector<ZSocket::Address> known_peers;
  for (const auto& peer : peer_mapping_.GetPeerList()) {
    if (!IsSelfAddress(peer.address, local_port_)) {
      known_peers.push_back(peer.address);
    }
  }

  if (!InitAsClient(base::StringRef(endpoint.ip), endpoint.port, local_port_)) {
    return false;
  }

  for (const auto& peer_address : known_peers) {
    if (!IsSelfAddress(peer_address, local_port_)) {
      peer_mapping_.GetOrCreatePeer(peer_address);
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
  const size_t size = packet.data.size();
  size_t cursor = 0;

  u32 magic = 0;
  if (!ReadU32(data, size, cursor, magic) || magic != kControlMagic) {
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
      if (type_ != Type::Host) {
        return;
      }
      if (!source_peer) {
        return;
      }
      peer_mapping_.GetOrCreatePeer(source_peer->address);
      BroadcastPeerRoster();
      break;
    }
    case ControlKind::PeerRoster: {
      if (type_ == Type::Client) {
        if (!source_peer || !(source_peer->address == host_endpoint_)) {
          return;
        }
      }
      u16 peer_count = 0;
      if (!ReadU16(data, size, cursor, peer_count)) {
        return;
      }
      for (u16 i = 0; i < peer_count; ++i) {
        ZSocket::Address peer_address{};
        if (!DeserializeAddress(data, size, cursor, peer_address)) {
          return;
        }
        if (IsSelfAddress(peer_address, local_port_)) {
          continue;
        }
        peer_mapping_.GetOrCreatePeer(peer_address);
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
      if (IsSelfAddress(next_host, local_port_)) {
        PromoteToHost(false);
        return;
      }
      if (!ReconnectToHost(next_host)) {
        BASE_LOGE(kLogTag, "Failed to reconnect to transitioned host {}:{}",
                  next_host.ip, next_host.port);
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
  PushU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::JoinHello));
  PushU16(payload, local_port_);
  PushControlPacket(ZPeerId::to_server, payload);
}

void ZP2PNode::BroadcastPeerRoster() {
  if (type_ != Type::Host) {
    return;
  }
  base::Vector<ZSocket::Address> roster;
  roster.push_back(host_endpoint_);
  for (const auto& peer : peer_mapping_.GetPeerList()) {
    if (!IsSelfAddress(peer.address, local_port_)) {
      roster.push_back(peer.address);
    }
  }

  if (roster.size() > 0xFFFFu) {
    BASE_LOGE(kLogTag, "Peer roster too large: {}", roster.size());
    return;
  }

  base::Vector<byte> payload;
  payload.reserve(16 + roster.size() * 24);
  PushU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::PeerRoster));
  PushU16(payload, static_cast<u16>(roster.size()));
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
  PushU32(payload, kControlMagic);
  payload.push_back(kControlVersion);
  payload.push_back(static_cast<byte>(ControlKind::HostTransition));
  if (!SerializeAddress(payload, endpoint)) {
    BASE_LOGE(kLogTag, "Failed to serialize host transition endpoint");
    return;
  }
  PushControlPacket(ZPeerId::to_all, payload);
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

bool ZP2PNode::SerializeAddress(base::Vector<byte>& buffer,
                                const ZSocket::Address& address) {
  const size_t ip_len = strnlen(address.ip, sizeof(address.ip));
  if (ip_len == 0 || ip_len > 0xFFu) {
    return false;
  }
  buffer.push_back(static_cast<byte>(address.address_family));
  buffer.push_back(static_cast<byte>(ip_len));
  for (size_t i = 0; i < ip_len; ++i) {
    buffer.push_back(static_cast<byte>(address.ip[i]));
  }
  PushU16(buffer, address.port);
  return true;
}

bool ZP2PNode::DeserializeAddress(const byte* data,
                                  size_t data_size,
                                  size_t& cursor,
                                  ZSocket::Address& address) {
  if (cursor >= data_size) {
    return false;
  }
  const u8 addr_family = data[cursor++];
  if (cursor >= data_size) {
    return false;
  }
  const size_t ip_len = data[cursor++];
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
  if (!ReadU16(data, data_size, cursor, port)) {
    return false;
  }
  address.port = port;
  return true;
}

bool ZP2PNode::IsSelfAddress(const ZSocket::Address& address, u16 self_port) {
  if (self_port == 0 || address.port != self_port) {
    return false;
  }
  if (std::strcmp(address.ip, "127.0.0.1") == 0 ||
      std::strcmp(address.ip, "0.0.0.0") == 0 ||
      std::strcmp(address.ip, "::1") == 0) {
    return true;
  }
  return false;
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
