// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_server.h"
#include "z_system_command.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-server";
static constexpr char kSelfAddress[] =
    "127.0.0.1";

bool ZServer::Begin(u16 port) {
  const ZAsyncTransportLayer::InitOptions options{
      .ip = kSelfAddress,
      .port = port,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kServer,
      .use_encryption = false,
      .use_compression = false,
      .allow_ipv6 = false};
  bool result = ZAsyncTransportLayer::Init(options);
  if (!result) {
    BASE_LOGE(kLogTag, "Failed to initialize ZAsyncTransportLayer");
    return false;
  }

  state_ = ZAsyncTransportLayer::State::kConnected;
  return true;
}

bool ZServer::Update() {
  IncomingPacket packet;
  if (Poll(PacketChannelType::Data, packet)) {
    BASE_LOGI(kLogTag, "Incoming data: {}", packet.data);
  }
  switch (state()) {
    case ZAsyncTransportLayer::State::kDisconnected:
      BASE_LOGI(kLogTag, "Disconnected");
      break;
    case ZAsyncTransportLayer::State::kConnecting:
      BASE_LOGI(kLogTag, "Connecting");
      break;
    case ZAsyncTransportLayer::State::kConnected:
      break;
    case ZAsyncTransportLayer::State::kDisconnecting:
      BASE_LOGI(kLogTag, "Disconnecting");
      break;
  }

  return true;
}

void ZServer::SendMessage(ZPeerId id, const std::string& data) {
  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Medium,
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(
      id.id, PacketType::Message, PacketChannelType::Data, flags,
      base::Span<byte>(reinterpret_cast<const byte*>(data.data()),
                       data.size()));
  Push(std::move(out));
}

void ZServer::ProcessSystemMessage(const IncomingPacket& p) {
  switch (p.type) {
    case PacketType::ClientHello: {
      BASE_LOGI(kLogTag, "Received ClientHello");
      SendServerHello(p.source_peer_id);
      break;
    }
    default:
      break;
  }
}

void ZServer::SendServerHello(ZPeerId dest) {
  constexpr EncryptionAlgorithm encryption_algorithms[] = {
      EncryptionAlgorithm::AESCBC128};
  constexpr CompressionAlgorithm compression_algorithms[] = {
      CompressionAlgorithm::LZ4};

  PacketWriter writer;
  system_commands::ServerHello request{
      .encryption_algo_list_len = (u8)_countof(encryption_algorithms),
      .compression_algo_list_len = (u8)_countof(compression_algorithms),
      .pub_key_list_len = 1};
  writer.Put(request);

  for (int i = 0; i < request.encryption_algo_list_len; i++) {
    writer.Put((u8)encryption_algorithms[i]);
  }
  for (int i = 0; i < request.compression_algo_list_len; i++) {
    writer.Put((u8)compression_algorithms[i]);
  }

  if (crypto_context_) {
    bool foundAesCBC = false;
    for (int i = 0; i < request.encryption_algo_list_len; i++) {
      if (encryption_algorithms[i] == EncryptionAlgorithm::AESCBC128) {
        foundAesCBC = true;
      }
    }
    if (foundAesCBC) {
      const auto key = crypto_context_->GetPublicKey();
      writer.PutList(base::Span<byte>((const byte*)key.data(),
                                      key.length()));
    }
  }

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 1,
                           .awaiting_ack = 0,
                           .reserved = 0};
  OutgoingPacket out(dest.id, PacketType::ServerHello,
                     PacketChannelType::Control, flags, writer.data());
  Push(std::move(out));
}
}  // namespace tx::network
