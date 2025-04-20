// Copyright (C) 2023 Team overLOAD.
// For licensing information see LICENSE at the root of this distribution.
#include "z_client.h"
#include "z_system_command.h"
#include <base/logging.h>

namespace tx::network {
static constexpr char kLogTag[] = "z-client";

bool ZClient::Connect(const base::StringRef address, u16 port) {
  const ZAsyncTransportLayer::InitOptions options{
      .ip = address,
      .port = port,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kClient,
      .use_encryption = true,
      .use_compression = false,
      .allow_ipv6 = false};
  bool result = ZAsyncTransportLayer::Init(options);
  if (result) {
    SendClientHello();
    state_ = State::kConnecting;
  }
  return result;
}

void ZClient::Disconnect() {
  ZAsyncTransportLayer::Deinit();
  state_ = State::kDisconnected;
}

void ZClient::Update() {
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
}
void ZClient::SendMessage(const ZPeerId id, const std::string& data) {
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
  Push(base::move(out));
}

void ZClient::ProcessSystemMessage(const IncomingPacket& p) {
  switch (p.type) {
    case PacketType::ServerHello: {
      BASE_LOGI(kLogTag, "Received ServerHello");
      if (state_ == State::kConnecting) {
        // oh boy, we're almost there
        PacketReader reader((byte*)p.data.data(), p.data.size());
        system_commands::ServerHello response;
        reader.Read(response);
        BASE_LOGI(kLogTag, "ServerHello: {}",
                  response.compression_algo_list_len);

        base::Vector<byte> key;
        reader.ReadList(key);

        crypto_context_->ProcessServerKey((const char*)key.data());

        state_ = State::kConnected;
      }
      break;
    }
  }
}
void ZClient::SendClientHello() {
  constexpr EncryptionAlgorithm encryption_algorithms[] = {
      EncryptionAlgorithm::AESCBC128};
  constexpr CompressionAlgorithm compression_algorithms[] = {
      CompressionAlgorithm::LZ4};

  system_commands::ClientHello request{
      .encryption_algo_list_len = _countof(encryption_algorithms),
      .compression_algo_list_len = _countof(compression_algorithms)};
  PacketWriter writer;
  writer.Put(request);
  for (int i = 0; i < request.encryption_algo_list_len; i++) {
    writer.Put((u8)encryption_algorithms[i]);
  }
  for (int i = 0; i < request.compression_algo_list_len; i++) {
    writer.Put((u8)compression_algorithms[i]);
  }

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 1,
                           .awaiting_ack = 0,
                           .reserved = 0};
  OutgoingPacket o(ZPeerId::to_server, PacketType::ClientHello,
                   PacketChannelType::Control, flags, writer.data());
  Push(base::move(o));
}
}  // namespace tx::network