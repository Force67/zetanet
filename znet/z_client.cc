// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_client.h"
#include "z_system_command.h"

#include <cstdlib>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-client";

bool ZClient::Connect(const base::StringRef address, u16 port) {
  const char* encryption_env = std::getenv("ZNET_ENABLE_ENCRYPTION");
  const bool use_encryption = encryption_env && encryption_env[0] != '0';
  const char* compression_env = std::getenv("ZNET_ENABLE_COMPRESSION");
  const bool use_compression = compression_env && compression_env[0] != '0';
  const ZAsyncTransportLayer::InitOptions options{
      .ip = address,
      .port = port,
      .local_bind_port = 0,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kClient,
      .use_encryption = use_encryption,
      .use_compression = use_compression,
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
  if (Poll(PacketChannelType::Control, packet)) {
    // Control packets are handled by ProcessSystemMessage inside Poll
  }
  while (Poll(PacketChannelType::Data, packet)) {
    if (!IsSystemMessage(packet.type)) {
      BASE_LOGI(kLogTag, "Incoming data: {}", packet.data);
    }
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
void ZClient::SendMessage(const ZPeerId id, const base::String& data) {
  if (crypto_context_ && !crypto_context_->IsAuthenticated()) {
    BASE_LOGW(kLogTag, "Cannot send message: not authenticated");
    return;
  }
  const u8 use_encryption = crypto_context_ ? 1 : 0;
  const u8 use_compression = compression_enabled() ? 1 : 0;
  const PackageFlags flags{.reliable = 1,
                           .encrypted = use_encryption,
                           .compressed = use_compression,
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

void ZClient::ProcessSystemMessage(const IncomingPacket& p) {
  switch (p.type) {
    case PacketType::ServerHello: {
      if (state_ != State::kConnecting) {
        BASE_LOGI(kLogTag, "Ignoring duplicate ServerHello (already connected)");
        break;
      }
      BASE_LOGI(kLogTag, "Received ServerHello");
      {
        PacketReader reader((byte*)p.data.data(), p.data.size());
        system_commands::ServerHello response;
        if (!reader.Read(response)) {
          BASE_LOGE(kLogTag, "Malformed ServerHello: missing header");
          return;
        }
        BASE_LOGI(kLogTag, "ServerHello: enc_algo={}, comp_algo={}",
                  response.encryption_algo_list_len, response.compression_algo_list_len);

        base::Vector<byte> encryption_algorithms(
            response.encryption_algo_list_len);
        if (!reader.ReadS(encryption_algorithms)) {
          BASE_LOGE(kLogTag,
                    "Malformed ServerHello: invalid encryption algorithm list");
          return;
        }

        base::Vector<byte> compression_algorithms(
            response.compression_algo_list_len);
        if (!reader.ReadS(compression_algorithms)) {
          BASE_LOGE(kLogTag,
                    "Malformed ServerHello: invalid compression algorithm list");
          return;
        }

        base::Vector<byte> key;
        if (!reader.ReadList(key)) {
          BASE_LOGE(kLogTag, "Malformed ServerHello: invalid public key list");
          return;
        }
        
        base::String server_challenge;
        if (response.challenge_len > 0) {
          base::Vector<byte> temp_challenge;
          if (!reader.ReadList(temp_challenge)) {
            BASE_LOGE(kLogTag, "Malformed ServerHello: missing server challenge");
            return;
          }
          server_challenge.assign(reinterpret_cast<const char*>(temp_challenge.data()), 
                                  temp_challenge.size());
        }
        
        base::String server_proof;
        if (response.proof_len > 0) {
          base::Vector<byte> temp_proof;
          if (!reader.ReadList(temp_proof)) {
            BASE_LOGE(kLogTag, "Malformed ServerHello: missing server proof");
            return;
          }
          server_proof.assign(reinterpret_cast<const char*>(temp_proof.data()), 
                             temp_proof.size());
        }

        if (crypto_context_) {
          crypto_context_->ProcessServerKey(
              base::String((const char*)key.data(), key.size()),
              server_challenge);
          
          if (!server_proof.empty()) {
            if (!crypto_context_->VerifyServerResponse(server_proof)) {
              BASE_LOGE(kLogTag, "Server authentication failed!");
              Disconnect();
              return;
            }
            BASE_LOGI(kLogTag, "Server authenticated successfully");
          }
          
          base::String client_proof = crypto_context_->GenerateClientProof();
          if (!client_proof.empty()) {
            SendClientAuthProof(client_proof);
          }
        }

        state_ = State::kConnected;
      }
      break;
    }
    default:
      break;
  }
}
void ZClient::SendClientHello() {
  constexpr EncryptionAlgorithm encryption_algorithms[] = {
      EncryptionAlgorithm::AESCBC128};
  constexpr CompressionAlgorithm compression_algorithms[] = {
      CompressionAlgorithm::LZ4};

  base::String client_public_key;
  base::String client_challenge;
  u8 pub_key_list_len = 0;
  if (crypto_context_) {
    client_public_key = crypto_context_->GetPublicKey();
    client_challenge = crypto_context_->GetChallenge();
    if (!client_public_key.empty()) {
      pub_key_list_len = 1;
    }
  }

  system_commands::ClientHello request{
      .encryption_algo_list_len = (u8)_countof(encryption_algorithms),
      .compression_algo_list_len = (u8)_countof(compression_algorithms),
      .pub_key_list_len = pub_key_list_len,
      .challenge_len = static_cast<u8>(client_challenge.size())};
  PacketWriter writer;
  writer.Put(request);
  for (int i = 0; i < request.encryption_algo_list_len; i++) {
    writer.Put((u8)encryption_algorithms[i]);
  }
  for (int i = 0; i < request.compression_algo_list_len; i++) {
    writer.Put((u8)compression_algorithms[i]);
  }

  if (!client_public_key.empty()) {
    writer.PutList(base::Span<byte>(reinterpret_cast<const byte*>(client_public_key.data()),
                                     client_public_key.size()));
  }

  if (!client_challenge.empty()) {
    writer.PutList(base::Span<byte>(reinterpret_cast<const byte*>(client_challenge.data()),
                                     client_challenge.size()));
  }

  const PackageFlags flags{.reliable = 0,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 0,
                           .reserved = 0};
  OutgoingPacket o(ZPeerId::to_server, PacketType::ClientHello,
                   PacketChannelType::Control, flags, writer.data());
  Push(std::move(o));
}

void ZClient::SendClientAuthProof(const base::String& proof) {
  system_commands::ClientAuthProof request{
      .proof_len = static_cast<u8>(proof.size())};
  PacketWriter writer;
  writer.Put(request);
  writer.PutList(base::Span<byte>(reinterpret_cast<const byte*>(proof.data()),
                                   proof.size()));

  const PackageFlags flags{.reliable = 0,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 0,
                           .reserved = 0};
  OutgoingPacket o(ZPeerId::to_server, PacketType::ClientAuthProof,
                   PacketChannelType::Control, flags, writer.data());
  Push(std::move(o));
}
}  // namespace tx::network
