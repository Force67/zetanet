// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_server.h"
#include "z_system_command.h"

#include <cstdlib>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-server";
static constexpr char kSelfAddress[] =
    "127.0.0.1";

namespace {
u32 BuildSupportedFeatureFlags(bool encryption_enabled, bool compression_enabled) {
  u32 flags = system_commands::kFeatureClockSync |
              system_commands::kFeatureAdaptiveCongestion;
  if (compression_enabled) {
    flags |= system_commands::kFeatureCompression;
  }
  if (encryption_enabled) {
    flags |= system_commands::kFeatureEncryption;
  }
  return flags;
}

bool IsProtocolVersionSupported(u16 version) {
  return version >= system_commands::kProtocolVersionMinSupported &&
         version <= system_commands::kProtocolVersionCurrent;
}
}  // namespace

bool ZServer::Begin(u16 port) {
  const char* encryption_env = std::getenv("ZNET_ENABLE_ENCRYPTION");
  const bool use_encryption = encryption_env && encryption_env[0] != '0';
  const char* compression_env = std::getenv("ZNET_ENABLE_COMPRESSION");
  const bool use_compression = compression_env && compression_env[0] != '0';
  const StartOptions options{
      .use_encryption = use_encryption,
      .use_compression = use_compression,
      .allow_ipv6 = false,
      .start_threads = false};
  return Begin(port, options);
}

bool ZServer::Begin(u16 port, const StartOptions& options) {
  const ZAsyncTransportLayer::InitOptions init_options{
      .ip = kSelfAddress,
      .port = port,
      .local_bind_port = 0,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kServer,
      .use_encryption = options.use_encryption,
      .use_compression = options.use_compression,
      .allow_ipv6 = options.allow_ipv6,
      .start_threads = options.start_threads};
  bool result = ZAsyncTransportLayer::Init(init_options);
  if (!result) {
    BASE_LOGE(kLogTag, "Failed to initialize ZAsyncTransportLayer");
    return false;
  }

  if (scaling_tier_count_ > 0) {
    packet_queue_.StartIncomingThread();  // Warm the receiving thread at boot
  }
  handshaked_peers_.clear();
  peer_handshake_info_.clear();
  state_ = ZAsyncTransportLayer::State::kConnected;
  return true;
}

bool ZServer::Update() {
  UpdateSynchronizedClock();

  IncomingPacket packet;
  if (Poll(PacketChannelType::Control, packet)) {
    // Control packets are handled by ProcessSystemMessage inside Poll
  }
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

void ZServer::SendMessage(ZPeerId id, const base::String& data) {
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

void ZServer::ProcessSystemMessage(const IncomingPacket& p) {
  switch (p.type) {
    case PacketType::ClientHello: {
      // Duplicate ClientHello can happen due reliable retransmits; respond with
      // ServerHello again so the client can complete handshake if it missed the
      // previous response.
      if (handshaked_peers_.count(p.source_peer_id)) {
        u16 protocol_version = system_commands::kProtocolVersionCurrent;
        u32 negotiated_features =
            BuildSupportedFeatureFlags(crypto_context_ != nullptr, compression_enabled());
        auto info_it = peer_handshake_info_.find(p.source_peer_id);
        if (info_it != peer_handshake_info_.end()) {
          protocol_version = info_it->second.protocol_version;
          negotiated_features = info_it->second.negotiated_features;
        }
        BASE_LOGI(kLogTag, "Re-sending ServerHello for duplicate ClientHello from peer {}",
                  p.source_peer_id);
        SendServerHello(p.source_peer_id, protocol_version, negotiated_features);
        break;
      }
      BASE_LOGI(kLogTag, "Received ClientHello from peer {}", p.source_peer_id);

      PacketReader reader((byte*)p.data.data(), p.data.size());
      system_commands::ClientHello request{};
      if (!reader.Read(request.protocol_version) ||
          !reader.Read(request.feature_flags) ||
          !reader.Read(request.encryption_algo_list_len) ||
          !reader.Read(request.compression_algo_list_len) ||
          !reader.Read(request.pub_key_list_len) ||
          !reader.Read(request.challenge_len)) {
        BASE_LOGE(kLogTag, "Malformed ClientHello: missing header");
        SendServerGoodbye(p.source_peer_id,
                          system_commands::HandshakeRejectReason::MalformedPacket);
        return;
      }
      if (!IsProtocolVersionSupported(request.protocol_version)) {
        BASE_LOGE(kLogTag,
                  "Rejected ClientHello from peer {}: unsupported protocol version {}",
                  p.source_peer_id, request.protocol_version);
        SendServerGoodbye(
            p.source_peer_id,
            system_commands::HandshakeRejectReason::ProtocolVersionMismatch);
        return;
      }
      const u32 local_features =
          BuildSupportedFeatureFlags(crypto_context_ != nullptr, compression_enabled());
      const u32 negotiated_features = request.feature_flags & local_features;
      if (crypto_context_ &&
          (negotiated_features & system_commands::kFeatureEncryption) == 0) {
        BASE_LOGE(kLogTag,
                  "Rejected ClientHello from peer {}: encryption feature is required",
                  p.source_peer_id);
        SendServerGoodbye(p.source_peer_id,
                          system_commands::HandshakeRejectReason::FeatureMismatch);
        return;
      }

      // Skip encryption algorithm list
      base::Vector<byte> enc_algos(request.encryption_algo_list_len);
      if (!reader.ReadS(enc_algos)) {
        BASE_LOGE(kLogTag, "Malformed ClientHello: invalid encryption algorithm list");
        SendServerGoodbye(p.source_peer_id,
                          system_commands::HandshakeRejectReason::MalformedPacket);
        return;
      }

      // Skip compression algorithm list
      base::Vector<byte> comp_algos(request.compression_algo_list_len);
      if (!reader.ReadS(comp_algos)) {
        BASE_LOGE(kLogTag, "Malformed ClientHello: invalid compression algorithm list");
        SendServerGoodbye(p.source_peer_id,
                          system_commands::HandshakeRejectReason::MalformedPacket);
        return;
      }

      // Read client public key
      base::Vector<byte> client_key;
      if (request.pub_key_list_len > 0) {
        if (!reader.ReadList(client_key)) {
          BASE_LOGE(kLogTag, "Malformed ClientHello: invalid public key");
          SendServerGoodbye(p.source_peer_id,
                            system_commands::HandshakeRejectReason::MalformedPacket);
          return;
        }
      }

      // Read client challenge
      base::String client_challenge;
      if (request.challenge_len > 0) {
        base::Vector<byte> temp_challenge;
        if (!reader.ReadList(temp_challenge)) {
          BASE_LOGE(kLogTag, "Malformed ClientHello: missing client challenge");
          SendServerGoodbye(p.source_peer_id,
                            system_commands::HandshakeRejectReason::MalformedPacket);
          return;
        }
        client_challenge.assign(reinterpret_cast<const char*>(temp_challenge.data()),
                                temp_challenge.size());
      }

      if (crypto_context_) {
        // Process client's key material
        base::String client_nonce(reinterpret_cast<const char*>(client_key.data()),
                                 client_key.size());
        crypto_context_->ProcessServerKey(client_nonce, client_challenge);
      }

      peer_handshake_info_[p.source_peer_id] = {
          request.protocol_version, negotiated_features, base::Clock::now()};
      handshaked_peers_.insert(p.source_peer_id);
      SendServerHello(p.source_peer_id, request.protocol_version,
                      negotiated_features);

      if (scaling_tier_count_ > 0 && !packet_queue_.outgoing_thread_running()) {
        packet_queue_.ReconfigureDispatchWorkers(1);
      }

      // Advance through thread scaling tiers as peer count grows.
      while (current_scaling_tier_ < scaling_tier_count_ &&
             handshaked_peers_.size() >= scaling_tiers_[current_scaling_tier_].peer_count) {
        packet_queue_.ReconfigureDispatchWorkers(
            scaling_tiers_[current_scaling_tier_].dispatch_workers);
        ++current_scaling_tier_;
      }
      break;
    }
    case PacketType::ClientAuthProof: {
      BASE_LOGI(kLogTag, "Received ClientAuthProof");
      if (!crypto_context_) {
        break;
      }
      if (!handshaked_peers_.count(p.source_peer_id)) {
        break;
      }
      PacketReader reader((byte*)p.data.data(), p.data.size());
      system_commands::ClientAuthProof request;
      if (!reader.Read(request)) {
        BASE_LOGE(kLogTag, "Malformed ClientAuthProof: missing header");
        return;
      }
      base::Vector<byte> proof_data;
      if (!reader.ReadList(proof_data)) {
        BASE_LOGE(kLogTag, "Malformed ClientAuthProof: missing proof");
        return;
      }
      base::String proof(reinterpret_cast<const char*>(proof_data.data()),
                        proof_data.size());
      if (!crypto_context_->VerifyClientProof(proof)) {
        BASE_LOGE(kLogTag, "Client authentication failed!");
        handshaked_peers_.erase(p.source_peer_id);
        peer_handshake_info_.erase(p.source_peer_id);
        SendServerGoodbye(
            p.source_peer_id,
            system_commands::HandshakeRejectReason::AuthenticationFailed);
        return;
      }
      BASE_LOGI(kLogTag, "Client authenticated successfully");
      break;
    }
    case PacketType::ClockSyncRequest: {
      if (!handshaked_peers_.count(p.source_peer_id)) {
        break;
      }
      auto info_it = peer_handshake_info_.find(p.source_peer_id);
      if (info_it != peer_handshake_info_.end() &&
          (info_it->second.negotiated_features &
           system_commands::kFeatureClockSync) == 0) {
        break;
      }
      const u64 server_receive_tick_ms = GetLocalClockTickMs();
      PacketReader reader((byte*)p.data.data(), p.data.size());
      u64 client_tick_ms = 0;
      if (!reader.Read(client_tick_ms)) {
        BASE_LOGE(kLogTag, "Malformed ClockSyncRequest payload");
        return;
      }
      SendClockSyncResponse(ZPeerId(p.source_peer_id), client_tick_ms,
                            server_receive_tick_ms);
      break;
    }
    default:
      break;
  }
}

void ZServer::SendServerHello(ZPeerId dest,
                              u16 protocol_version,
                              u32 negotiated_features) {
  constexpr EncryptionAlgorithm encryption_algorithms[] = {
      EncryptionAlgorithm::AESCBC128};
  constexpr CompressionAlgorithm compression_algorithms[] = {
      CompressionAlgorithm::LZ4};

  base::Vector<byte> public_key_data;
  u8 pub_key_list_len = 0;
  base::String server_challenge;
  base::String server_proof;
  
  if (crypto_context_ &&
      (negotiated_features & system_commands::kFeatureEncryption) != 0) {
    bool foundAesCBC = false;
    for (u8 i = 0; i < (u8)_countof(encryption_algorithms); i++) {
      if (encryption_algorithms[i] == EncryptionAlgorithm::AESCBC128) {
        foundAesCBC = true;
      }
    }
    if (foundAesCBC) {
      const auto key = crypto_context_->GetPublicKey();
      if (!key.empty()) {
        public_key_data.resize(key.length());
        std::memcpy(public_key_data.data(), key.data(), key.length());
        pub_key_list_len = 1;
      }
      
      server_challenge = crypto_context_->GetChallenge();
      
      const char* psk_env = std::getenv("ZNET_PSK");
      if (psk_env && psk_env[0] != '\0') {
        server_proof = crypto_context_->GenerateServerProof();
      }
    }
  }

  PacketWriter writer;
  system_commands::ServerHello request{
      .protocol_version = protocol_version,
      .feature_flags = negotiated_features,
      .encryption_algo_list_len = (u8)_countof(encryption_algorithms),
      .compression_algo_list_len = (u8)_countof(compression_algorithms),
      .pub_key_list_len = pub_key_list_len,
      .challenge_len = static_cast<u8>(server_challenge.size()),
      .proof_len = static_cast<u8>(server_proof.size())};
  system_commands::ServerHello::Build(writer, request);

  for (int i = 0; i < request.encryption_algo_list_len; i++) {
    writer.Put((u8)encryption_algorithms[i]);
  }
  for (int i = 0; i < request.compression_algo_list_len; i++) {
    writer.Put((u8)compression_algorithms[i]);
  }

  writer.PutList(
      base::Span<byte>(public_key_data.data(), public_key_data.size()));
  
  if (!server_challenge.empty()) {
    writer.PutList(base::Span<byte>(reinterpret_cast<const byte*>(server_challenge.data()),
                                     server_challenge.size()));
  }
  
  if (!server_proof.empty()) {
    writer.PutList(base::Span<byte>(reinterpret_cast<const byte*>(server_proof.data()),
                                     server_proof.size()));
  }

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(dest.id, PacketType::ServerHello,
                     PacketChannelType::Control, flags, writer.data());
  Push(std::move(out));
}

void ZServer::SendServerGoodbye(ZPeerId dest,
                                system_commands::HandshakeRejectReason reason) {
  PacketWriter writer;
  system_commands::ServerGoodbye goodbye{.reason = reason};
  system_commands::ServerGoodbye::Build(writer, goodbye);

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(dest.id, PacketType::ServerGoodbye,
                     PacketChannelType::Control, flags, writer.data());
  packet_queue_.Push(std::move(out));
}

void ZServer::SendClockSyncResponse(ZPeerId dest,
                                    u64 echoed_client_tick_ms,
                                    u64 server_receive_tick_ms) {
  PacketWriter writer;
  writer.Put(echoed_client_tick_ms);
  writer.Put(server_receive_tick_ms);
  writer.Put(GetLocalClockTickMs());

  const u8 use_encryption = crypto_context_ ? 1 : 0;
  const PackageFlags flags{.reliable = 0,
                           .encrypted = use_encryption,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::High),
                           .acknowledged = 0,
                           .awaiting_ack = 0,
                           .reserved = 0};
  OutgoingPacket out(dest.id, PacketType::ClockSyncResponse,
                     PacketChannelType::Control, flags, writer.data());
  Push(std::move(out));
}
}  // namespace tx::network
