// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_client.h"
#include "z_system_command.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-client";
static constexpr auto kClockSyncInterval = std::chrono::milliseconds(1000);
static constexpr auto kClientHelloRetryInterval = std::chrono::milliseconds(500);
static constexpr auto kHandshakeTimeout = std::chrono::seconds(8);

namespace {
bool ReadListWithExpectedSize(PacketReader& reader,
                              u8 expected_size,
                              base::Vector<byte>& out) {
  return reader.ReadList(out) && out.size() == expected_size;
}
}  // namespace

bool ZClient::Connect(const base::StringRef address, u16 port) {
  const ConnectionOptions options{
      .use_encryption = false,
      .pre_shared_key = {},
      .use_compression = false,
      .allow_ipv6 = false,
      .start_threads = false};
  return Connect(address, port, options);
}

bool ZClient::Connect(const base::StringRef address,
                      u16 port,
                      const ConnectionOptions& options) {
  const ZAsyncTransportLayer::InitOptions init_options{
      .ip = address,
      .port = port,
      .local_bind_port = 0,
      .setup_type = ZAsyncTransportLayer::ConnectionType::kClient,
      .use_encryption = options.use_encryption,
      .pre_shared_key = options.pre_shared_key,
      .use_compression = options.use_compression,
      .allow_ipv6 = options.allow_ipv6,
      .start_threads = options.start_threads,
      .chaos = options.chaos};
  bool result = ZAsyncTransportLayer::Init(init_options);
  if (result) {
    if (scaling_tier_count_ > 0 && !packet_queue_.outgoing_thread_running() &&
        !packet_queue_.StartOutgoingThread()) {
      BASE_LOGE(kLogTag, "Failed to start outgoing thread");
      Disconnect();
      return false;
    }

    SendClientHello();
    state_ = State::kConnecting;
    handshake_phase_ = HandshakePhase::kAwaitingServerHello;
    handshake_failure_reason_ = HandshakeFailureReason::kNone;
    negotiated_protocol_version_ = 0;
    negotiated_feature_flags_ = 0;
    handshake_start_time_ = base::Clock::now();
    next_clock_sync_request_time_ = base::Clock::time_point{};
    next_client_hello_retry_time_ =
        base::Clock::now() + kClientHelloRetryInterval;
  }
  return result;
}

void ZClient::Disconnect() {
  ZAsyncTransportLayer::Deinit();
  state_ = State::kDisconnected;
  if (handshake_phase_ == HandshakePhase::kAwaitingServerHello) {
    handshake_phase_ = HandshakePhase::kFailed;
  } else if (handshake_phase_ == HandshakePhase::kConnected) {
    handshake_phase_ = HandshakePhase::kIdle;
  }
  next_clock_sync_request_time_ = base::Clock::time_point{};
  next_client_hello_retry_time_ = base::Clock::time_point{};
  handshake_start_time_ = base::Clock::time_point{};
  negotiated_protocol_version_ = 0;
  negotiated_feature_flags_ = 0;
}

void ZClient::Update() {
  UpdateSynchronizedClock();

  // Control packets are handled by ProcessSystemMessage inside Poll. The
  // data channel is the application's: draining it here would drop user
  // messages, so callers poll it themselves.
  IncomingPacket packet;
  while (Poll(PacketChannelType::Control, packet)) {
  }
  switch (state()) {
    case ZAsyncTransportLayer::State::kDisconnected:
      BASE_LOGI(kLogTag, "Disconnected");
      break;
    case ZAsyncTransportLayer::State::kConnecting:
      {
        const auto now = base::Clock::now();
        if (handshake_start_time_.time_since_epoch().count() != 0 &&
            now - handshake_start_time_ >= kHandshakeTimeout) {
          MarkHandshakeFailure(HandshakeFailureReason::kTimeout,
                               "Handshake timed out waiting for ServerHello");
          Disconnect();
          break;
        }
      }
      if (!packet_queue_.outgoing_thread_running()) {
        const auto now = base::Clock::now();
        if (next_client_hello_retry_time_.time_since_epoch().count() == 0 ||
            now >= next_client_hello_retry_time_) {
          SendClientHelloDirect();
          next_client_hello_retry_time_ = now + kClientHelloRetryInterval;
        }
      }
      break;
    case ZAsyncTransportLayer::State::kConnected:
      if (crypto_context_ && !crypto_context_->IsAuthenticated()) {
        break;
      }
      if ((negotiated_feature_flags_ & system_commands::kFeatureClockSync) == 0) {
        break;
      }
      {
        const auto now = base::Clock::now();
        if (next_clock_sync_request_time_.time_since_epoch().count() == 0 ||
            now >= next_clock_sync_request_time_) {
          SendClockSyncRequest();
          next_clock_sync_request_time_ = now + kClockSyncInterval;
        }
      }
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
        system_commands::ServerHello response{};
        if (!reader.Read(response.protocol_version) ||
            !reader.Read(response.feature_flags) ||
            !reader.Read(response.encryption_algo_list_len) ||
            !reader.Read(response.compression_algo_list_len) ||
            !reader.Read(response.pub_key_list_len) ||
            !reader.Read(response.challenge_len) ||
            !reader.Read(response.proof_len)) {
          MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                               "Malformed ServerHello: missing header");
          Disconnect();
          return;
        }
        if (!IsProtocolVersionSupported(response.protocol_version)) {
          MarkHandshakeFailure(
              HandshakeFailureReason::kProtocolVersionMismatch,
              "ServerHello protocol version is unsupported");
          Disconnect();
          return;
        }
        const u32 local_features = BuildSupportedFeatureFlags();
        if ((response.feature_flags & ~local_features) != 0) {
          MarkHandshakeFailure(
              HandshakeFailureReason::kFeatureMismatch,
              "ServerHello negotiated unsupported features");
          Disconnect();
          return;
        }
        if (crypto_context_ &&
            (response.feature_flags & system_commands::kFeatureEncryption) == 0) {
          MarkHandshakeFailure(
              HandshakeFailureReason::kFeatureMismatch,
              "Server did not negotiate required encryption feature");
          Disconnect();
          return;
        }
        negotiated_protocol_version_ = response.protocol_version;
        negotiated_feature_flags_ = response.feature_flags;
        BASE_LOGI(kLogTag, "ServerHello: enc_algo={}, comp_algo={}",
                  response.encryption_algo_list_len, response.compression_algo_list_len);

        base::Vector<byte> encryption_algorithms(
            response.encryption_algo_list_len);
        if (!reader.ReadS(encryption_algorithms)) {
          MarkHandshakeFailure(
              HandshakeFailureReason::kMalformedServerHello,
              "Malformed ServerHello: invalid encryption algorithm list");
          Disconnect();
          return;
        }

        base::Vector<byte> compression_algorithms(
            response.compression_algo_list_len);
        if (!reader.ReadS(compression_algorithms)) {
          MarkHandshakeFailure(
              HandshakeFailureReason::kMalformedServerHello,
              "Malformed ServerHello: invalid compression algorithm list");
          Disconnect();
          return;
        }

        base::Vector<byte> key;
        if (!reader.ReadList(key)) {
          MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                               "Malformed ServerHello: invalid public key list");
          Disconnect();
          return;
        }
        if (response.pub_key_list_len > 1) {
          MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                               "Malformed ServerHello: unsupported public key count");
          Disconnect();
          return;
        }
        
        base::String server_challenge;
        if (response.challenge_len > 0) {
          base::Vector<byte> temp_challenge;
          if (!ReadListWithExpectedSize(reader, response.challenge_len,
                                        temp_challenge)) {
            MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                                 "Malformed ServerHello: invalid server challenge");
            Disconnect();
            return;
          }
          server_challenge.assign(reinterpret_cast<const char*>(temp_challenge.data()), 
                                  temp_challenge.size());
        }
        
        base::String server_proof;
        if (response.proof_len > 0) {
          base::Vector<byte> temp_proof;
          if (!ReadListWithExpectedSize(reader, response.proof_len,
                                        temp_proof)) {
            MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                                 "Malformed ServerHello: invalid server proof");
            Disconnect();
            return;
          }
          server_proof.assign(reinterpret_cast<const char*>(temp_proof.data()), 
                             temp_proof.size());
        }

        if (crypto_context_) {
          if (response.pub_key_list_len != 1 || key.empty() ||
              server_challenge.empty() || server_proof.empty()) {
            MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                                 "Malformed ServerHello: missing crypto proof material");
            Disconnect();
            return;
          }
          if (reader.remaining() != 0) {
            MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                                 "Malformed ServerHello: trailing bytes");
            Disconnect();
            return;
          }
          crypto_context_->ProcessServerKey(
              base::String((const char*)key.data(), key.size()),
              server_challenge);
          
          if (!server_proof.empty()) {
            if (!crypto_context_->VerifyServerResponse(server_proof)) {
              MarkHandshakeFailure(HandshakeFailureReason::kAuthenticationFailed,
                                   "Server authentication failed");
              Disconnect();
              return;
            }
            BASE_LOGI(kLogTag, "Server authenticated successfully");
          }
          
          base::String client_proof = crypto_context_->GenerateClientProof();
          if (!client_proof.empty()) {
            SendClientAuthProof(client_proof);
          }
        } else if (reader.remaining() != 0) {
          MarkHandshakeFailure(HandshakeFailureReason::kMalformedServerHello,
                               "Malformed ServerHello: trailing bytes");
          Disconnect();
          return;
        }

        if (scaling_tier_count_ > 0 &&
            !packet_queue_.outgoing_thread_running() &&
            !packet_queue_.StartOutgoingThread()) {
          BASE_LOGE(kLogTag, "Failed to start outgoing thread");
          Disconnect();
          return;
        }

        state_ = State::kConnected;
        handshake_phase_ = HandshakePhase::kConnected;
        next_client_hello_retry_time_ = base::Clock::time_point{};
        handshake_start_time_ = base::Clock::time_point{};
      }
      break;
    }
    case PacketType::ServerGoodbye: {
      PacketReader reader((byte*)p.data.data(), p.data.size());
      system_commands::ServerGoodbye goodbye{.reason =
                                                 system_commands::HandshakeRejectReason::None};
      if (!reader.Read(goodbye.reason)) {
        MarkHandshakeFailure(HandshakeFailureReason::kServerRejected,
                             "Received malformed ServerGoodbye");
      } else if (reader.remaining() != 0) {
        MarkHandshakeFailure(HandshakeFailureReason::kServerRejected,
                             "Received malformed ServerGoodbye");
      } else {
        BASE_LOGE(kLogTag, "Server rejected handshake with reason={}",
                  static_cast<u32>(goodbye.reason));
        if (goodbye.reason ==
            system_commands::HandshakeRejectReason::ProtocolVersionMismatch) {
          handshake_failure_reason_ =
              HandshakeFailureReason::kProtocolVersionMismatch;
        } else if (goodbye.reason ==
                   system_commands::HandshakeRejectReason::FeatureMismatch) {
          handshake_failure_reason_ = HandshakeFailureReason::kFeatureMismatch;
        } else if (goodbye.reason ==
                   system_commands::HandshakeRejectReason::AuthenticationFailed) {
          handshake_failure_reason_ =
              HandshakeFailureReason::kAuthenticationFailed;
        } else if (goodbye.reason == system_commands::HandshakeRejectReason::Timeout) {
          handshake_failure_reason_ = HandshakeFailureReason::kTimeout;
        } else {
          handshake_failure_reason_ = HandshakeFailureReason::kServerRejected;
        }
      }
      handshake_phase_ = HandshakePhase::kFailed;
      Disconnect();
      break;
    }
    case PacketType::ClockSyncResponse: {
      if (state_ != State::kConnected) {
        break;
      }

      const u64 local_recv_tick_ms = GetLocalClockTickMs();
      PacketReader reader((byte*)p.data.data(), p.data.size());
      u64 client_send_tick_ms = 0;
      u64 server_receive_tick_ms = 0;
      u64 server_send_tick_ms = 0;
      if (!reader.Read(client_send_tick_ms) || !reader.Read(server_receive_tick_ms) ||
          !reader.Read(server_send_tick_ms) || reader.remaining() != 0) {
        BASE_LOGE(kLogTag, "Malformed ClockSyncResponse payload");
        return;
      }

      if (local_recv_tick_ms < client_send_tick_ms) {
        return;
      }
      SynchronizeClockSample(client_send_tick_ms, local_recv_tick_ms,
                             server_receive_tick_ms, server_send_tick_ms);
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
      .protocol_version = system_commands::kProtocolVersionCurrent,
      .feature_flags = BuildSupportedFeatureFlags(),
      .encryption_algo_list_len = (u8)_countof(encryption_algorithms),
      .compression_algo_list_len = (u8)_countof(compression_algorithms),
      .pub_key_list_len = pub_key_list_len,
      .challenge_len = static_cast<u8>(client_challenge.size())};
  PacketWriter writer;
  system_commands::ClientHello::Build(writer, request);
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

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket o(ZPeerId::to_server, PacketType::ClientHello,
                   PacketChannelType::Control, flags, writer.data());
  Push(std::move(o));
}

void ZClient::SendClientHelloDirect() {
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
      .protocol_version = system_commands::kProtocolVersionCurrent,
      .feature_flags = BuildSupportedFeatureFlags(),
      .encryption_algo_list_len = (u8)_countof(encryption_algorithms),
      .compression_algo_list_len = (u8)_countof(compression_algorithms),
      .pub_key_list_len = pub_key_list_len,
      .challenge_len = static_cast<u8>(client_challenge.size())};
  PacketWriter writer;
  system_commands::ClientHello::Build(writer, request);
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

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket o(ZPeerId::to_server, PacketType::ClientHello,
                   PacketChannelType::Control, flags, writer.data());
  packet_queue_.PushDirect(std::move(o));
}

void ZClient::SendClientAuthProof(const base::String& proof) {
  if (proof.size() > std::numeric_limits<u8>::max()) {
    return;
  }
  system_commands::ClientAuthProof request{
      .proof_len = static_cast<u8>(proof.size())};
  PacketWriter writer;
  writer.Put(request);
  writer.PutList(base::Span<byte>(reinterpret_cast<const byte*>(proof.data()),
                                   proof.size()));

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = (u8)PacketPriority::Critical,
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket o(ZPeerId::to_server, PacketType::ClientAuthProof,
                   PacketChannelType::Control, flags, writer.data());
  Push(std::move(o));
}

void ZClient::SendClockSyncRequest() {
  if (state_ != State::kConnected) {
    return;
  }
  if ((negotiated_feature_flags_ & system_commands::kFeatureClockSync) == 0) {
    return;
  }
  if (crypto_context_ && !crypto_context_->IsAuthenticated()) {
    return;
  }

  PacketWriter writer;
  writer.Put(GetLocalClockTickMs());

  const u8 use_encryption = crypto_context_ ? 1 : 0;
  const PackageFlags flags{.reliable = 0,
                           .encrypted = use_encryption,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::High),
                           .acknowledged = 0,
                           .awaiting_ack = 0,
                           .reserved = 0};
  OutgoingPacket out(ZPeerId::to_server, PacketType::ClockSyncRequest,
                     PacketChannelType::Control, flags, writer.data());
  Push(std::move(out));
}

u32 ZClient::BuildSupportedFeatureFlags() const {
  u32 flags = system_commands::kFeatureClockSync |
              system_commands::kFeatureAdaptiveCongestion;
  if (compression_enabled()) {
    flags |= system_commands::kFeatureCompression;
  }
  if (crypto_context_) {
    flags |= system_commands::kFeatureEncryption;
  }
  return flags;
}

bool ZClient::IsProtocolVersionSupported(u16 version) const {
  return version >= system_commands::kProtocolVersionMinSupported &&
         version <= system_commands::kProtocolVersionCurrent;
}

void ZClient::MarkHandshakeFailure(HandshakeFailureReason reason,
                                   const char* message) {
  handshake_phase_ = HandshakePhase::kFailed;
  handshake_failure_reason_ = reason;
  if (message) {
    BASE_LOGE(kLogTag, "{}", message);
  }
}
}  // namespace tx::network
