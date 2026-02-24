// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_clock.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/memory/unique_pointer.h>
#endif

#include <znet/z_abi.h>
#include <znet/z_peer.h>
#include <znet/z_transport.h>

#undef SendMessage

namespace tx::network {

class ZNET_API ZClient final : public ZAsyncTransportLayer {
 public:
  struct ConnectionOptions {
    bool use_encryption{false};
    base::StringRef pre_shared_key{};
    bool use_compression{false};
    bool allow_ipv6{false};
    bool start_threads{false};
    ZSocket::ChaosOptions chaos{};
  };

  enum class HandshakePhase : u8 {
    kIdle = 0,
    kAwaitingServerHello,
    kConnected,
    kFailed,
  };

  enum class HandshakeFailureReason : u8 {
    kNone = 0,
    kTimeout,
    kProtocolVersionMismatch,
    kFeatureMismatch,
    kMalformedServerHello,
    kServerRejected,
    kAuthenticationFailed,
  };

  bool Connect(const base::StringRef address, u16 port);
  bool Connect(const base::StringRef address,
               u16 port,
               const ConnectionOptions& options);
  void Disconnect();
  void Update();
  void SendMessage(const ZPeerId, const base::String& data);
  HandshakePhase handshake_phase() const { return handshake_phase_; }
  HandshakeFailureReason handshake_failure_reason() const {
    return handshake_failure_reason_;
  }
  u16 negotiated_protocol_version() const { return negotiated_protocol_version_; }
  u32 negotiated_feature_flags() const { return negotiated_feature_flags_; }

  // Fetches the next packet from the queue
  inline bool Poll(PacketChannelType t, IncomingPacket& p) {
    if (packet_queue_.Pop(t, p)) {
      if (IsSystemMessage(p.type)) {
        ProcessSystemMessage(p);
      }
      return true;
    }
    return false;
  }

  inline void Push(OutgoingPacket&& p) { packet_queue_.Push(std::move(p)); }

  void ProcessSystemMessage(const IncomingPacket& p);

  void SendClientHello();
  void SendClientHelloDirect();
  void SendClientAuthProof(const base::String& proof);
  void SendClockSyncRequest();

 private:
  u32 BuildSupportedFeatureFlags() const;
  bool IsProtocolVersionSupported(u16 version) const;
  void MarkHandshakeFailure(HandshakeFailureReason reason, const char* message);

  HandshakePhase handshake_phase_{HandshakePhase::kIdle};
  HandshakeFailureReason handshake_failure_reason_{HandshakeFailureReason::kNone};
  u16 negotiated_protocol_version_{0};
  u32 negotiated_feature_flags_{0};
  base::Clock::time_point handshake_start_time_{};
  base::Clock::time_point next_clock_sync_request_time_{};
  base::Clock::time_point next_client_hello_retry_time_{};
};
}  // namespace tx::network
