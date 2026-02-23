// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ZNetContext ZNetContext;

#define ZNET_MAX_THREAD_SCALING_TIERS 4
#define ZNET_MAX_PACKET_ALLOCATOR_CLASSES 11

typedef void (*ZNetLogHandler)(void* user_pointer,
                               const char* channel_name,
                               int level,
                               const char* msg);

typedef enum ZNetResult {
  ZNET_RESULT_OK = 0,
  ZNET_RESULT_INVALID_ARGUMENT = 1,
  ZNET_RESULT_INVALID_STATE = 2,
  ZNET_RESULT_NOT_SUPPORTED = 3,
  ZNET_RESULT_NOT_READY = 4,
  ZNET_RESULT_IO_ERROR = 5,
  ZNET_RESULT_INTERNAL_ERROR = 6,
} ZNetResult;

typedef enum ZNetRole {
  ZNET_ROLE_NONE = 0,
  ZNET_ROLE_CLIENT = 1,
  ZNET_ROLE_SERVER = 2,
  ZNET_ROLE_P2P = 3,
} ZNetRole;

typedef enum ZNetConnectionState {
  ZNET_STATE_DISCONNECTED = 0,
  ZNET_STATE_CONNECTING = 1,
  ZNET_STATE_CONNECTED = 2,
  ZNET_STATE_DISCONNECTING = 3,
} ZNetConnectionState;

typedef enum ZNetPacketChannel {
  ZNET_CHANNEL_CONTROL = 0,
  ZNET_CHANNEL_DATA = 1,
} ZNetPacketChannel;

typedef enum ZNetPacketPriority {
  ZNET_PRIORITY_LOW = 0,
  ZNET_PRIORITY_MEDIUM = 1,
  ZNET_PRIORITY_HIGH = 2,
  ZNET_PRIORITY_CRITICAL = 3,
} ZNetPacketPriority;

typedef enum ZNetP2PNodeType {
  ZNET_P2P_HOST = 0,
  ZNET_P2P_CLIENT = 1,
} ZNetP2PNodeType;

typedef enum ZNetClientHandshakePhase {
  ZNET_HANDSHAKE_PHASE_IDLE = 0,
  ZNET_HANDSHAKE_PHASE_AWAITING_SERVER_HELLO = 1,
  ZNET_HANDSHAKE_PHASE_CONNECTED = 2,
  ZNET_HANDSHAKE_PHASE_FAILED = 3,
} ZNetClientHandshakePhase;

typedef enum ZNetClientHandshakeFailureReason {
  ZNET_HANDSHAKE_FAILURE_NONE = 0,
  ZNET_HANDSHAKE_FAILURE_TIMEOUT = 1,
  ZNET_HANDSHAKE_FAILURE_PROTOCOL_VERSION_MISMATCH = 2,
  ZNET_HANDSHAKE_FAILURE_FEATURE_MISMATCH = 3,
  ZNET_HANDSHAKE_FAILURE_MALFORMED_SERVER_HELLO = 4,
  ZNET_HANDSHAKE_FAILURE_SERVER_REJECTED = 5,
  ZNET_HANDSHAKE_FAILURE_AUTHENTICATION_FAILED = 6,
} ZNetClientHandshakeFailureReason;

typedef struct ZNetThreadScalingTier {
  size_t peer_count;
  size_t dispatch_workers;
} ZNetThreadScalingTier;

typedef struct ZNetTransportConfig {
  uint8_t use_encryption;
  uint8_t use_compression;
  uint8_t allow_ipv6;
  uint8_t start_threads;
  uint8_t disable_adaptive_threading;

  size_t dispatch_worker_count;
  size_t dispatch_max_queued_tasks;

  size_t thread_scaling_tier_count;
  ZNetThreadScalingTier thread_scaling_tiers[ZNET_MAX_THREAD_SCALING_TIERS];

  int32_t clock_asymmetry_compensation_ms;
} ZNetTransportConfig;

typedef struct ZNetRateLimitConfig {
  size_t max_packets_per_second;
  size_t max_bytes_per_second;
  size_t burst_allowance;
} ZNetRateLimitConfig;

typedef struct ZNetCongestionControlConfig {
  uint8_t enabled;
  size_t min_scale_per_mille;
  size_t max_scale_per_mille;
  size_t additive_increase_per_window;
  size_t ack_events_per_window;
  size_t retransmit_backoff_per_mille;
  size_t drop_backoff_per_mille;
  size_t min_data_dispatch_per_tick;
} ZNetCongestionControlConfig;

typedef struct ZNetSendOptions {
  uint16_t packet_type;
  uint32_t destination_peer_id;
  uint8_t channel;
  uint8_t reliable;
  uint8_t encrypted;
  uint8_t compressed;
  uint8_t priority;
  uint8_t acknowledged;
  uint8_t awaiting_ack;
} ZNetSendOptions;

typedef struct ZNetPacketView {
  uint16_t packet_type;
  uint32_t source_peer_id;
  uint32_t acknowledgement_number;
  uint32_t sequence_number;
  uint8_t channel;
  uint8_t reliable;
  uint8_t encrypted;
  uint8_t compressed;
  uint8_t priority;
  uint8_t acknowledged;
  uint8_t awaiting_ack;
  const uint8_t* payload;
  size_t payload_size;
} ZNetPacketView;

typedef struct ZNetOutboundPressure {
  size_t control_queued_packets;
  size_t control_queued_bytes;
  size_t data_queued_packets;
  size_t data_queued_bytes;
  size_t awaiting_ack_packets;
  size_t awaiting_ack_bytes;
} ZNetOutboundPressure;

typedef struct ZNetClientHandshakeStatus {
  uint8_t phase;
  uint8_t failure_reason;
  uint16_t negotiated_protocol_version;
  uint32_t negotiated_feature_flags;
} ZNetClientHandshakeStatus;

typedef struct ZNetFileTransferTuning {
  size_t chunk_size;
  size_t max_inflight_chunks;
  size_t max_inflight_bytes;
  size_t allocator_min_cached_blocks;
  uint32_t backpressure_sleep_ms;
  uint32_t backpressure_timeout_ms;
} ZNetFileTransferTuning;

typedef struct ZNetPacketAllocatorClassStats {
  size_t block_size;
  size_t request_count;
  size_t hit_count;
  size_t target_cached_blocks;
  size_t cached_free_blocks;
  double ewma_demand;
} ZNetPacketAllocatorClassStats;

typedef struct ZNetPacketAllocatorStats {
  size_t total_requests;
  size_t pool_hits;
  size_t fallback_allocations;
  size_t class_count;
  ZNetPacketAllocatorClassStats classes[ZNET_MAX_PACKET_ALLOCATOR_CLASSES];
} ZNetPacketAllocatorStats;

ZNET_API const char* ZNetResultToString(ZNetResult result);

ZNET_API ZNetContext* ZNetCreateContext(void);
ZNET_API void ZNetDestroyContext(ZNetContext* context);
ZNET_API void ZNetClearLastError(ZNetContext* context);
ZNET_API const char* ZNetGetLastError(const ZNetContext* context);

ZNET_API void ZNetSetLogHandler(void* user_pointer, ZNetLogHandler callback);

ZNET_API void ZNetGetDefaultTransportConfig(ZNetTransportConfig* out_config);
ZNET_API void ZNetGetDefaultRateLimitConfig(ZNetRateLimitConfig* out_config);
ZNET_API void ZNetGetDefaultCongestionControlConfig(
    ZNetCongestionControlConfig* out_config);
ZNET_API void ZNetGetDefaultSendOptions(ZNetSendOptions* out_options);
ZNET_API void ZNetGetDefaultFileTransferTuning(
    ZNetFileTransferTuning* out_tuning);

ZNET_API ZNetResult ZNetStartClient(ZNetContext* context,
                                    const char* address,
                                    uint16_t port,
                                    const ZNetTransportConfig* config);
ZNET_API ZNetResult ZNetStartServer(ZNetContext* context,
                                    uint16_t port,
                                    const ZNetTransportConfig* config);
ZNET_API ZNetResult ZNetStartP2PHost(ZNetContext* context,
                                     uint16_t port,
                                     const ZNetTransportConfig* config);
ZNET_API ZNetResult ZNetStartP2PClient(ZNetContext* context,
                                       const char* host_ip,
                                       uint16_t host_port,
                                       uint16_t local_port,
                                       const ZNetTransportConfig* config);
ZNET_API ZNetResult ZNetStop(ZNetContext* context);
ZNET_API ZNetResult ZNetUpdate(ZNetContext* context);

ZNET_API ZNetRole ZNetGetRole(const ZNetContext* context);
ZNET_API ZNetConnectionState ZNetGetConnectionState(const ZNetContext* context);
ZNET_API ZNetResult ZNetGetP2PNodeType(const ZNetContext* context,
                                       ZNetP2PNodeType* out_type);
ZNET_API ZNetResult ZNetBecomeP2PHost(ZNetContext* context);

ZNET_API ZNetResult ZNetSetRateLimitConfig(ZNetContext* context,
                                           const ZNetRateLimitConfig* config);
ZNET_API ZNetResult ZNetSetCongestionControlConfig(
    ZNetContext* context,
    const ZNetCongestionControlConfig* config);
ZNET_API ZNetResult ZNetGetOutboundPressure(const ZNetContext* context,
                                            ZNetOutboundPressure* out_pressure);
ZNET_API size_t ZNetGetCongestionScalePerMille(const ZNetContext* context);

ZNET_API uint64_t ZNetGetLocalClockTickMs(const ZNetContext* context);
ZNET_API uint64_t ZNetGetSynchronizedClockTickMs(const ZNetContext* context);
ZNET_API int ZNetIsClockSynchronized(const ZNetContext* context);
ZNET_API ZNetResult ZNetSetClockAsymmetryCompensationMs(ZNetContext* context,
                                                         int32_t compensation_ms);
ZNET_API int32_t ZNetGetClockAsymmetryCompensationMs(const ZNetContext* context);

ZNET_API ZNetResult ZNetGetClientHandshakeStatus(
    const ZNetContext* context,
    ZNetClientHandshakeStatus* out_status);

ZNET_API ZNetResult ZNetSend(ZNetContext* context,
                             const ZNetSendOptions* options,
                             const void* payload,
                             size_t payload_size);
ZNET_API ZNetResult ZNetPoll(ZNetContext* context,
                             ZNetPacketChannel channel,
                             ZNetPacketView* out_packet);

ZNET_API ZNetResult ZNetSendFile(ZNetContext* context,
                                 const char* file_path,
                                 uint32_t destination_peer_id,
                                 const ZNetFileTransferTuning* tuning);

ZNET_API void ZNetResetPacketAllocatorStats(void);
ZNET_API int ZNetGetPacketAllocatorStats(ZNetPacketAllocatorStats* out_stats);
ZNET_API void ZNetDumpPacketAllocatorStats(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
namespace tx::network {

ZNET_API void* ZCreateContext();
ZNET_API void ZDestroyContext(void* context);

ZNET_API void SetBaseLogHandlerFwd(
    void* user_pointer,
    void (*callback)(void* user_pointer,
                     const char* channel_name,
                     int level,
                     const char* msg));

struct ZPacketAllocatorClassStats {
  size_t block_size;
  size_t request_count;
  size_t hit_count;
  size_t target_cached_blocks;
  size_t cached_free_blocks;
  double ewma_demand;
};

struct ZPacketAllocatorStats {
  static constexpr size_t kMaxClasses = ZNET_MAX_PACKET_ALLOCATOR_CLASSES;
  size_t total_requests;
  size_t pool_hits;
  size_t fallback_allocations;
  size_t class_count;
  ZPacketAllocatorClassStats classes[kMaxClasses];
};

ZNET_API void ZResetPacketAllocatorStats();
ZNET_API bool ZGetPacketAllocatorStats(ZPacketAllocatorStats* out_stats);
ZNET_API void ZDumpPacketAllocatorStats();

}  // namespace tx::network
#endif
