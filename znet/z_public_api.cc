// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_public_api.h"

#include "z_client.h"
#include "z_file_transporter.h"
#include "z_network_allocator.h"
#include "z_p2p_node.h"
#include "z_server.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

#include <array>
#include <algorithm>
#include <cstdio>
#include <cstring>

enum class ContextRole {
  kNone = 0,
  kClient,
  kServer,
  kP2P,
};

struct ZNetContext {
  ContextRole role{ContextRole::kNone};
  base::UniquePointer<tx::network::ZClient> client{};
  base::UniquePointer<tx::network::ZServer> server{};
  base::UniquePointer<tx::network::ZP2PNode> p2p{};
  base::UniquePointer<tx::network::ZFileTransporter> file_transporter{};
  base::Vector<byte> packet_payload_scratch{};
  base::String last_error{};
  base::Queue<ZNetPeerEvent> peer_events{};
  void* peer_event_user_pointer{nullptr};
  ZNetPeerEventHandler peer_event_handler{nullptr};
  ZNetConnectionState last_connection_state{ZNET_STATE_DISCONNECTED};
  bool last_connection_state_valid{false};
  bool seen_connected_once{false};
  uint8_t last_emitted_handshake_failure{ZNET_HANDSHAKE_FAILURE_NONE};
};

namespace {

using tx::network::IncomingPacket;
using tx::network::OutgoingPacket;
using tx::network::PacketChannelType;
using tx::network::PacketPriority;
using tx::network::PacketType;
using tx::network::PackageFlags;
using tx::network::ZAsyncTransportLayer;
using tx::network::ZClient;
using tx::network::ZFileTransporter;
using tx::network::ZP2PNode;
using tx::network::ZPeerId;
using tx::network::ZServer;

ZAsyncTransportLayer* ActiveTransport(ZNetContext* context);
const ZAsyncTransportLayer* ActiveTransport(const ZNetContext* context);

base::StringRef MakeStringRef(const char* text) {
  if (!text) {
    return base::StringRef();
  }
  return base::StringRef(text, std::strlen(text));
}

ZNetConnectionState ToPublicState(ZAsyncTransportLayer::State state) {
  switch (state) {
    case ZAsyncTransportLayer::State::kDisconnected:
      return ZNET_STATE_DISCONNECTED;
    case ZAsyncTransportLayer::State::kConnecting:
      return ZNET_STATE_CONNECTING;
    case ZAsyncTransportLayer::State::kConnected:
      return ZNET_STATE_CONNECTED;
    case ZAsyncTransportLayer::State::kDisconnecting:
      return ZNET_STATE_DISCONNECTING;
  }
  return ZNET_STATE_DISCONNECTED;
}

PacketChannelType ToChannel(u8 channel) {
  return channel == ZNET_CHANNEL_CONTROL ? PacketChannelType::Control
                                         : PacketChannelType::Data;
}

PacketPriority ToPriority(u8 priority) {
  switch (priority) {
    case ZNET_PRIORITY_LOW:
      return PacketPriority::Low;
    case ZNET_PRIORITY_MEDIUM:
      return PacketPriority::Medium;
    case ZNET_PRIORITY_HIGH:
      return PacketPriority::High;
    case ZNET_PRIORITY_CRITICAL:
      return PacketPriority::Critical;
    default:
      return PacketPriority::Medium;
  }
}

void DispatchPeerEvent(ZNetContext* context, const ZNetPeerEvent& event) {
  if (!context) {
    return;
  }
  context->peer_events.push(event);
  if (context->peer_event_handler) {
    context->peer_event_handler(context->peer_event_user_pointer, &event);
  }
}

void EmitPeerEvent(ZNetContext* context,
                   ZNetPeerEventType type,
                   u32 peer_id,
                   u32 detail = 0) {
  ZNetPeerEvent event{};
  event.type = static_cast<u8>(type);
  event.peer_id = peer_id;
  event.detail = detail;
  DispatchPeerEvent(context, event);
}

void DrainP2PPeerEvents(ZNetContext* context) {
  if (!context || context->role != ContextRole::kP2P || !context->p2p) {
    return;
  }
  ZP2PNode::PeerEvent event{};
  while (context->p2p->PollPeerEvent(event)) {
    ZNetPeerEventType type = ZNET_PEER_EVENT_NONE;
    switch (event.type) {
      case ZP2PNode::PeerEventType::PeerJoined:
        type = ZNET_PEER_EVENT_PEER_JOINED;
        break;
      case ZP2PNode::PeerEventType::PeerLeft:
        type = ZNET_PEER_EVENT_PEER_LEFT;
        break;
      case ZP2PNode::PeerEventType::RelayFallback:
        type = ZNET_PEER_EVENT_RELAY_FALLBACK;
        break;
      case ZP2PNode::PeerEventType::Reconnected:
        type = ZNET_PEER_EVENT_RECONNECTED;
        break;
      case ZP2PNode::PeerEventType::ConnectionFailure:
        type = ZNET_PEER_EVENT_FAILURE;
        break;
    }
    if (type != ZNET_PEER_EVENT_NONE) {
      EmitPeerEvent(context, type, event.peer_id, event.detail);
    }
  }
}

void EmitConnectionStateTransitionEvents(ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  const ZNetConnectionState current_state =
      transport ? ToPublicState(transport->state()) : ZNET_STATE_DISCONNECTED;
  if (!context->last_connection_state_valid) {
    context->last_connection_state = current_state;
    context->last_connection_state_valid = true;
    return;
  }

  const ZNetConnectionState previous = context->last_connection_state;
  if (previous == current_state) {
    return;
  }

  if (current_state == ZNET_STATE_CONNECTED) {
    const ZNetPeerEventType type =
        context->seen_connected_once ? ZNET_PEER_EVENT_RECONNECTED
                                     : ZNET_PEER_EVENT_CONNECTION_ESTABLISHED;
    EmitPeerEvent(context, type, 0, 0);
    context->seen_connected_once = true;
  } else if (previous == ZNET_STATE_CONNECTED &&
             (current_state == ZNET_STATE_CONNECTING ||
              current_state == ZNET_STATE_DISCONNECTING)) {
    EmitPeerEvent(context, ZNET_PEER_EVENT_RECONNECTING, 0, 0);
  } else if (previous == ZNET_STATE_CONNECTED &&
             current_state == ZNET_STATE_DISCONNECTED) {
    EmitPeerEvent(context, ZNET_PEER_EVENT_CONNECTION_LOST, 0, 0);
  }
  context->last_connection_state = current_state;
}

void EmitHandshakeFailureEvent(ZNetContext* context) {
  if (!context || context->role != ContextRole::kClient || !context->client) {
    return;
  }
  const auto phase = context->client->handshake_phase();
  if (phase != ZClient::HandshakePhase::kFailed) {
    return;
  }
  const uint8_t reason =
      static_cast<uint8_t>(context->client->handshake_failure_reason());
  if (reason == ZNET_HANDSHAKE_FAILURE_NONE ||
      reason == context->last_emitted_handshake_failure) {
    return;
  }
  context->last_emitted_handshake_failure = reason;
  EmitPeerEvent(context, ZNET_PEER_EVENT_FAILURE, 0, reason);
}

void DrainRuntimeEvents(ZNetContext* context) {
  EmitConnectionStateTransitionEvents(context);
  EmitHandshakeFailureEvent(context);
  DrainP2PPeerEvents(context);
}

void WriteCappedFileName(char* output, const base::String& file_name) {
  if (!output) {
    return;
  }
  const size_t copy_size =
      std::min<size_t>(ZNET_MAX_FILE_NAME_LENGTH, file_name.size());
  if (copy_size > 0) {
    std::memcpy(output, file_name.data(), copy_size);
  }
  output[copy_size] = '\0';
}

void SetLastError(ZNetContext* context, const char* message) {
  if (!context) {
    return;
  }
  context->last_error = message ? message : "";
}

void ClearLastError(ZNetContext* context) {
  if (!context) {
    return;
  }
  context->last_error.clear();
}

ZNetResult ReturnError(ZNetContext* context,
                       ZNetResult result,
                       const char* message) {
  SetLastError(context, message);
  return result;
}

ZAsyncTransportLayer* ActiveTransport(ZNetContext* context) {
  if (!context) {
    return nullptr;
  }
  switch (context->role) {
    case ContextRole::kClient:
      return context->client.Get_UseOnlyIfYouKnowWhatYouareDoing();
    case ContextRole::kServer:
      return context->server.Get_UseOnlyIfYouKnowWhatYouareDoing();
    case ContextRole::kP2P:
      return context->p2p.Get_UseOnlyIfYouKnowWhatYouareDoing();
    case ContextRole::kNone:
      return nullptr;
  }
  return nullptr;
}

const ZAsyncTransportLayer* ActiveTransport(const ZNetContext* context) {
  if (!context) {
    return nullptr;
  }
  switch (context->role) {
    case ContextRole::kClient:
      return context->client.Get_UseOnlyIfYouKnowWhatYouareDoing();
    case ContextRole::kServer:
      return context->server.Get_UseOnlyIfYouKnowWhatYouareDoing();
    case ContextRole::kP2P:
      return context->p2p.Get_UseOnlyIfYouKnowWhatYouareDoing();
    case ContextRole::kNone:
      return nullptr;
  }
  return nullptr;
}

void CopyDefaultTransportConfig(ZNetTransportConfig& config) {
  std::memset(&config, 0, sizeof(config));
  config.use_encryption = 0;
  config.pre_shared_key = nullptr;
  config.use_compression = 0;
  config.allow_ipv6 = 0;
  config.start_threads = 0;
  config.disable_adaptive_threading = 0;
  config.dispatch_worker_count = 0;
  config.dispatch_max_queued_tasks = 0;
  config.thread_scaling_tier_count = 3;
  config.thread_scaling_tiers[0] = {32, 1};
  config.thread_scaling_tiers[1] = {64, 2};
  config.thread_scaling_tiers[2] = {128, 4};
  config.clock_asymmetry_compensation_ms = 0;
  config.chaos.drop_percent = 0;
  config.chaos.reorder_percent = 0;
  config.chaos.jitter_ms = 0;
  config.chaos.seed = 1;
}

void ApplyTransportConfig(const ZNetTransportConfig& config,
                          ZAsyncTransportLayer& transport) {
  transport.SetBuiltInTaskExecutorConfig(config.dispatch_worker_count,
                                         config.dispatch_max_queued_tasks);

  if (config.disable_adaptive_threading) {
    transport.DisableAdaptiveThreading();
  } else if (config.thread_scaling_tier_count > 0) {
    const size_t tier_count =
        config.thread_scaling_tier_count > ZNET_MAX_THREAD_SCALING_TIERS
            ? ZNET_MAX_THREAD_SCALING_TIERS
            : config.thread_scaling_tier_count;
    ZAsyncTransportLayer::ThreadScalingTier tiers[ZNET_MAX_THREAD_SCALING_TIERS]{};
    for (size_t i = 0; i < tier_count; ++i) {
      tiers[i].peer_count = config.thread_scaling_tiers[i].peer_count;
      tiers[i].dispatch_workers = config.thread_scaling_tiers[i].dispatch_workers;
    }
    transport.SetThreadScaling(tiers, tier_count);
  }
}

ZNetResult StopAndResetContext(ZNetContext* context) {
  if (!context) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (context->client) {
    context->client->Disconnect();
  }
  if (context->server) {
    context->server->Deinit();
  }
  if (context->p2p) {
    context->p2p->Deinit();
  }
  context->file_transporter.Reset();
  context->client.Reset();
  context->server.Reset();
  context->p2p.Reset();
  context->role = ContextRole::kNone;
  context->packet_payload_scratch.clear();
  while (!context->peer_events.empty()) {
    context->peer_events.pop();
  }
  context->last_connection_state = ZNET_STATE_DISCONNECTED;
  context->last_connection_state_valid = false;
  context->seen_connected_once = false;
  context->last_emitted_handshake_failure = ZNET_HANDSHAKE_FAILURE_NONE;
  return ZNET_RESULT_OK;
}

ZNetResult EnsureFileTransporter(ZNetContext* context) {
  if (!context) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (context->file_transporter) {
    return ZNET_RESULT_OK;
  }
  switch (context->role) {
    case ContextRole::kClient:
      if (!context->client) {
        return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                           "No active client transport");
      }
      context->file_transporter =
          base::MakeUnique<ZFileTransporter>(*context->client);
      return ZNET_RESULT_OK;
    case ContextRole::kServer:
      if (!context->server) {
        return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                           "No active server transport");
      }
      context->file_transporter =
          base::MakeUnique<ZFileTransporter>(*context->server);
      return ZNET_RESULT_OK;
    case ContextRole::kP2P:
      if (!context->p2p) {
        return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                           "No active p2p transport");
      }
      context->file_transporter = base::MakeUnique<ZFileTransporter>(*context->p2p);
      return ZNET_RESULT_OK;
    case ContextRole::kNone:
      return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                         "No active transport");
  }
  return ReturnError(context, ZNET_RESULT_INTERNAL_ERROR, "Unexpected role");
}

}  // namespace

extern "C" {

const char* ZNetResultToString(ZNetResult result) {
  switch (result) {
    case ZNET_RESULT_OK:
      return "ok";
    case ZNET_RESULT_INVALID_ARGUMENT:
      return "invalid_argument";
    case ZNET_RESULT_INVALID_STATE:
      return "invalid_state";
    case ZNET_RESULT_NOT_SUPPORTED:
      return "not_supported";
    case ZNET_RESULT_NOT_READY:
      return "not_ready";
    case ZNET_RESULT_IO_ERROR:
      return "io_error";
    case ZNET_RESULT_INTERNAL_ERROR:
      return "internal_error";
  }
  return "unknown";
}

ZNetContext* ZNetCreateContext(void) {
  return new ZNetContext();
}

void ZNetDestroyContext(ZNetContext* context) {
  if (!context) {
    return;
  }
  StopAndResetContext(context);
  delete context;
}

void ZNetClearLastError(ZNetContext* context) {
  ClearLastError(context);
}

const char* ZNetGetLastError(const ZNetContext* context) {
  if (!context) {
    return "context is null";
  }
  return context->last_error.empty() ? "" : context->last_error.c_str();
}

void ZNetSetLogHandler(void* user_pointer, ZNetLogHandler callback) {
#ifdef ZNET_USE_STL
  base::SetLogHandler(callback, user_pointer);
#else
  base::SetLogHandler(reinterpret_cast<base::LogHandler>(callback),
                      user_pointer);
#endif
}

void ZNetSetPeerEventHandler(ZNetContext* context,
                             void* user_pointer,
                             ZNetPeerEventHandler callback) {
  if (!context) {
    return;
  }
  context->peer_event_user_pointer = user_pointer;
  context->peer_event_handler = callback;
}

ZNetResult ZNetPollPeerEvent(ZNetContext* context, ZNetPeerEvent* out_event) {
  if (!context || !out_event) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (context->peer_events.empty()) {
    return ZNET_RESULT_NOT_READY;
  }
  *out_event = context->peer_events.front();
  context->peer_events.pop();
  return ZNET_RESULT_OK;
}

void ZNetGetDefaultTransportConfig(ZNetTransportConfig* out_config) {
  if (!out_config) {
    return;
  }
  CopyDefaultTransportConfig(*out_config);
}

void ZNetGetDefaultRateLimitConfig(ZNetRateLimitConfig* out_config) {
  if (!out_config) {
    return;
  }
  const tx::network::ZPacketQueue::RateLimitConfig defaults{};
  out_config->max_packets_per_second = defaults.max_packets_per_second;
  out_config->max_bytes_per_second = defaults.max_bytes_per_second;
  out_config->burst_allowance = defaults.burst_allowance;
}

void ZNetGetDefaultCongestionControlConfig(
    ZNetCongestionControlConfig* out_config) {
  if (!out_config) {
    return;
  }
  const tx::network::ZPacketQueue::CongestionControlConfig defaults{};
  out_config->enabled = defaults.enabled ? 1 : 0;
  out_config->min_scale_per_mille = defaults.min_scale_per_mille;
  out_config->max_scale_per_mille = defaults.max_scale_per_mille;
  out_config->additive_increase_per_window = defaults.additive_increase_per_window;
  out_config->ack_events_per_window = defaults.ack_events_per_window;
  out_config->retransmit_backoff_per_mille = defaults.retransmit_backoff_per_mille;
  out_config->drop_backoff_per_mille = defaults.drop_backoff_per_mille;
  out_config->min_data_dispatch_per_tick = defaults.min_data_dispatch_per_tick;
}

void ZNetGetDefaultSendOptions(ZNetSendOptions* out_options) {
  if (!out_options) {
    return;
  }
  out_options->packet_type = static_cast<u16>(PacketType::Message);
  out_options->destination_peer_id = ZPeerId::to_server;
  out_options->channel = ZNET_CHANNEL_DATA;
  out_options->reliable = 1;
  out_options->encrypted = 0;
  out_options->compressed = 0;
  out_options->priority = ZNET_PRIORITY_MEDIUM;
  out_options->acknowledged = 0;
  out_options->awaiting_ack = 1;
}

void ZNetGetDefaultFileTransferTuning(ZNetFileTransferTuning* out_tuning) {
  if (!out_tuning) {
    return;
  }
  const ZFileTransporter::TransferTuning defaults{};
  out_tuning->chunk_size = defaults.chunk_size;
  out_tuning->max_inflight_chunks = defaults.max_inflight_chunks;
  out_tuning->max_inflight_bytes = defaults.max_inflight_bytes;
  out_tuning->allocator_min_cached_blocks = defaults.allocator_min_cached_blocks;
  out_tuning->backpressure_sleep_ms = defaults.backpressure_sleep_ms;
  out_tuning->backpressure_timeout_ms = defaults.backpressure_timeout_ms;
}

ZNetResult ZNetStartClient(ZNetContext* context,
                           const char* address,
                           u16 port,
                           const ZNetTransportConfig* config) {
  if (!context || !address || address[0] == '\0' || port == 0) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid client address/port/context");
  }

  ZNetTransportConfig cfg{};
  CopyDefaultTransportConfig(cfg);
  if (config) {
    cfg = *config;
  }

  StopAndResetContext(context);
  context->client = base::MakeUnique<ZClient>();
  ApplyTransportConfig(cfg, *context->client);

  const ZClient::ConnectionOptions options{
      .use_encryption = cfg.use_encryption != 0,
      .pre_shared_key = MakeStringRef(cfg.pre_shared_key),
      .use_compression = cfg.use_compression != 0,
      .allow_ipv6 = cfg.allow_ipv6 != 0,
      .start_threads = cfg.start_threads != 0,
      .chaos =
          {.drop_percent = cfg.chaos.drop_percent,
           .reorder_percent = cfg.chaos.reorder_percent,
           .jitter_ms = cfg.chaos.jitter_ms,
           .seed = cfg.chaos.seed}};
  if (!context->client->Connect(MakeStringRef(address), port, options)) {
    context->client.Reset();
    return ReturnError(context, ZNET_RESULT_IO_ERROR, "Failed to start client");
  }

  context->role = ContextRole::kClient;
  context->client->SetClockAsymmetryCompensationMs(
      cfg.clock_asymmetry_compensation_ms);
  context->last_connection_state = ZNET_STATE_DISCONNECTED;
  context->last_connection_state_valid = true;
  context->seen_connected_once = false;
  context->last_emitted_handshake_failure = ZNET_HANDSHAKE_FAILURE_NONE;
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetStartServer(ZNetContext* context,
                           u16 port,
                           const ZNetTransportConfig* config) {
  if (!context || port == 0) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid server port/context");
  }

  ZNetTransportConfig cfg{};
  CopyDefaultTransportConfig(cfg);
  if (config) {
    cfg = *config;
  }

  StopAndResetContext(context);
  context->server = base::MakeUnique<ZServer>();
  ApplyTransportConfig(cfg, *context->server);

  const ZServer::StartOptions options{
      .use_encryption = cfg.use_encryption != 0,
      .pre_shared_key = MakeStringRef(cfg.pre_shared_key),
      .use_compression = cfg.use_compression != 0,
      .allow_ipv6 = cfg.allow_ipv6 != 0,
      .start_threads = cfg.start_threads != 0,
      .chaos =
          {.drop_percent = cfg.chaos.drop_percent,
           .reorder_percent = cfg.chaos.reorder_percent,
           .jitter_ms = cfg.chaos.jitter_ms,
           .seed = cfg.chaos.seed}};
  if (!context->server->Begin(port, options)) {
    context->server.Reset();
    return ReturnError(context, ZNET_RESULT_IO_ERROR, "Failed to start server");
  }

  context->role = ContextRole::kServer;
  context->server->SetClockAsymmetryCompensationMs(
      cfg.clock_asymmetry_compensation_ms);
  context->last_connection_state = ZNET_STATE_DISCONNECTED;
  context->last_connection_state_valid = true;
  context->seen_connected_once = false;
  context->last_emitted_handshake_failure = ZNET_HANDSHAKE_FAILURE_NONE;
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetStartP2PHost(ZNetContext* context,
                            u16 port,
                            const ZNetTransportConfig* config) {
  if (!context || port == 0) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid p2p host port/context");
  }

  ZNetTransportConfig cfg{};
  CopyDefaultTransportConfig(cfg);
  if (config) {
    cfg = *config;
  }

  StopAndResetContext(context);
  context->p2p = base::MakeUnique<ZP2PNode>();
  ApplyTransportConfig(cfg, *context->p2p);

  const ZP2PNode::StartOptions options{
      .use_encryption = cfg.use_encryption != 0,
      .pre_shared_key = MakeStringRef(cfg.pre_shared_key),
      .use_compression = cfg.use_compression != 0,
      .allow_ipv6 = cfg.allow_ipv6 != 0,
      .start_threads = cfg.start_threads != 0,
      .chaos =
          {.drop_percent = cfg.chaos.drop_percent,
           .reorder_percent = cfg.chaos.reorder_percent,
           .jitter_ms = cfg.chaos.jitter_ms,
           .seed = cfg.chaos.seed}};
  if (!context->p2p->Begin(port, options)) {
    context->p2p.Reset();
    return ReturnError(context, ZNET_RESULT_IO_ERROR, "Failed to start p2p host");
  }

  context->role = ContextRole::kP2P;
  context->p2p->SetClockAsymmetryCompensationMs(cfg.clock_asymmetry_compensation_ms);
  context->last_connection_state = ZNET_STATE_DISCONNECTED;
  context->last_connection_state_valid = true;
  context->seen_connected_once = false;
  context->last_emitted_handshake_failure = ZNET_HANDSHAKE_FAILURE_NONE;
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetStartP2PClient(ZNetContext* context,
                              const char* host_ip,
                              u16 host_port,
                              u16 local_port,
                              const ZNetTransportConfig* config) {
  if (!context || !host_ip || host_ip[0] == '\0' || host_port == 0 ||
      local_port == 0) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid p2p client parameters");
  }

  ZNetTransportConfig cfg{};
  CopyDefaultTransportConfig(cfg);
  if (config) {
    cfg = *config;
  }

  StopAndResetContext(context);
  context->p2p = base::MakeUnique<ZP2PNode>();
  ApplyTransportConfig(cfg, *context->p2p);

  const ZP2PNode::StartOptions options{
      .use_encryption = cfg.use_encryption != 0,
      .pre_shared_key = MakeStringRef(cfg.pre_shared_key),
      .use_compression = cfg.use_compression != 0,
      .allow_ipv6 = cfg.allow_ipv6 != 0,
      .start_threads = cfg.start_threads != 0,
      .chaos =
          {.drop_percent = cfg.chaos.drop_percent,
           .reorder_percent = cfg.chaos.reorder_percent,
           .jitter_ms = cfg.chaos.jitter_ms,
           .seed = cfg.chaos.seed}};
  if (!context->p2p->Connect(MakeStringRef(host_ip), host_port, local_port,
                             options)) {
    context->p2p.Reset();
    return ReturnError(context, ZNET_RESULT_IO_ERROR,
                       "Failed to start p2p client");
  }

  context->role = ContextRole::kP2P;
  context->p2p->SetClockAsymmetryCompensationMs(cfg.clock_asymmetry_compensation_ms);
  context->last_connection_state = ZNET_STATE_DISCONNECTED;
  context->last_connection_state_valid = true;
  context->seen_connected_once = false;
  context->last_emitted_handshake_failure = ZNET_HANDSHAKE_FAILURE_NONE;
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetStop(ZNetContext* context) {
  if (!context) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  StopAndResetContext(context);
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetUpdate(ZNetContext* context) {
  if (!context) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  switch (context->role) {
    case ContextRole::kClient:
      if (!context->client) {
        return ReturnError(context, ZNET_RESULT_INVALID_STATE, "Client is null");
      }
      context->client->Update();
      DrainRuntimeEvents(context);
      ClearLastError(context);
      return ZNET_RESULT_OK;
    case ContextRole::kServer:
      if (!context->server) {
        return ReturnError(context, ZNET_RESULT_INVALID_STATE, "Server is null");
      }
      if (!context->server->Update()) {
        return ReturnError(context, ZNET_RESULT_IO_ERROR, "Server update failed");
      }
      DrainRuntimeEvents(context);
      ClearLastError(context);
      return ZNET_RESULT_OK;
    case ContextRole::kP2P:
      if (!context->p2p) {
        return ReturnError(context, ZNET_RESULT_INVALID_STATE, "P2P node is null");
      }
      if (!context->p2p->Update()) {
        return ReturnError(context, ZNET_RESULT_IO_ERROR,
                           "P2P node update failed");
      }
      DrainRuntimeEvents(context);
      ClearLastError(context);
      return ZNET_RESULT_OK;
    case ContextRole::kNone:
      return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                         "No active transport");
  }
  return ReturnError(context, ZNET_RESULT_INTERNAL_ERROR, "Unexpected role");
}

ZNetRole ZNetGetRole(const ZNetContext* context) {
  if (!context) {
    return ZNET_ROLE_NONE;
  }
  switch (context->role) {
    case ContextRole::kClient:
      return ZNET_ROLE_CLIENT;
    case ContextRole::kServer:
      return ZNET_ROLE_SERVER;
    case ContextRole::kP2P:
      return ZNET_ROLE_P2P;
    case ContextRole::kNone:
      return ZNET_ROLE_NONE;
  }
  return ZNET_ROLE_NONE;
}

ZNetConnectionState ZNetGetConnectionState(const ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return ZNET_STATE_DISCONNECTED;
  }
  return ToPublicState(transport->state());
}

ZNetResult ZNetGetP2PNodeType(const ZNetContext* context,
                              ZNetP2PNodeType* out_type) {
  if (!context || !out_type) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (context->role != ContextRole::kP2P || !context->p2p) {
    return ZNET_RESULT_INVALID_STATE;
  }
  *out_type = context->p2p->is_host() ? ZNET_P2P_HOST : ZNET_P2P_CLIENT;
  return ZNET_RESULT_OK;
}

ZNetResult ZNetBecomeP2PHost(ZNetContext* context) {
  if (!context) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (context->role != ContextRole::kP2P || !context->p2p) {
    return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                       "Active transport is not a p2p node");
  }
  context->p2p->BecomeHost();
  if (!context->p2p->is_host()) {
    return ReturnError(context, ZNET_RESULT_IO_ERROR,
                       "Failed to promote p2p node to host");
  }
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetSetRateLimitConfig(ZNetContext* context,
                                  const ZNetRateLimitConfig* config) {
  if (!context || !config) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                       "No active transport");
  }
  tx::network::ZPacketQueue::RateLimitConfig native{};
  native.max_packets_per_second = config->max_packets_per_second;
  native.max_bytes_per_second = config->max_bytes_per_second;
  native.burst_allowance = config->burst_allowance;
  transport->SetRateLimitConfig(native);
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetSetCongestionControlConfig(
    ZNetContext* context,
    const ZNetCongestionControlConfig* config) {
  if (!context || !config) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                       "No active transport");
  }
  tx::network::ZPacketQueue::CongestionControlConfig native{};
  native.enabled = config->enabled != 0;
  native.min_scale_per_mille = config->min_scale_per_mille;
  native.max_scale_per_mille = config->max_scale_per_mille;
  native.additive_increase_per_window = config->additive_increase_per_window;
  native.ack_events_per_window = config->ack_events_per_window;
  native.retransmit_backoff_per_mille = config->retransmit_backoff_per_mille;
  native.drop_backoff_per_mille = config->drop_backoff_per_mille;
  native.min_data_dispatch_per_tick = config->min_data_dispatch_per_tick;
  transport->SetCongestionControlConfig(native);
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetGetOutboundPressure(const ZNetContext* context,
                                   ZNetOutboundPressure* out_pressure) {
  if (!context || !out_pressure) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return ZNET_RESULT_INVALID_STATE;
  }
  const ZAsyncTransportLayer::OutboundPressure pressure =
      transport->GetOutboundPressure();
  out_pressure->control_queued_packets = pressure.control_queued_packets;
  out_pressure->control_queued_bytes = pressure.control_queued_bytes;
  out_pressure->data_queued_packets = pressure.data_queued_packets;
  out_pressure->data_queued_bytes = pressure.data_queued_bytes;
  out_pressure->awaiting_ack_packets = pressure.awaiting_ack_packets;
  out_pressure->awaiting_ack_bytes = pressure.awaiting_ack_bytes;
  return ZNET_RESULT_OK;
}

size_t ZNetGetCongestionScalePerMille(const ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return 0;
  }
  return transport->GetCongestionScalePerMille();
}

u64 ZNetGetLocalClockTickMs(const ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return 0;
  }
  return transport->GetLocalClockTickMs();
}

u64 ZNetGetSynchronizedClockTickMs(const ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return 0;
  }
  return transport->GetSynchronizedClockTickMs();
}

int ZNetIsClockSynchronized(const ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return 0;
  }
  return transport->IsClockSynchronized() ? 1 : 0;
}

ZNetResult ZNetSetClockAsymmetryCompensationMs(ZNetContext* context,
                                                i32 compensation_ms) {
  if (!context) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                       "No active transport");
  }
  transport->SetClockAsymmetryCompensationMs(compensation_ms);
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

i32 ZNetGetClockAsymmetryCompensationMs(const ZNetContext* context) {
  const ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return 0;
  }
  return transport->GetClockAsymmetryCompensationMs();
}

ZNetResult ZNetGetClientHandshakeStatus(const ZNetContext* context,
                                        ZNetClientHandshakeStatus* out_status) {
  if (!context || !out_status) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (context->role != ContextRole::kClient || !context->client) {
    return ZNET_RESULT_INVALID_STATE;
  }
  out_status->phase =
      static_cast<u8>(context->client->handshake_phase());
  out_status->failure_reason =
      static_cast<u8>(context->client->handshake_failure_reason());
  out_status->negotiated_protocol_version =
      context->client->negotiated_protocol_version();
  out_status->negotiated_feature_flags =
      context->client->negotiated_feature_flags();
  return ZNET_RESULT_OK;
}

ZNetResult ZNetSend(ZNetContext* context,
                    const ZNetSendOptions* options,
                    const void* payload,
                    size_t payload_size) {
  if (!context || !options) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (payload_size > 0 && !payload) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Payload pointer is null but payload_size > 0");
  }
  ZAsyncTransportLayer* transport = ActiveTransport(context);
  if (!transport) {
    return ReturnError(context, ZNET_RESULT_INVALID_STATE,
                       "No active transport");
  }
  if (options->channel > ZNET_CHANNEL_DATA || options->priority > ZNET_PRIORITY_CRITICAL) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid channel or priority");
  }

  const PackageFlags flags{
      .reliable = static_cast<u8>(options->reliable != 0),
      .encrypted = static_cast<u8>(options->encrypted != 0),
      .compressed = static_cast<u8>(options->compressed != 0),
      .priority = static_cast<u8>(ToPriority(options->priority)),
      .acknowledged = static_cast<u8>(options->acknowledged != 0),
      .awaiting_ack = static_cast<u8>(options->awaiting_ack != 0),
      .reserved = 0};

  OutgoingPacket packet;
  if (payload_size > 0) {
    packet = OutgoingPacket(
        options->destination_peer_id,
        static_cast<PacketType>(options->packet_type),
        ToChannel(options->channel),
        flags,
        base::Span<byte>(reinterpret_cast<const byte*>(payload), payload_size));
  } else {
    packet = OutgoingPacket(options->destination_peer_id,
                            static_cast<PacketType>(options->packet_type),
                            ToChannel(options->channel), flags);
  }

  bool enqueued = false;
  if (context->role == ContextRole::kP2P && context->p2p) {
    enqueued = context->p2p->SendPacket(std::move(packet));
  } else {
    enqueued = transport->EnqueuePacket(std::move(packet));
  }
  if (!enqueued) {
    return ReturnError(context, ZNET_RESULT_IO_ERROR, "Failed to enqueue packet");
  }
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetPoll(ZNetContext* context,
                    ZNetPacketChannel channel,
                    ZNetPacketView* out_packet) {
  if (!context || !out_packet) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (channel != ZNET_CHANNEL_CONTROL && channel != ZNET_CHANNEL_DATA) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }

  IncomingPacket packet;
  const PacketChannelType native_channel =
      channel == ZNET_CHANNEL_CONTROL ? PacketChannelType::Control
                                      : PacketChannelType::Data;
  bool has_packet = false;
  switch (context->role) {
    case ContextRole::kClient:
      if (!context->client) {
        return ZNET_RESULT_INVALID_STATE;
      }
      has_packet = context->client->Poll(native_channel, packet);
      break;
    case ContextRole::kServer:
      if (!context->server) {
        return ZNET_RESULT_INVALID_STATE;
      }
      has_packet = context->server->Poll(native_channel, packet);
      break;
    case ContextRole::kP2P:
      if (!context->p2p) {
        return ZNET_RESULT_INVALID_STATE;
      }
      has_packet = context->p2p->Poll(native_channel, packet);
      break;
    case ContextRole::kNone:
      return ZNET_RESULT_INVALID_STATE;
  }

  if (!has_packet) {
    return ZNET_RESULT_NOT_READY;
  }

  context->packet_payload_scratch.resize(packet.data.size());
  if (!packet.data.empty()) {
    std::memcpy(context->packet_payload_scratch.data(), packet.data.data(),
                packet.data.size());
  }

  out_packet->packet_type = static_cast<u16>(packet.type);
  out_packet->source_peer_id = packet.source_peer_id;
  out_packet->acknowledgement_number = packet.acknowledgement_number;
  out_packet->sequence_number = packet.sequence_number;
  out_packet->channel =
      packet.channel == PacketChannelType::Control ? ZNET_CHANNEL_CONTROL
                                                   : ZNET_CHANNEL_DATA;
  out_packet->reliable = packet.flags.reliable;
  out_packet->encrypted = packet.flags.encrypted;
  out_packet->compressed = packet.flags.compressed;
  out_packet->priority = packet.flags.priority;
  out_packet->acknowledged = packet.flags.acknowledged;
  out_packet->awaiting_ack = packet.flags.awaiting_ack;
  out_packet->payload = context->packet_payload_scratch.empty()
                            ? nullptr
                            : context->packet_payload_scratch.data();
  out_packet->payload_size = context->packet_payload_scratch.size();
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetSendFile(ZNetContext* context,
                        const char* file_path,
                        u32 destination_peer_id,
                        const ZNetFileTransferTuning* tuning) {
  if (!context || !file_path || file_path[0] == '\0') {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid file transfer arguments");
  }
  const ZNetResult transport_result = EnsureFileTransporter(context);
  if (transport_result != ZNET_RESULT_OK) {
    return transport_result;
  }

  ZFileTransporter::TransferTuning native_tuning{};
  if (tuning) {
    native_tuning.chunk_size = tuning->chunk_size;
    native_tuning.max_inflight_chunks = tuning->max_inflight_chunks;
    native_tuning.max_inflight_bytes = tuning->max_inflight_bytes;
    native_tuning.allocator_min_cached_blocks = tuning->allocator_min_cached_blocks;
    native_tuning.backpressure_sleep_ms = tuning->backpressure_sleep_ms;
    native_tuning.backpressure_timeout_ms = tuning->backpressure_timeout_ms;
  }

  const bool success =
      context->file_transporter->SendFile(base::Path(base::String(file_path)),
                                          ZPeerId(destination_peer_id),
                                          native_tuning);
  if (!success) {
    return ReturnError(context, ZNET_RESULT_IO_ERROR, "Failed to send file");
  }
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetReceiveFileChunk(ZNetContext* context,
                                const ZNetPacketView* packet,
                                const char* temp_directory,
                                ZNetFileReceiveStatus* out_status) {
  if (!context || !packet) {
    return ZNET_RESULT_INVALID_ARGUMENT;
  }
  if (packet->packet_type != static_cast<u16>(PacketType::FileTransfer)) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Packet is not a file transfer chunk");
  }
  if (packet->payload_size > 0 && !packet->payload) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "File transfer packet payload is null");
  }

  const ZNetResult transport_result = EnsureFileTransporter(context);
  if (transport_result != ZNET_RESULT_OK) {
    return transport_result;
  }

  const char* temp_dir =
      (temp_directory && temp_directory[0] != '\0') ? temp_directory : ".";
  const byte* payload_data =
      reinterpret_cast<const byte*>(packet->payload);
  tx::network::ZFileTransporter::TransferChunk chunk{};
  if (!context->file_transporter->ParseTransferChunkPayload(
          base::Span<byte>(payload_data, packet->payload_size), chunk)) {
    return ReturnError(context, ZNET_RESULT_IO_ERROR,
                       "Malformed file transfer chunk payload");
  }

  bool completed = false;
  if (!context->file_transporter->StreamChunkToFile(
          chunk, base::Path(base::String(temp_dir)), &completed)) {
    return ReturnError(context, ZNET_RESULT_IO_ERROR,
                       "Failed to ingest incoming file transfer chunk");
  }

  if (out_status) {
    std::memset(out_status, 0, sizeof(*out_status));
    tx::network::ZFileTransporter::StreamProgress progress{};
    if (context->file_transporter->GetStreamProgress(chunk.transfer_id, progress)) {
      out_status->transfer_id = progress.transfer_id;
      out_status->file_size = progress.file_size;
      out_status->received_chunks = progress.received_chunks;
      out_status->total_chunks = progress.total_chunks;
      out_status->completed = progress.completed ? 1 : 0;
      out_status->has_file_name = progress.has_file_name ? 1 : 0;
      if (progress.has_file_name) {
        WriteCappedFileName(out_status->file_name, progress.file_name);
      } else {
        out_status->file_name[0] = '\0';
      }
    } else {
      out_status->transfer_id = chunk.transfer_id;
      out_status->file_size = chunk.file_size;
      out_status->received_chunks = chunk.chunk_index + 1;
      out_status->total_chunks = chunk.total_chunks;
      out_status->completed = completed ? 1 : 0;
      out_status->has_file_name = chunk.has_file_name ? 1 : 0;
      if (chunk.has_file_name) {
        WriteCappedFileName(out_status->file_name, chunk.file_name);
      } else {
        out_status->file_name[0] = '\0';
      }
    }
  }

  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetFinalizeReceivedFile(ZNetContext* context,
                                    u64 transfer_id,
                                    const char* output_path) {
  if (!context || transfer_id == 0 || !output_path || output_path[0] == '\0') {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid finalize file arguments");
  }
  const ZNetResult transport_result = EnsureFileTransporter(context);
  if (transport_result != ZNET_RESULT_OK) {
    return transport_result;
  }
  if (!context->file_transporter->FinalizeStreamedFile(
          transfer_id, base::Path(base::String(output_path)))) {
    return ReturnError(context, ZNET_RESULT_IO_ERROR,
                       "Failed to finalize streamed file");
  }
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

ZNetResult ZNetAbortReceivedFile(ZNetContext* context, u64 transfer_id) {
  if (!context || transfer_id == 0) {
    return ReturnError(context, ZNET_RESULT_INVALID_ARGUMENT,
                       "Invalid abort file arguments");
  }
  const ZNetResult transport_result = EnsureFileTransporter(context);
  if (transport_result != ZNET_RESULT_OK) {
    return transport_result;
  }
  context->file_transporter->AbortStreamedFile(transfer_id);
  ClearLastError(context);
  return ZNET_RESULT_OK;
}

void ZNetResetPacketAllocatorStats(void) {
  tx::network::PacketBufferPool::Instance().ResetStats();
}

int ZNetGetPacketAllocatorStats(ZNetPacketAllocatorStats* out_stats) {
  if (!out_stats) {
    return 0;
  }

  const tx::network::PacketBufferPool::Stats global =
      tx::network::PacketBufferPool::Instance().GetStats();
  base::Array<tx::network::PacketBufferPool::ClassStats,
              tx::network::PacketBufferPool::kClassCount>
      class_stats{};
  tx::network::PacketBufferPool::Instance().GetClassStats(class_stats);

  out_stats->total_requests = global.total_requests;
  out_stats->pool_hits = global.pool_hits;
  out_stats->fallback_allocations = global.fallback_allocations;
  out_stats->class_count = tx::network::PacketBufferPool::kClassCount;

  for (mem_size i = 0; i < out_stats->class_count &&
                      i < ZNET_MAX_PACKET_ALLOCATOR_CLASSES;
       ++i) {
    out_stats->classes[i].block_size = class_stats[i].block_size;
    out_stats->classes[i].request_count = class_stats[i].request_count;
    out_stats->classes[i].hit_count = class_stats[i].hit_count;
    out_stats->classes[i].target_cached_blocks =
        class_stats[i].target_cached_blocks;
    out_stats->classes[i].cached_free_blocks = class_stats[i].cached_free_blocks;
    out_stats->classes[i].ewma_demand = class_stats[i].ewma_demand;
  }
  return 1;
}

void ZNetDumpPacketAllocatorStats(void) {
  ZNetPacketAllocatorStats stats{};
  if (!ZNetGetPacketAllocatorStats(&stats)) {
    std::fprintf(stderr, "Allocator stats unavailable\n");
    return;
  }
  const double hit_rate =
      stats.total_requests == 0
          ? 0.0
          : (100.0 * static_cast<double>(stats.pool_hits) /
             static_cast<double>(stats.total_requests));
  std::fprintf(stderr,
               "PacketAllocator total=%zu hits=%zu hit_rate=%.2f%% fallback=%zu\n",
               stats.total_requests, stats.pool_hits, hit_rate,
               stats.fallback_allocations);
  for (mem_size i = 0; i < stats.class_count &&
                      i < ZNET_MAX_PACKET_ALLOCATOR_CLASSES;
       ++i) {
    const ZNetPacketAllocatorClassStats& c = stats.classes[i];
    if (c.request_count == 0 && c.cached_free_blocks == 0) {
      continue;
    }
    std::fprintf(stderr,
                 "  class[%zu] block=%zu req=%zu hit=%zu target=%zu free=%zu "
                 "ewma=%.2f\n",
                 i, c.block_size, c.request_count, c.hit_count,
                 c.target_cached_blocks, c.cached_free_blocks, c.ewma_demand);
  }
}

}  // extern "C"

ZNET_API void* tx::network::ZCreateContext() {
  return ZNetCreateContext();
}

ZNET_API void tx::network::ZDestroyContext(void* context) {
  ZNetDestroyContext(reinterpret_cast<ZNetContext*>(context));
}

ZNET_API void tx::network::SetBaseLogHandlerFwd(
    void* user_pointer,
    void (*callback)(void* user_pointer, const char* channel_name, int level,
                     const char* msg)) {
  ZNetSetLogHandler(user_pointer, callback);
}

ZNET_API void tx::network::ZResetPacketAllocatorStats() {
  ZNetResetPacketAllocatorStats();
}

ZNET_API bool tx::network::ZGetPacketAllocatorStats(
    ZPacketAllocatorStats* out_stats) {
  if (!out_stats) {
    return false;
  }

  ZNetPacketAllocatorStats c_stats{};
  if (!ZNetGetPacketAllocatorStats(&c_stats)) {
    return false;
  }

  out_stats->total_requests = c_stats.total_requests;
  out_stats->pool_hits = c_stats.pool_hits;
  out_stats->fallback_allocations = c_stats.fallback_allocations;
  out_stats->class_count = c_stats.class_count;

  for (mem_size i = 0; i < out_stats->class_count &&
                      i < ZPacketAllocatorStats::kMaxClasses;
       ++i) {
    out_stats->classes[i].block_size = c_stats.classes[i].block_size;
    out_stats->classes[i].request_count = c_stats.classes[i].request_count;
    out_stats->classes[i].hit_count = c_stats.classes[i].hit_count;
    out_stats->classes[i].target_cached_blocks =
        c_stats.classes[i].target_cached_blocks;
    out_stats->classes[i].cached_free_blocks =
        c_stats.classes[i].cached_free_blocks;
    out_stats->classes[i].ewma_demand = c_stats.classes[i].ewma_demand;
  }
  return true;
}

ZNET_API void tx::network::ZDumpPacketAllocatorStats() {
  ZNetDumpPacketAllocatorStats();
}
